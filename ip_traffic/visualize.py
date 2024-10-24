import argparse
import re

import matplotlib.pyplot as plt
import pandas as pd

MAX_LEGEND_LEN = 200


def shorten_cmd(cmd: str) -> str:
    node_match = re.search(r'__node:=(\S+)', cmd)
    ns_match = re.search(r'__ns:=(\S+)', cmd)

    node = node_match.group(1) if node_match else None
    ns = ns_match.group(1) if ns_match else None

    return f"{ns}/{node}" if node and ns else cmd[:MAX_LEGEND_LEN]


def plot_traffic_core(log_file: str, pid_to_cmd, output_path: str) -> None:
    df = pd.read_csv(log_file, header=0,
                     names=["timestamp", "pid", "tid", "comm", "bytes"])

    df = pd.merge(df, pid_to_cmd, on="pid", how="left")
    df = df.dropna(subset=["cmd"])
    df["cmd"] = df["cmd"].apply(shorten_cmd)
    df_grouped = df.groupby(["tid", "cmd"]).sum().nlargest(10, "bytes")

    for tid, cmd in df_grouped.index:
        data = df[(df["tid"] == tid) & (df["cmd"] == cmd)]
        plt.plot(data["timestamp"].values, data["bytes"].values,
                 label=f"{tid}:{cmd[:MAX_LEGEND_LEN]}")

    plt.legend(loc="upper left", fontsize=6, bbox_to_anchor=(-0.05, -0.15))
    plt.xlabel("Timestamp")
    plt.ylabel("Bytes per Second")
    plt.title(log_file.split("/")[-1])
    plt.savefig(output_path, format="pdf", bbox_inches='tight')
    plt.close()


def plot_traffic(dir: str) -> None:
    pid_to_cmd = pd.read_csv(f"{dir}/pid_to_cmdline.csv")
    plot_traffic_core(f"{dir}/send.log", pid_to_cmd, f"{dir}/send.pdf")
    plot_traffic_core(f"{dir}/recv.log", pid_to_cmd, f"{dir}/recv.pdf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dir", help="Directory containing log files", type=str)
    args = parser.parse_args()

    plot_traffic(args.dir)
