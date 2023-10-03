import pandas as pd
import matplotlib.pyplot as plt

def plot_traffic(logfile, pdf_name):
    df = pd.read_csv(logfile, header=None, names=["timestamp", "pid", "comm", "bytes"])
    df_grouped = df.groupby(["pid", "comm"]).sum().nlargest(10, "bytes")
    top_pids = df_grouped.index.get_level_values(0).tolist()

    for pid, comm in df_grouped.index:
        data = df[(df["pid"] == pid) & (df["comm"] == comm)]
        plt.plot(data["timestamp"].values, data["bytes"].values, label="{}:{}".format(pid, comm))

    plt.legend(loc="upper left")
    plt.xlabel("Timestamp")
    plt.ylabel("Bytes per Second")
    plt.title(logfile)

    plt.savefig(pdf_name, format="pdf")
    plt.close()

plot_traffic("send.log", "send.pdf")
plot_traffic("recv.log", "recv.pdf")

