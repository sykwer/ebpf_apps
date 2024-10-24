import csv
import os
import subprocess
import time

from bcc import BPF


def save_pid_to_cmd(dir: str) -> None:
    output_file = os.path.join(dir, "pid_to_cmdline.csv")
    ps_result = subprocess.run(["ps", "-eo", "pid,cmd"], capture_output=True, text=True)

    with open(output_file, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["pid", "cmd"])
        for line in ps_result.stdout.strip().split("\n")[1:]:
            pid, cmd = line.strip().split(None, 1)
            writer.writerow([pid, cmd])


if __name__ == "__main__":
    OUTPUT_DIR = os.path.join("output", str(int(time.time())))
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    b = BPF(src_file="ebpf.c")
    b.attach_kprobe(event="ip_send_skb", fn_name="count_send_bytes")
    b.attach_kprobe(event="ip_rcv", fn_name="count_recv_bytes")

    send_log_path = os.path.join(OUTPUT_DIR, "send.log")
    recv_log_path = os.path.join(OUTPUT_DIR, "recv.log")
    save_pid_to_cmd(OUTPUT_DIR)

    try:
        with open(send_log_path, "w") as send_log, open(recv_log_path, "w") as recv_log:
            send_log.write("timestamp,pid,tid,comm,bytes\n")
            recv_log.write("timestamp,pid,tid,comm,bytes\n")

            while True:
                send_bytes_count = b.get_table("send_bytes_count")
                recv_bytes_count = b.get_table("recv_bytes_count")

                current_time = time.time()

                for key, val in send_bytes_count.items():
                    send_log.write(
                        f"{current_time},{key.pid},{key.tid},{key.comm.decode('utf-8', 'replace')},{val.value}\n"
                    )

                for key, val in recv_bytes_count.items():
                    recv_log.write(
                        f"{current_time},{key.pid},{key.tid},{key.comm.decode('utf-8', 'replace')},{val.value}\n"
                    )

                send_bytes_count.clear()
                recv_bytes_count.clear()

                time.sleep(1)

    except KeyboardInterrupt:
        os.system(f"chmod 777 {OUTPUT_DIR}")
        print("Interrupted by user, shutting down...")
