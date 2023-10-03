from bcc import BPF
import time

# Load BPF program
with open("traffic_monitor.c", "r") as f:
    bpf_text = f.read()

b = BPF(text=bpf_text)
b.attach_kprobe(event="ip_rcv", fn_name="count_bytes")
b.attach_kprobe(event="ipt_do_table", fn_name="count_bytes")

log_path = "lo_traffic.log"

while True:
    try:
        with open(log_path, "a") as log_file:
            for k, v in b["bytes_count"].items():
                log_file.write("{},{},{},{}\n".format(time.time(), k.pid, k.comm, v.value))
            b["bytes_count"].clear()
        time.sleep(1)
    except KeyboardInterrupt:
        break
