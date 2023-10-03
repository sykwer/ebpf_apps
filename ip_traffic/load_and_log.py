from bcc import BPF
import time

b = BPF(src_file="ebpf.c")
b.attach_kprobe(event="ip_send_skb", fn_name="count_send_bytes")
b.attach_kprobe(event="ip_rcv", fn_name="count_recv_bytes")

send_log = open("send.log", "w")
recv_log = open("recv.log", "w")

while True:
    send_bytes_count = b.get_table("send_bytes_count")
    recv_bytes_count = b.get_table("recv_bytes_count")

    for key, val in send_bytes_count.items():
        send_log.write("{},{},{},{}\n".format(time.time(), key.pid, key.comm.decode('utf-8', 'replace'), val.value))
    for key, val in recv_bytes_count.items():
        recv_log.write("{},{},{},{}\n".format(time.time(), key.pid, key.comm.decode('utf-8', 'replace'), val.value))

    send_bytes_count.clear()
    recv_bytes_count.clear()

    time.sleep(1)

send_log.close()
recv_log.close()
