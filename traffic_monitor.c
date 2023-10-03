#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(send_bytes_count, struct key_t);
BPF_HASH(recv_bytes_count, struct key_t);

int count_send_bytes(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    val = send_bytes_count.lookup_or_init(&key, &zero);
    if (val) {
        (*val) += skb->len;
    }

    return 0;
}

int count_recv_bytes(struct pt_regs *ctx, struct sk_buff *skb) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    val = recv_bytes_count.lookup_or_init(&key, &zero);
    if (val) {
        (*val) += skb->len;
    }

    return 0;
}
