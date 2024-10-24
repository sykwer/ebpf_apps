#include <bcc/proto.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>

struct key_t {
  u32 pid;
  u32 tid;
  char comm[TASK_COMM_LEN];
};

BPF_HASH(send_bytes_count, struct key_t);
BPF_HASH(recv_bytes_count, struct key_t);

int count_send_bytes(struct pt_regs *ctx, struct net *net,
                     struct sk_buff *skb) {
  struct key_t key = {};
  u64 zero = 0, *val;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  key.pid = pid_tgid >> 32;
  key.tid = pid_tgid & 0xFFFFFFFF;
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

  u64 pid_tgid = bpf_get_current_pid_tgid();
  key.pid = pid_tgid >> 32;
  key.tid = pid_tgid & 0xFFFFFFFF;
  bpf_get_current_comm(&key.comm, sizeof(key.comm));

  val = recv_bytes_count.lookup_or_init(&key, &zero);
  if (val) {
    (*val) += skb->len;
  }

  return 0;
}
