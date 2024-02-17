//go:build ignore

#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define EVENTS_RING_SIZE (4*4096)
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct ipv4_lpm_key
{
  __u32 prefixlen;
  __u32 data;
};

struct event
{
  struct in_addr dst;
  __u8 comm[TASK_COMM_LEN];
};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, EVENTS_RING_SIZE);
} events SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} denied_ipaddr_map SEC(".maps");

const struct event *unused __attribute__((unused));
const struct ipv4_lpm_key *unused2 __attribute__((unused));

SEC("kprobe/security_socket_connect")
int handle_security_socket_connect(struct pt_regs *ctx)
{
  struct event evt;
  struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);

  __builtin_memset(&evt, 0, sizeof(evt));

  sa_family_t fam;
  bpf_core_read(&fam, sizeof(fam), &address->sa_family);

  if (fam != AF_INET)
  {
    return 0;
  }

  struct sockaddr_in *addr = (struct sockaddr_in *)address;

  bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
  evt.dst = BPF_CORE_READ(addr, sin_addr);

  struct ipv4_lpm_key key = {
      .prefixlen = 32,
      .data = evt.dst.s_addr
  };

  if (bpf_map_lookup_elem(&denied_ipaddr_map, &key)) {
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    // bpf_override_return(ctx, -1);
  }

  return 0;
}