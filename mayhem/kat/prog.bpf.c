/* Tiny BPF object for the libbpf known-answer probe; compiled with `clang -target bpf`. */
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, __u32);
} flows SEC(".maps");

SEC("xdp")
int xdp_pass_all(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("socket")
int sock_filter(struct __sk_buff *skb)
{
	return skb->len > 64;
}

char LICENSE[] SEC("license") = "GPL";
