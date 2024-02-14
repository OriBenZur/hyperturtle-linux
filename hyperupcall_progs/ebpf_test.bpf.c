// #include "vmlinux.h"               /* all kernel types */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} packets SEC(".maps");

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
	__u32 key = 0;
	__u64 counter = 0;
	__u64 *p = bpf_map_lookup_elem(&packets, &key);
	if (p != 0) {
		counter = *p;
	}
	counter++;
	bpf_map_update_elem(&packets, &key, &counter, 0);
	return XDP_PASS;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";