
#include <linux/bpf.h>
#include <linux/ptrace.h>

// Define the eBPF map to store the counts
BPF_PERCPU_ARRAY(counts, long long, 2); // Two entries: true and false

// Define the kretprobe handler
int kretprobe_handler(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx); // Get the return value
    long long *count = bpf_map_lookup_elem(&counts, &ret);
    if (count) {
        (*count)++;
    }

    bpf_map_update_elem(&counts, &ret, count, BPF_ANY);
    return 0;
}
