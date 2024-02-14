from bcc import BPF
import time

# Define the eBPF program
bpf_program = """
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <linux/kvm_host.h>
#include <bcc/proto.h>

// Define the eBPF map to store the counts
BPF_ARRAY(counts, long long, 1024); // Two entries: true and false

// Define the kprobe handler
//int kretprobe_handler(struct pt_regs *ctx, struct kvm_vcpu *vcpu) {
int kretprobe_handler(struct pt_regs *ctx) {
    //int is_guest = (vcpu->arch.hflags & HF_GUEST_MASK) ? 1 : 0; // Get the return value
    //counts.increment(is_guest);
    int ret = PT_REGS_RC(ctx); // Get the return value
    counts.increment(ret);
    
    
    return 0;
}
"""

# Load and attach the eBPF program
b = BPF(text=bpf_program)
b.attach_kretprobe(event="get_user_pages_fast_only", fn_name="kretprobe_handler")

# Print the contents of the maps every 2 seconds
while True:
    print([b["counts"][i].value for i in range(4)])
    # print("Counts:", b["counts"][0].value, b["counts"][1].value)
    time.sleep(2)
