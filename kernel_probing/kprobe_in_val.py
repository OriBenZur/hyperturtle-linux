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

#define N_ARGS 5

// Define the eBPF map to store the counts
BPF_ARRAY(args, u64, N_ARGS); // Two entries: true and false

// Define the kprobe handler
//int kretprobe_handler(struct pt_regs *ctx, struct kvm_vcpu *vcpu) {
int kprobe_handler(struct pt_regs *ctx, void *vcpu, u64 cr2_or_gpa,
			    int emulation_type, void *insn, int insn_len) {
    //int is_guest = (vcpu->arch.hflags & HF_GUEST_MASK) ? 1 : 0; // Get the return value
    //counts.increment(is_guest);
    int key = 0;
    key = 0;
    args.update(&key, (u64*)&vcpu);
    key = 1;
    args.update(&key, (u64*)&cr2_or_gpa);
    key = 2;
    args.update(&key, (u64*)&emulation_type);
    key = 3;
    args.update(&key, (u64*)&insn);
    key = 4;
    args.update(&key, (u64*)&insn_len);
    return 0;
}
"""

# Load and attach the eBPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="x86_emulate_instruction", fn_name="kprobe_handler")

# Print the contents of the maps every 2 seconds
while True:
    print([b["args"][i].value for i in range(5)])
    # print("Counts:", b["counts"][0].value, b["counts"][1].value)
    time.sleep(2)
