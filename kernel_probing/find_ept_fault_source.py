from bcc import BPF
import shlex
import sys
import subprocess

# eBPF program
bpf_program = """
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <linux/kvm_host.h>
#include <bcc/proto.h>

BPF_ARRAY(event_count, u64, 2);
BPF_ARRAY(event_count2, u64, 1024);
BPF_ARRAY(fault_count_between_l2, u64, 10);
BPF_HISTOGRAM(event_hist, u64, 64);
BPF_ARRAY(exit_values, u64, 16);

BPF_ARRAY(temp, u32, 1);
BPF_ARRAY(is_in_nested_ept_fault, u32, 1);

int trace_nested_fault_begin(struct pt_regs *ctx, struct kvm_vcpu *vcpu) {
    int key = 0;
    int *value;
    value = is_in_nested_ept_fault.lookup(&key);
    event_count.atomic_increment((vcpu->arch.hflags & HF_GUEST_MASK) == HF_GUEST_MASK);
    if (value == NULL)
        return 0;
    if ((vcpu->arch.hflags & HF_GUEST_MASK) == HF_GUEST_MASK) {
        *value = 1;
        is_in_nested_ept_fault.update(&key, value);
    }
    else if (*value == 1) {
        temp.atomic_increment(0);
    }
    return 0;
}

int trace_nested_fault_end(struct pt_regs *ctx, struct kvm_vcpu *vcpu) {
    int key = 0, value = 0;
    int *temp_value;
    temp_value = is_in_nested_ept_fault.lookup(&key);
    if (temp_value != NULL && *temp_value == 1 && (vcpu->arch.hflags & HF_GUEST_MASK) == HF_GUEST_MASK) {
        is_in_nested_ept_fault.update(&key, &value);
        temp_value = temp.lookup(&key);
        if (temp_value == NULL) return 0;
        event_count2.atomic_increment(*temp_value);
        *temp_value = 0;
        temp.update(&key, temp_value);
    }
    return 0;
}

int trace_vm_enter(struct pt_regs *ctx, struct kvm_vcpu *vcpu)
{
    event_count.atomic_increment((vcpu->arch.hflags & HF_GUEST_MASK) == HF_GUEST_MASK);
    return 0;
}

int trace_vm_exit(struct pt_regs *ctx)
{
    exit_values.atomic_increment(ctx->ax);
    return 0;
}

"""

# Load and attach the eBPF program
b = BPF(text=bpf_program)
event="ept_page_fault" # 0 from L1; ~75K entries from L2
# event="handle_ept_violation" # ~3K from L1; ~75K from L2
# event="kvm_inject_emulated_page_fault"
# event="handle_abnormal_pfn"
# event="nested_ept_inject_page_fault" # ~42K injections to L1 (entires from L2)
# event="kvm_tdp_page_fault" # ~3K from L1; 0 from L2
# event="kvm_faultin_pfn" # always returns false
# event="handle_abnormal_pfn" # always returns false
# event="kvm_tdp_mmu_map" 
print(f'Event: {event}')
b.attach_kprobe(event=event, fn_name="trace_vm_enter")
b.attach_kretprobe(event=event, fn_name="trace_vm_exit")

# b.attach_kprobe(event=event, fn_name="trace_nested_fault_begin")
# b.attach_kprobe(event="kvm_wait_lapic_expire", fn_name="trace_nested_fault_end")
cmd = [shlex.quote(arg) for arg in sys.argv[1:]] if len(sys.argv) > 1 else None
if cmd is not None:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
try:
    print("Attached probes, hit Ctrl-C to exit")
    if cmd is not None:
        stdout, stderr = process.communicate()
        # print(stdout.decode())
        print(stderr.decode())
    while True and cmd is None:
        pass
except KeyboardInterrupt:
    print("Detaching probes...")
    # Print the latency distribution
finally:
    L0_count = b["event_count"][0].value
    L1_count = b["event_count"][1].value
    L1_count20 = b["event_count2"][0].value
    L1_count21 = b["event_count2"][1].value
    L1_count22 = b["event_count2"][2].value
    L1_count23 = b["event_count2"][3].value
    L1_count24 = b["event_count2"][4].value
    print(f"L0: {L0_count}, L1: {L1_count}")
    print(f'L1_count2: {L1_count20}, {L1_count21}, {L1_count22}, {L1_count23}, {L1_count24}')
    print(f'exit values: {b["exit_values"].items()}')