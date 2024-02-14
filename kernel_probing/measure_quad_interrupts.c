#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <linux/kvm_host.h>
#include <asm/vmx.h>
#include <bcc/proto.h>

#define MAX_CPUS 128

BPF_HASH(vm_exit_time, u32, u64, MAX_CPUS); // cpu -> time_stamp
BPF_HISTOGRAM(quad_interrupts_handle_time, u64, 64);
BPF_ARRAY(total_quad_interrupts_handle_time, u64, 1);

int handle_vmexit(struct pt_regs *ctx, struct kvm_vcpu *vcpu) { // Attach to vmx_handle_exit
    u64 *does_entry_exist;
    if ((vcpu->arch.hflags & HF_GUEST_MASK) != HF_GUEST_MASK) return 0;
    int key = vcpu->vcpu_idx;

    does_entry_exist = vm_exit_time.lookup(&key);
    if (does_entry_exist != NULL) { // Nested L2 EPT faults???
        ept_fault_latencies.atomic_increment(bpf_log2l(1));
        return 0;
    }
    
    u64 start_time = bpf_ktime_get_ns();

    return 0;
}

int handle_vmenter(struct pt_regs *ctx, struct kvm_vcpu *vcpu) { //Attach to ret vmx_handle_exit
    if ((vcpu->arch.hflags & HF_GUEST_MASK) != HF_GUEST_MASK) return 0;
    u32 cpu = bpf_get_smp_processor_id();
    u64 tsc = bpf_ktime_get_ns();

    if (vcpu->mode == IN_GUEST_MODE) {
        start.update(&cpu, &tsc);
    }

    return 0;
}
