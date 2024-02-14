from bcc import BPF

# eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/kvm_host.h>

BPF_HASH(start_time, u32);
BPF_ARRAY(total_latency, u64, 1);
BPF_ARRAY(event_count, u64, 1);
BPF_ARRAY(ipi_count, u64, 1);
BPF_HISTOGRAM(latency_distribution, u64);

int trace_ipi_raise(struct pt_regs *ctx)
{
    u32 pid = 0;
    u64 ts = bpf_ktime_get_ns();

    start_time.update(&pid, &ts);
    ipi_count.increment(0);
    return 0;
}

int trace_vm_enter(struct pt_regs *ctx, struct kvm_vcpu *vcpu)
{
    u32 pid = 0;
    int core = bpf_get_smp_processor_id();
    u64 *ts = start_time.lookup(&pid);

    if (ts && vcpu && (vcpu->arch.hflags & HF_GUEST_MASK) == 0) {
        u64 delta = bpf_ktime_get_ns() - *ts;
        start_time.delete(&pid);
        event_count.atomic_increment(pid);

        total_latency.atomic_increment(pid, delta);


        latency_distribution.atomic_increment(bpf_log2l(delta));
    }

    return 0;
}

int view_ipi_count(struct pt_regs *ctx, const struct cpumask *mask, int vector) {
    int core = bpf_get_smp_processor_id();
    if (mask == NULL) {
        return 0;
    }
    char buf[256];
    bpf_trace_printk("%u %u %u", (int)mask->bits[0], vector, (1 << core));
    return 0;
}
"""

# Load and attach the eBPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="kvm_pv_send_ipi", fn_name="trace_ipi_raise")
b.attach_kprobe(event="kvm_wait_lapic_expire", fn_name="trace_vm_enter")
# b.attach_kprobe(event="__send_ipi_mask", fn_name="view_ipi_count")

try:
    print("Attached probes, hit Ctrl-C to exit")
    while True:
        pass
except KeyboardInterrupt:
    # Print the latency distribution
    b["latency_distribution"].print_log2_hist("latency")

    # Print the event count
    event_count = b["event_count"][0].value
    print("Event Count:", event_count)
    ipi_count = b["ipi_count"][0].value
    print("IPI Count:", ipi_count)

    # Print the total latency
    total_latency = b["total_latency"][0].value / 1000
    print(f'Total Latency: {total_latency}us')
    print(f'Average Latency: {total_latency / event_count}us')
