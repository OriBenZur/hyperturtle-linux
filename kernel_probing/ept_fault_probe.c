#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <linux/kvm_host.h>
#include <bcc/proto.h>

#ifndef DNDEBUG
#define DEBUG(X) do { \
(X) \
} while(0)
#else
#define DEBUG(X)
#endif

#define MAX_CPUS 128

#define NOT_NESTED_ENTER 0
#define DOUBLE_NESTED_ENTER 1

#define TEST_ONLY_NESTED true
#define TEST_ONLY_IF_GOING_THROUGH_L1 false
#define TEST_SPECIFIC_EVENT true

struct vmcs_hdr {
	u32 revision_id:31;
	u32 shadow_vmcs:1;
};

struct __packed vmcs12 {
	/* According to the Intel spec, a VMCS region must start with the
	 * following two fields. Then follow implementation-specific data.
	 */
	struct vmcs_hdr hdr;
	u32 abort;

	u32 launch_state; /* set to 0 by VMCLEAR, to 1 by VMLAUNCH */
	u32 padding[7]; /* room for future expansion */

	u64 io_bitmap_a;
	u64 io_bitmap_b;
	u64 msr_bitmap;
	u64 vm_exit_msr_store_addr;
	u64 vm_exit_msr_load_addr;
	u64 vm_entry_msr_load_addr;
	u64 tsc_offset;
	u64 virtual_apic_page_addr;
	u64 apic_access_addr;
	u64 posted_intr_desc_addr;
	u64 ept_pointer;
	u64 eoi_exit_bitmap0;
	u64 eoi_exit_bitmap1;
	u64 eoi_exit_bitmap2;
	u64 eoi_exit_bitmap3;
	u64 xss_exit_bitmap;
	u64 guest_physical_address;
	u64 vmcs_link_pointer;
	u64 guest_ia32_debugctl;
	u64 guest_ia32_pat;
	u64 guest_ia32_efer;
	u64 guest_ia32_perf_global_ctrl;
	u64 guest_pdptr0;
	u64 guest_pdptr1;
	u64 guest_pdptr2;
	u64 guest_pdptr3;
	u64 guest_bndcfgs;
	u64 host_ia32_pat;
	u64 host_ia32_efer;
	u64 host_ia32_perf_global_ctrl;
	u64 vmread_bitmap;
	u64 vmwrite_bitmap;
	u64 vm_function_control;
	u64 eptp_list_address;
	u64 pml_address;
	u64 encls_exiting_bitmap;
	u64 tsc_multiplier;
	u64 padding64[1]; /* room for future expansion */
	/*
	 * To allow migration of L1 (complete with its L2 guests) between
	 * machines of different natural widths (32 or 64 bit), we cannot have
	 * unsigned long fields with no explicit size. We use u64 (aliased
	 * natural_width) instead. Luckily, x86 is little-endian.
	 */
	u64 cr0_guest_host_mask;
	u64 cr4_guest_host_mask;
	u64 cr0_read_shadow;
	u64 cr4_read_shadow;
	u64 dead_space[4]; /* Last remnants of cr3_target_value[0-3]. */
	u64 exit_qualification;
	u64 guest_linear_address;
	u64 guest_cr0;
	u64 guest_cr3;
	u64 guest_cr4;
	u64 guest_es_base;
	u64 guest_cs_base;
	u64 guest_ss_base;
	u64 guest_ds_base;
	u64 guest_fs_base;
	u64 guest_gs_base;
	u64 guest_ldtr_base;
	u64 guest_tr_base;
	u64 guest_gdtr_base;
	u64 guest_idtr_base;
	u64 guest_dr7;
	u64 guest_rsp;
	u64 guest_rip;
	u64 guest_rflags;
	u64 guest_pending_dbg_exceptions;
	u64 guest_sysenter_esp;
	u64 guest_sysenter_eip;
	u64 host_cr0;
	u64 host_cr3;
	u64 host_cr4;
	u64 host_fs_base;
	u64 host_gs_base;
	u64 host_tr_base;
	u64 host_gdtr_base;
	u64 host_idtr_base;
	u64 host_ia32_sysenter_esp;
	u64 host_ia32_sysenter_eip;
	u64 host_rsp;
	u64 host_rip;
	u64 paddingl[8]; /* room for future expansion */
	u32 pin_based_vm_exec_control;
	u32 cpu_based_vm_exec_control;
	u32 exception_bitmap;
	u32 page_fault_error_code_mask;
	u32 page_fault_error_code_match;
	u32 cr3_target_count;
	u32 vm_exit_controls;
	u32 vm_exit_msr_store_count;
	u32 vm_exit_msr_load_count;
	u32 vm_entry_controls;
	u32 vm_entry_msr_load_count;
	u32 vm_entry_intr_info_field;
	u32 vm_entry_exception_error_code;
	u32 vm_entry_instruction_len;
	u32 tpr_threshold;
	u32 secondary_vm_exec_control;
	u32 vm_instruction_error;
	u32 vm_exit_reason;
	u32 vm_exit_intr_info;
	u32 vm_exit_intr_error_code;
	u32 idt_vectoring_info_field;
	u32 idt_vectoring_error_code;
	u32 vm_exit_instruction_len;
	u32 vmx_instruction_info;
	u32 guest_es_limit;
	u32 guest_cs_limit;
	u32 guest_ss_limit;
	u32 guest_ds_limit;
	u32 guest_fs_limit;
	u32 guest_gs_limit;
	u32 guest_ldtr_limit;
	u32 guest_tr_limit;
	u32 guest_gdtr_limit;
	u32 guest_idtr_limit;
	u32 guest_es_ar_bytes;
	u32 guest_cs_ar_bytes;
	u32 guest_ss_ar_bytes;
	u32 guest_ds_ar_bytes;
	u32 guest_fs_ar_bytes;
	u32 guest_gs_ar_bytes;
	u32 guest_ldtr_ar_bytes;
	u32 guest_tr_ar_bytes;
	u32 guest_interruptibility_info;
	u32 guest_activity_state;
	u32 guest_sysenter_cs;
	u32 host_ia32_sysenter_cs;
	u32 vmx_preemption_timer_value;
	u32 padding32[7]; /* room for future expansion */
	u16 virtual_processor_id;
	u16 posted_intr_nv;
	u16 guest_es_selector;
	u16 guest_cs_selector;
	u16 guest_ss_selector;
	u16 guest_ds_selector;
	u16 guest_fs_selector;
	u16 guest_gs_selector;
	u16 guest_ldtr_selector;
	u16 guest_tr_selector;
	u16 guest_intr_status;
	u16 host_es_selector;
	u16 host_cs_selector;
	u16 host_ss_selector;
	u16 host_ds_selector;
	u16 host_fs_selector;
	u16 host_gs_selector;
	u16 host_tr_selector;
	u16 guest_pml_index;
};


/* Data structures for general measurements */
BPF_ARRAY(enter_times, u64, MAX_CPUS); // 0 in the array means were not in a nested vm-exit
BPF_ARRAY(has_event_occured, bool, MAX_CPUS);
BPF_ARRAY(total_latency, u64, 1);
BPF_ARRAY(enter_counts, u64, 1);
BPF_HISTOGRAM(latencies_hist, u64, 64);
BPF_HASH(vm_exits_list, u64, u64);

/* Measurement specific data structures */
BPF_ARRAY(ept_fault_L1_entry_record, bool, MAX_CPUS); // 0 in the array means were not in a nested vm-exit
BPF_ARRAY(current_vmcs12_addrs, u64, MAX_CPUS);


/* General tracing functions */
int trace_fault_start(struct pt_regs *ctx, struct kvm_vcpu *vcpu); // Doesn't trace L1 fastpath
int trace_fault_end(struct pt_regs *ctx, struct kvm_vcpu *vcpu);
int mark_event_occured(struct pt_regs *ctx, struct kvm_vcpu *vcpu);
int kvm_reset_trace(struct pt_regs *ctx, struct kvm_vcpu *vcpu);
int kvm_reset_trace_on_halt(struct pt_regs *ctx, struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12); // Only works for L2

/* Measurement specific functions */
static inline int kvm_trace_L1_entery(struct pt_regs *ctx, struct kvm_vcpu *vcpu);
int mark_event_occured_vmcs12_transition(struct pt_regs *ctx, struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12);
int mark_vmexit_occured(struct pt_regs *ctx, struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12);

/* Helper functions */
static __always_inline bool is_L2(struct kvm_vcpu *vcpu);
static inline void __do_reset_trace(int vcpu_idx);


/* General tracing functions */
int trace_fault_start(struct pt_regs *ctx, struct kvm_vcpu *vcpu) { // handle_ept_violation
    if (vcpu == NULL) return 0;
    u64 time_ns;
    int key = vcpu->vcpu_idx;
	bool event_occured = false;
	if (!(vcpu->arch.hflags & HF_GUEST_MASK) && TEST_ONLY_NESTED) return 0;

	if (TEST_SPECIFIC_EVENT) {
		has_event_occured.update(&key, &event_occured); 
	}

    time_ns = bpf_ktime_get_ns();
    enter_times.update(&key, &time_ns);
    return 0;
}


int trace_fault_end(struct pt_regs *ctx, struct kvm_vcpu *vcpu) { //vmx_vcpu_run
    u64 end_time = bpf_ktime_get_ns();
    if (vcpu == NULL) return 0;
    if (TEST_ONLY_IF_GOING_THROUGH_L1 && TEST_ONLY_NESTED && (vcpu->arch.hflags & HF_GUEST_MASK) == 0) 
		return kvm_trace_L1_entery(ctx, vcpu);
    if (!(vcpu->arch.hflags & HF_GUEST_MASK) && TEST_ONLY_NESTED) return 0;
    u64 *time_ns;
    bool *did_enter_L1;
    bool *event_occured;
    int key = vcpu->vcpu_idx;

	if (TEST_ONLY_IF_GOING_THROUGH_L1) {
		did_enter_L1 = ept_fault_L1_entry_record.lookup(&key); 
		if (did_enter_L1 == NULL || *did_enter_L1 == false) return 0; // Comment this out if you want to also track L2 faults that don't enter L1
	}

	if (TEST_SPECIFIC_EVENT) {
		event_occured = has_event_occured.lookup(&key); 
		if (event_occured == NULL || *event_occured == false) return 0; // Comment this out if you want to also track L2 exits that return to the same L2
	}

    time_ns = enter_times.lookup(&key);
    if (time_ns == NULL || *time_ns == 0ULL) {
        return 0;
    }
    
    u64 latency = end_time - *time_ns;
    enter_counts.atomic_increment(0);
    total_latency.atomic_increment(0, latency);
    latencies_hist.atomic_increment(bpf_log2l(latency));
	
    *time_ns = 0ULL;
    enter_times.update(&key, time_ns);

	if (TEST_ONLY_IF_GOING_THROUGH_L1) {
		*did_enter_L1 = false;
		ept_fault_L1_entry_record.update(&key, did_enter_L1);
	}
	if (TEST_SPECIFIC_EVENT) {
		*event_occured = false;
		has_event_occured.update(&key, event_occured);
	}
	
    return 0;
}

int mark_which_vmexit_occured(struct pt_regs *ctx) {
	int key;
	bool *event_occured;
	event_occured = has_event_occured.lookup(&key);
	if (event_occured == NULL || *event_occured == false) return 0;
	u64 rip = ctx->ip;
	vm_exits_list.atomic_increment(rip);
	return false;
}

int mark_event_occured(struct pt_regs *ctx, struct kvm_vcpu *vcpu) {
	if (vcpu == NULL) return 0;
	// if ((vcpu->arch.hflags & HF_GUEST_MASK) != 0)
	if (!(vcpu->arch.hflags & HF_GUEST_MASK) && TEST_ONLY_NESTED) return 0;
	int key = vcpu->vcpu_idx;
	bool event_occured = true;
	has_event_occured.update(&key, &event_occured);
	return 0;
}


static inline void __do_reset_trace(int vcpu_idx) {
    u64 time_ns = 0ULL;
	bool event_occured = false;
	enter_times.update(&vcpu_idx, &time_ns);
	has_event_occured.update(&vcpu_idx, &event_occured);
}


int kvm_reset_trace(struct pt_regs *ctx, struct kvm_vcpu *vcpu) {
	for (int key = 0; key < MAX_CPUS; key++)
        __do_reset_trace(key);
    return 0;
}

#define CPU_BASED_HLT_EXITING 0x00000080

int reset_trace_on_halt(struct pt_regs *ctx) {
	u32 arg2;
	bpf_probe_read(&arg2, sizeof(arg2), &ctx->di); // Read the second argument as u32

	if (arg2 == CPU_BASED_HLT_EXITING)
	   for (int key = 0; key < MAX_CPUS; key++)
        __do_reset_trace(key);
	return 0;
}


int kvm_reset_trace_on_halt(struct pt_regs *ctx, struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12) {
    if (vcpu->arch.mp_state == KVM_MP_STATE_HALTED)
       __do_reset_trace(vcpu->vcpu_idx);
    return 0;
}


/* Measurement specific functions */
static __always_inline int kvm_trace_L1_entery(struct pt_regs *ctx, struct kvm_vcpu *vcpu) {
    if (vcpu == NULL) return 0;
    // if (!(vcpu->arch.hflags & HF_GUEST_MASK) && TEST_ONLY_NESTED) return 0;
    u64 *time_ns;
    bool did_enter_L1 = true;
    int key;
	bpf_probe_read(&key, sizeof(key), &vcpu->vcpu_idx);
    time_ns = enter_times.lookup(&key);
    if (time_ns == NULL) return 0;
    if (*time_ns != 0ULL) { // We're tracking an L2 fault
        ept_fault_L1_entry_record.update(&key, &did_enter_L1);
    }

    return 0;
}


int mark_event_occured_vmcs12_transition(struct pt_regs *ctx, struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12) { // Note that we are storing the ept pointer.
	if (vcpu == NULL || vmcs12 == NULL) return 0;
	bool is_transition;
	int key = vcpu->vcpu_idx;
    u64 eptp = vmcs12->ept_pointer;
	u64 *prev_vmcs12 = current_vmcs12_addrs.lookup(&key);
	if (prev_vmcs12 == NULL) {
		current_vmcs12_addrs.update(&key, &eptp);
		return 0;
	}

	if ((is_transition = (*prev_vmcs12 != eptp))) {
		has_event_occured.update(&key, &is_transition);
		current_vmcs12_addrs.update(&key, &eptp);
	}
	return 0;
}



/* Helper functions */
static __always_inline bool is_L2(struct kvm_vcpu *vcpu) {
    return (vcpu != NULL && vcpu->arch.hflags & HF_GUEST_MASK);
}