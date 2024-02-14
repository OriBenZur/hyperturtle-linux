from bcc import BPF
from time import sleep, time
from ctypes import c_int
import os
import subprocess
import shlex
import sys

class ProbingFunction:
    def __init__(self, kprobe:str, tracer):
        self.kprobe = kprobe
        self.tracer = tracer

    def __str__(self):
        return self.kprobe

general_options = {
    "live": False,
    "cmd": None,
    "trace_nested": False,
}

options = {
    "measure_all_latencies": False,
    "measure_vmswitch_latencies": False,
    "measure_ept_fault_latency": False,
    "measure_ept_misconfig_latency": True,
    "measure_only_faults_through_L1": False,
}

OPTIONS_FUNCTIONS = {
    "measure_ept_fault_latency": ProbingFunction("handle_ept_violation", "mark_event_occured"),
    "measure_ept_misconfig_latency": ProbingFunction("handle_ept_misconfig", "mark_event_occured"),
    "measure_vmswitch_latencies": ProbingFunction("nested_vmx_check_host_state", "mark_event_occured_vmcs12_transition"),
    "measure_only_faults_through_L1": False,
}
# b.attach_kprobe(event="sync_vmcs02_to_vmcs12", fn_name="prob_sync_vmcs02_to_vmcs12") # halt check

DEFAULT_EVENTS = {
    "handle_vmoff": "kvm_reset_trace",
    "handle_vmptrst": "kvm_reset_trace",
    "handle_vmptrld": "kvm_reset_trace",
    "kvm_arch_vcpu_destroy": "kvm_reset_trace",
    "kvm_load_host_xsave_state": "trace_fault_start",
    "kvm_wait_lapic_expire": "trace_fault_end"
    }

vmx_handle_functions = [
    "handle_exception_nmi",
    "handle_external_interrupt",
    "handle_triple_fault",
    "handle_nmi_window",
    "handle_io",
    "handle_cr",
    "handle_dr",
    "kvm_emulate_cpuid",
    "kvm_emulate_rdmsr",
    "kvm_emulate_wrmsr",
    "handle_interrupt_window",
    "kvm_emulate_halt",
    "kvm_emulate_invd",
    "handle_invlpg",
    "kvm_emulate_rdpmc",
    "kvm_emulate_hypercall",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "handle_tpr_below_threshold",
    "handle_apic_access",
    "handle_apic_write",
    "handle_apic_eoi_induced",
    "kvm_emulate_wbinvd",
    "kvm_emulate_xsetbv",
    "handle_task_switch",
    "handle_machine_check",
    "handle_desc",
    "handle_desc",
    "handle_ept_violation",
    "handle_ept_misconfig",
    "handle_pause",
    "kvm_emulate_mwait",
    "handle_monitor_trap",
    "kvm_emulate_monitor",
    "handle_vmx_instruction",
    "handle_vmx_instruction",
    "kvm_handle_invalid_op",
    "kvm_handle_invalid_op",
    "handle_pml_full",
    "handle_invpcid",
    "handle_vmx_instruction",
    "handle_preemption_timer",
    "handle_encls",
    "handle_bus_lock_vmexit",
    "handle_vmclear",
    "handle_vmlaunch",
    "handle_vmptrld",
    "handle_vmptrst",
    "handle_vmread",
    "handle_vmresume",
    "handle_vmwrite",
    "handle_vmoff",
    "handle_vmon",
    "handle_invept",
    "handle_invvpid",
    "handle_vmfunc"
]

def installStandardProbes(b:BPF):
    '''
    This function installs the probes that measure vm_entry and vm_exit latencies.
    '''
    for k,v in DEFAULT_EVENTS.items():
        b.attach_kprobe(event=k, fn_name=v)

def uninstallStandardProbes(b:BPF):
    for k in DEFAULT_EVENTS.keys():
        b.detach_kprobe(event=k)

'''
This should receive events to monitor, and then measure the overhead of those events in nested virtualization.
Additionnaly, it shold measure the overhead of nested virtualization as a whole (from vmexit to vmenter).
'''
def measureOverheadNestedEPTViolations(live:bool, cmd:str):
# Get the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Append the file name to the directory
    file_path = os.path.join(current_dir, "ept_fault_probe.c")

    # Open the file
    with open(file_path, "r") as file:
        bpf_text = file.read()
    bpf_text.replace("#define TEST_ONLY_NESTED true", "#define TEST_ONLY_NESTED false")
    # create a BPF object and compile the ebpf program
    b = BPF(text=bpf_text)
    dist = b["latencies_hist"]
    total_latency = b["total_latency"]
    count = b["enter_counts"]
    handlers = b["vm_exits_list"]
    installStandardProbes(b)
    for k,v in options.items():
        if v and OPTIONS_FUNCTIONS[k]:
            b.attach_kprobe(event=OPTIONS_FUNCTIONS[k].kprobe, fn_name=OPTIONS_FUNCTIONS[k].tracer)
        elif v and not OPTIONS_FUNCTIONS[k]:
            print(f"Warning: {k} is not supported yet.")
    start_time = time()
    
    # for vmexit_handler in vmx_handle_functions:
    #     b.attach_kprobe(event=vmexit_handler, fn_name="mark_which_vmexit_occured")

    # b.attach_kprobe(event="handle_ept_violation", fn_name="kvm_trace_L2_fault_start")
    # b.attach_kprobe(event="handle_preemption_timer", fn_name="kvm_trace_L2_fault_start")

    # run the ebpf program

    try:
        print("attached probes, hit Ctrl-C to exit")
        while cmd is None:
            if live:
                print("enter_counts")
                for key in count.keys():
                    print(key.value, ":", count[key].value)
                dist.print_log2_hist("nsec")

            sleep(2)
        if cmd is not None:
            # run the command and capture its output
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            # print the output
            print(stdout.decode())
            print(stderr.decode())
            

    except KeyboardInterrupt:
        print("Detaching probes...")
        if cmd is not None:
            process.kill()
            stdout, stderr = process.communicate()
            print(stdout.decode())
            print(stderr.decode())
    finally:
        end_time = time()
        uninstallStandardProbes(b)
        dist.print_log2_hist("nsec")
        pcount = count[c_int(0)].value
        if pcount == 0:
            print("No events were captured.")
            return
            if __name__ == '__main__':
                # Get the command line arguments as a string
                cmd = [shlex.quote(arg) for arg in sys.argv[1:]] if len(sys.argv) > 1 else None
                options["measure_ept_fault_latency"] = True
                # Execute the command as a subprocess
                measureOverheadNestedEPTViolations(False, cmd)

                # Iterate over the items of the handlers BPF hash map
                for key, value in handlers.items():
                    print(f"Key: {key.value}, Value: {value.value}")
        ptotal_latency = total_latency[c_int(0)].value / 1000
        pavg = ptotal_latency / pcount
        print(f'avg = {pavg:.3f}us, count = {pcount}, total overhead = {ptotal_latency}us, measurement time = {end_time - start_time:.3f}s')
        print("Detached probes.")


if __name__ == '__main__':
    # Get the command line arguments as a string
    cmd = [shlex.quote(arg) for arg in sys.argv[1:]] if len(sys.argv) > 1 else None
    options["measure_ept_fault_latency"] = True
    # Execute the command as a subprocess
    measureOverheadNestedEPTViolations(False, cmd)