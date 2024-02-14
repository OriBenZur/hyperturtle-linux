import asyncio
import os
import subprocess
import time
import socket
import signal
import paramiko
from enum import Enum
from qemu.qmp import QMPClient
# perf path /mnt/bigdisk/ori/linux-5.16/tools/perf/perf
HOME_DIR = "/mnt/bigdisk/ori"
TPT_DIR = HOME_DIR + "/nestedTPT_measurements"
SHARED_DIR = "/home/ubuntu/shared_folder/"
QCOW_PATH = HOME_DIR + "/qemu_rampup/qcow_images/pc.qcow2"
QCOW_PATH_IN_GUEST = "/home/ubuntu/qemu_rampup/qcow_images/pc.qcow2"
RUN_VIRT_PATH = TPT_DIR + "/run_virt_host"
VM_NETWORK_INTERFACE = "ens3"
VM_IP = "132.68.52.133"
REMOTE_IP = ""
REMOTE_USER = "ori"
PERF_EVENTS = {
    "def" : "kvm:kvm_entry,kvm:kvm_exit,kvm:kvm_nested_vmexit,kvm:kvm_nested_vmrun,cycles:G,cycles:H,instructions:G,instructions:H,kvm:kvm_page_fault:H,kvm:kvm_page_fault:G,ept.walk_cycles:H,ept.walk_cycles:G",
    "TLB" : "dtlb_load_misses.walk_duration:G,dtlb_store_misses.walk_duration:G,cycles:G,itlb_misses.walk_duration:G,dtlb_load_misses.walk_duration:H,dtlb_store_misses.walk_duration:H,cycles:H,itlb_misses.walk_duration:H",
    "Cache_Misses" : "mem_load_uops_retired.l1_miss:H,mem_load_uops_retired.l2_miss:H,mem_load_uops_retired.l3_miss:H,mem_load_uops_retired.l1_miss:G,mem_load_uops_retired.l2_miss:G,mem_load_uops_retired.l3_miss:G",
    "Cache_Hits" : "mem_load_uops_retired.l1_hit:H,mem_load_uops_retired.l2_hit:H,mem_load_uops_retired.l3_hit:H,mem_load_uops_retired.l1_hit:G,mem_load_uops_retired.l2_hit:G,mem_load_uops_retired.l3_hit:G"
}

benchmark_list = [
    "./osbench-throughput/out/mem_alloc",
    "./osbench-throughput/out/create_processes",
    "./osbench-throughput/out/launch_programs",
    "./osbench-throughput/out/create_threads",
    "./micro-benchs/demand-paging",
    "./micro-benchs/mprotect",
    "./gups/gups",
    "./kata_containers_benchmarks/run_mutilate.sh"
]
benchmark_args = [[""], [""], [""], [""], [""], [""], ["--log2_length 31"], ["24"]]


############################################

class TestConfigurations(Enum):
    COLD_START = 1
    PRE_HEATING = 2

class PageTableConfig(Enum):
    EPT = 1
    SHADOW = 2
    EPT_ON_EPT = 3
    SHADOW_ON_EPT = 4
    SHADOW_ON_SHADOW = 5



class VirtualMachine(object):
    test_config:TestConfigurations
    pt_config:PageTableConfig
    n_cores:int
    mem:int
    qemu_flags:list[str]
    level_identifier:str
    vm_pid:int
    tracer_invoker:list[str]
    powered_on:bool
    current_test:str
    guest_subprocess:subprocess.Popen

    
    class ExecutionCommand:
        def __init__(self, binary, args=None, location="", cores_to_run_on:str=None):
            self.bin = binary
            self.args = args
            self.location = location
            self.cores_to_run_on = cores_to_run_on
        
        def __str__(self) -> str:
            if self.bin is None:
                return ""
            else:
                return self.bin


    def __init__(self, pt_config:PageTableConfig, test_config:TestConfigurations = TestConfigurations.COLD_START, mem:int=20, cores:int=6, qmp_port:int=4444, ssh_port:int=22, ssh_forward:int=22, qemu_flags:list[str]=[""], level_identifier:str="L1"):
        self.test_config = test_config
        self.pt_config = pt_config
        self.n_cores = cores
        self.mem = mem
        self.qemu_flags = qemu_flags
        self.level_identifier = level_identifier
        self.tracer_invoker = ["sudo", "perf", "kvm", "stat", "--append"]
        self.powered_on = False
        self.guest_subprocess = None
        self.qmp_port = qmp_port
        self.ssh_port = ssh_port
        self.ssh_forward_port = ssh_forward
        self.ssh_session = None

        if self.level_identifier != "L1":
            return
        else:
            self.__set_paging_config(pt_config)

    def __del__(self):
        if self.powered_on:
            self.shutdown()
    
    def __set_paging_config(self, pt_config:PageTableConfig):
        '''
        @modifies KVM's paging mode. Shuts down guest if still on
        '''
        while True:
            if pt_config == PageTableConfig.EPT or pt_config == PageTableConfig.EPT_ON_EPT or pt_config == PageTableConfig.SHADOW_ON_EPT:
                rm_results = subprocess.run(["sudo", "rmmod", "kvm_intel"])
                probe_results = subprocess.run(["sudo", "modprobe", "kvm_intel"])
            else:
                rm_results = subprocess.run(["sudo", "rmmod", "kvm_intel"])
                probe_results = subprocess.run(["sudo", "modprobe", "kvm_intel", "ept=0"])
            if rm_results.returncode != 0 or probe_results.returncode != 0:
                time.sleep(3)
            else:
                break


    def _get_results_path(self, current_test:ExecutionCommand) -> str:
        '''
        Returns a path for the results file for current test. 
        Uses pt_config, level_indentifier
        '''
        return f'{SHARED_DIR}/{self.level_identifier}_{self.pt_config.name.lower()}_results/{os.path.basename(current_test.bin)}_{self.test_config.name}_{self.level_identifier}'
    

    def _get_trace_path(self, current_test:ExecutionCommand, src_dir:str=TPT_DIR) -> str:
        '''
        Returns the path for the trace file that'll be generated from 'current test' (including timestamp).
        Uses pt_config, level_indentifier.
        '''
        return f'{src_dir}/{self.level_identifier}_{self.pt_config.name.lower()}_traces/{os.path.basename(current_test.bin)}'


    def _get_tracer_invokation_cmd(self, current_test:ExecutionCommand, src_dir:str=TPT_DIR, pid=None, metric_group:str="def"):
        '''
        Returns a bash command that'll invoke perf. Uses 'current_test' and the VM's pid
        '''
        if pid is None:
            pid = self.vm_pid
        cmd = self.tracer_invoker + ["-o", self._get_trace_path(current_test, src_dir), "-p", str(pid), "-e", PERF_EVENTS[metric_group]]
        print(cmd)
        return cmd
    

    def _get_launch_virt_command(self, script_path:str=TPT_DIR, qcow_path:str=QCOW_PATH) -> list[str]:
        args = ["-i", qcow_path, "-m", str(self.mem), "-c", str(self.n_cores), "-q", str(self.qmp_port), "-S", str(self.ssh_port), "-H", str(self.ssh_forward_port), "-r", "null"]
        args += self.qemu_flags
        # args += [">", "/dev/null", "2>", "/dev/null"]
        cmd = [script_path + "/run_virt_host"] + args
        return cmd

    
    def _do_quit(self):
        '''
        Sends shutdown commands and waits for subprocess to quit
        @Modifies:
            self.guest_subprocess
            self.ssh_port
            self.ssh_session
            Guest
        '''
        while self.guest_subprocess.poll() is None:
            process = self.send_command_to_guest('echo ubuntu | sudo -S shutdown now', output=subprocess.DEVNULL)
            process.wait()
            time.sleep(3)
        self.guest_subprocess = None


    def warmup(self):
        heater = SHARED_DIR + "/micro-benchs/demand-for-host" if self.mem == 24 else SHARED_DIR + "/micro-benchs/demand-paging"
        process = self.send_command_to_guest(heater)
        process.communicate()

    def send_command_to_guest(self, bin:str, args:list[str]=[""], port:int=None, output=subprocess.PIPE, cores_to_run_on:str=None, use_remote:bool=False):
        '''
        Sends command to guest via ssh. If ssh isn't connected, connects to guest.
        @Parameters:
            bin: binary to run. Can be entire command
            args: arguments for the command
            port: port to use for ssh. self.ssh_port will be used if 'port' is blank
            outpu: channel to for command output
            core_to_run_on: string for taskset if necassery
            use_remote: indicates whether the command should be sent to VM or to remote server
        @Modifies:
            self.ssh_port
            self.ssh_session
            Guest
        '''
        if port is None:
            port = self.ssh_port
            
        if cores_to_run_on is not None:
            taskset = f'taskset -c {cores_to_run_on}'
        else:
            taskset = ""

        cmd = bin + " " + " ".join(args)
        # print(cmd)
        if use_remote:
            ssh_target = f'{self.level_identifier}ubuntu@{VM_IP}'
        else:
            ssh_target = f'{REMOTE_USER}@{REMOTE_IP}'
        ssh = f'ssh -p {port} {ssh_target} -i /home/ori/.ssh/id_ed25519'.split(' ')
        cmd = ssh + taskset.split(' ') + cmd.split(' ')
        print(f'SSH: {" ".join(cmd)}')
        process = subprocess.Popen(cmd, stdout=output, stderr=output)
        return process

    def shutdown(self):
        '''
        Shutdown VM
        @Modifies:
            self.powered_on
            self.guest_subprocess
            self.ssh_port
            self.ssh_session
            Guest
        '''
        if not self.powered_on:
            return
        self._do_quit()
        self.powered_on = False
        self.ssh_session = None
        print(f'{self.level_identifier} was shutdown!')

    def launch(self):
        '''
        Launch the virtual machine (poweron), pins vCPUs to pCPUs, runs pre-heat if necessary.
        '''
        self.guest_subprocess = subprocess.Popen(self._get_launch_virt_command(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(10)
        self.vm_pid = subprocess.check_output(["pidof", "qemu-system-x86_64"]).decode("utf-8")[:-1]
        if self.guest_subprocess.poll() is not None:
            print("Failed to launch guest!")
            quit()
        self.powered_on = True
        if self.test_config == TestConfigurations.PRE_HEATING:
            self.warmup()
        time.sleep(5)
        self.send_command_to_guest(f'export OMP_NUM_THREADS={self.n_cores}')
        self.send_command_to_guest(f'export OMP_THREAD_LIMIT={self.n_cores}')

    def get_ssh_forwarding_commang(self):
        return f'socat tcp-listen:{self.ssh_forward_port},reuseaddr,fork tcp:localhost:{self.ssh_port}'

    def do_test(self, test:ExecutionCommand, trace=True, metric_group:str="def", use_remote:str=None):
        '''
        Run a test in the virtual machine according to test configurations.
        '''
        # Run the test
        redirection = [">>", self._get_results_path(test), "2>>", self._get_results_path(test)]
        benchmark = self.send_command_to_guest(test.location + test.bin, test.args + redirection, cores_to_run_on=test.cores_to_run_on, use_remote=use_remote)
        
        # Run the tracer
        if trace:
            tracer_invoke_cmd = self._get_tracer_invokation_cmd(test, metric_group=metric_group)
            perf_process = subprocess.Popen(tracer_invoke_cmd)
        stdout, stderr = benchmark.communicate()
        status = benchmark.returncode
        if trace:
            kill = subprocess.Popen(["sudo", "kill", "-INT", str(perf_process.pid)])
            kill.wait()
            perf_process.wait()

        # Cleanup
        if status != 0 and trace:
            p = subprocess.Popen(["sudo", "rm", str(tracer_invoke_cmd[tracer_invoke_cmd.index("-o") + 1])])
            p.wait()
        return status


    def run_test(self, test:ExecutionCommand, trace=True, metric_group:str="def", use_remote:bool=False):
        '''
        Wrapper for launch, do_test and shutdown.
        '''
        while True:
            if not self.powered_on:
                self.launch()
            result = self.do_test(test, trace, metric_group, use_remote)
            if self.test_config == TestConfigurations.COLD_START:
                self.shutdown()
            if result == 0:
                break
        print("Finished test!")



class NestedVirtualMachine(VirtualMachine): 
    def __init__(self, pt_config:PageTableConfig, test_config:TestConfigurations = TestConfigurations.COLD_START, mem:int=20, cores:int=6, qmp_port:int=4444, ssh_port:int=22, ssh_forward:int=22, qemu_flags:list[str]=[""]):
        '''
        Launches L1, creates L2. L1 is preheated. Adjusts 
        '''
        assert False
        VirtualMachine.__init__(self, pt_config, test_config, mem, cores, qmp_port + 10, ssh_port, ssh_forward + 10, qemu_flags, "L2")
        self.guest_hv = VirtualMachine(pt_config, TestConfigurations.PRE_HEATING, 24, 8, qmp_port, ssh_port, ssh_forward)
        self.guest_hv.launch() # Preheats L1
        self.vm_pid = self.guest_hv.vm_pid
        self.__set_paging_config(pt_config)

    def __del__(self):
        if self.powered_on:
            self.shutdown()
        self.guest_hv.shutdown()
    
    
    def __set_paging_config(self, pt_config:PageTableConfig):
        assert self.guest_hv is not None
        while True:
            if pt_config == PageTableConfig.SHADOW_ON_EPT or pt_config == PageTableConfig.SHADOW_ON_SHADOW:
                process = self.guest_hv.send_command_to_guest("echo \"ubuntu\" | sudo -S rmmod kvm_intel ")
                process.communicate()
                res = process.returncode
                process = self.guest_hv.send_command_to_guest("echo \"ubuntu\" | sudo -S modprobe kvm_intel ept=0")
            elif pt_config == PageTableConfig.EPT_ON_EPT:
                process = self.guest_hv.send_command_to_guest("echo \"ubuntu\" | sudo -S rmmod kvm_intel")
                process.communicate()
                res = process.returncode
                process = self.guest_hv.send_command_to_guest("echo \"ubuntu\" | sudo -S modprobe kvm_intel")
            else:
                assert False
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                print(stderr.decode("utf8"))
            else:
                break
            time.sleep(1)


    def launch(self):
        '''
        Launch the virtual machine (poweron), pins vCPUs to pCPUs, runs pre-heat if necessary.
        '''
        launch_virt_command = self._get_launch_virt_command(SHARED_DIR, QCOW_PATH_IN_GUEST)
        launch_virt_command += ["-f", SHARED_DIR]

        process = self.guest_hv.send_command_to_guest("pkill socat")
        process.communicate()
        process = self.guest_hv.send_command_to_guest(self.guest_hv.get_ssh_forwarding_commang()) # ssh
        time.sleep(1)

        process = self.guest_hv.send_command_to_guest(f'echo ubuntu | sudo -S {launch_virt_command[0]}', launch_virt_command[1:], output=subprocess.DEVNULL)
        time.sleep(10)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            status = process.returncode
            print(f'Launch nested guest return code: {status}')
            if (status != 0):
                print(f'STDERR: {stderr.decode("utf8")}')
                print(f'PS STDOUT: {stdout.decode("utf8")}')
                process = self.guest_hv.send_command_to_guest(f'ps -A | grep qemu-system-x86')
                quit()
        if self.test_config == TestConfigurations.PRE_HEATING:
            self.warmup()
        while True:
            process = self.guest_hv.send_command_to_guest(f'ps -A | grep qemu-system-x86')
            stdout, stderr = process.communicate()
            res = stdout.decode("utf8")
            if res != "":
                res = res.strip()
                res = res.split(" ")
                self.guest_hv.vm_pid = int(res[0])
                break
        self.powered_on = True

    def send_command_to_guest(self, bin:str, args:list[str]=[""], port:int=None, output=subprocess.PIPE, cores_to_run_on:str=None):
        return VirtualMachine.send_command_to_guest(self, bin, args, self.guest_hv.ssh_forward_port, output, cores_to_run_on)


    def do_test(self, test:VirtualMachine.ExecutionCommand, trace_from_L0=True, metric_group:str="def", trace_from_L1=False, use_remote:bool=False):
        # Run the tracer in L1
        if trace_from_L1:
            tracer_invoke_cmd = self.guest_hv._get_tracer_invokation_cmd(test, SHARED_DIR, metric_group=metric_group)
            tracer_process = self.guest_hv.send_command_to_guest('echo ubuntu | sudo -S ' + " ".join(tracer_invoke_cmd))
        
        # Run the test in L2 + L0 tracer
        status = VirtualMachine.do_test(self, test, trace_from_L0, metric_group, use_remote)
        if trace_from_L1:
            kill_process = self.guest_hv.send_command_to_guest('echo ubuntu | sudo -S pkill -INT perf')
            tracer_process.communicate()
            kill_process.communicate()
            #Cleanup
            if status != 0:
                self.guest_hv.send_command_to_guest(f'echo ubuntu | sudo -S rm {tracer_invoke_cmd[tracer_invoke_cmd.index("-o") + 1]}')
            
        return status

        



    def run_test(self, test:VirtualMachine.ExecutionCommand, trace_from_L0=True, metric_group:str="def", trace_from_L1=False, use_remote:bool=False):
        '''
        Run a test in the virtual machine according to test configurations
        '''
        while True:
            if not self.powered_on:
                self.launch()
            result = self.do_test(test, trace_from_L0, metric_group, trace_from_L1, use_remote)
            if self.test_config == TestConfigurations.COLD_START:
                self.shutdown()
            if result == 0:
                break
        print("Finished test!")

    def _do_quit(self):
        '''
        Sends shutdown commands and waits for subprocess to quit
        '''
        while True:
            process = self.send_command_to_guest('echo ubuntu | sudo -S shutdown now', output=subprocess.DEVNULL)
            process.wait()
            # self.ssh_session.close()
            process = self.guest_hv.send_command_to_guest('ps -A | grep qemu-system-x86')
            stdout, err = process.communicate()
            status = process.returncode
            print(f'PS STDOUT: {stdout.decode("utf8")}')
            print(f'PS STDERR: {err.decode("utf8")}')
            if status == 1:
                break
            time.sleep(3)


def run_all_benchmarks(benchmarks:list[str], args:list[str]):
    for bin, arg in zip(benchmark_list, benchmark_args):
        for test_conf in TestConfigurations:
            for pt_conf in PageTableConfig:
                if pt_conf == PageTableConfig.EPT or pt_conf == PageTableConfig.SHADOW:
                    vm = VirtualMachine(pt_conf, test_conf)
                else:
                    vm = NestedVirtualMachine(pt_conf, test_conf)

def run_non_nested(skip_list=[]):
    for bin, arg in zip(benchmark_list, benchmark_args):
        for b in skip_list:
            if b in bin:
                continue
        test = VirtualMachine.ExecutionCommand(bin, arg)
        for test_conf in TestConfigurations:
            for pt_conf in PageTableConfig:
                if pt_conf == PageTableConfig.EPT or pt_conf == PageTableConfig.SHADOW:
                    vm = VirtualMachine(pt_conf, test_conf)
                else:
                    continue

                for i in range(16):
                    vm.run_test(test, True)
                vm.shutdown()


def virt_tester(test, iterations, tracer=None):
    vm = VirtualMachine(PageTableConfig.EPT, test_config=TestConfigurations.PRE_HEATING)
    for i in range(iterations):
        vm.run_test(test, False)
        # vm.run_test(test, True, "def")
        # vm.run_test(test, True, "TLB")
        # vm.run_test(test, True, "Cache_Misses")
        # vm.run_test(test, True, "Cache_Hits")
    del vm
    vm = VirtualMachine(PageTableConfig.SHADOW, test_config=TestConfigurations.PRE_HEATING)
    for i in range(iterations):
        vm.run_test(test, False)
        # vm.run_test(test, True, "def")
        # vm.run_test(test, True, "TLB")
        # vm.run_test(test, True, "Cache_Misses")
        # vm.run_test(test, True, "Cache_Hits")
    del vm


def nested_virt_tester(test, iterations, tracer=None):
    vm = NestedVirtualMachine(PageTableConfig.EPT_ON_EPT, TestConfigurations.PRE_HEATING)
    for i in range(iterations):
        vm.run_test(test, False)
        # vm.run_test(test, True, "def")
        # vm.run_test(test, True, "TLB")
        # vm.run_test(test, True, "Cache_Misses")
        # vm.run_test(test, True, "Cache_Hits")
    del vm
    vm = NestedVirtualMachine(PageTableConfig.SHADOW_ON_EPT, TestConfigurations.PRE_HEATING)
    for i in range(iterations):
        vm.run_test(test, False)
        # vm.run_test(test, True, "def")
        # vm.run_test(test, True, "TLB")
        # vm.run_test(test, True, "Cache_Misses")
        # vm.run_test(test, True, "Cache_Hits")
    del vm
    vm = NestedVirtualMachine(PageTableConfig.SHADOW_ON_SHADOW, TestConfigurations.PRE_HEATING)
    for i in range(iterations):
        vm.run_test(test, False)
        # vm.run_test(test, True, "def")
        # vm.run_test(test, True, "TLB")
        # vm.run_test(test, True, "Cache_Misses")
        # vm.run_test(test, True, "Cache_Hits")
    del vm


def tester(test, iterations, tracer=None):
    virt_tester(test, iterations, tracer)
    nested_virt_tester(test, iterations, tracer)


def test_code(test):
    vm = VirtualMachine(PageTableConfig.EPT, TestConfigurations.COLD_START)
    vm.run_test(test, False)


if __name__ == "__main__":
    test = VirtualMachine.ExecutionCommand("/usr/bin/time", ["-v", f'{SHARED_DIR}/graph500-2.1/16GB/repeat0/run.sh', "-s", "25"], cores_to_run_on="0,1,2,3,4,5")
    # test_code(test)
    # for i in range(4):
    #     cmd = f'sudo perf stat -o /home/ori/nestedTPTproject/nestedTPT_measurements/L0_traces/spawn --append -e {PERF_EVENTS["def"]} -- taskset -c 0 /home/ori/nestedTPTproject/nestedTPT_measurements/byte-unixbench/UnixBench/pgms/spawn 30'
    #     subprocess.run(cmd, shell=True)
    #     cmd = f'sudo perf stat -o /home/ori/nestedTPTproject/nestedTPT_measurements/L0_traces/spawn --append -e {PERF_EVENTS["TLB"]} -- taskset -c 0 /home/ori/nestedTPTproject/nestedTPT_measurements/byte-unixbench/UnixBench/pgms/spawn 30'
    #     subprocess.run(cmd, shell=True)
    #     cmd = f'sudo perf stat -o /home/ori/nestedTPTproject/nestedTPT_measurements/L0_traces/spawn --append -e {PERF_EVENTS["Cache_Hits"]} -- taskset -c 0 /home/ori/nestedTPTproject/nestedTPT_measurements/byte-unixbench/UnixBench/pgms/spawn 30'
    #     subprocess.run(cmd, shell=True)
    #     cmd = f'sudo perf stat -o /home/ori/nestedTPTproject/nestedTPT_measurements/L0_traces/spawn --append -e {PERF_EVENTS["Cache_Misses"]} -- taskset -c 0 /home/ori/nestedTPTproject/nestedTPT_measurements/byte-unixbench/UnixBench/pgms/spawn 30'
    #     subprocess.run(cmd, shell=True)
    #     cmd = "taskset -c 0 /home/ori/nestedTPTproject/nestedTPT_measurements/byte-unixbench/UnixBench/pgms/spawn 30"
        # cmd = "/usr/bin/time -v taskset -c 0,1,2,3,4,5 ./graph500-2.1/16GB/repeat0/omp-csr -s 25 2>> results.txt >> results.txt"
        # subprocess.run(cmd, shell=True)
    nested_virt_tester(test, 4)
    print("Done All!")