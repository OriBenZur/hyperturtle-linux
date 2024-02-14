from bcc import BPF
from time import sleep, time
from ctypes import c_int

bpf_code = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_HASH(tx_kick_map, u32, u64);
BPF_HISTOGRAM(latency_hist, u64);
BPF_ARRAY(count, u64, 1);
BPF_ARRAY(total_latency, u64, 1);
BPF_ARRAY(total_overhead, u64, 1);

int handle_tx_kick(struct pt_regs *ctx) {
    u64 timestamp = bpf_ktime_get_ns();
    u32 pid = 0;

    // Store the timestamp and PID in a map
    tx_kick_map.update(&pid, &timestamp);

    return 0;
}


int handle_ret_tx_kick(struct pt_regs *ctx) {
    u32 pid = 0;
    tx_kick_map.delete(&pid);
    return 0;
}

int trace_packet_tx(struct pt_regs *ctx) {
    u64 *timestamp;
    u32 pid = 0;
    total_overhead.increment(0, bpf_ktime_get_ns());
    // Retrieve the timestamp from the map
    timestamp = tx_kick_map.lookup(&pid);
    if (timestamp) {
        u64 latency = bpf_ktime_get_ns() - *timestamp;

        // Store the latency in the histogram
        latency_hist.increment(bpf_log2l(latency));
        count.increment(0);
        total_latency.increment(0, latency);

        
    }

    return 0;
}

"""

b = BPF(text=bpf_code)
b.attach_kprobe(event="handle_tx_kick", fn_name="handle_tx_kick")
# b.attach_kretprobe(event="handle_tx_kick", fn_name="handle_ret_tx_kick")
# b.attach_kretprobe(event="vhost_poll_queue", fn_name="handle_ret_tx_kick")

# For ping test only:
b.attach_kretprobe(event="handle_tx_kick", fn_name="trace_packet_tx")
## other tests:
# b.attach_kprobe(event="vhost_exceeds_weight", fn_name="trace_packet_tx")

# b.attach_kprobe(event="handle_rx", fn_name="handle_tx_kick")
# b.attach_kretprobe(event="handle_rx", fn_name="trace_packet_tx")

dist = b["latency_hist"]
count = b["count"]
total_latency = b["total_latency"]
try:
    print("attached probes, hit Ctrl-C to exit")
    start_time = time()
    while True:
        sleep(2)
except KeyboardInterrupt:
    end_time = time()
    dist.print_log2_hist("nsec")
    pcount = count[c_int(0)].value
    if pcount == 0:
        print("No events were captured.")
        exit()
    ptotal_latency = total_latency[c_int(0)].value / 1000
    pavg = ptotal_latency / pcount
    print(f'avg = {pavg:.3f}us, count = {pcount}, total overhead = {ptotal_latency}us, measurement time = {end_time - start_time:.3f}s')
    
    
    
        
