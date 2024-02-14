#include "packet.h"

BPF_HASH(packets);

int hello_packet(struct xdp_md *ctx) {
    u64 counter = 0;
    u64 key = 0, port = 0;
    u64 *p;

    key = lookup_protocol(ctx);
    if (key != 0) {
        p = packets.lookup(&key);
        if (p != 0) {
            counter = *p;
        }
        counter++;
        packets.update(&key, &counter);
    }
    port = lookup_port(ctx);
    if (port != 0) {
        p = packets.lookup(&port);
        if (p != 0) {
            counter = *p;
        }
        counter++;
        bpf_trace_printk("counter: %llu\n", counter);
        packets.update(&port, &counter);
    }
    

    return XDP_PASS;
}