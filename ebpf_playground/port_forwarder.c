#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

BPF_HASH(packets);
SEC("xdp")
int port_forwarder(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;  // Not enough space for Ethernet header
    }

    // Check if it's an IPv4 packet
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if (ip + 1 > (struct iphdr *)data_end) {
            return XDP_PASS;  // Not enough space for IP header
        }

        // Check if it's a TCP packet and the destination port is 11211
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (tcp + 1 > (struct tcphdr *)data_end) {
                return XDP_PASS;  // Not enough space for TCP header
            }

            if (tcp->dest == htons(11211)) {
                // Modify the destination IP address to 192.17.0.2
                ip->daddr = htonl(0xC0110202);  // 192.17.0.2 in hexadecimal
                bpf_redirect_map(&port_map, 0, 0);  // Redirect the packet
                u64 key = 0;
                u64 counter = 0;
                u64 *p = packets.lookup(&key);
                if (p != 0) {
                    counter = *p;
                }
                counter++;
                packets.update(&key, &counter);

                // Redirect the packet
                return XDP_REDIRECT;
            }
        }
    }

    return XDP_PASS;
}
