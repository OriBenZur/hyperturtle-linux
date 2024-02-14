#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/cdefs.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "jhash.h"

#define PORT 7999

#ifndef memcpy
 #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define bpf_printk(fmt, ...)        \
({                                  \
    char ____fmt[] = fmt;           \
    bpf_trace_printk(____fmt, sizeof(____fmt),  \
        ##__VA_ARGS__);    \
})


#define MAX_SERVERS 512
/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

#define MAX_UDP_LENGTH 1480

struct pkt_meta {
    __be32 src;
    __be32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
};

#pragma pack(push, 1)
struct dest_info {
    __u32 saddr;
    __u32 daddr;
    __u64 bytes;
    __u64 pkts;
    __u8 dmac[6];
    __u16 ifindex;
};
#pragma pack(pop)

struct bpf_elf_map SEC("maps") servers = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct dest_info),
    .max_elem = MAX_SERVERS,
    .pinning = PIN_GLOBAL_NS,
};

static __always_inline struct dest_info *hash_get_dest(struct pkt_meta *pkt)
{
    __u32 key;
    struct dest_info *tnl;

    /* hash packet source ip with both ports to obtain a destination */
    key = jhash_2words(pkt->src, pkt->ports, MAX_SERVERS) % MAX_SERVERS;

    /* get destination's network details from map */
    tnl = bpf_map_lookup_elem(&servers, &key);
    if (!tnl) {
        /* if entry does not exist, fallback to key 0 */
        bpf_printk("Forwarding entry doesn't exist, falling back to key 0\n");
        key = 0;
        tnl = bpf_map_lookup_elem(&servers, &key);
    }
    bpf_printk("Got key %d\n", key);
    return tnl;
}

static __always_inline __u16 ip_checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}


static __always_inline int do_redirect(struct ethhdr *eth, struct iphdr *iph, struct pkt_meta *pkt, __u16 size) {
    struct dest_info *tnl;
    __u16 pkt_size = size; /* payload size excl L2 crc */

    tnl = hash_get_dest(pkt);
    if (!tnl) {
        return XDP_DROP;
    }

    iph->saddr = tnl->saddr;
    iph->daddr = tnl->daddr;

    memcpy(eth->h_source, arr, sizeof(eth->h_source));
    memcpy(eth->h_dest , tnl->dmac, sizeof(eth->h_dest));
    
    bpf_printk("1.redirect mac %d %d %d", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_printk("2.redirect mac %d %d %d", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("3.redirect ifindex %d", tnl->ifindex);
    iph->id = iph->id + 1;

    iph->check = 0;
    iph->check = ip_checksum((__u16 *)iph, sizeof(struct iphdr));

    __sync_fetch_and_add(&tnl->pkts, 1);
    __sync_fetch_and_add(&tnl->bytes, pkt_size);
    return bpf_redirect(tnl->ifindex, 0);
}


static __always_inline int process_udp(struct xdp_md *ctx, __u64 off, struct pkt_meta *pkt) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udp;

    eth = data;
    iph = data + off;
    udp = data + off + sizeof(struct iphdr);

    if (udp + 1 > data_end) { // No need to check eth and IP because < udp
        bpf_printk("packet was dropped due to invalid size");
        return XDP_DROP;
    }

    if (udp->dest != bpf_htons(PORT)) {
        return XDP_PASS;
    }
    pkt->port16[0] = udp->source;
    pkt->port16[1] = udp->dest;
    return do_redirect(eth, iph, pkt, data_end - data);
}


static __always_inline int process_tcp(struct xdp_md *ctx, __u64 off, struct pkt_meta *pkt) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcp;

    eth = data;
    iph = data + off;
    tcp = data + off + sizeof(struct iphdr);

    if (tcp + 1 > data_end) { // No need to check eth and IP because < tcp
        bpf_printk("packet was dropped due to invalid size");
        return XDP_DROP;
    }

    if (tcp->dest != bpf_htons(PORT)) {
        return XDP_PASS;
    }
    pkt->port16[0] = tcp->source;
    pkt->port16[1] = tcp->dest;
    return do_redirect(eth, iph, pkt, data_end - data);
}


static __always_inline int process_packet(struct xdp_md *ctx, __u64 off)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct iphdr *iph;
    struct pkt_meta pkt = {};
    __u8 protocol;

    iph = data + off;
    protocol = iph->protocol;
    if (iph + 1 > data_end)
        return XDP_DROP;

    if (iph->ihl != 5)
        return XDP_DROP;
  
    /* do not support fragmented packets as L4 headers may be missing */
    if (iph->frag_off & IP_FRAGMENTED)
        return XDP_DROP;

    pkt.src = iph->saddr;
    pkt.dst = iph->daddr;

    if (protocol == IPPROTO_UDP) {
        return process_udp(ctx, off, &pkt);
    }

    if (protocol == IPPROTO_TCP) {
        return process_tcp(ctx, off, &pkt);
    }

    return XDP_PASS;
}


SEC("xdp")
int loadbal(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 eth_proto;
    __u32 nh_off;

    nh_off = sizeof(struct ethhdr);
    if (data + nh_off > data_end)
        return XDP_DROP;
    eth_proto = eth->h_proto;

    /* demo program only accepts ipv4 packets */
    if (eth_proto == bpf_htons(ETH_P_IP))
        return process_packet(ctx, nh_off);
    else
        return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
