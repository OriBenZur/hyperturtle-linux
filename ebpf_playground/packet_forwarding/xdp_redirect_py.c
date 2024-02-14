// #include <stdbool.h>
// #include <stddef.h>
// #include <string.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>
// #include <sys/cdefs.h>

#include "bpf_endian.h"
// #include "bpf_helpers.h"
#include "jhash.h"

#define PORT 7999

#ifndef memcpy
 #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define CHECK_PACKET(X) do { \
        if ((void *)((X) + 1) > data_end) { \
            return XDP_DROP; \
        } \
    } while(0) \

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

enum {
    SPORT = 0,
    DPORT
};

enum RedirDirection {
    TO_VM = 0,
    FROM_VM
};

// struct bpf_elf_map SEC("maps") servers = {
//     .type = BPF_MAP_TYPE_HASH,
//     .size_key = sizeof(__u32),
//     .size_value = sizeof(struct dest_info),
//     .max_elem = MAX_SERVERS,
//     .pinning = PIN_GLOBAL_NS,
// };
BPF_HASH(local_ips, __u32, __u32, MAX_SERVERS);
BPF_HASH(incoming_redirections, __u16, struct dest_info, MAX_SERVERS);
BPF_HASH(outgoing_redirections, __u16, struct dest_info, MAX_SERVERS);
BPF_DEVMAP(devmap, MAX_SERVERS);

/* Get redirection info as a function of ports
@Returns redir exists ? 0 : XDP_PASS
@Effects Stores redir info in tnl */
static __always_inline int hash_get_dest(struct pkt_meta *pkt, __u16 *key, enum RedirDirection *direction, struct dest_info **tnl)
{
    int *r;

    if (pkt == NULL || key == NULL || tnl == NULL || direction == NULL)
        return XDP_PASS;

    r = local_ips.lookup(&pkt->src);
    if (r) {
        *key = pkt->port16[SPORT];
        // bpf_trace_printk("src matched local ip; key: %d", *key);
        *direction = FROM_VM;
        *tnl = outgoing_redirections.lookup(key);
        return *tnl ? 0 : XDP_PASS;
    }

    r = local_ips.lookup(&pkt->dst);
    if (r) {
        *key = pkt->port16[DPORT];
        // bpf_trace_printk("dst matched local ip; key: %d", *key);
        *direction = TO_VM;
        *tnl = incoming_redirections.lookup(key);
        return *tnl ? 0 : XDP_PASS;
    }
    
    return XDP_PASS;
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


static __always_inline __u16 pseudoheader_checksum(struct iphdr *ip, __u16 len , void * data_end) {
    __u32 csum = 0;

    csum += 0xFFFF & (ip->saddr);
    csum += 0xFFFF & (ip->saddr >> 16);
    csum += 0xFFFF & (ip->daddr);
    csum += 0xFFFF & (ip->daddr >> 16);
    csum += (__u16)ip->protocol << 8;
    csum += len;
    bpf_trace_printk("Psuedo-header checksum: %d", htons(csum));
    // csum += 2;
    return (csum & 0xFFFF) + ((csum >> 16) & 0xFFFF);
}

// static __always_inline __u32 update_l4_checksum(__u32 checksum, __u32 old_val, __u32 new_val) {
//     __u32 csum = 0;
//     csum = ~(checksum) & 0xFFFF;
//     if (old_val != 0) csum += ~old_val;
//     csum = (csum & 0xFFFF) + (csum >> 16);
//     if (new_val != 0) csum += new_val;
//     csum = (csum & 0xFFFF) + (csum >> 16);
//     csum = (csum & 0xFFFF) + (csum >> 16);
//     checksum = (~csum & 0xFFFF);
//     return csum;
// }

static __always_inline __u64 fold(__u64 sum) {
    sum = (sum & 0xFFFF) + ((sum >> 16) & 0xFFFF) + ((sum >> 32) & 0xFFFF) + ((sum >> 48) & 0xFFFF);
    sum = (sum & 0xFFFF) + ((sum >> 16) & 0xFFFF); //+ ((sum >> 32) & 0xFFFF) + ((sum >> 48) & 0xFFFF);
    sum = (sum & 0xFFFF) + ((sum >> 16) & 0xFFFF); //+ ((sum >> 32) & 0xFFFF) + ((sum >> 48) & 0xFFFF);
    return sum;
}


// static __always_inline __u16 udp_checksum(struct iphdr *ip, struct udphdr * udp, void * data_end) {
//     __u32 csum = 0;
//     __u16 *buf = (__u16*)udp;
//     int i = 0;

//     // Compute pseudo-header checksum
//     csum += 0xFFFF & (ip->saddr);
//     csum += 0xFFFF & (ip->saddr >> 16);
//     csum += 0xFFFF & (ip->daddr);
//     csum += 0xFFFF & (ip->daddr >> 16);
//     csum += (__u16)ip->protocol << 8;
//     csum += udp->len;
//     bpf_trace_printk("Psuedo-header checksum: %d", htons(csum));


// //     // Compute checksum on udp header + payload
// //     for (i = 0; i * 2 < MAX_UDP_LENGTH; i += 1) {
// //         if ((void *)(buf + i + 1) > data_end) {
// //             break;
// //         }
// //         csum += buf[i];
// //         if (csum & 0x80000000)
// //             csum = (csum & 0xFFFF) + (csum >> 16);
// //     }

// //     if (((void *)(buf + i)) + 1 <= data_end) {
// //        // In case payload is not 2 bytes aligned
// //         csum += *(__u8 *)(buf + i);
// //     }

// //     if (csum & 0x80000000)
// //         csum = (csum & 0xFFFF) + (csum >> 16);
        
//    csum += 2;
//    return (csum & 0xFFFF) + (csum >> 16);
// }

static __always_inline int process_udp(struct udphdr *udp, struct pkt_meta *pkt, void *data_end) {
    CHECK_PACKET(udp);

    pkt->port16[SPORT] = htons(udp->source);
    pkt->port16[DPORT] = htons(udp->dest);
    
    return 0;
}


static __always_inline int process_tcp(struct tcphdr *tcp, struct pkt_meta *pkt, void *data_end) {
    CHECK_PACKET(tcp);

    pkt->port16[SPORT] = htons(tcp->source);
    pkt->port16[DPORT] = htons(tcp->dest);
    return 0;
}

union l4_header {
    struct tcphdr tcp;
    struct udphdr udp;
};

static __always_inline int process_packet(struct xdp_md *ctx, __u64 off)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int r = 0;
    struct ethhdr *eth;
    struct iphdr *iph;
    union l4_header *l4;
    struct pkt_meta pkt = {};
    struct dest_info *tnl;
    enum RedirDirection direction;
    __u64 temp_csum = 0;
    __u16 key;
    __u8 protocol;

    __u64 start, fin;
    start = bpf_ktime_get_ns();

    eth = data;
    CHECK_PACKET(eth);

    iph = data + off;
    CHECK_PACKET(iph);

    protocol = iph->protocol;
    if (iph->ihl != 5) {
        bpf_trace_printk("packet was passed due to iph->ihl != 5");
        return XDP_PASS;
    }
  
    /* do not support fragmented packets as L4 headers may be missing */
    if (iph->frag_off & IP_FRAGMENTED) {
        bpf_trace_printk("packet was passed due to fragmented");
        return XDP_PASS;
    }

    pkt.src = htonl(iph->saddr);
    pkt.dst = htonl(iph->daddr);
    pkt.ports = 1;
    
    // bpf_trace_printk("IP OK, moving to L4");
    
    l4 = data + off + sizeof(struct iphdr);
    r = XDP_PASS;
    if (protocol == IPPROTO_UDP && (r = process_udp(&l4->udp, &pkt, data_end)) == 0) {
        // bpf_trace_printk("Process UDP");
    } else if (protocol == IPPROTO_TCP && (r = process_tcp(&l4->tcp, &pkt, data_end)) == 0) {
        // bpf_trace_printk("Process TCP");
    } else {
        bpf_trace_printk("Not UDP or TCP");
        return r;
    }

    r = hash_get_dest(&pkt, &key, &direction, &tnl);
    if (r != 0) {
        return r;
    }
    
    // bpf_trace_printk("hash_get_dest successful");
    temp_csum += ~iph->saddr;
    temp_csum += ~iph->daddr;

    iph->saddr = tnl->saddr == 0 ? iph->saddr : htonl(tnl->saddr);
    iph->daddr = tnl->daddr == 0 ? iph->daddr : htonl(tnl->daddr);

    // char arr[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_source));
    memcpy(eth->h_dest , tnl->dmac, sizeof(eth->h_dest));
    
    // bpf_trace_printk("1.redirect mac %d %d %d", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    // bpf_trace_printk("2.redirect mac %d %d %d", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    // bpf_trace_printk("3.redirect ifindex %d", tnl->ifindex);
    iph->id = iph->id + 1;
    iph->ttl--;
    iph->check = 0;
    iph->check = ip_checksum((__u16 *)iph, sizeof(struct iphdr));
    temp_csum += iph->saddr;
    temp_csum += iph->daddr;
    if (protocol == IPPROTO_UDP) {
        CHECK_PACKET(&l4->udp);
        temp_csum += l4->udp.check & 0xFFFF;
        temp_csum = fold(temp_csum);
        l4->udp.check = (__u16)(temp_csum & 0xFFFF);
    }
    if (protocol == IPPROTO_TCP) {
        CHECK_PACKET(&l4->tcp);
        temp_csum += l4->tcp.check & 0xFFFF;
        temp_csum = fold(temp_csum);
        l4->tcp.check = (__u16)(temp_csum & 0xFFFF);
    }

    tnl->pkts++;
    tnl->bytes += (__u16)(data_end - data);
    if (direction == FROM_VM)
        outgoing_redirections.update(&key, tnl);
    else
        incoming_redirections.update(&key, tnl);
    fin = bpf_ktime_get_ns();
    if (fin - start > 10000)
        bpf_trace_printk("Redirected packet in %lu ns", fin - start);
    return devmap.redirect_map(tnl->ifindex, 0);
}


// SEC("xdp")
int loadbal(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int r = XDP_PASS;
    __u32 eth_proto;
    __u32 nh_off;
    // return XDP_PASS;
    nh_off = sizeof(struct ethhdr);
    if (data + nh_off > data_end)
        return XDP_DROP;
    if (eth->)
    eth_proto = eth->h_proto;
    
    /* demo program only accepts ipv4 packets */
    if (eth_proto == bpf_htons(ETH_P_IP))
        r = process_packet(ctx, nh_off);
    if (r == XDP_DROP)
        bpf_trace_printk("Dropping packet");
    if (r == XDP_ABORTED)
        bpf_trace_printk("Packet aborted");
    // bpf_trace_printk("Returningg %d", r);
    return r;
}
