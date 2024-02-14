// #include "../../vmlinux_guest.h"
#include "../packet.h"
#include <linux/bpf.h>
#include <linux/jhash.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

#define MAP_SIZE 1024
#define HASH_SEED 0xdeadbeef

/**
 * This progra
*/

typedef struct rule_t {
    __u32 port;
    __u32 action;
} rule;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAP_SIZE);
    __type(key, __u32);
    __type(value, rule);
	__uint(map_flags, 1024); // BPF_F_MMAPABLE
} rules SEC(".maps");


static __always_inline __u64 lookup_port(struct xdp_md *ctx)
{
    __u64 ret = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end && iph->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end)
                ret = htons(tcph->dest);
        }
    }

    return ret;
}

// static __always_inline hash_val *lookup_hash_array(struct xdp_md *ctx, __u64 key) {
//     for (int i = 0; i < MAP_SIZE / sizeof(hash_val); i++) {
//         __u32 hash = jhash_1word(key, HASH_SEED);
//         __u32 index = hash % MAP_SIZE;
//         hash_val *val = bpf_map_lookup_elem(&packets_to_filter, &index);
//         if (val == NULL || val->key == 0)
//             return NULL;
//         if (val->key == key)
//             return val;
//         key = index;
//     }
// }

SEC("xdp")
int packet_filter(struct xdp_md *ctx) {
    __u64 port = 0;
    __u32 key = 0;
    __u64 *p;

    port = lookup_port(ctx);

    for (int i = 0; i < MAP_SIZE / sizeof(rule); i++) {
        rule *r = bpf_map_lookup_elem(&rules, &i);
        if (r == NULL || r->port == 0)
            break;
        if (r->port == port)
            return r->action;
    }
    return XDP_DROP;
}