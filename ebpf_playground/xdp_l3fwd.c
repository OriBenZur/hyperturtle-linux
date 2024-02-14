// SPDX-License-Identifier: GPL-2.0
/* Example of L3 forwarding via XDP and use of bpf FIB lookup helper.
 *
 * Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "xdp_l3fwd"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// #include <bpf/bpf_helpers.h>

#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)

// struct bpf_map_def SEC("maps") xdp_l3fwd_ports = {
// 	.type = BPF_MAP_TYPE_DEVMAP,
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(int),
// 	.max_entries = 512,
// };
BPF_HASH(packets);
BPF_HASH(xdp_l3fwd_ports, int, int);
BPF_DEVMAP(xdp_l3fwd_devs, 512);

static __always_inline void update_packets(u64 key) {
	u64 counter = 0;
	u64 *p = packets.lookup(&key);
	if (p != 0) {
		counter = *p;
	}
	counter++;
	packets.update(&key, &counter);
}


/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))

static inline void update_ip_checksum(struct iphdr *iph)
{
    __u16 *next_iph_u16 = (__u16 *)iph;
	iph->check = 0;

	#pragma clang loop unroll(full)
	for (int i = 0; i < sizeof(*iph) >> 1; i++)
		iph->check += *next_iph_u16++;

	iph->check = ~((iph->check & 0xffff) + (iph->check >> 16));
}


static __always_inline int xdp_l3fwd_flags(struct xdp_md *ctx, u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph, *old_iph;
	struct tcphdr *tcp;
	u16 h_proto;
	u64 nh_off;
	int rc;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	iph = data + nh_off;

	if (iph + 1 > data_end)
		return XDP_DROP;

	if (iph->ttl <= 1)
		return XDP_PASS;

	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	tcp = (struct tcphdr *)((void *)iph + sizeof(*iph));
	if (tcp + 1 > data_end)
        return XDP_DROP;  // malformed packet
	
	if (tcp->dest != htons(11211))
        return XDP_PASS;
	
	// if (iph->frag_off != 0) {
	// 	update_packets(htons(iph->frag_off));
	// 	return XDP_PASS;
	// }

        // Update destination IP to 172.17.02
	iph->daddr = htonl(0xac110002);
	update_ip_checksum(iph);
	
	fib_params.family	= AF_INET;
	fib_params.tos		= iph->tos;
	fib_params.l4_protocol	= iph->protocol;
	fib_params.tot_len	= ntohs(iph->tot_len);
	fib_params.ipv4_src	= iph->saddr;
	fib_params.ipv4_dst	= iph->daddr;
	fib_params.ifindex = ctx->ingress_ifindex;

	fib_params.sport = tcp->source;
	fib_params.dport = tcp->dest;


	// iph->check = 
        // } else if (h_proto == htons(ETH_P_IPV6)) {
	// 	struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
	// 	struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

	// 	ip6h = data + nh_off;
	// 	if (ip6h + 1 > data_end)
	// 		return XDP_DROP;

	// 	if (ip6h->hop_limit <= 1)
	// 		return XDP_PASS;

	// 	fib_params.family	= AF_INET6;
	// 	fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
	// 	fib_params.l4_protocol	= ip6h->nexthdr;
	// 	fib_params.tot_len	= ntohs(ip6h->payload_len);
	// 	*src			= ip6h->saddr;
	// 	*dst			= ip6h->daddr;





	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		// update_packets(fib_params.ifindex);
		// if (!xdp_l3fwd_ports.lookup(&fib_params.ifindex))
		// 	return XDP_PASS;

		if (h_proto == htons(ETH_P_IP))
			ip_decrease_ttl(iph);
	
		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		for (int i = 0; i < 6; i++) {
			update_packets(fib_params.dmac[i]);
		}
		return xdp_l3fwd_devs.redirect_map(fib_params.ifindex, 0);
	}
	else if (rc > 0)
		update_packets(-rc);
	else
		update_packets(-1);

	return XDP_PASS;
}

// SEC("xdp")
int xdp_l3fwd_prog(struct xdp_md *ctx)
{   
    int r = xdp_l3fwd_flags(ctx, 0);
	// update_packets(r);
    return r;
}

// SEC("xdp")
int xdp_l3fwd_direct_prog(struct xdp_md *ctx)
{
	return xdp_l3fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
}

// char _license[] SEC("license") = "GPL";