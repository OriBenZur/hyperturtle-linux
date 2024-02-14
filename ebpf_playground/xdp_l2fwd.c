// SPDX-License-Identifier: GPL-2.0
/* Example of L2 forwarding via XDP. FDB is a <vlan,dmac> hash table
 * returning device index to redirect packet.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "xdp_l2fwd"
#include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/if_packet.h>
// #include <linux/if_vlan.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/version.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>

// #include "xdp_fdb.h"

/* For TX-traffic redirect requires net_device ifindex to be in this devmap */
// struct bpf_map_def SEC("maps") xdp_fwd_ports = {
// 	.type = BPF_MAP_TYPE_DEVMAP_HASH,
// 	.key_size = sizeof(u32),
// 	.value_size = sizeof(struct bpf_devmap_val),
// 	.max_entries = 512,
// };

// /* <vlan,dmac> to device index map */
// struct bpf_map_def SEC("maps") fdb_map = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(struct fdb_key),
// 	.value_size = sizeof(u32),
// 	.max_entries = 512,
// };

// SEC("xdp_l2fwd")
BPF_HASH(packets);
int xdp_l2fwd(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_devmap_val *entry;
	struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    // u8 smac[ETH_ALEN];
	// u16 h_proto = 0;
	void *nh;
	int rc;
    u64 key = 0;

	/* data in context points to ethernet header */
	eth = data;

	/* set pointer to header after ethernet header */
	nh = data + sizeof(*eth);
	if (nh > data_end)
		return XDP_DROP; // malformed packet


	if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    ip = nh;
    if (ip + 1 > data_end)
        return XDP_DROP;  // malformed packet

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
    if (tcp + 1 > data_end)
        return XDP_DROP;  // malformed packet

    if (tcp->dest != htons(11211))
        return XDP_PASS;

    // if (ip->saddr == htonl(0xac110002)) {// Going out of VM
    //     ip->saddr = htonl(0x0A00020F);  // 10.0.2.15 in hexadecimal
    //     key = 1;
    // } else                              // Change source to 10.0.2.15

    ip->daddr = htonl(0xac110002);  // 172.17.0.2 in hexadecimal
    ip->ttl--;

    // u8 src[] = {0x02,0x42,0xac,0x11,0x00,0x02}; // Docker container MAC address
    u8 src[] = {0x02,0x42,0x43,0x46,0x51,0xaf}; // Docker bridge MAC address
    u8 dst[] = {0x02,0x42,0x43,0x46,0x51,0xaf}; // Docker bridge MAC address
    for (int i = 0; i < 6; i++) {
        eth->h_dest[i] = dst[i];
        eth->h_source[i] = src[i];
    }

    u64 counter = 0;
    u64 *p = packets.lookup(&key);
    if (p != 0) {
        counter = *p;
    }
    // bpf_redirect(2, 0);
    counter++;
    packets.update(&key, &counter);

    return bpf_redirect(3, 0);
}

// char _license[] SEC("license") = "GPL";
// int _version SEC("version") = LINUX_VERSION_CODE;