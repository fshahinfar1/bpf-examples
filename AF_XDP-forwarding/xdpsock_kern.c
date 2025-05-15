// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "xdpsock.h"

#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

unsigned int num_socks = 0;

// #define DEBUG 1
#define DEST_PORT_MULTIPLEX 1

#ifndef DEST_PORT_MULTIPLEX
static unsigned int rr = 0;
#endif

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	int ret;
	// send only the udp traffic to AF_XDP
	void *data = (void *)(__u64)ctx->data;
	void *data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (struct iphdr *)(eth + 1);
#if defined (DEST_PORT_MULTIPLEX)
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
#else
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
#endif
	if (eth->h_proto != bpf_ntohs(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
#if defined(DEST_PORT_MULTIPLEX)
	unsigned short dest_port = bpf_ntohs(udp->dest);
	unsigned int xsk_index = dest_port % num_socks;
	ret = bpf_redirect_map(&xsks_map, xsk_index, XDP_DROP);
#else
	// Round robin
	// rr = (rr + 1) & (num_socks - 1);
	rr = (rr + 1) % (num_socks);
	ret = bpf_redirect_map(&xsks_map, rr, XDP_DROP);
#endif
#ifdef DEBUG
	if (ret == XDP_DROP) {
		bpf_printk("failed to redirect %d / %d", rr, num_socks);
	} else {
		bpf_printk("to %d", rr);
	}
#endif
	return ret;
}

char  _license[] SEC("license") = "GPL";
