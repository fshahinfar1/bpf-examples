// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "xdpsock.h"

#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* This XDP program is only needed for multi-buffer and XDP_SHARED_UMEM modes.
 * If you do not use these modes, libbpf can supply an XDP program for you.
 */

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

int num_socks = 0;
static unsigned int rr = 0;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	// send only the udp traffic to AF_XDP
	void *data = (void *)(__u64)ctx->data;
	void *data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_ntohs(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	rr = (rr + 1) & (num_socks - 1);
	int ret =  bpf_redirect_map(&xsks_map, rr, XDP_DROP);
	if (ret == XDP_DROP) {
		bpf_printk("failed to redirect %d / %d", rr, num_socks);
	} else {
		// bpf_printk("to %d", rr);
	}
	return ret;
}

char  _license[] SEC("license") = "GPL";
