#include <string.h>

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "relay.h"

struct iph_pseudo {
	ipaddr_t	saddr;
	ipaddr_t	daddr;
	uint8_t		reserved;
	uint8_t		protocol;
	uint16_t	l4_len;
} __attribute__((packed)) __attribute__((aligned(4)));

struct relay_connection connections[65536];

ipaddr_t public_host_ip;

static inline unsigned short from32to16(unsigned int x)
{
	x = (x & 0xffff) + (x >> 16);
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static __always_inline uint16_t onec_add(uint16_t x, uint16_t y)
{
	uint32_t z = x + y;
	return from32to16(z);
}

/* from samples/bpf/xdp_adjust_tail.c */
static __always_inline uint16_t csum_fold_helper(uint32_t csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void ipv4_csum(void *data_start, int data_size,
				      uint32_t *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

static void recompute_iph_csum(struct iphdr *iph)
{
	uint32_t csum = 0;

	iph->check = 0;
	csum = 0;
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;
}

static void ipv4_mk_pheader(struct iphdr *iph, struct iph_pseudo *iphp)
{
	iphp->saddr = iph->saddr;
	iphp->daddr = iph->daddr;
	iphp->reserved = 0;
	iphp->protocol = iph->protocol;
	iphp->l4_len = bpf_htons(bpf_ntohs(iph->tot_len) - sizeof(struct iphdr));
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data_start = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = data_start;

	struct ethhdr *eth = data;
	data = eth + 1;
	if (data > data_end)
		return XDP_DROP;

	bool eth_is_multicast = eth->h_dest[0] & 1;
	if (eth_is_multicast)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = data;
	data = iph + 1;
	if (data > data_end)
		return XDP_DROP;

	if (iph->daddr != public_host_ip)
		return XDP_PASS;

 	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	struct udphdr *udph = data;
	data = udph + 1;
	if (data > data_end)
		return XDP_DROP;

	// In verifier, bpf_ntohs lose reg min max info. Fix it here.
	volatile int dest_port = bpf_ntohs(udph->dest);
	struct relay_connection *conn = &connections[dest_port & 0xFFFF];
	if (!conn->exists)
		return XDP_PASS;

	if (iph->saddr != conn->recv_rem_ip)
		return XDP_PASS;

	// Handle port remapping here
	if (bpf_ntohs(udph->source) != conn->recv_rem_port) {
		conn->recv_rem_port = bpf_ntohs(udph->source);
		connections[conn->send_loc_port].send_rem_port = conn->recv_rem_port;
	}

	struct iph_pseudo iphp_orig;
	ipv4_mk_pheader(iph, &iphp_orig);

	if (udph->check) {
		udph->check = onec_add(udph->check, udph->source);
		udph->check = onec_add(udph->check, udph->dest);
		udph->check = onec_add(udph->check, ~bpf_htons(conn->send_loc_port));
		udph->check = onec_add(udph->check, ~bpf_htons(conn->send_rem_port));
	}
	udph->source = bpf_htons(conn->send_loc_port);
	udph->dest = bpf_htons(conn->send_rem_port);

	iph->saddr = public_host_ip;
	iph->daddr = conn->send_rem_ip;
	recompute_iph_csum(iph);

	struct iph_pseudo iphp_new;
	ipv4_mk_pheader(iph, &iphp_new);

	if (udph->check) {
		uint32_t csum = 0;
		csum = bpf_csum_diff((void *)&iphp_orig, sizeof(struct iph_pseudo),
			             (void *)&iphp_new, sizeof(struct iph_pseudo),
			             ~udph->check);
		udph->check = csum_fold_helper(csum);
		if (!udph->check)
			udph->check = 0xffff;
	}

	macaddr_t h_source;
	memcpy(h_source, eth->h_source, sizeof(macaddr_t));
	memcpy(eth->h_source, eth->h_dest, sizeof(macaddr_t));
	memcpy(eth->h_dest, h_source, sizeof(macaddr_t));

	return XDP_TX;
}
