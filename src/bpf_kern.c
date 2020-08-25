
#include <stdbool.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf_kern.h"
#include "pkt.h"
#include "pkt.inc.c"

#define SECOND_NS 1000000000ULL

// It would be NAT Type B otherwise
#define NAT_TYPE_A

struct conntrack_key {
	uint8_t  protocol;
	uint16_t sport;
#ifndef NAT_TYPE_A
	ipaddr_t daddr;
	uint16_t dport;
#endif
} __attribute__((packed));
struct conntrack_entry {
	ipaddr_t saddr;
	uint64_t ktime_ns;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conntrack_key);
	__type(value, struct conntrack_entry);
	__uint(max_entries, 1024);
} conntrack_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, ipaddr_t);
	__type(value, struct remote_addr);
	__uint(max_entries, 256);
} remote_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_XSKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct iph_pseudo {
	ipaddr_t	saddr;
	ipaddr_t	daddr;
	uint8_t		reserved;
	uint8_t		protocol;
	uint16_t	l4_len;
} __attribute__((packed)) __attribute__((aligned(4)));

struct overhead_csum {
	struct iph_pseudo	iphp;
	struct udphdr		udph_n;
	struct iphdr		iph_o;
} __attribute__((packed)) __attribute__((aligned(4)));

macaddr_t switch_mac;
macaddr_t host_mac;
macaddr_t gateway_mac;

ipaddr_t switch_ip;
ipaddr_t public_host_ip;
ipaddr_t fake_gateway_ip;

ipaddr_t subnet_mask;

uint16_t vpn_port;

// #define debug_printk(...) do {} while (0)
#define debug_printk(...) bpf_printk(__VA_ARGS__)

/* from include/net/ip.h, samples/bpf/xdp_fwd_user.c */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	uint32_t check = (uint32_t)iph->check;

	check += (uint32_t)bpf_htons(0x0100);
	iph->check = (uint16_t)(check + (check >= 0xFFFF));
	return --iph->ttl;
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

static void recompute_l4_csum_fast(struct xdp_md *ctx, struct iphdr *iph,
				   struct iph_pseudo *iphp_orig)
{
	struct iph_pseudo iphp_new;
	ipv4_mk_pheader(iph, &iphp_new);

	void *l4 = (void *)(iph + 1);

	uint16_t *csum_field;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = l4;
		csum_field = &tcph->check;
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = l4;
		csum_field = &udph->check;

		// if ipv4
		if (!*csum_field)
			return;
	} else
		return;

	void *data_end = (void *)(long)ctx->data_end;
	if ((void *)(csum_field + 1) > data_end)
		return;

	uint32_t csum = 0;
	csum = bpf_csum_diff((void *)iphp_orig, sizeof(struct iph_pseudo),
		             (void *)&iphp_new, sizeof(struct iph_pseudo),
		             ~(*csum_field));
	*csum_field = csum_fold_helper(csum);
	if (!*csum_field)
		*csum_field = 0xffff;
}

static __always_inline bool mac_eq(macaddr_t a, macaddr_t b)
{
	// return !memcmp(a, b, sizeof(macaddr_t))
	return (a[0] == b[0] &&
		a[1] == b[1] &&
		a[2] == b[2] &&
		a[3] == b[3] &&
		a[4] == b[4] &&
		a[5] == b[5]);
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

	bool eth_is_broadcast = mac_eq(eth->h_dest, BROADCAST_MAC);

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		uint16_t src_port, dst_port;

		struct iphdr *iph = data;
		data = iph + 1;
		if (data > data_end)
			return XDP_DROP;

		struct iph_pseudo iphp_orig;
		ipv4_mk_pheader(iph, &iphp_orig);

		uint16_t old_csum;

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph = data;
			data = tcph + 1;
			if (data > data_end)
				return XDP_DROP;

			src_port = tcph->source;
			dst_port = tcph->dest;

			old_csum = tcph->check;
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph = data;
			data = udph + 1;
			if (data > data_end)
				return XDP_DROP;

			src_port = udph->source;
			dst_port = udph->dest;

			old_csum = udph->check;

			if (dst_port == bpf_htons(49152) &&
			    eth_is_broadcast && !switch_ip) {
				switch_ip = iph->saddr;
				memcpy(switch_mac, eth->h_source, sizeof(macaddr_t));
			}
		} else // TODO: ICMP?
			return XDP_PASS;

		if (mac_eq(switch_mac, eth->h_source)) {
			if (eth_is_broadcast) {
				if (iph->protocol == IPPROTO_UDP &&
				    dst_port == bpf_htons(67) &&
				    dst_port == bpf_htons(68))
					// DHCP
					return XDP_PASS;

				/* VPN broadcast route */
				// source: tools/lib/bpf/xsk.c
				int ret, index = ctx->rx_queue_index;

				// A set entry here means that the correspnding queue_id
				// has an active AF_XDP socket bound to it.
				ret = bpf_redirect_map(&xsks_map, index, XDP_PASS);
				if (ret > 0)
					return ret;

				// Fallback for pre-5.3 kernels, not supporting default
				// action in the flags parameter.
				if (bpf_map_lookup_elem(&xsks_map, &index))
					return bpf_redirect_map(&xsks_map, index, 0);

				return XDP_PASS;
			}

			if (fake_gateway_ip &&
			    same_subnet(iph->saddr, fake_gateway_ip, subnet_mask) &&
			    !same_subnet(iph->daddr, fake_gateway_ip, subnet_mask)) {
				/* NAT route */
				if (iph->ttl <= 1)
					return XDP_PASS;

				ip_decrease_ttl(iph);

				struct conntrack_key conntrack_key = {
					.protocol = iph->protocol,
					.sport = src_port,
#ifndef NAT_TYPE_A
					.daddr = iph->daddr,
					.dport = dst_port,
#endif
				};
				struct conntrack_entry conntrack_entry = {
					.saddr = iph->saddr,
					.ktime_ns = bpf_ktime_get_ns(),
				};
				bpf_map_update_elem(&conntrack_map, &conntrack_key,
						    &conntrack_entry, BPF_ANY);

				iph->saddr = public_host_ip;
				recompute_iph_csum(iph);
				recompute_l4_csum_fast(ctx, iph, &iphp_orig);

				memcpy(eth->h_dest, gateway_mac, sizeof(macaddr_t));
				memcpy(eth->h_source, host_mac, sizeof(macaddr_t));

				return XDP_TX;
			}

			struct remote_addr *remote_addr =
				bpf_map_lookup_elem(&remote_addrs, &iph->daddr);
			if (!remote_addr)
				return XDP_PASS;

			/* VPN route */
			if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct iphdr) +
						sizeof(struct udphdr))))
				return XDP_DROP;

			data_start = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			data = data_start;

			eth = data;
			data = eth + 1;
			if (data > data_end)
				return XDP_DROP;

			iph = data;
			data = iph + 1;
			if (data > data_end)
				return XDP_DROP;

			struct udphdr *udph = data;
			data = udph + 1;
			if (data > data_end)
				return XDP_DROP;

			struct iphdr *iph_o = data;
			data = iph_o + 1;
			if (data > data_end)
				return XDP_DROP;

			udph->source = bpf_htons(vpn_port);
			udph->dest = bpf_htons(remote_addr->port);
			udph->len = bpf_htons((char *)data_end - (char *)udph);
			udph->check = 0;

			iph->ihl = 5;
			iph->version = 4;
			iph->tos = 0;
			iph->tot_len = bpf_htons((char *)data_end - (char *)iph);
			iph->id = iph_o->id;
			iph->frag_off = bpf_htons(IP_DF);
			iph->ttl = 64;
			iph->protocol = IPPROTO_UDP;
			iph->saddr = public_host_ip;
			iph->daddr = remote_addr->ip;

			recompute_iph_csum(iph);

			if (old_csum) {
				struct overhead_csum ovh;
				ipv4_mk_pheader(iph, &ovh.iphp);
				ovh.udph_n = *udph;
				ovh.iph_o = *iph_o;

				uint32_t csum = 0;
				csum = bpf_csum_diff((void *)&iphp_orig, sizeof(struct iph_pseudo),
					             (void *)&ovh, sizeof(struct overhead_csum),
					             0);
				udph->check = csum_fold_helper(csum);
				if (!udph->check)
					udph->check = 0xffff;
			}

			memcpy(eth->h_dest, gateway_mac, sizeof(macaddr_t));
			memcpy(eth->h_source, host_mac, sizeof(macaddr_t));
			eth->h_proto = bpf_htons(ETH_P_IP);

			return XDP_TX;
		}

		if (iph->daddr == public_host_ip) {
			if (iph->protocol == IPPROTO_UDP &&
			    dst_port == bpf_htons(vpn_port)) {
				/* VPN route */
				if (bpf_xdp_adjust_head(ctx, sizeof(struct iphdr) +
							sizeof(struct udphdr)))
					return XDP_DROP;

				data_start = (void *)(long)ctx->data;
				data_end = (void *)(long)ctx->data_end;
				data = data_start;

				eth = data;
				data = eth + 1;
				if (data > data_end)
					return XDP_DROP;

				iph = data;
				data = iph + 1;
				if (data > data_end)
					return XDP_DROP;

				if (iph->ihl != 5 || iph->version != 4)
					return XDP_DROP;

				ipaddr_t subnet_broadcast =
					((switch_ip & subnet_mask) | ~subnet_mask);
				if (iph->daddr != switch_ip &&
				    iph->daddr != subnet_broadcast &&
				    iph->daddr != 0xFFFFFFFFUL &&
				    (bpf_ntohl(iph->daddr) & 0xF0000000UL) != 0xE0000000UL)
					return XDP_DROP;

				if (!bpf_map_lookup_elem(&remote_addrs, &iph->saddr))
					return XDP_DROP;

				memcpy(eth->h_dest, switch_mac, sizeof(macaddr_t));
				memcpy(eth->h_source, host_mac, sizeof(macaddr_t));
				eth->h_proto = bpf_htons(ETH_P_IP);

				return XDP_TX;
			}

			if (fake_gateway_ip &&
			    !same_subnet(iph->saddr, fake_gateway_ip, subnet_mask)) {
				/* NAT return route */
				if (iph->ttl <= 1)
					return XDP_PASS;

				ip_decrease_ttl(iph);

				struct conntrack_key conntrack_key = {
					.protocol = iph->protocol,
					.sport = dst_port,
#ifndef NAT_TYPE_A
					.daddr = iph->saddr,
					.dport = src_port,
#endif
				};
				struct conntrack_entry *conntrack_entry =
					bpf_map_lookup_elem(&conntrack_map, &conntrack_key);
				if (!conntrack_entry)
					return XDP_PASS;
				// 5 minutes expiry
				if (bpf_ktime_get_ns() - conntrack_entry->ktime_ns
				    > 5 * 60 * SECOND_NS) {
					bpf_map_delete_elem(&conntrack_map, &conntrack_key);
					return XDP_PASS;
				}
				conntrack_entry->ktime_ns = bpf_ktime_get_ns();

				iph->daddr = conntrack_entry->saddr;
				recompute_iph_csum(iph);
				recompute_l4_csum_fast(ctx, iph, &iphp_orig);

				memcpy(eth->h_dest, switch_mac, sizeof(macaddr_t));
				memcpy(eth->h_source, host_mac, sizeof(macaddr_t));

				return XDP_TX;
			}
		}

		return XDP_PASS;
	} else if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
		struct arphdr *arph = data;
		data = arph + 1;
		if (data > data_end)
			return XDP_DROP;

		if (arph->ar_pro != bpf_htons(ETH_P_IP) ||
		    arph->ar_hln != 6 ||
		    arph->ar_pln != 4 ||
		    arph->ar_op != bpf_htons(ARPOP_REQUEST))
			return XDP_PASS;

		struct arp_ipv4_payload *arppl = data;
		data = arppl + 1;
		if (data > data_end)
			return XDP_DROP;

		if (arppl->ar_tip != fake_gateway_ip &&
		    !bpf_map_lookup_elem(&remote_addrs, &arppl->ar_tip))
			return XDP_PASS;

		ipaddr_t tmp_ip;

		memcpy(arppl->ar_tha, arppl->ar_sha, sizeof(macaddr_t));
		memcpy(arppl->ar_sha, host_mac, sizeof(macaddr_t));

		tmp_ip = arppl->ar_tip;
		arppl->ar_tip = arppl->ar_sip;
		arppl->ar_sip = tmp_ip;

		arph->ar_op = bpf_htons(ARPOP_REPLY);

		memcpy(eth->h_dest, eth->h_source, sizeof(macaddr_t));
		memcpy(eth->h_source, host_mac, sizeof(macaddr_t));

		return XDP_TX;
	} else
		return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
