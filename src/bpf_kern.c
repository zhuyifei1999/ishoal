#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf_kern.h"
#include "pkt.h"
#include "pkt.inc.c"

#define ACCESS_ONCE(x)	(*(__volatile__  __typeof__(x) *)&(x))
#define barrier() __asm__ __volatile__ ("" : : : "memory")

#define SECOND_NS 1000000000ULL

#ifdef SERVER_BUILD
struct track_entry {
	ipaddr_t saddr;
	uint64_t ktime_ns;
} __attribute__((packed));

struct conntrack_key {
	uint8_t  protocol;
	uint16_t sport;
} __attribute__((packed));
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conntrack_key);
	__type(value, struct track_entry);
	__uint(max_entries, 1024);
} conntrack_map SEC(".maps");
#endif

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

ipaddr_t public_host_ip;
ipaddr_t fake_gateway_ip;

ipaddr_t ikiwi_ip;
uint16_t ikiwi_port;

ipaddr_t subnet_mask;

uint16_t vpn_port;

#ifdef SERVER_BUILD
/* from include/net/ip.h, samples/bpf/xdp_fwd_user.c */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	uint32_t check = (uint32_t)iph->check;

	check += (uint32_t)bpf_htons(0x0100);
	iph->check = (uint16_t)(check + (check >= 0xFFFF));
	return --iph->ttl;
}
#endif

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

#ifdef SERVER_BUILD
static __always_inline uint16_t onec_add(uint16_t x, uint16_t y)
{
	uint32_t z = x + y;

	/* after two iterations, there does not exist a z where the most
	 * significant 16 bits is non-zero. This can be shown with a SAT solver:
	 *
	 * import claripy
	 * val = claripy.BVS('val', 32)
	 * z = val
	 * s = claripy.Solver()
	 * hex(s.eval(val, 1, extra_constraints=[z & 0xffff0000 != 0])[0])
	 * z = (z & 0xffff) + (z >> 16)
	 * hex(s.eval(val, 1, extra_constraints=[z & 0xffff0000 != 0])[0])
	 * z = (z & 0xffff) + (z >> 16)
	 * hex(s.eval(val, 1, extra_constraints=[z & 0xffff0000 != 0])[0])
	 */

	z = (z & 0xffff) + (z >> 16);
	z = (z & 0xffff) + (z >> 16);
	return z;
}

static uint16_t recompute_l4_csum_fast(struct xdp_md *ctx, struct iphdr *iph,
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
			return 0;
	} else
		return 0;

	void *data_end = (void *)(long)ctx->data_end;
	if ((void *)(csum_field + 1) > data_end)
		return 0;

	uint32_t old_csum = *csum_field;

	uint32_t csum = 0;
	csum = bpf_csum_diff((void *)iphp_orig, sizeof(struct iph_pseudo),
		             (void *)&iphp_new, sizeof(struct iph_pseudo),
		             ~old_csum);
	*csum_field = csum_fold_helper(csum);
	if (!*csum_field)
		*csum_field = 0xffff;

	return onec_add(*csum_field, ~old_csum);
}
#endif

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

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		bool is_icmp = false;
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
			if (!old_csum)
				old_csum = 0xffff;
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph = data;
			data = udph + 1;
			if (data > data_end)
				return XDP_DROP;

			src_port = udph->source;
			dst_port = udph->dest;

			old_csum = udph->check;
		} else if (iph->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmph = data;
			data = icmph + 1;
			if (data > data_end)
				return XDP_DROP;

			is_icmp = true;
		} else
			return XDP_PASS;

#ifdef SERVER_BUILD
		if (iph->daddr == public_host_ip) {
			if (iph->protocol == IPPROTO_UDP &&
			    dst_port == bpf_htons(vpn_port) &&
			    iph->saddr == ikiwi_ip) {
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

				ikiwi_port = bpf_ntohs(src_port);

				/* Begin NAT */
				ipv4_mk_pheader(iph, &iphp_orig);

				if (iph->protocol == IPPROTO_TCP) {
					struct tcphdr *tcph = data;
					data = tcph + 1;
					if (data > data_end)
						return XDP_DROP;

					src_port = tcph->source;
				} else if (iph->protocol == IPPROTO_UDP) {
					struct udphdr *udph = data;
					data = udph + 1;
					if (data > data_end)
						return XDP_DROP;

					src_port = udph->source;
				} else
					return XDP_DROP;

				if (iph->ttl <= 1)
					return XDP_DROP;

				struct track_entry track_entry = {
					.saddr = iph->saddr,
					.ktime_ns = bpf_ktime_get_ns(),
				};

				struct conntrack_key conntrack_key = {
					.protocol = iph->protocol,
					.sport = src_port,
				};
				bpf_map_update_elem(&conntrack_map, &conntrack_key,
						    &track_entry, BPF_ANY);

				ip_decrease_ttl(iph);

				iph->saddr = public_host_ip;
				recompute_iph_csum(iph);
				recompute_l4_csum_fast(ctx, iph, &iphp_orig);

				memcpy(eth->h_dest, gateway_mac, sizeof(macaddr_t));
				memcpy(eth->h_source, host_mac, sizeof(macaddr_t));
				eth->h_proto = bpf_htons(ETH_P_IP);

				return XDP_TX;
			}

			if (!same_subnet(iph->saddr, fake_gateway_ip, subnet_mask)) {
				/* NAT return route */
				struct track_entry *track_entry;

				if (is_icmp)
					return XDP_PASS;

				struct conntrack_key conntrack_key = {
					.protocol = iph->protocol,
					.sport = dst_port,
				};
				track_entry =
					bpf_map_lookup_elem(&conntrack_map, &conntrack_key);

				if (!track_entry)
					return XDP_PASS;
				// 5 minutes expiry
				if (bpf_ktime_get_ns() - track_entry->ktime_ns
				    > 5 * 60 * SECOND_NS) {
					bpf_map_delete_elem(&conntrack_map, &conntrack_key);
					return XDP_PASS;
				}
				track_entry->ktime_ns = bpf_ktime_get_ns();

				if (iph->ttl <= 1)
					return XDP_DROP;

				iph->daddr = track_entry->saddr;
				ip_decrease_ttl(iph);

				recompute_iph_csum(iph);
				recompute_l4_csum_fast(ctx, iph, &iphp_orig);

				/* Begin VPN */
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
				udph->dest = bpf_htons(ikiwi_port);
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
				iph->daddr = ikiwi_ip;

				recompute_iph_csum(iph);

				/* ACCESS_ONCE here to prevent reordering causing
				 * verifier failures -- old_csum is uninitialized
				 */
				if (ACCESS_ONCE(old_csum)) {
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
		}
#else
		if (!eth_is_multicast && fake_gateway_ip && ikiwi_ip &&
		    same_subnet(iph->saddr, fake_gateway_ip, subnet_mask) &&
		    !same_subnet(iph->daddr, fake_gateway_ip, subnet_mask) &&
		    // FIXME: should this be 'real subnet mask'?
		    !same_subnet(iph->daddr, public_host_ip, subnet_mask)) {
			/* VPN route */
			memcpy(switch_mac, eth->h_source, sizeof(macaddr_t));

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
			udph->dest = bpf_htons(ikiwi_port);
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
			iph->daddr = ikiwi_ip;

			recompute_iph_csum(iph);

			if (!is_icmp) {
				/* ACCESS_ONCE here to prevent reordering causing
				 * verifier failures -- old_csum is uninitialized
				 */
				if (ACCESS_ONCE(old_csum)) {
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
			}

			memcpy(eth->h_dest, gateway_mac, sizeof(macaddr_t));
			memcpy(eth->h_source, host_mac, sizeof(macaddr_t));
			eth->h_proto = bpf_htons(ETH_P_IP);

			return XDP_TX;
		}

		if (iph->daddr == public_host_ip) {
			if (iph->protocol == IPPROTO_UDP &&
			    dst_port == bpf_htons(vpn_port) &&
			    iph->saddr == ikiwi_ip &&
			    src_port == bpf_htons(ikiwi_port)) {
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

				memcpy(eth->h_dest, switch_mac, sizeof(macaddr_t));
				memcpy(eth->h_source, host_mac, sizeof(macaddr_t));
				eth->h_proto = bpf_htons(ETH_P_IP);

				return XDP_TX;
			}
		}
#endif

		return XDP_PASS;
	} else if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
#ifdef SERVER_BUILD
		return XDP_PASS;
#endif
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

		if (arppl->ar_tip != fake_gateway_ip)
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
