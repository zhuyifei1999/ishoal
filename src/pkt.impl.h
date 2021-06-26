#include <errno.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "pkt.h"

#ifdef __BPF__

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

typedef struct xdp_md context_t;
#define DATA(ctx) ((void *)(long)ctx->data)
#define DATA_END(ctx) ((void *)(long)ctx->data_end)

#define ACCESS_ONCE(x)	(*(__volatile__  __typeof__(x) *)&(x))
#define barrier() __asm__ __volatile__ ("" : : : "memory")

#define BSS(variable) variable

static int redirect_to_userspace(context_t *ctx)
{
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

#define DECLARE_MAP_LOOKUP_VAR(type, name) typeof(type) *name
#define MAP_LOOKUP_DEREF(name) (*name)

#define pkt_map_update_elem(map, key, value, flags) \
	bpf_map_update_elem(&map, key, value, flags)

#define pkt_map_lookup_elem(map, key, value) \
	({ value = bpf_map_lookup_elem(&map, key); value ? 0 : -ENOENT; })

#define pkt_map_delete_elem(map, key) \
	bpf_map_delete_elem(&map, key)

#define pkt_map_update_lookup(map, key, value)

#else

#include <arpa/inet.h>
#include <urcu.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ishoal.h"
#include "xdpfilter.skel.h"

static int bpf_xdp_adjust_head(context_t *xdp_md, int delta);
static int bpf_xdp_adjust_tail(context_t *xdp_md, int delta);

static __always_inline uint32_t bpf_htonl(uint32_t hostlong)
{
	return htonl(hostlong);
}

static __always_inline uint16_t bpf_htons(uint16_t hostshort)
{
	return htons(hostshort);
}

static __always_inline uint32_t bpf_ntohl(uint32_t netlong)
{
	return ntohl(netlong);
}

static __always_inline uint16_t bpf_ntohs(uint16_t netshort)
{
	return ntohs(netshort);
}

#define DECLARE_MAP_LOOKUP_VAR(type, name) typeof(type) name
#define MAP_LOOKUP_DEREF(name) name

#define pkt_map_update_elem(map, key, value, flags) \
	bpf_map_update_elem(bpf_map__fd(obj->maps.map), key, value, flags)

#define pkt_map_lookup_elem(map, key, value) \
	bpf_map_lookup_elem(bpf_map__fd(obj->maps.map), key, &value)

#define pkt_map_delete_elem(map, key) \
	bpf_map_delete_elem(bpf_map__fd(obj->maps.map), key)

#define pkt_map_update_lookup(map, key, value) \
	pkt_map_update_elem(map, key, &MAP_LOOKUP_DEREF(value), BPF_ANY)

static uint64_t bpf_ktime_get_ns(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now))
		perror_exit("clock_gettime");

	return (uint64_t) now.tv_sec * SECOND_NS + now.tv_nsec;
}

/* source: lib/checksum.c */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

static uint32_t csum_partial(const void *buff, int len, uint32_t wsum)
{
	unsigned int sum = (unsigned int)wsum;
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return (uint32_t)result;
}

static uint32_t bpf_csum_diff(uint32_t *from, uint32_t from_size,
			      uint32_t *to, uint32_t to_size, uint32_t seed)
{
	uint32_t diff_size = from_size + to_size;
	uint32_t sp[diff_size];
	int i, j = 0;

	if (caa_unlikely((from_size | to_size) & (sizeof(uint32_t) - 1)))
		return -EINVAL;

	for (i = 0; i < from_size / sizeof(uint32_t); i++, j++)
		sp[j] = ~from[i];
	for (i = 0; i <   to_size / sizeof(uint32_t); i++, j++)
		sp[j] = to[i];

	return csum_partial(sp, diff_size, seed);
}

#define ACCESS_ONCE(x)	CMM_ACCESS_ONCE(x)
#define barrier() cmm_barrier()

#define SEC(x)

#define BSS(variable) obj->bss->variable

#endif

#include "xdpfilter.h"

struct icmperrpl {
	struct iphdr iph;
	char ipdat[8];
};

struct overhead_csum {
	struct iph_pseudo	iphp;
	struct udphdr		udph_n;
	struct iphdr		iph_o;
} __attribute__((packed)) __attribute__((aligned(4)));

/* from include/net/ip.h, samples/bpf/xdp_fwd_user.c */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	uint32_t check = (uint32_t)iph->check;

	check += (uint32_t)bpf_htons(0x0100);
	iph->check = (uint16_t)(check + (check >= 0xFFFF));
	return --iph->ttl;
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

static uint16_t recompute_l4_csum_fast(context_t *ctx, struct iphdr *iph,
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

	void *data_end = DATA_END(ctx);
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

static __always_inline bool mac_eq(macaddr_t a, macaddr_t b)
{
#ifdef __BPF__
	return (a[0] == b[0] &&
		a[1] == b[1] &&
		a[2] == b[2] &&
		a[3] == b[3] &&
		a[4] == b[4] &&
		a[5] == b[5]);
#else
	return !memcmp(a, b, sizeof(macaddr_t));
#endif
}

static __always_inline void memcpy_dyn(void *dst, void *src, void *end, size_t len)
{
#ifdef __BPF__
	char *dst_c = dst;
	char *src_c = src;
	char *end_c = end;

	#pragma unroll
	for (size_t i = 0; i < len; i++)
		if (src_c + 2 < end_c)
			*(dst_c++) = *(src_c++);
#else
	memcpy(dst, src, caa_min(len, end - src));
#endif
}

// source: samples/bpf/xdp_adjust_tail_kern.c
static __always_inline int send_icmp4_timeout_exceeded(context_t *xdp)
{
	void *data, *data_end;

	data = DATA(xdp);
	data_end = DATA_END(xdp);
	if ((void *)data + sizeof(struct ethhdr) > data_end)
		return XDP_DROP;

	struct ethhdr eth_orig = *(struct ethhdr *)data;

	if (bpf_xdp_adjust_head(xdp, 0 - (int)(sizeof(struct iphdr) + sizeof(struct icmphdr))))
		return XDP_DROP;

	if (bpf_xdp_adjust_tail(xdp, (int)(sizeof(struct ethhdr) +
					   sizeof(struct iphdr) +
					   sizeof(struct icmphdr) +
					   sizeof(struct icmperrpl)) -
				((long)xdp->data_end - (long)xdp->data)))
		return XDP_DROP;

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;

	struct ethhdr *eth = data;
	data = eth + 1;
	if (data > data_end)
		return XDP_DROP;

	struct iphdr *iph = data;
	data = iph + 1;
	if (data > data_end)
		return XDP_DROP;

	struct icmphdr *icmph = data;
	data = icmph + 1;
	if (data > data_end)
		return XDP_DROP;

	struct icmperrpl *icmp_pl = data;
	data = icmp_pl + 1;
	if (data > data_end)
		return XDP_DROP;

	memset(icmph, 0, sizeof(*icmph));
	icmph->type = ICMP_TIME_EXCEEDED;
	icmph->code = ICMP_EXC_TTL;
	uint32_t csum = 0;
	ipv4_csum(icmph, sizeof(*icmph) + sizeof(*icmp_pl), &csum);
	icmph->checksum = csum;

	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = bpf_htons((char *)data_end - (char *)iph);
	iph->tos = 0;
	iph->id = 0;
	iph->frag_off = bpf_htons(IP_DF);
	iph->ttl = 64;
	iph->protocol = IPPROTO_ICMP;
	iph->daddr = icmp_pl->iph.saddr;
	iph->saddr = BSS(public_host_ip);
	recompute_iph_csum(iph);

	memcpy(eth->h_dest, eth_orig.h_source, sizeof(macaddr_t));
	memcpy(eth->h_source, BSS(host_mac), sizeof(macaddr_t));
	eth->h_proto = bpf_htons(ETH_P_IP);

	return XDP_TX;
}

SEC("xdp")
int xdp_prog(context_t *ctx)
{
	/* BPF needs sign extension to make sure it's all 1s.
	 * EMU needs zero extension to make sure it's all 0s.
	 * Annoying, ikr.
	 */
	void *data_start = DATA(ctx);
	void *data_end = DATA_END(ctx);
	void *data = data_start;

	struct ethhdr *eth = data;
	data = eth + 1;
	if (data > data_end)
		return XDP_DROP;

	bool eth_is_multicast = eth->h_dest[0] & 1;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		uint16_t src_port, dst_port;

#ifndef __clang__
		// XXX: GCC inference can't see that some cases are
		// unreachable if these are uninitialized.
		src_port = dst_port = 0;
#endif

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
		} else
			return XDP_PASS;

		if (!eth_is_multicast && BSS(fake_gateway_ip) &&
		    same_subnet(iph->saddr, BSS(fake_gateway_ip), BSS(subnet_mask)) &&
		    !same_subnet(iph->daddr, BSS(fake_gateway_ip), BSS(subnet_mask)) &&
		    // FIXME: should this be 'real subnet mask'?
		    !same_subnet(iph->daddr, BSS(public_host_ip), BSS(subnet_mask))) {
			/* NAT route */
			if (iph->ttl <= 1)
				return send_icmp4_timeout_exceeded(ctx);

			DECLARE_MAP_LOOKUP_VAR(int, ip_whitelist_unused);
			if (pkt_map_lookup_elem(ip_whitelist, &iph->daddr, ip_whitelist_unused))
				return XDP_PASS;

			struct track_entry track_entry = {
				.saddr = iph->saddr,
				.ktime_ns = bpf_ktime_get_ns(),
			};

			struct conntrack_key conntrack_key = {
				.protocol = iph->protocol,
				.sport = src_port,
			};
			memcpy(track_entry.h_source, eth->h_source, sizeof(macaddr_t));

			pkt_map_update_elem(conntrack_map, &conntrack_key,
					    &track_entry, BPF_ANY);

			ip_decrease_ttl(iph);

			iph->saddr = BSS(public_host_ip);
			recompute_iph_csum(iph);
			recompute_l4_csum_fast(ctx, iph, &iphp_orig);

			memcpy(eth->h_dest, BSS(gateway_mac), sizeof(macaddr_t));
			memcpy(eth->h_source, BSS(host_mac), sizeof(macaddr_t));

			return XDP_TX;
		}

		if (iph->daddr == BSS(public_host_ip)) {
			if (BSS(fake_gateway_ip) &&
			    !same_subnet(iph->saddr, BSS(fake_gateway_ip), BSS(subnet_mask))) {
				/* NAT return route */
				if (iph->ttl <= 1)
					return send_icmp4_timeout_exceeded(ctx);

				macaddr_t h_source;
				DECLARE_MAP_LOOKUP_VAR(struct track_entry, track_entry);

				struct conntrack_key conntrack_key = {
					.protocol = iph->protocol,
					.sport = dst_port,
				};

				if (pkt_map_lookup_elem(conntrack_map, &conntrack_key, track_entry))
					return XDP_PASS;
				// 5 minutes expiry
				if (bpf_ktime_get_ns() - MAP_LOOKUP_DEREF(track_entry).ktime_ns
				    > 5 * 60 * SECOND_NS) {
					pkt_map_delete_elem(conntrack_map, &conntrack_key);
					return XDP_PASS;
				}
				MAP_LOOKUP_DEREF(track_entry).ktime_ns = bpf_ktime_get_ns();
				pkt_map_update_lookup(conntrack_map, &conntrack_key, track_entry);

				DECLARE_MAP_LOOKUP_VAR(int, ip_whitelist_unused);
				if (pkt_map_lookup_elem(ip_whitelist, &iph->saddr, ip_whitelist_unused))
					return XDP_PASS;

				if (iph->protocol == IPPROTO_UDP && src_port == bpf_htons(53)) {
#ifdef __BPF__
					return redirect_to_userspace(ctx);
#else
					dns_whitelist_process_pkt(data, data_end-data);
#endif
				}

				iph->daddr = MAP_LOOKUP_DEREF(track_entry).saddr;
				memcpy(h_source, MAP_LOOKUP_DEREF(track_entry).h_source, sizeof(macaddr_t));

				ip_decrease_ttl(iph);

				recompute_iph_csum(iph);
				recompute_l4_csum_fast(ctx, iph, &iphp_orig);

				memcpy(eth->h_dest, h_source, sizeof(macaddr_t));
				memcpy(eth->h_source, BSS(host_mac), sizeof(macaddr_t));

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

		if (arppl->ar_tip != BSS(fake_gateway_ip))
			return XDP_PASS;

		ipaddr_t tmp_ip;

		memcpy(arppl->ar_tha, arppl->ar_sha, sizeof(macaddr_t));
		memcpy(arppl->ar_sha, BSS(host_mac), sizeof(macaddr_t));

		tmp_ip = arppl->ar_tip;
		arppl->ar_tip = arppl->ar_sip;
		arppl->ar_sip = tmp_ip;

		arph->ar_op = bpf_htons(ARPOP_REPLY);

		memcpy(eth->h_dest, eth->h_source, sizeof(macaddr_t));
		memcpy(eth->h_source, BSS(host_mac), sizeof(macaddr_t));

		return XDP_TX;
	} else
		return XDP_PASS;
}
