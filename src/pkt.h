#ifndef __PKT_H
#define __PKT_H

#include <stdbool.h>
#include <unistd.h>

#include "xdpfilter.h"

struct arp_ipv4_payload {
	macaddr_t	ar_sha;
	ipaddr_t	ar_sip;
	macaddr_t	ar_tha;
	ipaddr_t	ar_tip;
} __attribute__((packed));

struct iph_pseudo {
	ipaddr_t	saddr;
	ipaddr_t	daddr;
	uint8_t		reserved;
	uint8_t		protocol;
	uint16_t	l4_len;
} __attribute__((packed)) __attribute__((aligned(4)));

struct track_entry {
	ipaddr_t saddr;
	macaddr_t h_source;
	uint64_t ktime_ns;
} __attribute__((packed));

struct conntrack_key {
	uint8_t  protocol;
	uint16_t sport;
} __attribute__((packed));

#define ICMP_ECHOTRACK_SIZE 64

struct icmp_echotrack_key {
	size_t length;
	char data[ICMP_ECHOTRACK_SIZE];
};

/* from include/net/ip.h */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define BROADCAST_MAC ((macaddr_t){0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

static inline bool same_subnet(ipaddr_t a, ipaddr_t b, ipaddr_t subnet_mask)
{
	return (a & subnet_mask) == (b & subnet_mask);
}

static inline unsigned short from32to16(unsigned int x)
{
	x = (x & 0xffff) + (x >> 16);
	x = (x & 0xffff) + (x >> 16);
	return x;
}

#endif
