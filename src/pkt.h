#ifndef __PKT_H
#define __PKT_H

#include <stdbool.h>

#include "bpf_kern.h"

struct arp_ipv4_payload {
	macaddr_t	ar_sha;
	ipaddr_t	ar_sip;
	macaddr_t	ar_tha;
	ipaddr_t	ar_tip;
} __attribute__((packed));

/* from include/net/ip.h */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define BROADCAST_MAC ((macaddr_t){0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

static __always_inline bool same_subnet(ipaddr_t a, ipaddr_t b, ipaddr_t subnet_mask)
{
	return (a & subnet_mask) == (b & subnet_mask);
}

#endif
