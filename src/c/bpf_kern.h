#ifndef __BPF_KERN_H
#define __BPF_KERN_H

#include <stdint.h>

#include <linux/if_ether.h>

typedef unsigned char macaddr_t[ETH_ALEN];
typedef uint32_t ipaddr_t;

#define MAX_XSKS 64

#define SECOND_NS 1000000000ULL

struct remote_addr {
	ipaddr_t ip;
	uint16_t port;
};

struct connection {
	ipaddr_t local_ip;
	uint16_t local_port;
	struct remote_addr remote;
};

#endif
