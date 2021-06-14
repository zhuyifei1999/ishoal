#ifndef __RELAY_H
#define __RELAY_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/if_ether.h>

typedef unsigned char macaddr_t[ETH_ALEN];
typedef uint32_t ipaddr_t;

struct relay_connection {
	bool exists;
	ipaddr_t recv_rem_ip;
	uint16_t recv_rem_port;
	// uint16_t recv_loc_port;  // as key
	uint16_t send_loc_port;
	ipaddr_t send_rem_ip;
	uint16_t send_rem_port;
};

#endif
