#include "features.h"

#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <urcu.h>

#include "ishoal.h"
#include "pkt.h"

struct dnshdr {
	uint16_t transaction_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority_rrs;
	uint16_t additional_rrs;
};

static void *end_str(void *data, void *data_end)
{
	while (data < data_end && *(char *)data)
		data++;

	return data + 1;
}

void dns_whitelist_process_pkt(void *data, size_t len)
{
	void *data_end = data + len;

	struct dnshdr *dnsh = data;
	data = dnsh + 1;
	if (data > data_end)
		return;

	if (ntohs(dnsh->flags) != 0x8180)
		return;

	for (int i = 0; i < ntohs(dnsh->questions); i++) {
		if (data + 2 >= data_end)
			return;

		if ((*(char *)data & 0b11000000) == 0b11000000)
			data += 2;
		else
			data = end_str(data, data_end);
		data += 4; // 2 bytes type. 2 bytes class
	}

	for (int i = 0; i < ntohs(dnsh->answers); i++) {
		if (data + 2 >= data_end)
			return;

		if ((*(char *)data & 0b11000000) == 0b11000000)
			data += 2;
		else
			data = end_str(data, data_end);

		uint16_t *type = data;
		data = type + 1;
		if (data > data_end)
			return;

		uint16_t *class = data;
		data = class + 1;
		if (data > data_end)
			return;

		uint32_t *ttl = data;
		data = ttl + 1;
		if (data > data_end)
			return;

		uint16_t *rdlen = data;
		data = rdlen + 1;
		if (data > data_end)
			return;

		if (ntohs(*type) == 1 && ntohs(*class) == 1 && ntohs(*rdlen) == 4) {
			ipaddr_t *resip = data;
			data = resip + 1;
			if (data > data_end)
				return;

			bpf_whitelist_ip(*resip);

			char tmpbuf[IP_STR_BULEN];
			ip_str(*resip, tmpbuf);
			printf("Whitelist: %s\n", tmpbuf);
		} else
			data += ntohs(*rdlen);
	}
}
