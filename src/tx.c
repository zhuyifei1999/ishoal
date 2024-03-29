#include "features.h"

#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ishoal.h"

/* Ideally we should use AF_XDP, but decrypting xdpsock.user.c is too
 * much for mw. If you can, please send me a patch.
 */

static int tx_sock;

void tx(const void *pkt, size_t length)
{
	static atomic_flag init_done = ATOMIC_FLAG_INIT;
	if (!atomic_flag_test_and_set(&init_done)) {
		tx_sock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
		if (tx_sock < 0)
			crash_with_perror("socket(AF_PACKET, SOCK_RAW)");

		struct sockaddr_ll addr_bind = {
			.sll_family = AF_PACKET,
			.sll_protocol = 0,
			.sll_ifindex = ifindex,
			.sll_hatype = htons(ARPHRD_ETHER),
			.sll_pkttype = PACKET_HOST,
			.sll_halen = sizeof(macaddr_t),
		};
		memcpy(addr_bind.sll_addr, host_mac, sizeof(macaddr_t));

		if (bind(tx_sock, (struct sockaddr *)&addr_bind, sizeof(addr_bind)))
			crash_with_perror("bind");
	}

	if (send(tx_sock, pkt, length, 0) < 0)
		crash_with_perror("send");
}
