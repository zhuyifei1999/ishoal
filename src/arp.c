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

struct arppkt {
	struct ethhdr eth;
	struct arphdr arph;
	struct arp_ipv4_payload arppl;
} __attribute__((packed));

static void resolve_arp_user_cb(int fd, const void *_ctx, bool expired)
{
	const struct resolve_arp_user *ctx = _ctx;

	if (expired) {
		eventloop_remove_event_current(ctx->el);
		close(fd);
		ctx->cb(false, ctx->ctx);
		return;
	}

	struct arppkt arp_response;

	ssize_t recvsize = recv(fd, &arp_response, sizeof(arp_response), 0);
	if (recvsize < 0)
		crash_with_perror("recv");
	if (recvsize != sizeof(arp_response))
		return;

	if (arp_response.eth.h_proto != htons(ETH_P_ARP))
		return;

	if (arp_response.arph.ar_pro != htons(ETH_P_IP) ||
	    arp_response.arph.ar_hln != 6 ||
	    arp_response.arph.ar_pln != 4 ||
	    arp_response.arph.ar_op != htons(ARPOP_REPLY))
		return;

	if (arp_response.arppl.ar_sip != ctx->ipaddr)
		return;

	if (ctx->macaddr)
		memcpy(ctx->macaddr, arp_response.arppl.ar_sha, sizeof(macaddr_t));
	eventloop_remove_event_current(ctx->el);
	close(fd);
	ctx->cb(true, ctx->ctx);
}

void resolve_arp_user(const struct resolve_arp_user *ctx)
{
	if (ctx->ipaddr == public_host_ip) {
		if (ctx->macaddr)
			memcpy(ctx->macaddr, host_mac, sizeof(macaddr_t));
		ctx->cb(true, ctx->ctx);
		return;
	}

	if (!same_subnet(ctx->ipaddr, public_host_ip, real_subnet_mask)) {
		ctx->cb(false, ctx->ctx);
		return;
	}

	int sock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ARP));
	if (sock < 0)
		crash_with_perror("socket(AF_PACKET, SOCK_RAW)");

	struct sockaddr_ll addr_bind = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ARP),
		.sll_ifindex = ifindex,
		.sll_hatype = htons(ARPHRD_ETHER),
		.sll_pkttype = PACKET_HOST,
		.sll_halen = sizeof(macaddr_t),
	};
	memcpy(addr_bind.sll_addr, host_mac, sizeof(macaddr_t));

	if (bind(sock, (struct sockaddr *)&addr_bind, sizeof(addr_bind)))
		crash_with_perror("bind");

	/* Min L2 frame size: 64 bytes w/ 4 bytes CRC added by driver */
	char arp_request_buf[caa_max(sizeof(struct arppkt), 60)] = {0};
	struct arppkt *arp_request = (void *)arp_request_buf;

	memcpy(arp_request->eth.h_dest, BROADCAST_MAC, sizeof(macaddr_t));
	memcpy(arp_request->eth.h_source, host_mac, sizeof(macaddr_t));
	arp_request->eth.h_proto = htons(ETH_P_ARP);

	arp_request->arph.ar_hrd = htons(ARPHRD_ETHER);
	arp_request->arph.ar_pro = htons(ETH_P_IP);
	arp_request->arph.ar_hln = 6;
	arp_request->arph.ar_pln = 4;
	arp_request->arph.ar_op = htons(ARPOP_REQUEST);

	memcpy(arp_request->arppl.ar_sha, host_mac, sizeof(macaddr_t));
	arp_request->arppl.ar_sip = public_host_ip;
	memset(arp_request->arppl.ar_tha, 0, sizeof(macaddr_t));
	arp_request->arppl.ar_tip = ctx->ipaddr;

	if (send(sock, arp_request, sizeof(arp_request_buf), 0) < 0)
		crash_with_perror("send");

	eventloop_install_event_sync(ctx->el, &(struct event) {
		.fd = sock,
		.expiry = { .tv_sec = 1, .tv_nsec = 0 },
		.eventfd_ack = false,
		.handler_type = EVT_CALL_FN,
		.handler_fn_const = resolve_arp_user_cb,
		.handler_ctx_const = ctx,
	});
}
