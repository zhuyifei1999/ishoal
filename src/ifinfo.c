#include "features.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ishoal.h"

macaddr_t host_mac;
macaddr_t gateway_mac;

ipaddr_t public_host_ip;
ipaddr_t real_subnet_mask;

static void get_if_ipaddr(char *iface, ipaddr_t *addr)
{
	struct ifreq ifr;

	int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFADDR, &ifr))
		perror_exit("ioctl(SIOCGIFADDR)");
	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	close(sock);
}

static void get_if_netmask(char *iface, ipaddr_t *addr)
{
	struct ifreq ifr;

	int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFNETMASK, &ifr))
		perror_exit("ioctl(SIOCGIFNETMASK)");
	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	close(sock);
}

static void get_if_macaddr(char *iface, macaddr_t *addr)
{
	struct ifreq ifr;

	int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr))
		perror_exit("ioctl(SIOCGIFHWADDR)");
	memcpy(addr, ifr.ifr_hwaddr.sa_data, sizeof(macaddr_t));

	close(sock);
}

static void get_if_gateway(char *iface, ipaddr_t *addr)
{
	bool found = false;
	char *buf = read_whole_file("/proc/net/route", NULL);

	char *line = strtok(buf, "\n");
	while ((line = strtok(NULL, "\n"))) {
		char *line_iface = NULL;
		ipaddr_t line_dest, line_gateway;
		uint16_t line_flags;

		int scanres = sscanf(line, "%ms\t%x\t%x\t%hx",
				     &line_iface,
				     &line_dest,
				     &line_gateway,
				     &line_flags);

		if (scanres != 4)
			fprintf_exit("Malformed /proc/net/route\n");

		if (!strcmp(line_iface, iface) &&
		    line_dest == 0 &&
		    (line_flags & 3) == 3) {
			*addr = line_gateway;
			found = true;
		}

		free(line_iface);
	}

	free(buf);

	if (!found)
		fprintf_exit("Unable to determine default gateway IP address\n");
}

static bool resolve_arp_kernel(char *iface, ipaddr_t ipaddr, macaddr_t *macaddr)
{
	bool found = false;
	char *buf = read_whole_file("/proc/net/arp", NULL);

	char *line = strtok(buf, "\n");
	while ((line = strtok(NULL, "\n"))) {
		char *line_ipaddr = NULL;
		char *line_macaddr = NULL;
		char *line_iface = NULL;

		int scanres = sscanf(line, "%ms\t%*s\t%*s\t%ms\t%*s\t%ms",
				     &line_ipaddr,
				     &line_macaddr,
				     &line_iface);

		if (scanres != 3)
			fprintf_exit("Malformed /proc/net/arp\n");

		ipaddr_t line_ipaddr_num;
		if (inet_pton(AF_INET, line_ipaddr, &line_ipaddr_num) != 1)
			fprintf_exit("Malformed /proc/net/arp\n");

		if (!strcmp(line_iface, iface) &&
		    line_ipaddr_num == ipaddr) {
			int scanres = sscanf(line_macaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
					     &(*macaddr)[0],
					     &(*macaddr)[1],
					     &(*macaddr)[2],
					     &(*macaddr)[3],
					     &(*macaddr)[4],
					     &(*macaddr)[5]);

			if (scanres != 6)
				fprintf_exit("Malformed /proc/net/arp\n");

			found = true;
		}

		free(line_ipaddr);
		free(line_macaddr);
		free(line_iface);
	}

	free(buf);

	return found;
}

struct ifinfo_rau_ctx {
	int done_eventfd;
	bool solved;
	struct resolve_arp_user rau;
};

static void rau_cb(bool solved, void *_ctx)
{
	struct ifinfo_rau_ctx *ctx = _ctx;

	ctx->solved = solved;

	if (eventfd_write(ctx->done_eventfd, 1))
		perror_exit("eventfd_write");
}

static bool resolve_arp_user_wrapped(char *iface, ipaddr_t ipaddr, macaddr_t *macaddr)
{
	struct eventloop *el = eventloop_new();
	struct ifinfo_rau_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		perror_exit("calloc");

	ctx->done_eventfd = eventfd(0, EFD_CLOEXEC);
	if (ctx->done_eventfd < 0)
		perror_exit("eventfd");

	eventloop_install_break(el, thread_stop_eventfd(current));
	eventloop_install_break(el, ctx->done_eventfd);

	ctx->rau.ipaddr = ipaddr;
	ctx->rau.macaddr = macaddr;
	ctx->rau.el = el;
	ctx->rau.cb = rau_cb;
	ctx->rau.ctx = ctx;
	resolve_arp_user(&ctx->rau);

	eventloop_enter(el, -1);

	close(ctx->done_eventfd);
	bool solved = ctx->solved;
	free(ctx);
	eventloop_destroy(el);

	return solved;
}

void ifinfo_init(void)
{
	get_if_ipaddr(iface, &public_host_ip);
	get_if_netmask(iface, &real_subnet_mask);
	get_if_macaddr(iface, &host_mac);

	ipaddr_t gateway_ip = 0;
	get_if_gateway(iface, &gateway_ip);

	if (!resolve_arp_kernel(iface, gateway_ip, &gateway_mac) &&
	    !resolve_arp_user_wrapped(iface, gateway_ip, &gateway_mac)) {
		char str[IP_STR_BULEN];
		ip_str(gateway_ip, str);
		fprintf_exit("Unable to resolve ARP for %s\n", str);
	}
}
