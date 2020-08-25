#include "features.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
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

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
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

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
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


static void resolve_arp_kernel(char *iface, ipaddr_t ipaddr, macaddr_t *macaddr)
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

	if (!found)
		fprintf_exit("Unable to resolve ARP for %s\n", ip_str(ipaddr));
}

void ifinfo_init(void)
{
	get_if_ipaddr(iface, &public_host_ip);
	get_if_netmask(iface, &real_subnet_mask);
	get_if_macaddr(iface, &host_mac);

	ipaddr_t gateway_ip = 0;
	get_if_gateway(iface, &gateway_ip);
	resolve_arp_kernel(iface, gateway_ip, &gateway_mac);
}
