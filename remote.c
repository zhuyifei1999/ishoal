#include <assert.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

#include "ishoal.h"

uint16_t vpn_port;

static int endpoint_fd;

static char str_port[6];

static struct UPNPDev *upnp_devlist;
static size_t upnp_numdevices;

static struct UPNPUrls *upnp_urls;
static struct IGDdatas *upnp_datas;
static char (*upnp_lanaddrs)[64];

static void upnp_clear()
{
	for (int i = 0; i < upnp_numdevices; i++) {
		struct UPNPUrls *urls = &upnp_urls[i];
		struct IGDdatas *data = &upnp_datas[i];

		UPNP_DeletePortMapping(
			urls->controlURL,
			data->first.servicetype,
			str_port, "UDP", NULL);
	}
}


static void upnp_thread(void *args)
{
	int error;
	upnp_devlist = upnpDiscover(2000, iface, NULL,
			       UPNP_LOCAL_PORT_ANY, 0, 2, &error);

	if (!upnp_devlist)
		return;

	snprintf(str_port, 6, "%hu", vpn_port);

	for (struct UPNPDev *device = upnp_devlist; device; device = device->pNext)
		upnp_numdevices++;

	upnp_urls = calloc(upnp_numdevices, sizeof(*upnp_urls));
	upnp_datas = calloc(upnp_numdevices, sizeof(*upnp_datas));
	upnp_lanaddrs = calloc(upnp_numdevices, sizeof(*upnp_lanaddrs));

	if (!upnp_urls || !upnp_datas || !upnp_lanaddrs)
		perror_exit("calloc");

	for (int i = 0; i < upnp_numdevices; i++) {
		struct UPNPUrls *urls = &upnp_urls[i];
		struct IGDdatas *data = &upnp_datas[i];
		char *lanaddr = upnp_lanaddrs[i];

		UPNP_GetValidIGD(upnp_devlist, urls, data, lanaddr, 64);
		UPNP_AddPortMapping(
			urls->controlURL,
			data->first.servicetype,
			str_port, str_port, lanaddr, NULL,
			"UDP", NULL, NULL);
	}

	atexit(upnp_clear);

	while (!thread_should_stop(current)) {
		struct pollfd fds[1] = {{thread_stop_eventfd(current), POLLIN}};
		poll(fds, 1, 20 * 60 * 1000);

		if (thread_should_stop(current))
			break;

		for (int i = 0; i < upnp_numdevices; i++) {
			struct UPNPUrls *urls = &upnp_urls[i];
			struct IGDdatas *data = &upnp_datas[i];
			char *lanaddr = upnp_lanaddrs[i];

			int err = UPNP_GetSpecificPortMappingEntry(
				urls->controlURL,
				data->first.servicetype,
				str_port, "UDP", NULL,
				"", "", NULL, NULL, NULL);

			if (err == UPNPCOMMAND_SUCCESS)
				continue;

			UPNP_AddPortMapping(
				urls->controlURL,
				data->first.servicetype,
				str_port, str_port, lanaddr, NULL,
				"UDP", NULL, NULL);
		}
	}
}

void start_endpoint(void)
{
	endpoint_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (endpoint_fd < 0)
		perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");

	struct ifreq ifr;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (setsockopt(endpoint_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
		perror_exit("setsockopt");

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = { public_host_ip },
	};
	socklen_t addrlen = sizeof(addr);
	if (bind(endpoint_fd, (struct sockaddr *)&addr, addrlen) < 0)
		perror_exit("bind");


	if (getsockname(endpoint_fd, (struct sockaddr *)&addr, &addrlen) == -1)
		perror_exit("bind");

	vpn_port = ntohs(addr.sin_port);
	assert(vpn_port);

	// thread_start(upnp_thread, NULL, "upnp");
}
