#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

#include "ishoal.h"
#include "list.h"

uint16_t vpn_port;

static int endpoint_fd;

static char str_port[6];

static struct UPNPDev *upnp_devlist;
static size_t upnp_numdevices;

static struct UPNPUrls *upnp_urls;
static struct IGDdatas *upnp_datas;
static char (*upnp_lanaddrs)[64];

struct remote_switch {
	struct list_head list;
	ipaddr_t local;
	struct remote_addr remote;
};

static pthread_mutex_t remotes_lock;
static LIST_HEAD(remotes);

int remotes_fd;
static FILE *remotes_log;

__attribute__((constructor))
static void remote_init(void)
{
	pthread_mutex_init(&remotes_lock, NULL);
}

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
	remotes_fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
	if (remotes_fd < 0)
		perror_exit("open(O_TMPFILE)");

	remotes_log = fdopen(remotes_fd, "a");
	if (!remotes_log)
		perror_exit("fdopen");

	setvbuf(remotes_log, NULL, _IONBF, 0);

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

	fprintf(remotes_log, "Endpoint UDP port: %d\n", vpn_port);

	thread_start(upnp_thread, NULL, "upnp");
}

void set_remote_addr(ipaddr_t local_ip, ipaddr_t remote_ip, uint16_t remote_port)
{
	if (local_ip == switch_ip)
		return;

	struct remote_switch *remote;
	pthread_mutex_lock(&remotes_lock);
	list_for_each_entry(remote, &remotes, list) {
		if (remote->local == local_ip) {
			remote->remote.ip = remote_ip;
			remote->remote.port = remote_port;
			goto next;
		}
	}

next:
	remote = calloc(1, sizeof(*remote));
	if (!remote)
		perror_exit("calloc");
	remote->local = local_ip;
	remote->remote.ip = remote_ip;
	remote->remote.port = remote_port;

	list_add(&remote->list, &remotes);
	pthread_mutex_unlock(&remotes_lock);

	fprintf(remotes_log, "+ Remote IP %s\n", ip_str(local_ip));

	bpf_set_remote_addr(local_ip, &remote->remote);
}

void delete_remote_addr(ipaddr_t local_ip)
{
	if (local_ip == switch_ip)
		return;

	struct remote_switch *remote;
	pthread_mutex_lock(&remotes_lock);
	list_for_each_entry(remote, &remotes, list) {
		if (remote->local == local_ip) {
			list_del(&remote->list);
			goto found;
		}
	}
	pthread_mutex_unlock(&remotes_lock);
	return;

found:
	pthread_mutex_unlock(&remotes_lock);

	fprintf(remotes_log, "- Remote IP %s\n", ip_str(local_ip));

	bpf_delete_remote_addr(local_ip);
}

void broadcast_all_remotes(void *buf, size_t len)
{
	struct remote_switch *remote;
	pthread_mutex_lock(&remotes_lock);
	list_for_each_entry(remote, &remotes, list) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(remote->remote.port),
			.sin_addr = { remote->remote.ip },
		};
		sendto(endpoint_fd, buf, len, 0,
		       (struct sockaddr *)&addr, sizeof(addr));
	}
	pthread_mutex_unlock(&remotes_lock);
}
