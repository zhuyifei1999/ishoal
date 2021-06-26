#include "features.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#include "ishoal.h"
#include "xdpfilter.skel.h"

struct xdpfilter_bpf *obj;

ipaddr_t fake_gateway_ip;

static void close_obj(void)
{
	xdpfilter_bpf__destroy(obj);
}

static void detach_obj(void)
{
	bpf_set_link_xdp_fd(ifindex, -1, 0);
}

static void clear_map(void)
{
	for (int i = 0; i < 64; i++) {
		int key = i;
		bpf_map_delete_elem(bpf_map__fd(obj->maps.xsks_map), &key);
	}
}

static void update_subnet_mask(void)
{
	if (fake_gateway_ip)
		obj->bss->subnet_mask = htonl(0xFFFFFF00);
	else
		obj->bss->subnet_mask = real_subnet_mask;
}

void bpf_set_fake_gateway_ip(ipaddr_t addr)
{
	if (fake_gateway_ip == addr)
		return;

	fake_gateway_ip = addr;
	obj->bss->fake_gateway_ip = addr;

	update_subnet_mask();
}

static void on_xsk_pkt(void *ptr, size_t length)
{
	xdpemu(ptr, length);
}

void bpf_load_thread(void *arg)
{
	struct rlimit unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &unlimited))
		perror_exit("setrlimit(RLIMIT_MEMLOCK)");

	/* Enable promiscuous mode in order to workaround VirtualBox WiFi issues */
	int promisc_sock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (promisc_sock < 0)
		perror_exit("socket(AF_PACKET, SOCK_RAW)");

	struct packet_mreq mreq = {
		.mr_ifindex = ifindex,
		.mr_type = PACKET_MR_PROMISC,
	};
	if (setsockopt(promisc_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq)))
		perror_exit("setsockopt");

	obj = xdpfilter_bpf__open_and_load();
	if (!obj)
		exit(1);

	atexit(close_obj);

	obj->bss->public_host_ip = public_host_ip;
	memcpy(obj->bss->host_mac, host_mac, sizeof(macaddr_t));
	memcpy(obj->bss->gateway_mac, gateway_mac, sizeof(macaddr_t));

	obj->bss->fake_gateway_ip = fake_gateway_ip;
	update_subnet_mask();

	if (bpf_set_link_xdp_fd(ifindex, bpf_program__fd(obj->progs.xdp_prog), 0) < 0)
		perror_exit("bpf_set_link_xdp_fd");
	atexit(detach_obj);

	for (int i = 0; i < MAX_XSKS; i++) {
		struct xsk_socket *xsk = xsk_configure_socket(iface, i, on_xsk_pkt);
		if (!xsk) {
			if (i)
				break;
			else
				perror_exit("xsk_configure_socket");
		}

		int fd = xsk_socket__fd(xsk);
		int key = i;
		if (bpf_map_update_elem(bpf_map__fd(obj->maps.xsks_map), &key, &fd, 0))
			perror_exit("bpf_map_update_elem");
	}

	atexit(clear_map);
}
