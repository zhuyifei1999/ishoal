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

macaddr_t switch_mac;
ipaddr_t switch_ip;

ipaddr_t fake_gateway_ip;

ipaddr_t relay_ip;

int xsk_broadcast_evt_broadcast_primary;
struct broadcast_event *xsk_broadcast_evt_broadcast;

int switch_change_broadcast_primary;
struct broadcast_event *switch_change_broadcast;

__attribute__((constructor))
static void switch_change_broadcast_init(void)
{
	switch_change_broadcast_primary = eventfd(0, EFD_CLOEXEC);
	if (switch_change_broadcast_primary < 0)
		crash_with_perror("eventfd");

	switch_change_broadcast = broadcast_new(switch_change_broadcast_primary);

	xsk_broadcast_evt_broadcast_primary = eventfd(0, EFD_CLOEXEC);
	if (xsk_broadcast_evt_broadcast_primary < 0)
		crash_with_perror("eventfd");

	xsk_broadcast_evt_broadcast = broadcast_new(xsk_broadcast_evt_broadcast_primary);
}

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

void bpf_add_connection(const struct connection *conn)
{
	if (bpf_map_update_elem(bpf_map__fd(obj->maps.conn_by_ip), &conn->local_ip,
				conn, BPF_ANY))
		crash_with_perror("bpf_map_update_elem");
	if (bpf_map_update_elem(bpf_map__fd(obj->maps.conn_by_port), &conn->local_port,
				conn, BPF_ANY))
		crash_with_perror("bpf_map_update_elem");
}

void bpf_delete_connection(ipaddr_t local_ip, uint16_t local_port)
{
	bpf_map_delete_elem(bpf_map__fd(obj->maps.conn_by_ip), &local_ip);
	bpf_map_delete_elem(bpf_map__fd(obj->maps.conn_by_port), &local_port);
}

static void __on_switch_change(void)
{
	if (eventfd_write(switch_change_broadcast_primary, 1))
		crash_with_perror("eventfd_write");
}

void bpf_set_switch_ip(const ipaddr_t addr)
{
	if (switch_ip == addr)
		return;

	switch_ip = addr;
	obj->bss->switch_ip = addr;
	__on_switch_change();
}

void bpf_set_switch_mac(const macaddr_t addr)
{
	if (!memcmp(switch_mac, addr, sizeof(macaddr_t)))
		return;

	memcpy(switch_mac, addr, sizeof(macaddr_t));
	memcpy(obj->bss->switch_mac, addr, sizeof(macaddr_t));
	__on_switch_change();
}

static void update_subnet_mask(void)
{
	if (fake_gateway_ip)
		obj->bss->subnet_mask = htonl(0xFFFFFF00);
	else
		obj->bss->subnet_mask = real_subnet_mask;
}

void bpf_set_fake_gateway_ip(const ipaddr_t addr)
{
	if (fake_gateway_ip == addr)
		return;

	fake_gateway_ip = addr;
	obj->bss->fake_gateway_ip = addr;

	update_subnet_mask();
}

static void on_xsk_pkt(void *ptr, size_t length)
{
	if (obj->bss->switch_ip != switch_ip ||
	    memcmp(obj->bss->switch_mac, switch_mac, sizeof(macaddr_t))) {
		switch_ip = obj->bss->switch_ip;
		memcpy(switch_mac, obj->bss->switch_mac, sizeof(macaddr_t));

		__on_switch_change();
	}

	if (eventfd_write(xsk_broadcast_evt_broadcast_primary, 1))
		crash_with_perror("eventfd_write");

	xdpemu(ptr, length);
}

void bpf_load_thread_fn(void *arg)
{
	struct rlimit unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &unlimited))
		crash_with_perror("setrlimit(RLIMIT_MEMLOCK)");

	/* Enable promiscuous mode in order to workaround VirtualBox WiFi issues */
	int promisc_sock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (promisc_sock < 0)
		crash_with_perror("socket(AF_PACKET, SOCK_RAW)");

	struct packet_mreq mreq = {
		.mr_ifindex = ifindex,
		.mr_type = PACKET_MR_PROMISC,
	};
	if (setsockopt(promisc_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq)))
		crash_with_perror("setsockopt");

	obj = xdpfilter_bpf__open_and_load();
	if (!obj)
		exit(1);

	atexit(close_obj);

	obj->bss->switch_ip = switch_ip;
	memcpy(obj->bss->switch_mac, switch_mac, sizeof(macaddr_t));

	obj->bss->public_host_ip = public_host_ip;
	memcpy(obj->bss->host_mac, host_mac, sizeof(macaddr_t));
	memcpy(obj->bss->gateway_mac, gateway_mac, sizeof(macaddr_t));

	obj->bss->fake_gateway_ip = fake_gateway_ip;
	update_subnet_mask();

	obj->bss->relay_ip = relay_ip;

	if (bpf_set_link_xdp_fd(ifindex, bpf_program__fd(obj->progs.xdp_prog), 0) < 0)
		crash_with_perror("bpf_set_link_xdp_fd");
	atexit(detach_obj);

	for (int i = 0; i < MAX_XSKS; i++) {
		struct xsk_socket *xsk = xsk_configure_socket(iface, i, on_xsk_pkt);
		if (!xsk) {
			if (i)
				break;
			else
				crash_with_perror("xsk_configure_socket");
		}

		int fd = xsk_socket__fd(xsk);
		int key = i;
		if (bpf_map_update_elem(bpf_map__fd(obj->maps.xsks_map), &key, &fd, 0))
			crash_with_perror("bpf_map_update_elem");
	}

	atexit(clear_map);
}
