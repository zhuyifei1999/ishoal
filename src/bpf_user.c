#include "features.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#include "ishoal.h"
#include "bpf_kern.skel.h"

static struct bpf_kern *obj;

macaddr_t switch_mac;
ipaddr_t switch_ip;

ipaddr_t fake_gateway_ip;

ipaddr_t ikiwi_ip;
uint16_t ikiwi_port;

static int ikiwi_addr_set_broadcast_primary;
struct broadcast_event *ikiwi_addr_set_broadcast;

static struct bpf_kern__bss bss_shadow;

#define bssvar(var) *(obj->bss ? &obj->bss->var : &bss_shadow.var)

static inline void prop_bss(void)
{
	int ind = 0;
	if (!obj->bss) {
		bpf_map_update_elem(bpf_map__fd(obj->maps.bss), &ind, &bss_shadow, BPF_ANY);
	}
}

__attribute__((constructor))
static void ikiwi_addr_set_broadcast_init(void)
{
	ikiwi_addr_set_broadcast_primary = eventfd(0, EFD_CLOEXEC);
	if (ikiwi_addr_set_broadcast_primary < 0)
		perror_exit("eventfd");

	ikiwi_addr_set_broadcast = broadcast_new(ikiwi_addr_set_broadcast_primary);
}

static void close_obj(void)
{
	bpf_kern__destroy(obj);
}

static void detach_obj(void)
{
	bpf_set_link_xdp_fd(ifindex, -1, 0);
}

void bpf_set_ikiwi_addr(ipaddr_t arg_ikiwi_ip, uint16_t arg_ikiwi_port)
{
	ikiwi_ip = arg_ikiwi_ip;
	ikiwi_port = arg_ikiwi_port;

	bssvar(ikiwi_ip) = arg_ikiwi_ip;
#ifndef SERVER_BUILD
	bssvar(ikiwi_port) = arg_ikiwi_port;
#endif

	prop_bss();

	if (eventfd_write(ikiwi_addr_set_broadcast_primary, 1))
		perror_exit("eventfd_write");
}

static void update_subnet_mask(void)
{
	if (fake_gateway_ip)
		bssvar(subnet_mask) = htonl(0xFFFFFF00);
	else
		bssvar(subnet_mask) = real_subnet_mask;
}

void bpf_set_fake_gateway_ip(ipaddr_t addr)
{
	if (fake_gateway_ip == addr)
		return;

	fake_gateway_ip = addr;
	bssvar(fake_gateway_ip) = addr;

	update_subnet_mask();

	prop_bss();
}

void bpf_load_thread(void *arg)
{
	obj = bpf_kern__open_and_load();
	if (!obj)
		exit(1);

	atexit(close_obj);

	bssvar(public_host_ip) = public_host_ip;
	memcpy(bssvar(host_mac), host_mac, sizeof(macaddr_t));
	memcpy(bssvar(gateway_mac), gateway_mac, sizeof(macaddr_t));

	bssvar(fake_gateway_ip) = fake_gateway_ip;
	update_subnet_mask();

	bssvar(vpn_port) = vpn_port;

	prop_bss();

	if (bpf_set_link_xdp_fd(ifindex, bpf_program__fd(obj->progs.xdp_prog), 0) < 0)
		perror_exit("bpf_set_link_xdp_fd");
	atexit(detach_obj);
}
