#include <poll.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <unistd.h>

#include "ishoal.h"
#include "bpf_kern.skel.h"

static struct bpf_kern *obj;

static int num_xsk;

static void close_obj(void)
{
	bpf_kern__destroy(obj);
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

static void disp_thread(void *arg)
{
	while (!thread_should_stop(current)) {
		printf("switch_mac = %s\n", mac_str(obj->bss->switch_mac));
		printf("switch_ip = %s\n", ip_str(obj->bss->switch_ip));

		struct pollfd fds[1] = {{thread_stop_eventfd(current), POLLIN}};
		poll(fds, 1, 1000);
	}
}

void bpf_load_thread(void *arg)
{
	obj = bpf_kern__open_and_load();
	if (!obj)
		exit(1);

	atexit(close_obj);

	get_if_ipaddr(iface, &obj->bss->public_host_ip);
	get_if_netmask(iface, &obj->bss->subnet_mask);
	get_if_macaddr(iface, &obj->bss->host_mac);

	ipaddr_t gateway_ip;
	get_if_gateway(iface, &gateway_ip);
	resolve_arp(iface, gateway_ip, &obj->bss->gateway_mac);

	if (bpf_set_link_xdp_fd(ifindex, bpf_program__fd(obj->progs.xdp_prog), 0) < 0)
		perror_exit("bpf_set_link_xdp_fd");
	atexit(detach_obj);

	for (int i = 0; i < MAX_XSKS; i++) {
		struct xsk_socket *xsk = xsk_configure_socket(iface, i, hex_dump);
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

		num_xsk++;
	}

	atexit(clear_map);

	thread_start(disp_thread, NULL, "display");
}
