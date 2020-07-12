#include <net/if.h>
#include <sys/resource.h>
#include <poll.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <unistd.h>
#include <signal.h>

#include "ishoal.h"
#include "bpf_kern.skel.h"

static struct bpf_kern *obj;
static char *iface;
static int ifindex;

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

static void disp_thread_fn(void *arg)
{
	while (!thread_should_stop()) {
		printf("switch_mac = %s\n", mac_str(obj->bss->switch_mac));
		printf("switch_ip = %s\n", ip_str(obj->bss->switch_ip));

		struct pollfd fds[1] = {{thread_stop_eventfd(current), POLLIN}};
		poll(fds, 1, 1000);
	}
}

static void sig_handler(int sig_num)
{
	thread_all_stop();

}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
		exit(1);
	}

	iface = argv[1];
	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		perror(iface);
		exit(1);
	};

	struct rlimit unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &unlimited))
		perror_exit("setrlimit(RLIMIT_MEMLOCK)");

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

	thread_start(disp_thread_fn, NULL);

	signal(SIGINT, sig_handler);

	while (!thread_should_stop()) {
		struct pollfd fds[1] = {{thread_stop_eventfd(current), POLLIN}};
		poll(fds, 1, -1);
	}

	thread_join_rest();
}
