#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <unistd.h>

#include "ishoal.h"

int exitcode;

char *progname;
char *iface;
int ifindex;

static int promisc_sock;

static void sig_handler(int sig_num)
{
	if (eventfd_write(stop_broadcast_primary, 1))
		perror_exit("eventfd_write");
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
		exit(1);
	}

	progname = argv[0];
	iface = argv[1];
	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		perror(iface);
		exit(1);
	};

	ifinfo_init();
	start_endpoint();
	load_conf();

	struct rlimit unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &unlimited))
		perror_exit("setrlimit(RLIMIT_MEMLOCK)");

	/* Enable promiscuous mode in order to workaround WiFi issues */
	promisc_sock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (promisc_sock < 0)
		perror_exit("socket(AF_PACKET, SOCK_RAW)");

	struct packet_mreq mreq = {
		.mr_ifindex = ifindex,
		.mr_type = PACKET_MR_PROMISC,
	};
	if (setsockopt(promisc_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq))) {
		perror_exit("setsockopt");
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	thread_start(bpf_load_thread, NULL, "bpf");
	thread_start(python_thread, NULL, "python");
	thread_start(tui_thread, NULL, "tui");

	__broadcast_finalize_init();

	struct eventloop *main_el = eventloop_new();
	eventloop_install_break(main_el, thread_stop_eventfd(current));

	eventloop_enter(main_el, -1);
	eventloop_destroy(main_el);

	thread_all_stop();
	thread_join_rest();

	return exitcode;
}
