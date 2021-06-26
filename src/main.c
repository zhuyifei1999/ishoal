#include "features.h"

#include <netdb.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <urcu.h>

#include "ishoal.h"

int exitcode;

char *progname;
char *iface;
int ifindex;

static void sig_handler(int sig_num)
{
	if (eventfd_write(stop_broadcast_primary, 1))
		perror_exit("eventfd_write");
}

int main(int argc, char *argv[])
{
	if (argc != 2)
		fprintf_exit("Usage: %s [interface]\n", argv[0]);

	progname = argv[0];
	iface = argv[1];
	ifindex = if_nametoindex(iface);
	if (!ifindex)
		perror_exit(iface);

	rcu_init();
	rcu_register_thread();

	free_rcu_init();

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	worker_start();

	ifinfo_init();
	load_conf();

	start_endpoint();

	thread_start(bpf_load_thread, NULL, "bpf");
	thread_start(python_thread, NULL, "python");
	thread_start(tui_thread, NULL, "tui");

	struct eventloop *main_el = eventloop_new();
	eventloop_install_break(main_el, thread_stop_eventfd(current));

	eventloop_enter(main_el, -1);
	eventloop_destroy(main_el);

	thread_all_stop();
	thread_join_rest();

	rcu_unregister_thread();

	return exitcode;
}
