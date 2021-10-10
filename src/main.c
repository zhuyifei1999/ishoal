#include "features.h"

#include <errno.h>
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

long pagesize;

struct thread *tui_thread;
struct thread *bpf_load_thread;
struct thread *python_thread;

static void sig_handler(int sig_num)
{
	int save_errno = errno;

	if (eventfd_write(stop_broadcast_primary, 1))
		crash_with_perror("eventfd_write");

	errno = save_errno;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
		crash_with_printf("Usage: %s [interface]", argv[0]);

	progname = argv[0];
	iface = argv[1];
	ifindex = if_nametoindex(iface);
	if (!ifindex)
		crash_with_perror(iface);

	if (geteuid())
		crash_with_errormsg("You must be root");

	pagesize = sysconf(_SC_PAGESIZE);

	crashhandler_init();

	rcu_init();
	rcu_register_thread();

	free_rcu_init();

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	worker_start();

	struct addrinfo *results = NULL;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
	};

	if (getaddrinfo("ishoal.ink", NULL, &hints, &results))
		crash_with_perror("getaddrinfo");

	relay_ip = ((struct sockaddr_in *)results->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(results);

	ifinfo_init();
	load_conf();

	start_endpoint();

	bpf_load_thread = thread_start(bpf_load_thread_fn, NULL, "bpf");
	python_thread = thread_start(python_thread_fn, NULL, "python");
	tui_thread = thread_start(tui_thread_fn, NULL, "tui");

	struct eventloop *main_el = eventloop_new();
	eventloop_install_break(main_el, thread_stop_eventfd(current));

	eventloop_enter(main_el, -1);
	eventloop_destroy(main_el);

	thread_all_stop();
	thread_join_rest();

	rcu_unregister_thread();

	return exitcode;
}
