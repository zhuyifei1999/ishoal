#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "ishoal.h"

char *iface;
int ifindex;

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

	signal(SIGINT, sig_handler);

	thread_start(bpf_load_thread, NULL, "display");

	while (!thread_should_stop()) {
		struct pollfd fds[1] = {{thread_stop_eventfd(current), POLLIN}};
		poll(fds, 1, -1);
	}

	thread_join_rest();
}
