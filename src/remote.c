#include "features.h"

#include <assert.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <urcu.h>
#include <urcu/rculist.h>

#include "ishoal.h"

uint16_t vpn_port;

static int endpoint_fd;

int remotes_fd;
static FILE *remotes_log;

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
}
