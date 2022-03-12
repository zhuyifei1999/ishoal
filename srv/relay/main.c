#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "relay.h"
#include "xdpfilter.skel.h"

#define RELAYCTL_CMD_JTC_CLEAR 1
#define RELAYCTL_CMD_JTC_ADD 2
#define RELAYCTL_CMD_JTC_DEL 3

#define RELAYCTL_CMD_CTJ_DUMP 1
#define RELAYCTL_CMD_CTJ_ADDACK 2

static struct xdpfilter_bpf *obj;

static char *iface;
static int ifindex;

static ipaddr_t public_host_ip;

static int sock_fds[65536];

__attribute__ ((format(printf, 1, 2)))
static void fprintf_exit(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static void perror_exit(char *msg)
{
	perror(msg);
	exit(1);
}

static void sig_handler(int sig_num)
{
	exit(0);
}

static void get_if_ipaddr(char *iface, ipaddr_t *addr)
{
	struct ifreq ifr;

	int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFADDR, &ifr))
		perror_exit("ioctl(SIOCGIFADDR)");
	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	close(sock);
}

static void close_obj(void)
{
	xdpfilter_bpf__destroy(obj);
}

static void detach_obj(void)
{
	bpf_set_link_xdp_fd(ifindex, -1, 0);
}

int main(int argc, char *argv[])
{
	if (argc != 2)
		fprintf_exit("Usage: %s [interface]\n", argv[0]);

	iface = argv[1];
	ifindex = if_nametoindex(iface);
	if (!ifindex)
		perror_exit(iface);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	for (int i = 0; i < 65536; i++)
		sock_fds[i] = -1;

	get_if_ipaddr(iface, &public_host_ip);

	struct rlimit unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &unlimited))
		perror_exit("setrlimit(RLIMIT_MEMLOCK)");

	obj = xdpfilter_bpf__open_and_load();
	if (!obj)
		exit(1);

	atexit(close_obj);

	obj->bss->public_host_ip = public_host_ip;

	if (bpf_set_link_xdp_fd(ifindex, bpf_program__fd(obj->progs.xdp_prog),
				XDP_FLAGS_SKB_MODE) < 0)
		perror_exit("bpf_set_link_xdp_fd");
	atexit(detach_obj);

	int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");

	struct sockaddr_in servaddr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = htons(5001),
	};
	if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		perror_exit("bind");

	struct sockaddr_in defcliaddr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = htons(5000),
	};
	if (connect(sock, (struct sockaddr *)&defcliaddr, sizeof(defcliaddr)) < 0)
		perror_exit("bind");

	char cmd = RELAYCTL_CMD_CTJ_DUMP;
	send(sock, &cmd, sizeof(cmd), 0);

	while (true) {
		struct sockaddr_in cliaddr;
		socklen_t cliaddrlen = sizeof(cliaddr);

		int size = recvfrom(sock, NULL, 0, MSG_PEEK|MSG_TRUNC,
				    (struct sockaddr *)&cliaddr, &cliaddrlen);
		if (size < 0) {
			if (errno == ECONNREFUSED)
				continue;
			perror_exit("recvfrom");
		}

		if (cliaddr.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || cliaddr.sin_port != htons(5000)) {
			recv(sock, NULL, 0, MSG_TRUNC);
			continue;
		}

		char buf[size];
		if (recv(sock, buf, size, 0) != size)
			perror_exit("recv");

		if (!size)
			continue;

		cmd = buf[0];

		switch (cmd) {
		case RELAYCTL_CMD_JTC_CLEAR:
			if (size != sizeof(cmd))
				break;

			for (int i = 0; i < 65536; i++)
				obj->bss->connections[i].exists = false;

			for (int i = 0; i < 65536; i++)
				if (sock_fds[i] >= 0) {
					close(sock_fds[i]);
					sock_fds[i] = -1;
				}

			break;
		case RELAYCTL_CMD_JTC_DEL: {
			struct {
				char cmd;
				uint16_t this_relay_port;
				uint16_t that_relay_port;
			} __attribute__((packed)) *cmd_struct = (void *)&buf;

			if (size != sizeof(*cmd_struct))
				break;

			uint16_t this_relay_port = ntohs(cmd_struct->this_relay_port);
			uint16_t that_relay_port = ntohs(cmd_struct->that_relay_port);

			obj->bss->connections[this_relay_port].exists = false;
			obj->bss->connections[that_relay_port].exists = false;
			close(sock_fds[this_relay_port]);
			close(sock_fds[that_relay_port]);

			break;
		}
		case RELAYCTL_CMD_JTC_ADD: {
			struct {
				char cmd;
				uint16_t rpc_id;
				ipaddr_t this_ip;
				uint16_t this_port;
				uint16_t this_relay_port;
				ipaddr_t that_ip;
				uint16_t that_port;
				uint16_t that_relay_port;
			} __attribute__((packed)) *cmd_struct = (void *)&buf;

			if (size != sizeof(*cmd_struct))
				break;

			struct sockaddr_in bindaddr = {
				.sin_family = AF_INET,
				.sin_addr = { .s_addr = public_host_ip },
			};
			struct sockaddr_in gsnaddr;
			socklen_t gsnaddrlen;

			int this_relay_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
			if (this_relay_sock < 0)
				perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");
			bindaddr.sin_port = cmd_struct->this_relay_port;
			if (bind(this_relay_sock, (struct sockaddr *)&bindaddr,
				 sizeof(bindaddr)) < 0)
				perror_exit("bind");
			gsnaddrlen = sizeof(gsnaddr);
			if (getsockname(this_relay_sock, (struct sockaddr *)&gsnaddr, &gsnaddrlen) < 0)
				perror_exit("getsockname");
			uint16_t this_relay_port = ntohs(gsnaddr.sin_port);
			sock_fds[this_relay_port] = this_relay_sock;

			int that_relay_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
			if (that_relay_sock < 0)
				perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");
			bindaddr.sin_port = cmd_struct->that_relay_port;
			if (bind(that_relay_sock, (struct sockaddr *)&bindaddr,
				 sizeof(bindaddr)) < 0)
				perror_exit("bind");
			gsnaddrlen = sizeof(gsnaddr);
			if (getsockname(that_relay_sock, (struct sockaddr *)&gsnaddr, &gsnaddrlen) < 0)
				perror_exit("getsockname");
			uint16_t that_relay_port = ntohs(gsnaddr.sin_port);
			sock_fds[that_relay_port] = that_relay_sock;

			obj->bss->connections[this_relay_port] = (struct relay_connection) {
				.exists = true,
				.recv_rem_ip = cmd_struct->this_ip,
				.recv_rem_port = ntohs(cmd_struct->this_port),
				// .recv_loc_port = this_relay_port,  // as key
				.send_loc_port = that_relay_port,
				.send_rem_ip = cmd_struct->that_ip,
				.send_rem_port = ntohs(cmd_struct->that_port),
			};

			obj->bss->connections[that_relay_port] = (struct relay_connection) {
				.exists = true,
				.recv_rem_ip = cmd_struct->that_ip,
				.recv_rem_port = ntohs(cmd_struct->that_port),
				// .recv_loc_port = that_relay_port,  // as key
				.send_loc_port = this_relay_port,
				.send_rem_ip = cmd_struct->this_ip,
				.send_rem_port = ntohs(cmd_struct->this_port),
			};

			struct {
				char cmd;
				uint16_t rpc_id;
				uint16_t this_relay_port;
				uint16_t that_relay_port;
			} __attribute__((packed)) reply_struct = {
				.cmd = RELAYCTL_CMD_CTJ_ADDACK,
				.rpc_id = cmd_struct->rpc_id,
				.this_relay_port = htons(this_relay_port),
				.that_relay_port = htons(that_relay_port),
			};

			send(sock, &reply_struct, sizeof(reply_struct), MSG_CONFIRM);

			break;
		}
		}
	}

	return 0;
}
