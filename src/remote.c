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
uint16_t public_vpn_port;

static int endpoint_fd;

struct remote_switch {
	struct cds_list_head list;
	struct rcu_head rcu;
	ipaddr_t local;
	struct remote_addr remote;
};

static pthread_mutex_t remotes_lock = PTHREAD_MUTEX_INITIALIZER;
static CDS_LIST_HEAD(remotes);

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

	ipaddr_t public_ip;
	do_stun(endpoint_fd, &public_ip, &public_vpn_port);

	if (public_vpn_port == vpn_port)
		fprintf(remotes_log, "Endpoint UDP port: %d\n", vpn_port);
	else
		fprintf(remotes_log, "Endpoint UDP port: %d, STUN resolved to: %d\n",
			vpn_port, public_vpn_port);
}

struct remotes_arp_ctx {
	ipaddr_t local_ip;
	ipaddr_t remote_ip;
	uint16_t remote_port;
	struct resolve_arp_user rau;
};

static void __set_remote_addr(ipaddr_t local_ip, ipaddr_t remote_ip,
			      uint16_t remote_port, bool checked);

static void remotes_arp_cb(bool solved, void *_ctx)
{
	struct remotes_arp_ctx *ctx = _ctx;

	if (solved) {
		fprintf(remotes_log,
			"x Remote IP %s -- Detected IP collision. "
			"Not adding.\n",
			ip_str(ctx->local_ip));
	} else {
		__set_remote_addr(ctx->local_ip, ctx->remote_ip, ctx->remote_port, true);
	}

	free(ctx);
}

static int remotes_arp_rpc_cb(void *_ctx)
{
	struct remotes_arp_ctx *ctx = _ctx;

	resolve_arp_user(&ctx->rau);

	return 0;
}


static void __set_remote_addr(ipaddr_t local_ip, ipaddr_t remote_ip,
			      uint16_t remote_port, bool checked)
{
	if (local_ip == switch_ip)
		return;

	struct remote_switch *remote;
	pthread_mutex_lock(&remotes_lock);
	cds_list_for_each_entry(remote, &remotes, list) {
		if (remote->local == local_ip) {
			remote->remote.ip = remote_ip;
			remote->remote.port = remote_port;

			pthread_mutex_unlock(&remotes_lock);
			fprintf(remotes_log, "* Remote IP %s\n", ip_str(local_ip));
			bpf_set_remote_addr(local_ip, &remote->remote);
			return;
		}
	}

	if (checked) {
		remote = calloc(1, sizeof(*remote));
		if (!remote)
			perror_exit("calloc");
		remote->local = local_ip;
		remote->remote.ip = remote_ip;
		remote->remote.port = remote_port;

		cds_list_add_rcu(&remote->list, &remotes);

		pthread_mutex_unlock(&remotes_lock);
		fprintf(remotes_log, "+ Remote IP %s\n", ip_str(local_ip));
		bpf_set_remote_addr(local_ip, &remote->remote);
	} else {
		pthread_mutex_unlock(&remotes_lock);

		struct remotes_arp_ctx *rpc_ctx = malloc(sizeof(*rpc_ctx));
		if (!rpc_ctx)
			perror_exit("malloc");

		*rpc_ctx = (struct remotes_arp_ctx) {
			.local_ip = local_ip,
			.remote_ip = remote_ip,
			.remote_port = remote_port,
			.rau = {
				.ipaddr = local_ip,
				.el = worker_el,
				.cb = remotes_arp_cb,
				.ctx = rpc_ctx,
			}
		};

		worker_async(remotes_arp_rpc_cb, rpc_ctx);
	}
}

void set_remote_addr(ipaddr_t local_ip, ipaddr_t remote_ip, uint16_t remote_port)
{
	__set_remote_addr(local_ip, remote_ip, remote_port, false);
}


void delete_remote_addr(ipaddr_t local_ip)
{
	if (local_ip == switch_ip)
		return;

	struct remote_switch *remote;
	pthread_mutex_lock(&remotes_lock);
	cds_list_for_each_entry(remote, &remotes, list) {
		if (remote->local == local_ip) {
			cds_list_del_rcu(&remote->list);
			free_rcu(remote, rcu);
			goto found;
		}
	}
	pthread_mutex_unlock(&remotes_lock);
	return;

found:
	pthread_mutex_unlock(&remotes_lock);

	fprintf(remotes_log, "- Remote IP %s\n", ip_str(local_ip));

	bpf_delete_remote_addr(local_ip);
}

void broadcast_all_remotes(void *buf, size_t len)
{
	struct remote_switch *remote;

	rcu_read_lock();
	cds_list_for_each_entry_rcu(remote, &remotes, list) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(remote->remote.port),
			.sin_addr = { remote->remote.ip },
		};
		sendto(endpoint_fd, buf, len, 0,
		       (struct sockaddr *)&addr, sizeof(addr));
	}
	rcu_read_unlock();
}
