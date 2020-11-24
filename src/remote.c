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
#include <urcu/rculfhash.h>

#include "ishoal.h"
#include "jhash.h"

struct userspace_connection {
	struct cds_lfht_node node;
	struct rcu_head rcu;
	struct connection conn;
	int endpoint_fd;
};

static int match_ip(struct cds_lfht_node *ht_node, const void *_key)
{
	struct userspace_connection *conn =
		caa_container_of(ht_node, struct userspace_connection, node);
	const ipaddr_t *key = _key;

	return *key == conn->conn.local_ip;
}

static uint32_t seed;

static pthread_mutex_t remotes_lock = PTHREAD_MUTEX_INITIALIZER;
static struct cds_lfht *ht_by_ip;

int remotes_log_fd;
static FILE *remotes_log;

static struct thread *keepalive_thread;

static void keepalive_thread_fn(void *arg)
{
	struct eventloop *el = eventloop_new();
	eventloop_install_break(el, thread_stop_eventfd(current));

	while (!thread_should_stop(current)) {
		eventloop_enter(el, 2000);

		char buf[] = "\xFF\xFEISHOAL KEEPALIVE";

		struct userspace_connection *conn;
		struct cds_lfht_iter iter;

		rcu_read_lock();
		cds_lfht_for_each_entry(ht_by_ip, &iter, conn, node) {
			struct sockaddr_in addr = {
				.sin_family = AF_INET,
				.sin_port = htons(conn->conn.remote.port),
				.sin_addr = { conn->conn.remote.ip },
			};
			sendto(conn->endpoint_fd, buf, sizeof(buf), 0,
			       (struct sockaddr *)&addr, sizeof(addr));
		}
		rcu_read_unlock();
	}

	eventloop_destroy(el);
}

void start_endpoint(void)
{
	remotes_log_fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
	if (remotes_log_fd < 0)
		perror_exit("open(O_TMPFILE)");

	remotes_log = fdopen(remotes_log_fd, "a");
	if (!remotes_log)
		perror_exit("fdopen");

	setbuf(remotes_log, NULL);

	seed = (uint32_t) time(NULL);

	ht_by_ip = cds_lfht_new(1, 1, 0,
		CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!ht_by_ip)
		perror_exit("cds_lfht_new");

	keepalive_thread = thread_start(keepalive_thread_fn, NULL, "keepalive");
}

struct remotes_arp_ctx {
	ipaddr_t local_ip;
	uint16_t local_port;
	ipaddr_t remote_ip;
	uint16_t remote_port;
	int endpoint_fd;
	struct resolve_arp_user rau;
};

static void __add_connection(ipaddr_t local_ip, uint16_t local_port,
			     ipaddr_t remote_ip, uint16_t remote_port,
			     int endpoint_fd, bool checked);

static void remotes_arp_cb(bool solved, void *_ctx)
{
	struct remotes_arp_ctx *ctx = _ctx;

	if (solved) {
		char str[IP_STR_BULEN];

		ip_str(ctx->local_ip, str);
		fprintf(remotes_log,
			"x Remote IP %s -- Detected IP collision. "
			"Not adding.\n",
			str);
		close(ctx->endpoint_fd);
	} else {
		__add_connection(ctx->local_ip, ctx->local_port,
				  ctx->remote_ip, ctx->remote_port,
				  ctx->endpoint_fd, true);
	}

	free(ctx);
}

static int remotes_arp_rpc_cb(void *_ctx)
{
	struct remotes_arp_ctx *ctx = _ctx;

	resolve_arp_user(&ctx->rau);

	return 0;
}


static void __add_connection(ipaddr_t local_ip, uint16_t local_port,
			     ipaddr_t remote_ip, uint16_t remote_port,
			     int endpoint_fd, bool checked)
{
	char str[IP_STR_BULEN];

	if (local_ip == switch_ip)
		return;

	struct userspace_connection *conn;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ht_node;

	unsigned long hash;

	pthread_mutex_lock(&remotes_lock);

	hash = jhash(&local_ip, sizeof(local_ip), seed);
	cds_lfht_lookup(ht_by_ip, hash, match_ip, &local_ip, &iter);
	ht_node = cds_lfht_iter_get_node(&iter);
	if (ht_node) {
		pthread_mutex_unlock(&remotes_lock);
		fprintf(remotes_log, "Assertion error on remote addition -- "
			"Connection already exists.\n");
		close(endpoint_fd);
		return;
	}

	if (checked) {
		conn = calloc(1, sizeof(*conn));
		if (!conn)
			perror_exit("calloc");

		cds_lfht_node_init(&conn->node);

		conn->conn.local_ip = local_ip;
		conn->conn.local_port = local_port;
		conn->conn.remote.ip = remote_ip;
		conn->conn.remote.port = remote_port;
		conn->endpoint_fd = endpoint_fd;

		hash = jhash(&local_ip, sizeof(local_ip), seed);
		cds_lfht_add(ht_by_ip, hash, &conn->node);

		pthread_mutex_unlock(&remotes_lock);
		ip_str(local_ip, str);
		fprintf(remotes_log, "+ Remote IP %s, handled by port %d -> %d\n",
			str, local_port, remote_port);
		bpf_add_connection(&conn->conn);
	} else {
		pthread_mutex_unlock(&remotes_lock);

		struct remotes_arp_ctx *rpc_ctx = malloc(sizeof(*rpc_ctx));
		if (!rpc_ctx)
			perror_exit("malloc");

		*rpc_ctx = (struct remotes_arp_ctx) {
			.local_ip = local_ip,
			.local_port = local_port,
			.remote_ip = remote_ip,
			.remote_port = remote_port,
			.endpoint_fd = endpoint_fd,
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

void add_connection(ipaddr_t local_ip, uint16_t local_port,
		    ipaddr_t remote_ip, uint16_t remote_port,
		    int endpoint_fd)
{
	int _endpoint_fd = dup(endpoint_fd);
	if (endpoint_fd < 0)
		perror_exit("dup");

	__add_connection(local_ip, local_port, remote_ip, remote_port,
			 _endpoint_fd, false);
}

static void _delete_connection_rcu_cb(struct rcu_head *head)
{
	struct userspace_connection *conn = caa_container_of(head,
		struct userspace_connection, rcu);

	close(conn->endpoint_fd);
	free(conn);
}

void delete_connection(ipaddr_t local_ip)
{
	char str[IP_STR_BULEN];

	if (local_ip == switch_ip)
		return;

	struct userspace_connection *conn;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ht_node;

	unsigned long hash;

	pthread_mutex_lock(&remotes_lock);

	hash = jhash(&local_ip, sizeof(local_ip), seed);
	cds_lfht_lookup(ht_by_ip, hash, match_ip, &local_ip, &iter);
	ht_node = cds_lfht_iter_get_node(&iter);
	if (!ht_node)
		goto out_unlock;

	int ret = cds_lfht_del(ht_by_ip, ht_node);
	if (ret)
		goto out_unlock;

	conn = caa_container_of(ht_node,
		struct userspace_connection, node);
	uint16_t local_port = conn->conn.local_port;

	call_rcu(&conn->rcu, _delete_connection_rcu_cb);

	pthread_mutex_unlock(&remotes_lock);

	ip_str(local_ip, str);
	fprintf(remotes_log, "- Remote IP %s\n", str);

	bpf_delete_connection(local_ip, local_port);
	return;

out_unlock:
	pthread_mutex_unlock(&remotes_lock);
}

void update_connection_remote_port(ipaddr_t local_ip, uint16_t new_port)
{
	char str[IP_STR_BULEN];

	if (local_ip == switch_ip)
		return;

	struct userspace_connection *conn;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ht_node;

	unsigned long hash;

	rcu_read_lock();

	hash = jhash(&local_ip, sizeof(local_ip), seed);
	cds_lfht_lookup(ht_by_ip, hash, match_ip, &local_ip, &iter);
	ht_node = cds_lfht_iter_get_node(&iter);
	if (!ht_node)
		goto out_unlock;

	int ret = cds_lfht_del(ht_by_ip, ht_node);
	if (ret)
		goto out_unlock;

	conn = caa_container_of(ht_node,
		struct userspace_connection, node);

	uint16_t old_port = conn->conn.remote.port;
	conn->conn.remote.port = new_port;
	rcu_read_unlock();

	ip_str(local_ip, str);
	fprintf(remotes_log, "* Remote IP %s, updated port %d -> %d\n",
		str, old_port, new_port);

	return;

out_unlock:
	rcu_read_unlock();
}

void broadcast_all_remotes(void *buf, size_t len)
{
	char buf_clone[sizeof(uint16_t) + len];

	*(uint16_t *)buf_clone = 0xFFFF;
	memcpy(buf_clone + sizeof(uint16_t), buf, len);

	struct userspace_connection *conn;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	cds_lfht_for_each_entry(ht_by_ip, &iter, conn, node) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(conn->conn.remote.port),
			.sin_addr = { conn->conn.remote.ip },
		};
		sendto(conn->endpoint_fd, buf_clone, sizeof(uint16_t) + len, 0,
		       (struct sockaddr *)&addr, sizeof(addr));
	}
	rcu_read_unlock();
}
