#include "features.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <urcu.h>

#include "ishoal.h"
#include "darray.h"

struct eventloop {
	struct DARRAY(struct event) events;
};

struct eventloop *eventloop_new(void)
{
	return calloc(1, sizeof(struct eventloop));
}

void eventloop_destroy(struct eventloop *el)
{
	darray_destroy(el->events);
	free(el);
}

void eventloop_clear_events(struct eventloop *el)
{
	darray_resize(el->events, 0);
}

void eventloop_install_event_sync(struct eventloop *el, struct event *evt)
{
	darray_inc(el->events);
	*darray_tail(el->events) = *evt;
}

struct eventloop_install_async {
	struct eventloop *el;
	struct event evt;
};

static int rpc_install_event_async_cb(void *_ctx)
{
	struct eventloop_install_async *ctx = _ctx;

	eventloop_install_event_sync(ctx->el, &ctx->evt);
	free(ctx);

	return 0;
}

static void eventloop_rpc_cb(int fd, void *ctx)
{
	handle_rpc(fd);
}

void eventloop_install_rpc(struct eventloop *el, int rpc_recv_fd)
{
	eventloop_install_event_sync(el, &(struct event){
		.fd = rpc_recv_fd,
		.eventfd_ack = false,
		.handler_type = EVT_CALL_FN,
		.handler_fn = eventloop_rpc_cb,
	});
}

void eventloop_install_break(struct eventloop *el, int break_evt_fd)
{
	eventloop_install_event_sync(el, &(struct event){
		.fd = break_evt_fd,
		.eventfd_ack = false,
		.handler_type = EVT_BREAK,
	});
}

void eventloop_install_event_async(struct eventloop *el, struct event *evt,
				   int rpc_send_fd)
{
	struct eventloop_install_async *rpc_ctx = malloc(sizeof(*rpc_ctx));
	if (!rpc_ctx)
		perror_exit("malloc");

	*rpc_ctx = (struct eventloop_install_async) {
		.el = el,
		.evt = *evt,
	};

	invoke_rpc_async(rpc_send_fd, rpc_install_event_async_cb, rpc_ctx);
}

int eventloop_enter(struct eventloop *el, int timeout_ms)
{
	bool do_break = false;

	while (!do_break) {
		int size = darray_nmemb(el->events);

		struct pollfd fds[size];

		for (int i = 0; i < size; i++) {
			fds[i].fd = darray_idx(el->events, i)->fd;
			fds[i].events = POLLIN;
		}

		int res = poll(fds, size, timeout_ms);
		if (res < 0) {
			if (errno == EINTR)
				continue;
			perror_exit("poll");
		}

		if (!res)
			return 1;

		for (int i = 0; i < size; i++) {
			struct event *evt = darray_idx(el->events, i);

			assert(fds[i].fd == evt->fd);
			if (fds[i].revents) {
				if (evt->eventfd_ack) {
					eventfd_t event_value;
					if (eventfd_read(evt->fd, &event_value))
						perror_exit("eventfd_read");
				}

				switch (evt->handler_type) {
				case EVT_CALL_FN:
					evt->handler_fn(evt->fd, evt->handler_ctx);
					break;
				case EVT_BREAK:
					do_break = true;
					break;
				}
			}
		}
	}

	return 0;
}

void eventloop_thread_fn(void *arg)
{
	eventloop_install_break(arg, thread_stop_eventfd(current));
	eventloop_enter(arg, -1);
}

struct broadcast_replica {
	struct cds_list_head list;
	int fd;
};

struct broadcast_event {
	pthread_mutex_t replica_fds_mutex;
	struct cds_list_head replica_fds;
};

static void broadcast_event_cb(int fd, void *_ctx)
{
	struct broadcast_event *ctx = _ctx;
	struct broadcast_replica *bcr;

	pthread_mutex_lock(&ctx->replica_fds_mutex);
	cds_list_for_each_entry(bcr, &ctx->replica_fds, list)
		if (eventfd_write(bcr->fd, 1))
			perror_exit("eventfd_write");
	pthread_mutex_unlock(&ctx->replica_fds_mutex);
}

static struct eventloop *broadcast_relay_el;
static int broadcast_relay_rpc;

struct broadcast_event *broadcast_new(int primary_event_fd)
{
	static atomic_flag init_done;
	if (!atomic_flag_test_and_set(&init_done)) {
		int broadcast_relay_rpc_recv;
		make_fd_pair(&broadcast_relay_rpc, &broadcast_relay_rpc_recv);

		broadcast_relay_el = eventloop_new();
		eventloop_install_rpc(broadcast_relay_el, broadcast_relay_rpc_recv);
	}

	struct broadcast_event *bce = calloc(1, sizeof(*bce));
	if (!bce)
		perror_exit("calloc");

	pthread_mutex_init(&bce->replica_fds_mutex, 0);

	CDS_INIT_LIST_HEAD(&bce->replica_fds);

	eventloop_install_event_async(broadcast_relay_el, &(struct event){
		.fd = primary_event_fd,
		.eventfd_ack = true,
		.handler_type = EVT_CALL_FN,
		.handler_fn = broadcast_event_cb,
		.handler_ctx = bce,
	}, broadcast_relay_rpc);

	return bce;
}

void __broadcast_finalize_init(void)
{
	static atomic_flag init_done;
	if (!atomic_flag_test_and_set(&init_done)) {
		thread_start(eventloop_thread_fn, broadcast_relay_el, "bc_relay");
	}
}

int broadcast_replica(struct broadcast_event *bce)
{
	int fd = eventfd(0, EFD_CLOEXEC);
	if (fd < 0)
		perror_exit("eventfd");

	struct broadcast_replica *bcr = calloc(1, sizeof(*bcr));
	if (!bcr)
		perror_exit("calloc");

	bcr->fd = fd;

	pthread_mutex_lock(&bce->replica_fds_mutex);
	cds_list_add(&bcr->list, &bce->replica_fds);
	pthread_mutex_unlock(&bce->replica_fds_mutex);

	return fd;
}

void broadcast_replica_del(struct broadcast_event *bce, int fd)
{
	struct broadcast_replica *bcr, *tmp;

	pthread_mutex_lock(&bce->replica_fds_mutex);
	cds_list_for_each_entry_safe(bcr, tmp, &bce->replica_fds, list)
		if (bcr->fd == fd) {
			cds_list_del(&bcr->list);
			free(bcr);
		}
	pthread_mutex_unlock(&bce->replica_fds_mutex);

	close(fd);
}

static int inotify_fd;

static CDS_LIST_HEAD(inotifyeventfd_wd);

struct inotifyeventfd_wd_entry {
	struct cds_list_head list;
	int wd;
	int eventfd;
};

struct inotifyeventfd_add_ctx {
	char *pathname;
	uint32_t mask;
	int eventfd;
};

static struct eventloop *inotifyeventfd_relay_el;
static int inotifyeventfd_relay_rpc;

// adapted from:
// https://man7.org/tlpi/code/online/book/inotify/demo_inotify.c.html
static void inotify_cb(int fd, void *ctx)
{
	char buf[10 * (sizeof(struct inotify_event) + NAME_MAX + 1)] __attribute__ ((aligned(8)));

	ssize_t len = read(inotify_fd, buf, sizeof(buf));
	assert(len);

	if (len < 0)
		perror_exit("read(inotify)");

	for (char *p = buf; p < buf + len;) {
		struct inotify_event *event = (void *)p;

		struct inotifyeventfd_wd_entry *iew;

		cds_list_for_each_entry(iew, &inotifyeventfd_wd, list)
			if (iew->wd == event->wd)
				if (eventfd_write(iew->eventfd, 1))
					perror_exit("eventfd_write");

		p += sizeof(struct inotify_event) + event->len;
	}
}

static int inotifyeventfd_add_cb(void *_ctx)
{
	struct inotifyeventfd_add_ctx *ctx = _ctx;

	int wd = inotify_add_watch(inotify_fd, ctx->pathname, ctx->mask);
	if (wd < 0)
		perror_exit("inotify_add_watch");

	struct inotifyeventfd_wd_entry *iew = malloc(sizeof(*iew));
	if (!iew)
		perror_exit("malloc");

	iew->wd = wd;
	iew->eventfd = ctx->eventfd;

	cds_list_add(&iew->list, &inotifyeventfd_wd);

	return 0;
}

static int inotifyeventfd_rm_cb(void *_ctx)
{
	int *ctx = _ctx;
	int fd = *ctx;

	struct inotifyeventfd_wd_entry *iew, *tmp;

	cds_list_for_each_entry_safe(iew, tmp, &inotifyeventfd_wd, list)
		if (iew->eventfd == fd) {
			inotify_rm_watch(inotify_fd, iew->wd);
			cds_list_del(&iew->list);
			free(iew);
		}

	return 0;
}

int inotifyeventfd_add(char *pathname, uint32_t mask)
{
	static atomic_flag init_done;
	if (!atomic_flag_test_and_set(&init_done)) {
		int inotifyeventfd_relay_rpc_recv;
		make_fd_pair(&inotifyeventfd_relay_rpc, &inotifyeventfd_relay_rpc_recv);

		inotifyeventfd_relay_el = eventloop_new();
		eventloop_install_rpc(inotifyeventfd_relay_el, inotifyeventfd_relay_rpc_recv);

		inotify_fd = inotify_init1(IN_CLOEXEC);
		if (inotify_fd < 0)
			perror_exit("inotify_init1");

		eventloop_install_event_sync(inotifyeventfd_relay_el, &(struct event){
			.fd = inotify_fd,
			.eventfd_ack = false,
			.handler_type = EVT_CALL_FN,
			.handler_fn = inotify_cb,
		});

		thread_start(eventloop_thread_fn, inotifyeventfd_relay_el, "ie_relay");
	}

	int fd = eventfd(0, EFD_CLOEXEC);
	if (fd < 0)
		perror_exit("eventfd");

	struct inotifyeventfd_add_ctx ctx = {
		.pathname = pathname,
		.mask = mask,
		.eventfd = fd,
	};

	invoke_rpc_sync(inotifyeventfd_relay_rpc, inotifyeventfd_add_cb, &ctx);

	return fd;
}

void inotifyeventfd_rm(int fd)
{
	invoke_rpc_sync(inotifyeventfd_relay_rpc, inotifyeventfd_rm_cb, &fd);
	close(fd);
}
