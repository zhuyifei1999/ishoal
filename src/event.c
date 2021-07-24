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
#include <time.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/rculist.h>

#include "ishoal.h"
#include "darray.h"

struct eventloop_elem {
	struct cds_list_head list;
	struct event evt;
};

struct eventloop {
	struct cds_list_head events;
	size_t num_events;
	struct eventloop_elem *current_evt;
	bool (*intr_should_restart)(struct eventloop *e, void *ctxl);
	void *intr_should_restart_ctx;
};

struct eventloop *eventloop_new(void)
{
	struct eventloop *el = calloc(1, sizeof(*el));
	if (!el)
		perror_exit("calloc");

	CDS_INIT_LIST_HEAD(&el->events);
	return el;
}

void eventloop_destroy(struct eventloop *el)
{
	eventloop_clear_events(el);
	free(el);
}

void eventloop_clear_events(struct eventloop *el)
{
	struct eventloop_elem *ele, *tmp;

	cds_list_for_each_entry_safe(ele, tmp, &el->events, list) {
		cds_list_del(&ele->list);
		free(ele);
	}

	el->num_events = 0;
}

void eventloop_install_event_sync(struct eventloop *el, const struct event *evt)
{
	struct eventloop_elem *ele = malloc(sizeof(*ele));
	if (!ele)
		perror_exit("malloc");

	ele->evt = *evt;

	if (evt->expiry.tv_sec || evt->expiry.tv_nsec) {
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			perror_exit("clock_gettime");

		timespec_add(&ele->evt.expiry, &now);
	}

	cds_list_add(&ele->list, &el->events);
	el->num_events++;
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

static void eventloop_rpc_cb(int fd, void *ctx, bool expired)
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

void eventloop_install_event_async(struct eventloop *el, const struct event *evt,
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

void eventloop_remove_event_current(struct eventloop *el)
{
	assert(el->current_evt);

	cds_list_del(&el->current_evt->list);
	el->num_events--;

	free(el->current_evt);
	el->current_evt = NULL;
}

void eventloop_set_intr_should_restart(struct eventloop *el,
				       bool (*cb)(struct eventloop *el, void *ctx),
				       void *ctx)
{
	el->intr_should_restart = cb;
	el->intr_should_restart_ctx = ctx;
}

int eventloop_enter(struct eventloop *el, int timeout_ms)
{
	assert (!el->current_evt);

	bool has_timeout = false;
	struct timespec timeout_abs;

	if (timeout_ms >= 0) {
		has_timeout = true;

		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			perror_exit("clock_gettime");

		timeout_abs = (struct timespec) {
			.tv_sec = timeout_ms / 1000,
			.tv_nsec = (timeout_ms % 1000) * 1000000,
		};

		timespec_add(&timeout_abs, &now);
	}

	bool do_break = false;

	while (!do_break) {
		struct eventloop_elem *ele, *tmp;
		int i;
		int size = el->num_events;

		struct pollfd fds[size];

		bool has_expiry = has_timeout;
		struct timespec min_expiry = timeout_abs;

		i = 0;
		cds_list_for_each_entry(ele, &el->events, list) {
			assert(i < size);

			fds[i].fd = ele->evt.fd;
			fds[i].events = POLLIN;
			fds[i].revents = 0;

			if (ele->evt.expiry.tv_sec || ele->evt.expiry.tv_nsec) {
				if (!has_expiry) {
					has_expiry = true;
					min_expiry = ele->evt.expiry;
				} else if (timespec_cmp(&ele->evt.expiry, &min_expiry) < 0) {
					min_expiry = ele->evt.expiry;
				}
			}
			i++;
		}

		struct timespec now;
		int timeout_ms_poll = -1;

		if (has_expiry) {
			if (clock_gettime(CLOCK_MONOTONIC, &now))
				perror_exit("clock_gettime");

			if (timespec_cmp(&min_expiry, &now) <= 0)
				timeout_ms_poll = 0;
			else {
				timespec_sub(&min_expiry, &now);
#define ceildiv(x, y) (!!(x) + (((x) - !!(x)) / (y)) )
				timeout_ms_poll = min_expiry.tv_sec * 1000 +
						  ceildiv(min_expiry.tv_nsec, 1000000);
#undef ceildiv
			}
		}

		int res = poll(fds, size, timeout_ms_poll);
		if (res < 0) {
			if (errno == EINTR) {
				if (!el->intr_should_restart ||
				    el->intr_should_restart(el, el->intr_should_restart_ctx))
					continue;
				return 1;
			}
			perror_exit("poll");
		}

		if (has_expiry) {
			if (clock_gettime(CLOCK_MONOTONIC, &now))
				perror_exit("clock_gettime");
		}

		i = 0;
		cds_list_for_each_entry_safe(ele, tmp, &el->events, list) {
			assert(i < size);
			assert(fds[i].fd == ele->evt.fd);

			if (fds[i].revents) {
				if (ele->evt.eventfd_ack) {
					eventfd_t event_value;
					if (eventfd_read(ele->evt.fd, &event_value))
						perror_exit("eventfd_read");
				}

				switch (ele->evt.handler_type) {
				case EVT_CALL_FN:
					el->current_evt = ele;
					ele->evt.handler_fn(ele->evt.fd, ele->evt.handler_ctx, false);
					el->current_evt = NULL;
					break;
				case EVT_BREAK:
					do_break = true;
					break;
				}
			} else if ((ele->evt.expiry.tv_sec || ele->evt.expiry.tv_nsec) &&
				   timespec_cmp(&ele->evt.expiry, &now) <= 0) {
				el->current_evt = ele;
				ele->evt.handler_fn(ele->evt.fd, ele->evt.handler_ctx, true);
				el->current_evt = NULL;
			}

			i++;
		}

		if (has_timeout && timespec_cmp(&timeout_abs, &now) <= 0 && !do_break)
			return 1;
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
	struct rcu_head rcu;
	int fd;
};

struct broadcast_event {
	pthread_mutex_t replica_fds_mutex;
	struct cds_list_head replica_fds;
};

static void broadcast_event_cb(int fd, void *_ctx, bool expired)
{
	struct broadcast_event *ctx = _ctx;
	struct broadcast_replica *bcr;

	rcu_read_lock();
	cds_list_for_each_entry_rcu(bcr, &ctx->replica_fds, list)
		if (eventfd_write(bcr->fd, 1))
			perror_exit("eventfd_write");
	rcu_read_unlock();
}

struct broadcast_event *broadcast_new(int primary_event_fd)
{
	struct broadcast_event *bce = calloc(1, sizeof(*bce));
	if (!bce)
		perror_exit("calloc");

	pthread_mutex_init(&bce->replica_fds_mutex, 0);

	CDS_INIT_LIST_HEAD(&bce->replica_fds);

	worker_install_event(&(struct event){
		.fd = primary_event_fd,
		.eventfd_ack = true,
		.handler_type = EVT_CALL_FN,
		.handler_fn = broadcast_event_cb,
		.handler_ctx = bce,
	});

	return bce;
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
	rcu_read_lock();
	cds_list_add_rcu(&bcr->list, &bce->replica_fds);
	rcu_read_unlock();
	pthread_mutex_unlock(&bce->replica_fds_mutex);

	return fd;
}

void broadcast_replica_del(struct broadcast_event *bce, int fd)
{
	struct broadcast_replica *bcr;

	pthread_mutex_lock(&bce->replica_fds_mutex);
	rcu_read_lock();
	cds_list_for_each_entry_rcu(bcr, &bce->replica_fds, list)
		if (bcr->fd == fd) {
			cds_list_del_rcu(&bcr->list);
			free_rcu(bcr, rcu);
		}
	rcu_read_unlock();
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
	const char *pathname;
	uint32_t mask;
	int eventfd;
};

// adapted from:
// https://man7.org/tlpi/code/online/book/inotify/demo_inotify.c.html
static void inotify_cb(int fd, void *ctx, bool expired)
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

int inotifyeventfd_add(const char *pathname, uint32_t mask)
{
	static atomic_flag init_done = ATOMIC_FLAG_INIT;
	if (!atomic_flag_test_and_set(&init_done)) {
		inotify_fd = inotify_init1(IN_CLOEXEC);
		if (inotify_fd < 0)
			perror_exit("inotify_init1");

		worker_install_event(&(struct event){
			.fd = inotify_fd,
			.eventfd_ack = false,
			.handler_type = EVT_CALL_FN,
			.handler_fn = inotify_cb,
		});
	}

	int fd = eventfd(0, EFD_CLOEXEC);
	if (fd < 0)
		perror_exit("eventfd");

	struct inotifyeventfd_add_ctx ctx = {
		.pathname = pathname,
		.mask = mask,
		.eventfd = fd,
	};

	worker_sync(inotifyeventfd_add_cb, &ctx);

	return fd;
}

void inotifyeventfd_rm(int fd)
{
	worker_sync(inotifyeventfd_rm_cb, &fd);
	close(fd);
}
