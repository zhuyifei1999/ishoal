#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/eventfd.h>

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
			if (errno = EINTR)
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

struct broadcast_event {
	pthread_mutex_t replica_fds_mutex;
	struct DARRAY(int) replica_fds;
};

static void broadcast_event_cb(int fd, void *_ctx)
{
	struct broadcast_event *ctx = _ctx;

	pthread_mutex_lock(&ctx->replica_fds_mutex);
	for (int i = 0; i < darray_nmemb(ctx->replica_fds); i++)
		if (eventfd_write(*darray_idx(ctx->replica_fds, i), 1))
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
	pthread_mutex_init(&bce->replica_fds_mutex, 0);

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

	pthread_mutex_lock(&bce->replica_fds_mutex);
	darray_inc(bce->replica_fds);
	*darray_tail(bce->replica_fds) = fd;
	pthread_mutex_unlock(&bce->replica_fds_mutex);

	return fd;
}
