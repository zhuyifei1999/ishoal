#include "features.h"

#include <assert.h>
#include <stdatomic.h>

#include "ishoal.h"

static int worker_rpc_recv;
static int worker_rpc;
struct eventloop *worker_el;
static struct thread *worker_thread;

// This is both constructor and atomic-guarded because we have a chicken-egg
// problem. When other constructors create broadcasts they create an async
// call to the worker, which we must initialize before their call.

__attribute__((constructor))
static void init_worker(void)
{
	static atomic_flag init_done;
	if (!atomic_flag_test_and_set(&init_done)) {
		make_fd_pair(&worker_rpc, &worker_rpc_recv);

		worker_el = eventloop_new();
		eventloop_install_rpc(worker_el, worker_rpc_recv);
	}
}

void worker_start(void)
{
	init_worker();

	static atomic_flag init_done;
	if (!atomic_flag_test_and_set(&init_done)) {
		worker_thread = thread_start(eventloop_thread_fn, worker_el, "worker");
	}
}

int worker_sync(int (*fn)(void *ctx), void *ctx)
{
	assert(worker_thread);

	if (current == worker_thread)
		return fn(ctx);
	return invoke_rpc_sync(worker_rpc, fn, ctx);
}

void worker_async(int (*fn)(void *ctx), void *ctx)
{
	init_worker();
	invoke_rpc_async(worker_rpc, fn, ctx);
}

void worker_install_event(struct event *evt)
{
	init_worker();
	eventloop_install_event_async(worker_el, evt, worker_rpc);
}
