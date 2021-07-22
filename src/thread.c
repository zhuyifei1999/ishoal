#include "features.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/rculist.h>

#include "ishoal.h"

struct thread {
	struct cds_list_head list;
	pthread_t pthread;
	void (*fn)(void *arg);
	void *arg;
	int stop_eventfd;
	bool should_stop;
	bool exited;
	pthread_mutex_t join_mutex;
	bool joined;
};

static struct thread main_thread;

__thread struct thread *current;

static pthread_mutex_t threads_lock = PTHREAD_MUTEX_INITIALIZER;
static CDS_LIST_HEAD(threads);

int stop_broadcast_primary;
static struct broadcast_event *stop_broadcast;

__attribute__((constructor))
static void thread_init(void)
{
	stop_broadcast_primary = eventfd(0, EFD_CLOEXEC);
	if (stop_broadcast_primary < 0)
		perror_exit("eventfd");

	stop_broadcast = broadcast_new(stop_broadcast_primary);

	current = &main_thread;
	main_thread.stop_eventfd = broadcast_replica(stop_broadcast);

	cds_list_add(&main_thread.list, &threads);
}

static void *thread_wrapper_fn(void *thread)
{
	current = thread;

	faulthandler_altstack_init();
	rcu_register_thread();

	pthread_mutex_lock(&threads_lock);
	rcu_read_lock();
	cds_list_add_rcu(&current->list, &threads);
	rcu_read_unlock();
	pthread_mutex_unlock(&threads_lock);

	current->fn(current->arg);

	pthread_mutex_lock(&threads_lock);
	rcu_read_lock();
	cds_list_del_rcu(&current->list);
	rcu_read_unlock();
	pthread_mutex_unlock(&threads_lock);

	rcu_unregister_thread();
	faulthandler_altstack_deinit();

	current->exited = true;

	return NULL;
}

struct thread *thread_start(void (*fn)(void *arg), void *arg, char *name)
{
	struct thread *thread = calloc(1, sizeof(*thread));
	if (!thread)
		perror_exit("calloc");

	thread->fn = fn;
	thread->arg = arg;

	thread->stop_eventfd = broadcast_replica(stop_broadcast);
	pthread_mutex_init(&thread->join_mutex, NULL);

	if (pthread_create(&thread->pthread, NULL, thread_wrapper_fn, thread))
		perror_exit("pthread_create");

	pthread_setname_np(thread->pthread, name);

	return thread;
}

void thread_stop(struct thread *thread)
{
	if (CMM_ACCESS_ONCE(thread->should_stop) ||
	    CMM_ACCESS_ONCE(thread->exited) ||
	    CMM_ACCESS_ONCE(thread->joined))
		return;

	thread->should_stop = true;

	if (eventfd_write(thread->stop_eventfd, 1))
		perror_exit("eventfd_write");
}

bool thread_should_stop(struct thread *thread)
{
	return thread->should_stop;
}

int thread_stop_eventfd(struct thread *thread)
{
	return thread->stop_eventfd;
}

bool thread_is_main(struct thread *thread)
{
	return thread == &main_thread;
}

void thread_join(struct thread *thread)
{
	assert(thread != current && thread != &main_thread);

	pthread_mutex_lock(&thread->join_mutex);
	if (!thread->joined) {
		pthread_join(thread->pthread, NULL);
		thread->joined = true;
	}
	pthread_mutex_unlock(&thread->join_mutex);
}

void thread_release(struct thread *thread)
{
	assert(thread->exited);
	close(thread->stop_eventfd);
	free(thread);
}

void thread_all_stop(void)
{
	struct thread *thread;

	rcu_read_lock();
	cds_list_for_each_entry_rcu(thread, &threads, list)
		thread->should_stop = true;
	rcu_read_unlock();

	if (eventfd_write(stop_broadcast_primary, 1))
		perror_exit("eventfd_write");
}

void thread_join_rest(void)
{
	struct thread *thread, *tmp;

	pthread_mutex_lock(&threads_lock);
	rcu_read_lock();
	cds_list_for_each_entry_safe(thread, tmp, &threads, list)
		if (thread != current) {
			pthread_mutex_unlock(&threads_lock);
			thread_join(thread);
			pthread_mutex_lock(&threads_lock);
		}
	rcu_read_unlock();
	pthread_mutex_unlock(&threads_lock);
}
