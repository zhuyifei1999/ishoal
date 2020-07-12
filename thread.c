#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <unistd.h>

#include "ishoal.h"
#include "list.h"

struct thread {
	struct list_head list;
	pthread_t pthread;
	void (*fn)(void *arg);
	void *arg;
	int stop_eventfd;
	bool should_stop;
	bool exited;
};

static struct thread main_thread;

__thread struct thread *current;

pthread_mutex_t threads_lock;
static LIST_HEAD(threads);

__attribute__((constructor))
static void thread_init(void)
{
	pthread_mutex_init(&threads_lock, NULL);

	current = &main_thread;

	current->stop_eventfd = eventfd(0, EFD_CLOEXEC);
	if (current->stop_eventfd < 0)
		perror_exit("eventfd");

	list_add(&current->list, &threads);
}

static void *thread_wrapper_fn(void *thread)
{
	current = thread;
	pthread_mutex_lock(&threads_lock);
	list_add(&current->list, &threads);
	pthread_mutex_unlock(&threads_lock);

	current->fn(current->arg);

	pthread_mutex_lock(&threads_lock);
	list_del(&current->list);
	pthread_mutex_unlock(&threads_lock);

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

	thread->stop_eventfd = eventfd(0, EFD_CLOEXEC);
	if (thread->stop_eventfd < 0)
		perror_exit("eventfd");

	if (pthread_create(&thread->pthread, NULL, thread_wrapper_fn, thread))
		perror_exit("pthread_create");

	pthread_setname_np(thread->pthread, name);

	return thread;
}

void thread_stop(struct thread *thread)
{
	thread->should_stop = true;

	uint64_t event_data = 1;
	if (write(thread->stop_eventfd, &event_data, sizeof(event_data)) !=
	    sizeof(event_data))
		perror_exit("write(eventfd)");
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
	assert(thread != current);
	pthread_join(thread->pthread, NULL);
}

void thread_release(struct thread *thread)
{
	assert(thread->exited);
	close(thread->stop_eventfd);
	free(thread);
}

void thread_all_stop(void)
{
	struct thread *thread, *tmp;

	pthread_mutex_lock(&threads_lock);
	list_for_each_entry_safe(thread, tmp, &threads, list) {
		thread_stop(thread);
	}
	pthread_mutex_unlock(&threads_lock);
}

void thread_join_rest(void)
{
	struct thread *thread, *tmp;

	pthread_mutex_lock(&threads_lock);
	list_for_each_entry_safe(thread, tmp, &threads, list) {
		if (thread != current) {
			pthread_mutex_unlock(&threads_lock);
			thread_join(thread);
			pthread_mutex_lock(&threads_lock);
		}
	}
	pthread_mutex_unlock(&threads_lock);
}
