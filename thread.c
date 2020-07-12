#include <stdlib.h>
#include <pthread.h>

#include "ishoal.h"
#include "list.h"

struct thread {
	struct list_head list;
	pthread_t pthread;
	void (*fn)(void *arg);
	void *arg;
	bool should_stop;
};

__thread struct thread *current;

static LIST_HEAD(threads);

static void *thread_wrapper_fn(void *thread)
{
	current = thread;
	list_add(&current->list, &threads);

	current->fn(current->arg);

	list_del(&current->list);

	return NULL;
}

struct thread *thread_start(void (*fn)(void *arg), void *arg)
{
	struct thread *thread = calloc(1, sizeof(*thread));
	if (!thread)
		perror_exit("calloc");

	thread->fn = fn;
	thread->arg = arg;

	if (pthread_create(&thread->pthread, NULL, thread_wrapper_fn, thread))
		perror_exit("pthread_create");

	return thread;
}

void thread_stop(struct thread *thread)
{
	thread->should_stop = true;
}

bool thread_should_stop(void)
{
	return current->should_stop;
}

void thread_join(struct thread *thread)
{
	pthread_join(thread->pthread, NULL);
}

void thread_release(struct thread *thread)
{
	free(thread);
}

void thread_all_stop_join(void)
{
	struct thread *thread, *tmp;
	list_for_each_entry_safe(thread, tmp, &threads, list) {
		thread_stop(thread);
	}

	list_for_each_entry_safe(thread, tmp, &threads, list) {
		thread_join(thread);
	}
}
