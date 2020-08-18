#include "features.h"

#define UNW_LOCAL_ONLY

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <urcu.h>

#include "ishoal.h"
#include "darray.h"

#define MAGIC 0xDEADBEEF

static void *trampoline;
static size_t trampoline_len;
static size_t trampoline_func_offset;
static size_t trampoline_magic_offset;

static size_t trampoline_code_off;
static size_t trampoline_code_len;
static size_t trampoline_data_off;
static size_t trampoline_data_len;

static struct DARRAY_RCU(void *) trampolines;
static pthread_mutex_t trampolines_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *offset_start, *offset_stop;

__attribute__ ((section("free_rcu_trampoline_data"), used))
static void (*free_ptr)(void *ptr) = free;

__attribute__ ((section("free_rcu_trampoline"), used, noinline, noclone, optimize(0)))
static void free_rcu_trampoline_fn(struct rcu_head *rcu)
{
	volatile uint32_t offset;

lbl_offset_start:
	offset = MAGIC;
lbl_offset_stop:

	if (caa_likely(offset != MAGIC))
		free_ptr((void *)rcu - offset);
	else {
		offset_start = &&lbl_offset_start;
		offset_stop = &&lbl_offset_stop;
	}
}

void *free_rcu_get_cb(size_t offset)
{
	void *res;

	rcu_read_lock();

	if (caa_unlikely(darray_nmemb_rcu(trampolines) <= offset)) {
		pthread_mutex_lock(&trampolines_mutex);
		goto resize;
	}

	res = uatomic_read(darray_idx_rcu(trampolines, offset));
	if (caa_unlikely(!res)) {
		pthread_mutex_lock(&trampolines_mutex);
		goto fill;
	}

	goto out;

resize:;
	if (darray_nmemb_rcu(trampolines) <= offset)
		darray_resize_rcu(trampolines, offset + 1);

fill:
	res = *darray_idx_rcu(trampolines, offset);
	if (!res) {
		void *page = mmap(NULL, trampoline_len, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (page == MAP_FAILED)
			perror_exit("mmap");

		memcpy(page + trampoline_code_off, trampoline + trampoline_code_off,
		       trampoline_code_len);
		memcpy(page + trampoline_data_off, trampoline + trampoline_data_off,
		       trampoline_data_len);
		*(uint32_t *)(page + trampoline_magic_offset) = offset;

		if (mprotect(page, trampoline_len, PROT_READ))
			perror_exit("mprotect");

		if (mprotect(page + trampoline_code_off, trampoline_code_len,
			     PROT_READ | PROT_EXEC))
			perror_exit("mprotect");

		res = page + trampoline_func_offset;

		cmm_wmb();
		uatomic_set(darray_idx_rcu(trampolines, offset), res);
	}

	pthread_mutex_unlock(&trampolines_mutex);

out:
	rcu_read_unlock();

	return res;
}

void free_rcu_init(void)
{
	free_rcu_trampoline_fn((void *)MAGIC);

	extern void *__start_free_rcu_trampoline;
	extern void *__stop_free_rcu_trampoline;

	extern void *__start_free_rcu_trampoline_data;
	extern void *__stop_free_rcu_trampoline_data;

	void *trampoline_start = caa_min(&__start_free_rcu_trampoline,
		&__start_free_rcu_trampoline_data);
	void *trampoline_stop = caa_max(&__stop_free_rcu_trampoline,
		&__stop_free_rcu_trampoline_data);

	assert(trampoline_start <= (void *)&free_rcu_trampoline_fn);
	assert((void *)&free_rcu_trampoline_fn < offset_start);
	assert(offset_start < offset_stop);
	assert(offset_stop < trampoline_stop);

	trampoline = trampoline_start;
	trampoline_len = trampoline_stop - trampoline;

	trampoline_code_off =
		(void *)&__start_free_rcu_trampoline - trampoline_start;
	trampoline_code_len =
		(void *)&__stop_free_rcu_trampoline - (void *)&__start_free_rcu_trampoline;
	trampoline_data_off =
		(void *)&__start_free_rcu_trampoline_data - trampoline_start;
	trampoline_data_len =
		(void *)&__stop_free_rcu_trampoline_data - (void *)&__start_free_rcu_trampoline_data;

	uint32_t magic = MAGIC;

	void *magic_ptr =
		memmem(offset_start, offset_stop - offset_start,
		       &magic, sizeof(magic));

	assert(magic_ptr);
	assert(!memmem(magic_ptr + 1, offset_stop - magic_ptr - 1,
		       &magic, sizeof(magic)));

	trampoline_magic_offset = (void *)&free_rcu_trampoline_fn - trampoline;
	trampoline_magic_offset = magic_ptr - trampoline;

	// Test this against a few cases
	{
		struct { struct rcu_head rcu; } *test = malloc(sizeof(*test));
		if (!test)
			perror_exit("malloc");

		free_rcu(test, rcu);
	}
	{
		struct { char a[10]; struct rcu_head rcu; } *test = malloc(sizeof(*test));
		if (!test)
			perror_exit("malloc");

		free_rcu(test, rcu);
	}
	{
		struct { struct rcu_head rcu; char a[10]; } *test = malloc(sizeof(*test));
		if (!test)
			perror_exit("malloc");

		free_rcu(test, rcu);
	}
}
