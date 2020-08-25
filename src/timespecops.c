#include "features.h"

#include <time.h>

#include "ishoal.h"

#define SECOND_NS 1000000000ULL

int timespec_cmp(const struct timespec *x, const struct timespec *y)
{
	return x->tv_sec - y->tv_sec ? : x->tv_nsec - y->tv_nsec;
}

void timespec_add(struct timespec *x, const struct timespec *y)
{
	x->tv_sec += y->tv_sec;
	x->tv_nsec += y->tv_nsec;

	if (x->tv_nsec >= SECOND_NS) {
		x->tv_sec++;
		x->tv_nsec -= SECOND_NS;
	}
}

void timespec_sub(struct timespec *x, const struct timespec *y)
{
	if (x->tv_nsec < y->tv_nsec) {
		x->tv_sec--;
		x->tv_nsec += SECOND_NS;
	}

	x->tv_sec -= y->tv_sec;
	x->tv_nsec -= y->tv_nsec;
}
