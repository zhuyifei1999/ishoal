#ifndef __DARRAY_H
#define __DARRAY_H

#include <stdlib.h>

#include "ishoal.h"

/* Dynamically resizeable array via realloc, thread unsafe on resize */
#define DARRAY(type) { size_t nmemb; typeof (type) *arr; }

#define darray_nmemb(darray) ( (darray).nmemb )
#define darray_idx(darray, idx) ( &(darray).arr[idx] )

#define darray_resize(darray, new_nmemb) do {                 \
	(darray).arr = reallocarray((darray).arr, new_nmemb,  \
				    sizeof((darray).arr[0])); \
	if (new_nmemb && !(darray).arr)                       \
		perror_exit("darray_resize");                 \
	(darray).nmemb = new_nmemb;                           \
} while (0)

#define darray_inc(darray) darray_resize(darray, darray_nmemb(darray) + 1)
#define darray_dec(darray) darray_resize(darray, darray_nmemb(darray) - 1)

#define darray_head(darray) darray_idx(darray, 0)
#define darray_tail(darray) darray_idx(darray, darray_nmemb(darray) - 1)

#endif
