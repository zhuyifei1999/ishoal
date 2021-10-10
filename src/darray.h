#ifndef __DARRAY_H
#define __DARRAY_H

#include <stdlib.h>

#include "ishoal.h"

/* Dynamically resizeable array via realloc, thread unsafe on resize */
#define DARRAY(type) { size_t nmemb; typeof (type) *arr; }

#define darray_nmemb(darray) ( (darray).nmemb )
#define darray_idx(darray, idx) ( &(darray).arr[idx] )

#define darray_head(darray) darray_idx(darray, 0)
#define darray_tail(darray) darray_idx(darray, darray_nmemb(darray) - 1)

#define darray_resize(darray, new_nmemb) do {                       \
	(darray).arr = reallocarray(darray_head(darray), new_nmemb, \
				    sizeof((darray).arr[0]));       \
	if ((new_nmemb) && !(darray).arr)                           \
		crash_with_perror("darray_resize");                 \
	darray_nmemb(darray) = (new_nmemb);                         \
} while (0)

#define darray_inc(darray) darray_resize(darray, darray_nmemb(darray) + 1)
#define darray_dec(darray) darray_resize(darray, darray_nmemb(darray) - 1)

#define darray_destroy(darray) free((darray).arr)



#define DARRAY_RCU(type) { size_t nmemb; struct { struct rcu_head rcu; typeof (type) arr[0]; } *aref; }

#define darray_nmemb_rcu(darray) rcu_dereference((darray).nmemb)
#define darray_idx_rcu(darray, idx) &rcu_dereference((darray).aref)->arr[idx]

#define darray_head_rcu(darray) darray_idx_rcu(darray, 0)
#define darray_tail_rcu(darray) darray_idx_rcu(darray, darray_nmemb_rcu(darray) - 1)

#define darray_resize_rcu(darray, new_nmemb) do {                                   \
	size_t newsize = (new_nmemb) * sizeof((darray).aref->arr[0]);               \
	if (newsize / sizeof((darray).aref->arr[0]) != (new_nmemb))                 \
		crash_with_errormsg("darray_resize_rcu: Overflow");                 \
	newsize += sizeof(struct rcu_head);                                         \
	typeof ((darray).aref) newaref = calloc(1, newsize);                        \
	if (newaref)                                                                \
		memcpy(newaref->arr, darray_head_rcu(darray),                       \
		       darray_nmemb_rcu(darray) * sizeof((darray).aref->arr[0]));   \
	typeof ((darray).aref) oldaref = rcu_xchg_pointer(&(darray).aref, newaref); \
	rcu_assign_pointer((darray).nmemb, new_nmemb);                              \
	free_rcu(oldaref, rcu);                                                     \
} while (0)

#define darray_inc_rcu(darray) darray_resize_rcu(darray, darray_nmemb_rcu(darray) + 1)
#define darray_dec_rcu(darray) darray_resize_rcu(darray, darray_nmemb_rcu(darray) - 1)

#define darray_destroy_rcu(darray) free((darray).aref)

#endif
