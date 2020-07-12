#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/xsk.h>

#include "ishoal.h"
#include "darray.h"

#define NUM_FRAMES 256
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_umem_info umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	void (*handler)(void *pkt, size_t length);
};

static int xsks_change_eventfd;
pthread_mutex_t xsks_lock;
static struct DARRAY(struct xsk_socket_info *) xsks;

__attribute__((constructor))
static void thread_init(void)
{
	pthread_mutex_init(&xsks_lock, NULL);
}

static void del_socket(void)
{
	for (int i = 0; i < darray_nmemb(xsks); i++) {
		xsk_socket__delete((*darray_idx(xsks, i))->xsk);
		xsk_umem__delete((*darray_idx(xsks, i))->umem.umem);
	}
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static void rx(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, nb_free, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, 64, &idx_rx);
	if (!rcvd)
		return;

	nb_free = xsk_prod_nb_free(&xsk->umem.fq, xsk_umem_free_frames(xsk));

	if (nb_free) {
		ret = xsk_ring_prod__reserve(&xsk->umem.fq, nb_free, &idx_fq);

		while (ret != nb_free)
			ret = xsk_ring_prod__reserve(&xsk->umem.fq, nb_free, &idx_fq);

		for (i = 0; i < nb_free; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem.fq, nb_free);
	}

	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem.buffer, addr);
		xsk->handler(pkt, len);

		xsk_free_umem_frame(xsk, addr);
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
}

static void xsk_rx_thread(void *arg)
{
	while (!thread_should_stop()) {
		uint64_t change_val;
		(void)!read(xsks_change_eventfd, &change_val, sizeof(change_val));

		pthread_mutex_lock(&xsks_lock);
		int nxsks = darray_nmemb(xsks);
		int size = nxsks + 2;

		struct pollfd fds[size];
		struct xsk_socket_info *xsks_copy[nxsks];

		memcpy(xsks_copy, darray_head(xsks), nxsks * sizeof(*xsks_copy));

		for (int i = 0; i < nxsks; i++) {
			fds[i].fd = xsk_socket__fd(xsks_copy[i]->xsk);
			fds[i].events = POLLIN;
		}

		fds[nxsks].fd = thread_stop_eventfd(current);
		fds[nxsks].events = POLLIN;

		fds[nxsks + 1].fd = xsks_change_eventfd;
		fds[nxsks + 1].events = POLLIN;
		pthread_mutex_unlock(&xsks_lock);

		int res = poll(fds, size, -1);
		if (res <= 0)
			continue;

		for (int i = 0; i < nxsks; i++)
			rx(xsks_copy[i]);
	}
}

struct xsk_socket *xsk_configure_socket(char *iface, int queue,
	void (*handler)(void *pkt, size_t length))
{
	static bool init_done;
	if (!init_done) {
		init_done = true;
		atexit(del_socket);

		xsks_change_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (xsks_change_eventfd < 0)
			perror_exit("eventfd");

		thread_start(xsk_rx_thread, NULL, "xsk_rx");
	}

	struct xsk_socket_info *xsk = calloc(1, sizeof(*xsk));

	size_t bufs_size = NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE;

	xsk->handler = handler;

	xsk->umem.buffer = mmap(NULL, bufs_size,
			  PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (xsk->umem.buffer == MAP_FAILED)
		perror_exit("mmap");

	if (xsk_umem__create(&xsk->umem.umem, xsk->umem.buffer, bufs_size,
	    &xsk->umem.fq, &xsk->umem.cq, NULL))
		perror_exit("xsk_umem__create");

	uint32_t idx;

	for (int i = 0; i < NUM_FRAMES; i++)
		xsk->umem_frame_addr[i] = i * XSK_UMEM__DEFAULT_FRAME_SIZE;

	xsk->umem_frame_free = NUM_FRAMES;

	if (xsk_ring_prod__reserve(&xsk->umem.fq,
				   XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx) !=
					XSK_RING_PROD__DEFAULT_NUM_DESCS)
		perror_exit("xsk_ring_prod__reserve");
	for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx++) =
			xsk_alloc_umem_frame(xsk);
	xsk_ring_prod__submit(&xsk->umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
	};

	if (xsk_socket__create(&xsk->xsk, iface, queue, xsk->umem.umem,
			       &xsk->rx, NULL, &cfg)) {
		xsk_umem__delete(xsk->umem.umem);
		free(xsk);
		return NULL;
	}

	pthread_mutex_lock(&xsks_lock);
	darray_inc(xsks);
	*darray_tail(xsks) = xsk;
	pthread_mutex_unlock(&xsks_lock);

	uint64_t event_data = 1;
	if (write(xsks_change_eventfd, &event_data, sizeof(event_data)) !=
	    sizeof(event_data))
		perror_exit("write(eventfd)");

	return xsk->xsk;
}
