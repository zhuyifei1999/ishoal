#include <assert.h>
#include <poll.h>
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

static struct DARRAY(struct xsk_socket_info *) xsks;

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
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, 64, &idx_rx);
	if (!rcvd)
		return;

	stock_frames = xsk_prod_nb_free(&xsk->umem.fq, xsk_umem_free_frames(xsk));

	if (stock_frames) {
		ret = xsk_ring_prod__reserve(&xsk->umem.fq, stock_frames, &idx_fq);

		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem.fq, stock_frames, &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem.fq, stock_frames);
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

void poller_thread_fn(void *arg)
{
	size_t last_size = 0;
	struct DARRAY(struct pollfd) fds = {0};

	while (!thread_should_stop()) {
		int size = darray_nmemb(xsks);

		if (size != last_size) {
			last_size = size;
			darray_resize(fds, size);
		}

		for (int i = 0; i < size; i++) {
			darray_idx(fds, i)->fd =
				xsk_socket__fd((*darray_idx(xsks, i))->xsk);
			darray_idx(fds, i)->events = POLLIN;
		}

		if (!size) {
			usleep(500 * 1000);
			continue;
		}

		int res = poll(darray_head(fds), size, 500);
		if (res <= 0)
			continue;

		for (int i = 0; i < size; i++)
			rx(*darray_idx(xsks, i));
	}
}

struct xsk_socket *xsk_configure_socket(char *iface, int queue,
	void (*handler)(void *pkt, size_t length))
{
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

	darray_inc(xsks);
	*darray_tail(xsks) = xsk;

	static bool init_done;
	if (!init_done) {
		init_done = true;
		atexit(del_socket);

		thread_start(poller_thread_fn, NULL);
	}

	return xsk->xsk;
}
