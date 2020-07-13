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

static void rx(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, 64, &idx_rx);
	if (!rcvd)
		return;

	ret = xsk_ring_prod__reserve(&xsk->umem.fq, rcvd, &idx_fq);
	while (ret != rcvd)
		ret = xsk_ring_prod__reserve(&xsk->umem.fq, rcvd, &idx_fq);

	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		uint64_t orig = xsk_umem__extract_addr(addr);

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem.buffer, addr);
		xsk->handler(pkt, len);

		*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx_fq++) = orig;
	}

	xsk_ring_prod__submit(&xsk->umem.fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
}

static void xsk_rx_thread(void *arg)
{
	while (!thread_should_stop(current)) {
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

	struct xsk_umem_config umem_cfg = {
		.fill_size = NUM_FRAMES * 2,
		.comp_size = NUM_FRAMES * 2,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	};
	if (xsk_umem__create(&xsk->umem.umem, xsk->umem.buffer, bufs_size,
	    &xsk->umem.fq, &xsk->umem.cq, &umem_cfg))
		perror_exit("xsk_umem__create");

	uint32_t idx;

	if (xsk_ring_prod__reserve(&xsk->umem.fq,
				   NUM_FRAMES, &idx) !=
					NUM_FRAMES)
		perror_exit("xsk_ring_prod__reserve");
	for (int i = 0; i < NUM_FRAMES; i++)
		*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx++) =
			i * XSK_UMEM__DEFAULT_FRAME_SIZE;
	xsk_ring_prod__submit(&xsk->umem.fq, NUM_FRAMES);

	struct xsk_socket_config xsk_cfg = {
		.rx_size = NUM_FRAMES,
		.tx_size = NUM_FRAMES,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
	};
	if (xsk_socket__create(&xsk->xsk, iface, queue, xsk->umem.umem,
			       &xsk->rx, NULL, &xsk_cfg)) {
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
