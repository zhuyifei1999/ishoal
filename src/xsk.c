#include "features.h"

#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/xsk.h>

#include "extern/plthook/plthook.h"

#include "ishoal.h"
#include "darray.h"

static int wrapper_socket(int domain, int type, int protocol)
{
	return socket(domain, type | SOCK_CLOEXEC, protocol);
}

struct dl_iterate_phdr_ctx {
	char libbpf_path[PATH_MAX];
};

static int
dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t size, void *_ctx)
{
	struct dl_iterate_phdr_ctx *ctx = _ctx;

	if (strstr(info->dlpi_name, "libbpf"))
		strncpy(ctx->libbpf_path, info->dlpi_name, PATH_MAX - 1);

	return 0;
}

static void monkey_patch(void)
{
	struct dl_iterate_phdr_ctx ctx = {0};
	dl_iterate_phdr(dl_iterate_phdr_cb, &ctx);

	if (!strlen(ctx.libbpf_path))
		crash_with_errormsg("failed to locate libbpf library path");

	plthook_t *plthook;

	if (plthook_open(&plthook, ctx.libbpf_path) != 0)
		crash_with_printf("plthook_open error: %s", plthook_error());

	if (plthook_replace(plthook, "socket", wrapper_socket, NULL))
		crash_with_errormsg("failed to hook libbpf");

	plthook_close(plthook);
}

/* This file is massively copied from Kernel samples/bpf/xdpsock_user.c
 * And lots of trial and error. Not much idea how it works.
 */

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

	void (*handler)(void * restrict pkt, size_t length);
};

static pthread_mutex_t xsks_lock = PTHREAD_MUTEX_INITIALIZER;
static struct DARRAY(struct xsk_socket_info *) xsks;

static void del_socket(void)
{
	for (int i = 0; i < darray_nmemb(xsks); i++) {
		xsk_socket__delete((*darray_idx(xsks, i))->xsk);
		xsk_umem__delete((*darray_idx(xsks, i))->umem.umem);
	}
}

static void rx_cb(int fd, void *ctx, bool expired)
{
	unsigned int rcvd, i;
	struct xsk_socket_info *xsk = ctx;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	assert(xsk_socket__fd(xsk->xsk) == fd);

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

static struct eventloop *xsk_rx_el;
static int xsk_rx_rpc;

struct xsk_socket *xsk_configure_socket(const char *iface, int queue,
	void (*handler)(void *pkt, size_t length))
{
	static atomic_flag init_done = ATOMIC_FLAG_INIT;
	if (!atomic_flag_test_and_set(&init_done)) {
		monkey_patch();

		atexit(del_socket);

		int xsk_rx_rpc_recv;
		make_fd_pair(&xsk_rx_rpc, &xsk_rx_rpc_recv);

		xsk_rx_el = eventloop_new();
		eventloop_install_rpc(xsk_rx_el, xsk_rx_rpc_recv);
		thread_start(eventloop_thread_fn, xsk_rx_el, "xsk_rx");
	}

	struct xsk_socket_info *xsk = calloc(1, sizeof(*xsk));

	size_t bufs_size = NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE;

	xsk->handler = handler;

	xsk->umem.buffer = mmap(NULL, bufs_size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (xsk->umem.buffer == MAP_FAILED)
		crash_with_perror("mmap");

	struct xsk_umem_config umem_cfg = {
		.fill_size = NUM_FRAMES * 2,
		.comp_size = NUM_FRAMES * 2,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	};
	if (xsk_umem__create(&xsk->umem.umem, xsk->umem.buffer, bufs_size,
	    &xsk->umem.fq, &xsk->umem.cq, &umem_cfg))
		crash_with_perror("xsk_umem__create");

	uint32_t idx;

	if (xsk_ring_prod__reserve(&xsk->umem.fq,
				   NUM_FRAMES, &idx) != NUM_FRAMES)
		crash_with_perror("xsk_ring_prod__reserve");
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

	eventloop_install_event_async(xsk_rx_el, &(struct event){
		.fd = xsk_socket__fd(xsk->xsk),
		.handler_type = EVT_CALL_FN,
		.handler_fn = rx_cb,
		.handler_ctx = xsk,
	}, xsk_rx_rpc);

	return xsk->xsk;
}
