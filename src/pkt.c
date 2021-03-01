#include "features.h"

#include <assert.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <urcu.h>

struct xdpemu_env {
	void *data;
	void *data_end;
	bool using_scratch;
	char scratch[2048];
};

typedef struct xdpemu_env context_t;
#define DATA(ctx) (ctx->data)
#define DATA_END(ctx) (ctx->data_end)

#define HEADROOM 512
static void copy_to_scratch(struct xdpemu_env *env)
{
	size_t len = env->data_end - env->data;

	assert(len <= sizeof(env->scratch) - HEADROOM);
	memcpy(env->scratch + HEADROOM,
	       env->data,
	       len);

	env->data = env->scratch + HEADROOM;
	env->data_end = env->scratch + HEADROOM + len;

	env->using_scratch = true;
}
#undef HEADROOM

static int bpf_xdp_adjust_head(struct xdpemu_env *xdp_md, int delta)
{
	struct xdpemu_env *env = (void *)xdp_md;

	if (!env->using_scratch)
		copy_to_scratch(env);

	void *data_start = env->scratch;
	void *data = env->data + delta;

	if (caa_unlikely(data < data_start ||
		     data > env->data_end - ETH_HLEN))
		return -EINVAL;

	if (delta < 0)
		memset(data, 0, -delta);

	env->data = data;

	return 0;
}

static int bpf_xdp_adjust_tail(struct xdpemu_env *xdp_md, int delta)
{
	struct xdpemu_env *env = (void *)xdp_md;

	if (!env->using_scratch)
		copy_to_scratch(env);

	void *data_hard_end = env->scratch + sizeof(env->scratch);
	void *data_end = env->data_end + delta;

	if (caa_unlikely(data_end > data_hard_end))
		return -EINVAL;

	if (caa_unlikely(data_end < env->data + ETH_HLEN))
		return -EINVAL;

	if (delta > 0)
		memset(env->data_end, 0, delta);

	env->data_end = data_end;

	return 0;
}

#include "pkt.impl.h"

void xdpemu(void *pkt, size_t length)
{
	struct xdpemu_env env = {
		.data = pkt,
		.data_end = pkt + length,
	};
	int res = xdp_prog(&env);

	switch (res) {
	case XDP_DROP:
		break;
	case XDP_TX:
		tx(env.data, env.data_end - env.data);
		break;
	default:
		assert(false);
	}
}
