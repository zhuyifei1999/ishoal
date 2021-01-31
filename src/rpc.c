#include "features.h"

#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "ishoal.h"

/* Inter-thread PRC */

struct pipe_data {
	int ret_send_fd;
	int (*fn)(void *ctx);
	void *ctx;
};

void make_fd_pair(int *send_fd, int *recv_fd)
{
	int pipefd[2];
	if (pipe2(pipefd, O_CLOEXEC) == -1)
		perror_exit("pipe");

	*recv_fd = pipefd[0];
	*send_fd = pipefd[1];
}

void handle_rpc(int call_recv_fd)
{
	struct pipe_data dat;

	int read_len = read(call_recv_fd, &dat, sizeof(dat));
	if (read_len < 0)
		perror_exit("read");
	assert(read_len == sizeof(dat));

	int res = dat.fn(dat.ctx);

	if (dat.ret_send_fd < 0)
		return;

	int write_len = write(dat.ret_send_fd, &res, sizeof(res));
	if (write_len < 0)
		perror_exit("write");
	assert(write_len == sizeof(res));
	close(dat.ret_send_fd);
}

int invoke_rpc_sync(int call_send_fd, int (*fn)(void *ctx), void *ctx)
{
	int ret_send_fd, ret_recv_fd;

	make_fd_pair(&ret_send_fd, &ret_recv_fd);

	struct pipe_data dat = {
		.ret_send_fd = ret_send_fd,
		.fn = fn,
		.ctx = ctx,
	};

	int write_len = write(call_send_fd, &dat, sizeof(dat));
	if (write_len < 0)
		perror_exit("write");
	assert(write_len == sizeof(dat));

	int res;

	int read_len = read(ret_recv_fd, &res, sizeof(res));
	if (read_len < 0)
		perror_exit("read");
	assert(read_len == sizeof(res));
	close(ret_recv_fd);

	return res;
}

void invoke_rpc_async(int call_send_fd, int (*fn)(void *ctx), void *ctx)
{
	struct pipe_data dat = {
		.ret_send_fd = -1,
		.fn = fn,
		.ctx = ctx,
	};

	int write_len = write(call_send_fd, &dat, sizeof(dat));
	if (write_len < 0)
		perror_exit("write");
	assert(write_len == sizeof(dat));
}
