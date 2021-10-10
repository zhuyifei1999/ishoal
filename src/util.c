#include "features.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ishoal.h"

char *read_whole_file(const char *path, size_t *nbytes)
{
	FILE *f = fopen(path, "r");
	if (!f)
		crash_with_perror(path);

	char *buf = NULL;
	size_t buf_size = 0;
	ssize_t read_size = 0;
	while (true) {
		if (read_size + 1024 > buf_size) {
			buf_size += 1024;
			buf = realloc(buf, buf_size);
			if (!buf)
				crash_with_perror("realloc");
		}
		size_t read_bytes = fread(buf + read_size, 1, 1024, f);
		if (read_bytes) {
			read_size += read_bytes;
			continue;
		}

		if (feof(f))
			break;

		perror("fread");
		exit(1);
	}

	buf = realloc(buf, read_size + 1);
	if (!buf)
		crash_with_perror("realloc");

	buf[read_size] = 0;
	fclose(f);

	if (nbytes)
		*nbytes = read_size;

	return buf;
}

void hex_dump(const void *ptr, size_t length)
{
	const unsigned char *address = ptr;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	int i = 0;

	printf("length = %zu\n", length);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
		}
	}
	printf("\n");
}

void fork_tee(void)
{
	// May be called by crash handler. Async signal safe functions only.
	static atomic_flag tee_forked = ATOMIC_FLAG_INIT;
	if (atomic_flag_test_and_set(&tee_forked))
		return;

	int error_log_fd;
	int orig_stderr_fd;
	int log_pipe_fds[2];

	// Best effort logging. If it fails we don't care.
	error_log_fd = open("/var/log/ishoal-error.log",
			    O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0400);
	if (error_log_fd < 0)
		return;

	orig_stderr_fd = dup(STDERR_FILENO);
	if (orig_stderr_fd < 0)
		return;

	if (pipe2(log_pipe_fds, O_CLOEXEC) < 0)
		return;

	// tee is forked instead of clones to avoid us dying killing the tee
	// while is still has content to print.
	pid_t tee_child = fork();
	if (tee_child < 0)
		return;
	if (tee_child) {
		// parent
		dup2(log_pipe_fds[1], STDERR_FILENO);
	} else {
		// child, tee log_pipe_fds[0] -> error_log_fd & orig_stderr_fd
		close(log_pipe_fds[1]);

		while (true) {
			char buf[4096];
			char *c_buf;
			ssize_t n_read = read(log_pipe_fds[0], buf, sizeof(buf));

			if (n_read <= 0)
				_exit(0);

			ssize_t n_read_copy = n_read;

			c_buf = buf;
			while (n_read) {
				ssize_t n_write = write(error_log_fd, c_buf, n_read);

				if (n_write < 0)
					_exit(0);

				n_read -= n_write;
				c_buf += n_write;
			}

			n_read = n_read_copy;

			c_buf = buf;
			while (n_read) {
				ssize_t n_write = write(orig_stderr_fd, c_buf, n_read);

				if (n_write < 0)
					_exit(0);

				n_read -= n_write;
				c_buf += n_write;
			}
		}
	}
}
