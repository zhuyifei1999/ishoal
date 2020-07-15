#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "ishoal.h"

__attribute__ ((format(printf, 1, 2)))
void fprintf_exit(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

void perror_exit(char *msg)
{
	perror(msg);
	exit(1);
}

char *read_whole_file(char *path, size_t *nbytes)
{
	FILE *f = fopen(path, "r");
	if (!f)
		perror_exit(path);

	char *buf = NULL;
	size_t buf_size = 0;
	ssize_t read_size = 0;
	while (true) {
		if (read_size + 1024 > buf_size) {
			buf_size += 1024;
			buf = realloc(buf, buf_size);
			if (!buf)
				perror_exit("realloc");
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
		perror_exit("realloc");

	buf[read_size] = 0;
	fclose(f);

	if (nbytes)
		*nbytes = read_size;

	return buf;
}

void hex_dump(void *ptr, size_t length)
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
