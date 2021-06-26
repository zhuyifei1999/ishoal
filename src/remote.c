#include "features.h"

#include <fcntl.h>
#include <stdio.h>

#include "ishoal.h"

int remotes_log_fd;
static FILE *remotes_log;

void start_endpoint(void)
{
	remotes_log_fd = open(".", O_TMPFILE | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (remotes_log_fd < 0)
		perror_exit("open(O_TMPFILE)");

	remotes_log = fdopen(remotes_log_fd, "a");
	if (!remotes_log)
		perror_exit("fdopen");

	setbuf(remotes_log, NULL);
}
