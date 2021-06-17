#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

// somewhat adapted from https://github.com/libarchive/libarchive/blob/master/contrib/untar.c

__attribute__ ((format(printf, 1, 2)))
static void fprintf_exit(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static void perror_exit(char *msg)
{
	perror(msg);
	exit(1);
}

/* Parse an octal number, ignoring leading and trailing nonsense. */
static long parseoct(const char *p, size_t n)
{
	long i = 0;

	while ((*p < '0' || *p > '7') && n > 0) {
		++p;
		--n;
	}
	while (*p >= '0' && *p <= '7' && n > 0) {
		i *= 8;
		i += *p - '0';
		++p;
		--n;
	}
	return i;
}

/* Returns true if this is 512 zero bytes. */
static bool is_end_of_archive(const char *p)
{
	int n;
	for (n = 511; n >= 0; --n)
		if (p[n] != '\0')
			return false;
	return true;
}

// https://stackoverflow.com/a/2336245/13673228
static bool ensure_dir_exists(char *path)
{
	char tmp[PATH_MAX];
	char *dir;
	char *p = NULL;
	size_t len;

	snprintf(tmp, PATH_MAX, "%s", path);
	dir = dirname(tmp);
	len = strlen(dir);
	if (dir[len - 1] == '/')
		dir[len - 1] = 0;
	for (p = dir + 1; *p; p++)
		if (*p == '/') {
			*p = 0;
			if (access(dir, F_OK)) {
				if (mkdir(dir, 0755))
					return false;
			}
			*p = '/';
		}
	if (access(dir, F_OK)) {
		if (mkdir(dir, 0755))
			return false;
	}

	return true;
}

static int verify_checksum(const char *p)
{
	int n, u = 0;
	for (n = 0; n < 512; ++n) {
		if (n < 148 || n > 155)
			/* Standard tar checksum adds unsigned bytes. */
			u += ((unsigned char *)p)[n];
		else
			u += 0x20;

	}
	return (u == parseoct(p + 148, 8));
}

static void spin(char *msg)
{
	static char *last_msg;
	static int counter, index;

	if (msg != last_msg)
		counter = 0;

	if (!counter) {
		printf("\r%s %c", msg, "\\|/-"[index]);
		fflush(stdout);
		index = (index + 1) % 4;
	}

	counter = (counter + 1) % 16;
}

struct ustar_metadata {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char checksum[8];
	char type;
	char link_target[100];
	char ustar_indicator[6];
	char ustar_version[2];
	char owner_user[32];
	char owner_group[32];
	char dev_major[8];
	char dev_minor[8];
	char filename_prefix[155];
};

int main(int argc, char *argv[])
{
	if (chdir("/"))
		perror_exit("chdir");

	struct stat root_stat, boot_stat;

	if (stat("/", &root_stat))
		perror_exit("/");
	if (stat("/boot", &boot_stat))
		perror_exit("/boot");

	FILE *filelist = fopen("/root/ishoal-filelist", "r");
	if (!filelist)
		perror_exit("/root/ishoal-filelist");

	gzFile update_tgz = gzopen("/tmp/ishoal-update.tgz", "r");
	if (!update_tgz)
		perror_exit("/tmp/ishoal-update.tgz");

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	while ((read = getline(&line, &len, filelist)) != -1) {
		size_t linelen = strlen(line);
		if (linelen && line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		struct stat this_stat;

		if (lstat(line, &this_stat)) {
			if (errno == ENOENT)
				continue;
			perror_exit(line);
		}

		if (this_stat.st_dev != root_stat.st_dev &&
		    this_stat.st_dev != boot_stat.st_dev)
			continue;

		spin("Deleting current install...");

		if (S_ISDIR(this_stat.st_mode))
			rmdir(line);
		else
			unlink(line);
	}
	printf("\n");

	fclose(filelist);
	if (line)
		free(line);

	bool long_name = false;
	bool long_linkname = false;

	char link_target[512];
	char filename[512];
	char buff[512];
	FILE *f = NULL;
	size_t bytes_read;

	while (true) {
		spin("Unpacking new install...");

next:
		bytes_read = gzread(update_tgz, buff, 512);
		if (bytes_read < 512)
			fprintf_exit("Short read: expected 512, got %zd\n",
				     bytes_read);
		if (is_end_of_archive(buff))
			break;
		if (!verify_checksum(buff))
			fprintf_exit("Checksum failure\n");

		struct ustar_metadata *metadata = (void *)buff;

		int filesize = parseoct(metadata->size, 12);
		int mode = parseoct(metadata->mode, 8);
		int dev = makedev(parseoct(metadata->dev_major, 8),
				  parseoct(metadata->dev_minor, 8));
		time_t mtime = parseoct(metadata->mtime, 12);

		char type = metadata->type;

		if (!long_name)
			strncpy(filename, metadata->name, 512);
		if (!long_linkname)
			strncpy(link_target, metadata->link_target, 512);

		for (int attempt = 0; attempt < 2; attempt++) {
			switch (type) {
			case '0':
				if (mknod(filename, mode | S_IFREG, dev))
					goto err;

				f = fopen(filename, "wb+");
				if (!f)
					perror_exit(filename);

				break;
			case '1':
				if (link(link_target, filename))
					goto err;

				filesize = 0;
				break;
			case '2':
				if (symlink(link_target, filename))
					goto err;

				filesize = 0;
				break;
			case '3':
				if (mknod(filename, mode | S_IFCHR, dev))
					goto err;

				filesize = 0;
				break;
			case '4':
				if (mknod(filename, mode | S_IFBLK, dev))
					goto err;

				filesize = 0;
				break;
			case '5':
				if (filename[strlen(filename) - 1] == '/')
					filename[strlen(filename) - 1] = '\0';

				if (mkdir(filename, mode) && errno != EEXIST)
					goto err;

				filesize = 0;
				break;
			case '6':
				if (mknod(filename, mode | S_IFIFO, dev))
					goto err;

				filesize = 0;
				break;
			case 'L':
			case 'K':
				if (filesize >= 512)
					fprintf_exit("Filename too long\n");

				bytes_read = gzread(update_tgz, buff, 512);
				if (bytes_read < 512)
					fprintf_exit("Short read: expected 512, got %zd\n",
						     bytes_read);

				if (type == 'L') {
					strncpy(filename, buff, 512);
					long_name = true;
				} else if (type == 'K') {
					strncpy(link_target, buff, 512);
					long_linkname = true;
				} else
					assert(false);

				goto next;
			default:
				fprintf_exit("%s: Unsupported type: %c\n",
					     filename, type);
			}

			long_name = long_linkname = false;
			break;
err:
			if (attempt)
				perror_exit(filename);

			if (errno == ENOENT)
				ensure_dir_exists(filename);
			else if (errno == EEXIST)
				unlink(filename);
		}

		while (filesize > 0) {
			bytes_read = gzread(update_tgz, buff, 512);
			if (bytes_read < 512)
				fprintf_exit("Short read: expected 512, got %zd\n",
					     bytes_read);
			if (filesize < 512)
				bytes_read = filesize;

			if (f) {
				if (fwrite(buff, 1, bytes_read, f) != bytes_read)
					perror_exit("fwrite");
			}

			filesize -= bytes_read;
		}

		if (f) {
			fclose(f);
			f = NULL;
		}

		struct timeval times[2] = {
			{ .tv_sec = time(NULL) },
			{ .tv_sec = mtime },
		};
		lutimes(filename, times);
	}

	printf("\n");
}
