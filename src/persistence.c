#include "features.h"

#include <libgen.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wordexp.h>

#include "ishoal.h"

struct ishoal_conf_v1 {
	uint32_t version;
	ipaddr_t fake_gateway_ip;
} __attribute__((packed));

static char *CONF_PATH;

__attribute__((constructor))
static void init_conf_path(void)
{
	wordexp_t p;
	if (wordexp("~/.config/isolo.conf", &p, 0))
		perror_exit("wordexp");

	CONF_PATH = strdup(p.we_wordv[0]);
	if (!CONF_PATH)
		perror_exit("strdup");

	wordfree(&p);
}

// https://stackoverflow.com/a/2336245/13673228
static bool ensure_dir_exists(void)
{
	char tmp[PATH_MAX];
	char *dir;
	char *p = NULL;
	size_t len;

	snprintf(tmp, PATH_MAX, "%s", CONF_PATH);
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

void save_conf(void)
{
	if (!ensure_dir_exists())
		return;

	struct ishoal_conf_v1 conf = {
		.version = 1,
		.fake_gateway_ip = fake_gateway_ip,
	};


	FILE *f = fopen(CONF_PATH, "w");
	if (!f)
		return;

	fwrite(&conf, sizeof(conf), 1, f);
	fclose(f);
}

void load_conf(void)
{
	atexit(save_conf);

	if (access(CONF_PATH, R_OK))
		return;

	size_t nbytes;
	void *buf = read_whole_file(CONF_PATH, &nbytes);
	uint32_t version;

	if (nbytes < sizeof(uint32_t))
		return;

	version = *(uint32_t *)buf;

	if (version == 1) {
		if (nbytes != sizeof(struct ishoal_conf_v1))
			return;

		struct ishoal_conf_v1 *conf = buf;
		fake_gateway_ip = conf->fake_gateway_ip;
	}
}
