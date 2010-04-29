#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <libconfig/cish_defines.h>
#include <libconfig/debug.h>
#include <libconfig/error.h>

#include "cish_config.h"

cish_config *cish_cfg;

int set_default_cfg(void)
{
	FILE *f;
	cish_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	f = fopen(CISH_CFG_FILE, "wb");
	if (!f) {
		pr_error(1, "Can't write configuration");
		return (-1);
	}
	fwrite(&cfg, sizeof(cish_config), 1, f);
	fclose(f);
	return 0;
}

int check_cfg(void)
{
	struct stat st;

	if (stat(CISH_CFG_FILE, &st))
		return set_default_cfg();
	return 0;
}

int mmap_cfg(void)
{
	int fd;

	check_cfg();

	if ((fd = open(CISH_CFG_FILE, O_RDWR)) < 0) {
		pr_error(1, "Could not open configuration");
		_exit(1);
	}
	cish_cfg = mmap(NULL, sizeof(cish_config), PROT_READ | PROT_WRITE,
	                MAP_SHARED, fd, 0);
	if (cish_cfg == ((void *) -1)) {
		pr_error(1, "Could not open configuration");
		_exit(1);
	}
	close(fd);

	recover_debug_all(); /* debug persistent */
	return 0;
}

int munmap_cfg(void)
{
	return (munmap(cish_cfg, sizeof(cish_config)) < 0);
}

