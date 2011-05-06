/*
 * config_banner.c
 *
 *  Created on: May 5, 2011
 *      Author: tgrande
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "commands.h"
#include "commandtree.h"

extern struct router_config *router_cfg;

void config_banner_login(const char *cmdline)
{
	char *banner;
	arglist *args;

	args = librouter_make_args(cmdline);

	memset(router_cfg->banner_login, 0, sizeof(router_cfg->banner_login));

	if (!strcmp(args->argv[0], "no")) {
		librouter_destroy_args(args);
		return;
	}

	librouter_destroy_args(args);
	printf("Please enter text for login banner (enter empty line when finished):\n");

	while (1) {
		banner = readline(NULL);
		if (banner == NULL) {
			/* This will happend on abort (CTRL + D) */
			memset(router_cfg->banner_login, 0, sizeof(router_cfg->banner_login));
			return;
		}
		strncat(router_cfg->banner_login, banner, sizeof(router_cfg->banner_login));
		strcat(router_cfg->banner_login, "\n");
		if (strlen(banner) == 0) {
			free(banner);
			break;
		}
		free(banner);
	}

	librouter_nv_save_banner_login(router_cfg->banner_login);

}

void config_banner_system(const char *cmdline)
{
	char *banner;
	arglist *args;

	args = librouter_make_args(cmdline);

	memset(router_cfg->banner_system, 0, sizeof(router_cfg->banner_system));

	if (!strcmp(args->argv[0], "no")) {
		librouter_destroy_args(args);
		return;
	}

	librouter_destroy_args(args);
	printf("Please enter text for system banner (enter empty line when finished):\n");

	while (1) {
		banner = readline(NULL);
		if (banner == NULL) {
			/* This will happend on abort (CTRL + D) */
			memset(router_cfg->banner_system, 0, sizeof(router_cfg->banner_system));
			return;
		}
		strncat(router_cfg->banner_system, banner, sizeof(router_cfg->banner_system));
		strcat(router_cfg->banner_system, "\n");
		if (strlen(banner) == 0) {
			free(banner);
			break;
		}
		free(banner);
	}

	librouter_nv_save_banner_system(router_cfg->banner_system);
}

void show_banner(const char *cmdline)
{
	if (router_cfg->banner_system[0] == 0) {
		printf("System banner not set\n");
		return;
	}

	printf("\n##################################################################\n");
	printf("%s" ,router_cfg->banner_system);
	printf("\n##################################################################\n");
}
