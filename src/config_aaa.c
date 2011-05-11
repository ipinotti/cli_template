#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h> /* fstat */

#include "commands.h"
#include "commandtree.h"

#include "cish_main.h"
#include "pprintf.h"

struct pam_types_t {
	char cish_name[32];
	char conf_filename[64];
} pam_types[] = {
		{ "cli", FILE_PAM_GENERIC },
		{ "ppp", FILE_PAM_PPP },
		{ "web", FILE_PAM_WEB },
		{ "enable", FILE_PAM_ENABLE }
};

#define PAM_TYPES_SIZE 	sizeof(pam_types)/sizeof(struct pam_types_t)

/**
 * 	get_pam_filename
 *
 * 	Check for pam configuration file depending on type of service,
 * 	e.g. login, web, etc.
 *
 * 	@param cish_string
 * 	@return
 */
static char *get_pam_filename(char *cish_string)
{
	int i;

	for (i = 0; i < PAM_TYPES_SIZE; i++) {
		if (!strcmp(cish_string, pam_types[i].cish_name))
			return (char *) pam_types[i].conf_filename;
	}

	return NULL;
}

/**
 * 	cmd_aaa_authen
 *	e.g. [no] aaa authentication [login|web] [group|local|none] [radius|tacacs] [local]
 *
 * 	Configure authentication editing the PAM
 * 	configuration files
 *
 * 	@param cmd
 */
void cmd_aaa_authen(const char *cmd)
{
	int exec_line_args_len;
	arg_list exec_line_args = NULL;
	FILE *server;
	struct stat buf;
	char *filename = NULL;
	char *service;
	int no = 0, none = 0;

	exec_line_args_len = librouter_parse_args_din((char *) cmd, &exec_line_args);

	if (exec_line_args_len < 5) {
		librouter_destroy_args_din(&exec_line_args);
		return;
	}

	if (!strcmp(exec_line_args[0], "no"))
		no = 1;
	else if (!strcmp(exec_line_args[4], "none"))
		none = 1;

	service = no ? exec_line_args[3] : exec_line_args[2] ;

	filename = get_pam_filename(service);

	if (filename == NULL) {
		printf("%% Authentication file for %s not found ....\n", service);
		return;
	}

	if (no || none) {
		if (!librouter_pam_config_mode(AAA_AUTH_NONE, filename)) {
			printf("%% Not possible to execute command with success\n");
			librouter_destroy_args_din(&exec_line_args);
			return;
		}
	} else if (!strcmp(exec_line_args[4], "local")) {
		if (!librouter_pam_config_mode(AAA_AUTH_LOCAL, filename)) {
			printf("%% Not possible to execute command with success\n");
			librouter_destroy_args_din(&exec_line_args);
			return;
		}
	} else if (!strcmp(exec_line_args[5], "radius")) {
		if (!(server = fopen(FILE_RADDB_SERVER, "r"))) {
			printf("%% Please configure server first\n");
			return;
		}
		fstat(fileno(server), &buf);
		if (!buf.st_size) { /* File exists but it is empty */
			printf("%% Please configure server first\n");
			return;
		}
		fclose(server);

		if (!librouter_pam_config_mode(
		                (exec_line_args_len == 7 ? AAA_AUTH_RADIUS_LOCAL : AAA_AUTH_RADIUS),
		                filename)) {
			printf("%% Not possible to execute command with success\n");
			librouter_destroy_args_din(&exec_line_args);
			return;
		}

	} else if (!strcmp(exec_line_args[5], "tacacs+")) {
		if (!(server = fopen(FILE_TACDB_SERVER, "r"))) {
			printf("%% Please configure server first\n");
			return;
		}
		fstat(fileno(server), &buf);
		if (!buf.st_size) { /* File exists but it is empty */
			printf("%% Please configure server first\n");
			return;
		}
		fclose(server);

		if (!librouter_pam_config_mode(
		                (exec_line_args_len == 7 ? AAA_AUTH_TACACS_LOCAL : AAA_AUTH_TACACS),
		                filename)) {
			printf("%% Not possible to execute command with success\n");
			librouter_destroy_args_din(&exec_line_args);
			return;
		}
	}
}

/* [no] aaa accounting exec default start-stop group tacacs+ */
/* [no] aaa accounting commands [1-15] default start-stop group tacacs+ */
void cmd_aaa_acct(const char *cmd)
{
	int exec_line_args_len;
	arg_list exec_line_args = NULL;
	FILE *server;
	struct stat buf;

	if ((exec_line_args_len = librouter_parse_args_din((char *) cmd, &exec_line_args))) {
		/* [no] aaa accounting exec */
		if (exec_line_args_len < 5) {
			librouter_destroy_args_din(&exec_line_args);
			return;
		}
		if (!strcmp(exec_line_args[0], "no") || !strcmp(exec_line_args[4], "none")) {
			if (!librouter_pam_config_mode(AAA_ACCT_NONE, FILE_PAM_GENERIC)) {
				printf("%% Not possible to execute command with success\n");
				librouter_destroy_args_din(&exec_line_args);
				return;
			}
		} else if (!strcmp(exec_line_args[2], "exec")) {
			if (!(server = fopen(FILE_TACDB_SERVER, "r"))) {
				printf("%% Please configure server first\n");
				return;
			}
			fstat(fileno(server), &buf);
			if (!buf.st_size) { /* File exists but it is empty */
				printf("%% Please configure server first\n");
				return;
			}
			fclose(server);
			if (!librouter_pam_config_mode(AAA_ACCT_TACACS, FILE_PAM_GENERIC)) {
				printf("%% Not possible to execute command with success\n");
				librouter_destroy_args_din(&exec_line_args);
				return;
			}
		}

		/* [no] aaa accounting commands */
		if (exec_line_args_len < 6) {
			librouter_destroy_args_din(&exec_line_args);
			return;
		}
		if (!strcmp(exec_line_args[0], "no")) {
			if (!strcmp(exec_line_args[4], "1")) {
				if (!librouter_pam_config_mode(AAA_ACCT_TACACS_NO_CMD_1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					librouter_destroy_args_din(&exec_line_args);
					return;
				}
			} else if (!strcmp(exec_line_args[4], "15")) {
				if (!librouter_pam_config_mode(AAA_ACCT_TACACS_NO_CMD_15,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					librouter_destroy_args_din(&exec_line_args);
					return;
				}
			}
		} else if (!strcmp(exec_line_args[5], "none")) {
			if (!strcmp(exec_line_args[3], "1")) {
				if (!librouter_pam_config_mode(AAA_ACCT_TACACS_NO_CMD_1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					librouter_destroy_args_din(&exec_line_args);
					return;
				}
			} else if (!strcmp(exec_line_args[3], "15")) {
				if (!librouter_pam_config_mode(AAA_ACCT_TACACS_NO_CMD_15,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					librouter_destroy_args_din(&exec_line_args);
					return;
				}
			}
		} else if (!strcmp(exec_line_args[2], "commands")) {
			if (!(server = fopen(FILE_TACDB_SERVER, "r"))) {
				printf("%% Please configure server first\n");
				return;
			}
			fstat(fileno(server), &buf);
			if (!buf.st_size) { /* File exists but it is empty */
				printf("%% Please configure server first\n");
				return;
			}
			fclose(server);

			if (!strcmp(exec_line_args[3], "1")) {
				if (!librouter_pam_config_mode(AAA_ACCT_TACACS_CMD_1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					librouter_destroy_args_din(&exec_line_args);
					return;
				}
			} else if (!strcmp(exec_line_args[3], "15")) {
				if (!librouter_pam_config_mode(AAA_ACCT_TACACS_CMD_15,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					librouter_destroy_args_din(&exec_line_args);
					return;
				}
			}
		}
	}
}

void cmd_aaa_author(const char *cmd)
{
	int exec_line_args_len;
	arg_list exec_line_args = NULL;
	FILE *server;
	struct stat buf;

	if ((exec_line_args_len = librouter_parse_args_din((char *) cmd, &exec_line_args))) {
		if (exec_line_args_len < 5) {
			librouter_destroy_args_din(&exec_line_args);
			return;
		}

		/* NO COMMAND */
		if (!strcmp(exec_line_args[0], "no") || !strcmp(exec_line_args[4], "none")) {
			if (!librouter_pam_config_mode(AAA_AUTHOR_NONE, FILE_PAM_GENERIC)) {
				printf("%% Not possible to execute command with success\n");
				librouter_destroy_args_din(&exec_line_args);
				return;
			}
		} else if (!strcmp(exec_line_args[4], "group")) {
			if (!strcmp(exec_line_args[5], "tacacs+")) {
				if (!(server = fopen(FILE_TACDB_SERVER, "r"))) {
					printf("%% Please configure server first\n");
					return;
				}
				fstat(fileno(server), &buf);
				if (!buf.st_size) { /* File exists but it is empty */
					printf("%% Please configure server first\n");
					return;
				}
				fclose(server);
				if (!librouter_pam_config_mode(
				                (exec_line_args_len == 7 ? AAA_AUTHOR_TACACS_LOCAL : AAA_AUTHOR_TACACS),
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					librouter_destroy_args_din(&exec_line_args);
					return;
				}
			}
		}
		librouter_destroy_args_din(&exec_line_args);
	}
}



void add_user(const char *cmd) /* aaa username <user> password [hash] <pass> *//* tinylogin */
{
	arglist *args;

	args = librouter_make_args(cmd);
	librouter_pam_add_user(args->argv[2], args->argv[4]);
	librouter_destroy_args(args);
}

void del_user(const char *cmd) /* no aaa username <user> *//* tinylogin */
{
	arglist *args;

	args = librouter_make_args(cmd);
	librouter_pam_del_user(args->argv[3]);
	librouter_destroy_args(args);
}

void add_radiusserver(const char *cmd) /* radius-server host <ipaddr> [key <secret> [timeout <1-1000>]] */
{
	arglist *args;
	struct auth_server server;
	int ret;

	memset(&server, 0, sizeof(server));

	args = librouter_make_args(cmd);

	if (args->argc < 3) {
		printf("%% Wrong number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	server.ipaddr = args->argv[2];

	if (args->argc > 3)
		server.key = args->argv[4];

	if (args->argc > 5)
		server.timeout = atoi(args->argv[6]);

	ret = librouter_pam_add_radius_server(&server);
	if (ret == -1)
		printf("%% Maximum number of servers reached!\n");
	librouter_destroy_args(args);
}

void del_radiusserver(const char *cmd) /* no radius-server [host <ipaddr>] */
{
	arglist *args;
	struct auth_server server;

	memset(&server, 0, sizeof(server));

	args = librouter_make_args(cmd);

	if (librouter_pam_get_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_RADIUS
	                || librouter_pam_get_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_RADIUS_LOCAL
	                || librouter_pam_get_current_mode(FILE_PAM_PPP) == AAA_AUTH_RADIUS
	                || librouter_pam_get_current_mode(FILE_PAM_PPP) == AAA_AUTH_RADIUS_LOCAL) {
		printf("%% please disable RADIUS authentication first\n");
		librouter_destroy_args(args);
		return;
	}

	if (args->argc == 3) {
		server.ipaddr = args->argv[3];
		librouter_pam_del_radius_server(&server);
	} else
		librouter_pam_del_radius_server(NULL); /* Delete all servers */

	librouter_destroy_args(args);
}



void add_tacacsserver(const char *cmd) /* tacacs-server host <ipaddr> key <secret> [timeout <1-1000>] */
{
	arglist *args;
	struct auth_server server;
	int ret;

	memset(&server, 0, sizeof(server));

	args = librouter_make_args(cmd);

	if (args->argc < 3) {
		printf("%% Wrong number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	server.ipaddr = args->argv[2];

	if (args->argc > 3)
		server.key = args->argv[4];

	if (args->argc > 5)
		server.timeout = atoi(args->argv[6]);

	ret = librouter_pam_add_tacacs_server(&server);
	if (ret == -1)
		printf("%% Maximum number of servers reached!\n");
	librouter_destroy_args(args);
}

void del_tacacsserver(const char *cmd) /* no tacacs-server [host <ipaddr>] */
{
	arglist *args;
	struct auth_server server;

	memset(&server, 0, sizeof(server));

	args = librouter_make_args(cmd);

	if (librouter_pam_get_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_TACACS
	                || librouter_pam_get_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_TACACS_LOCAL
	                || librouter_pam_get_current_mode(FILE_PAM_PPP) == AAA_AUTH_TACACS
	                || librouter_pam_get_current_mode(FILE_PAM_PPP) == AAA_AUTH_TACACS_LOCAL) {
		printf("%% please disable TACACS+ authentication first\n");
		librouter_destroy_args(args);
		return;
	}
	if (librouter_pam_get_current_author_mode(FILE_PAM_GENERIC) == AAA_AUTHOR_TACACS) {
		printf("%% please disable TACACS+ authorization first\n");
		librouter_destroy_args(args);
		return;
	}
	if (librouter_pam_get_current_acct_mode(FILE_PAM_GENERIC) == AAA_ACCT_TACACS) {
		printf("%% please disable TACACS+ accounting first\n");
		librouter_destroy_args(args);
		return;
	}
	if (librouter_pam_get_current_acct_cmd_mode(FILE_PAM_GENERIC) != AAA_ACCT_TACACS_CMD_NONE) {
		printf("%% please disable TACACS+ accounting first\n");
		librouter_destroy_args(args);
		return;
	}

	if (args->argc == 4) {
		server.ipaddr = args->argv[3];
		librouter_pam_del_tacacs_server(&server);
	} else
		librouter_pam_del_tacacs_server(NULL); /* Delete all servers */

	librouter_destroy_args(args);
}
