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
} pam_types[] = { { "login", FILE_PAM_GENERIC }, { "ppp", FILE_PAM_PPP }, { "web", FILE_PAM_WEB } };

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

	exec_line_args_len = parse_args_din((char *) cmd, &exec_line_args);

	if (exec_line_args_len < 5) {
		free_args_din(&exec_line_args);
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
		if (!conf_pam_mode(cish_cfg, AAA_AUTH_NONE, 1, filename)) {
			printf("%% Not possible to execute command with success\n");
			free_args_din(&exec_line_args);
			return;
		}
	} else if (!strcmp(exec_line_args[4], "local")) {
		if (!conf_pam_mode(cish_cfg, AAA_AUTH_LOCAL, 1, filename)) {
			printf("%% Not possible to execute command with success\n");
			free_args_din(&exec_line_args);
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

		if (!conf_pam_mode(
		                cish_cfg,
		                (exec_line_args_len == 7 ? AAA_AUTH_RADIUS_LOCAL : AAA_AUTH_RADIUS),
		                1, filename)) {
			printf("%% Not possible to execute command with success\n");
			free_args_din(&exec_line_args);
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

		if (!conf_pam_mode(
		                cish_cfg,
		                (exec_line_args_len == 7 ? AAA_AUTH_TACACS_LOCAL : AAA_AUTH_TACACS),
		                1, filename)) {
			printf("%% Not possible to execute command with success\n");
			free_args_din(&exec_line_args);
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

	if ((exec_line_args_len = parse_args_din((char *) cmd, &exec_line_args))) {
		/* [no] aaa accounting exec */
		if (exec_line_args_len < 5) {
			free_args_din(&exec_line_args);
			return;
		}
		if (!strcmp(exec_line_args[0], "no") || !strcmp(exec_line_args[4], "none")) {
			if (!conf_pam_mode(cish_cfg, AAA_ACCT_NONE, 1, FILE_PAM_GENERIC)) {
				printf("%% Not possible to execute command with success\n");
				free_args_din(&exec_line_args);
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
			if (!conf_pam_mode(cish_cfg, AAA_ACCT_TACACS, 1, FILE_PAM_GENERIC)) {
				printf("%% Not possible to execute command with success\n");
				free_args_din(&exec_line_args);
				return;
			}
		}

		/* [no] aaa accounting commands */
		if (exec_line_args_len < 6) {
			free_args_din(&exec_line_args);
			return;
		}
		if (!strcmp(exec_line_args[0], "no")) {
			if (!strcmp(exec_line_args[4], "1")) {
				if (!conf_pam_mode(cish_cfg, AAA_ACCT_TACACS_NO_CMD_1, 1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					free_args_din(&exec_line_args);
					return;
				}
			} else if (!strcmp(exec_line_args[4], "15")) {
				if (!conf_pam_mode(cish_cfg, AAA_ACCT_TACACS_NO_CMD_15, 1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					free_args_din(&exec_line_args);
					return;
				}
			}
		} else if (!strcmp(exec_line_args[5], "none")) {
			if (!strcmp(exec_line_args[3], "1")) {
				if (!conf_pam_mode(cish_cfg, AAA_ACCT_TACACS_NO_CMD_1, 1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					free_args_din(&exec_line_args);
					return;
				}
			} else if (!strcmp(exec_line_args[3], "15")) {
				if (!conf_pam_mode(cish_cfg, AAA_ACCT_TACACS_NO_CMD_15, 1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					free_args_din(&exec_line_args);
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
				if (!conf_pam_mode(cish_cfg, AAA_ACCT_TACACS_CMD_1, 1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					free_args_din(&exec_line_args);
					return;
				}
			} else if (!strcmp(exec_line_args[3], "15")) {
				if (!conf_pam_mode(cish_cfg, AAA_ACCT_TACACS_CMD_15, 1,
				                FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					free_args_din(&exec_line_args);
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

	if ((exec_line_args_len = parse_args_din((char *) cmd, &exec_line_args))) {
		if (exec_line_args_len < 5) {
			free_args_din(&exec_line_args);
			return;
		}

		/* NO COMMAND */
		if (!strcmp(exec_line_args[0], "no") || !strcmp(exec_line_args[4], "none")) {
			if (!conf_pam_mode(cish_cfg, AAA_AUTHOR_NONE, 1, FILE_PAM_GENERIC)) {
				printf("%% Not possible to execute command with success\n");
				free_args_din(&exec_line_args);
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
				if (!conf_pam_mode(
				                cish_cfg,
				                (exec_line_args_len == 7 ? AAA_AUTHOR_TACACS_LOCAL : AAA_AUTHOR_TACACS),
				                1, FILE_PAM_GENERIC)) {
					printf("%% Not possible to execute command with success\n");
					free_args_din(&exec_line_args);
					return;
				}
			}
		}
		free_args_din(&exec_line_args);
	}
}

const char *users[7] = { "root", "admin", "ppp", "uucp", "upload", "nobody", NULL };

void add_user(const char *cmd) /* aaa username <user> password [hash] <pass> *//* tinylogin */
{
	arglist *args;
	char buffer[256];
	int i;

	args = make_args(cmd);
	for (i = 0; users[i]; i++) {
		if (strcmp(users[i], args->argv[2]) == 0) {
			destroy_args(args);
			printf("%% Invalid user!\n");
			return;
		}
	}
	snprintf(buffer, 255, "/bin/deluser %s >/dev/null 2>/dev/null", args->argv[2]);
	system(buffer);
	if (args->argc == 6)
		snprintf(buffer, 255, "/bin/adduser %s -c '%s' >/dev/null 2>/dev/null",
		                args->argv[2], args->argv[5]);
	else
		snprintf(buffer, 255, "/bin/adduser %s -p '%s' >/dev/null 2>/dev/null",
		                args->argv[2], args->argv[4]);
	system(buffer);
	destroy_args(args);
}

void del_user(const char *cmd) /* no aaa username <user> *//* tinylogin */
{
	int i;
	arglist *args;
	char buffer[256];

	args = make_args(cmd);
	for (i = 0; users[i]; i++) {
		if (strcmp(users[i], args->argv[3]) == 0) {
			destroy_args(args);
			printf("%% Invalid user!\n");
			return;
		}
	}
	snprintf(buffer, 255, "/bin/deluser %s >/dev/null 2>/dev/null", args->argv[3]);
	system(buffer);
	destroy_args(args);
}

void add_radiusserver(const char *cmd) /* radius-server host <ipaddr> [key <secret> [timeout <1-1000>]] */
{
	int i;
	arglist *args;
	FILE *server;

	args = make_args(cmd);
	for (i = 0; i < MAX_SERVERS; i++) {
		if (cish_cfg->radius[i].ip_addr[0] == 0 || !strncmp(cish_cfg->radius[i].ip_addr,
		                args->argv[2], 16)) {
			strncpy(cish_cfg->radius[i].ip_addr, args->argv[2], 16);
			if (args->argc >= 5)
				strncpy(cish_cfg->radius[i].authkey, args->argv[4],
				                MAX_SERVER_AUTH_KEY);
			else
				strcpy(cish_cfg->radius[i].authkey, "");
			if (args->argc == 7)
				cish_cfg->radius[i].timeout = atoi(args->argv[6]);
			else
				cish_cfg->radius[i].timeout = 0;
			break;
		}
	}
	if (i == MAX_SERVERS) {
		printf("%% Maximum servers reached!\n");
		destroy_args(args);
		return;
	}
	if ((server = fopen(FILE_RADDB_SERVER, "w"))) {
		for (i = 0; i < MAX_SERVERS; i++) {
			if (cish_cfg->radius[i].ip_addr[0]) { /* server[:port] secret [timeout] */
				if (cish_cfg->radius[i].authkey[0])
					fprintf(server, "%s\t%s\t%d\n",
					                cish_cfg->radius[i].ip_addr,
					                cish_cfg->radius[i].authkey,
					                cish_cfg->radius[i].timeout);
				else
					fprintf(server, "%s\n", cish_cfg->radius[i].ip_addr);
			}
		}
		fclose(server);
	}
	destroy_args(args);
}

void del_radiusserver(const char *cmd) /* no radius-server [host <ipaddr>] */
{
	int i;
	FILE *server;
	arglist *args;

	args = make_args(cmd);

	if (discover_pam_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_RADIUS
	                || discover_pam_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_RADIUS_LOCAL
	                || discover_pam_current_mode(FILE_PAM_PPP) == AAA_AUTH_RADIUS
	                || discover_pam_current_mode(FILE_PAM_PPP) == AAA_AUTH_RADIUS_LOCAL) {
		printf("%% please disable RADIUS authentication first\n");
		destroy_args(args);
		return;
	}

	for (i = 0; i < MAX_SERVERS; i++) {
		if (args->argc == 4) {
			if (!strncmp(cish_cfg->radius[i].ip_addr, args->argv[3], 16)) {
				cish_cfg->radius[i].ip_addr[0] = 0;
				break;
			}
		} else
			cish_cfg->radius[i].ip_addr[0] = 0;
	}
	if (i == MAX_SERVERS && args->argc == 4) {
		printf("%% Server not found!\n");
		destroy_args(args);
		return;
	}
	if ((server = fopen(FILE_RADDB_SERVER, "w"))) {
		for (i = 0; i < MAX_SERVERS; i++) {
			if (cish_cfg->radius[i].ip_addr[0]) { /* server[:port] secret [timeout] */
				if (cish_cfg->radius[i].authkey[0])
					fprintf(server, "%s\t%s\t%d\n",
					                cish_cfg->radius[i].ip_addr,
					                cish_cfg->radius[i].authkey,
					                cish_cfg->radius[i].timeout);
				else
					fprintf(server, "%s\n", cish_cfg->radius[i].ip_addr);
			}
		}
		fclose(server);
	}
	destroy_args(args);
}

void add_tacacsserver(const char *cmd) /* tacacs-server host <ipaddr> key <secret> [timeout <1-1000>] */
{
	int i;
	arglist *args;
	FILE *server;

	args = make_args(cmd);
	for (i = 0; i < MAX_SERVERS; i++) {
		if (cish_cfg->tacacs[i].ip_addr[0] == 0 || !strncmp(cish_cfg->tacacs[i].ip_addr,
		                args->argv[2], 16)) {
			strncpy(cish_cfg->tacacs[i].ip_addr, args->argv[2], 16);
			if (args->argc >= 5)
				strncpy(cish_cfg->tacacs[i].authkey, args->argv[4],
				                MAX_SERVER_AUTH_KEY);
			else
				strcpy(cish_cfg->tacacs[i].authkey, "");
			if (args->argc == 7)
				cish_cfg->tacacs[i].timeout = atoi(args->argv[6]);
			else
				cish_cfg->tacacs[i].timeout = 0;
			break;
		}
	}
	if (i == MAX_SERVERS) {
		printf("%% Maximum servers reached!\n");
		destroy_args(args);
		return;
	}
	if ((server = fopen(FILE_TACDB_SERVER, "w"))) {
		for (i = 0; i < MAX_SERVERS; i++) {
			if (cish_cfg->tacacs[i].ip_addr[0]) { /* server[:port] secret [timeout] */
				if (cish_cfg->tacacs[i].authkey[0])
					fprintf(server, "%s\t%s\t%d\n",
					                cish_cfg->tacacs[i].ip_addr,
					                cish_cfg->tacacs[i].authkey,
					                cish_cfg->tacacs[i].timeout);
				else
					fprintf(server, "%s\n", cish_cfg->tacacs[i].ip_addr);
			}
		}
		fclose(server);
	}
	destroy_args(args);
}

void del_tacacsserver(const char *cmd) /* no tacacs-server [host <ipaddr>] */
{
	int i;
	FILE *server;
	arglist *args;

	args = make_args(cmd);

	if (discover_pam_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_TACACS
	                || discover_pam_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_TACACS_LOCAL
	                || discover_pam_current_mode(FILE_PAM_PPP) == AAA_AUTH_TACACS
	                || discover_pam_current_mode(FILE_PAM_PPP) == AAA_AUTH_TACACS_LOCAL) {
		printf("%% please disable TACACS+ authentication first\n");
		destroy_args(args);
		return;
	}
	if (discover_pam_current_author_mode(FILE_PAM_GENERIC) == AAA_AUTHOR_TACACS) {
		printf("%% please disable TACACS+ authorization first\n");
		destroy_args(args);
		return;
	}
	if (discover_pam_current_acct_mode(FILE_PAM_GENERIC) == AAA_ACCT_TACACS) {
		printf("%% please disable TACACS+ accounting first\n");
		destroy_args(args);
		return;
	}
	if (discover_pam_current_acct_command_mode(FILE_PAM_GENERIC) != AAA_ACCT_TACACS_CMD_NONE) {
		printf("%% please disable TACACS+ accounting first\n");
		destroy_args(args);
		return;
	}

	for (i = 0; i < MAX_SERVERS; i++) {
		if (args->argc == 4) {
			if (!strncmp(cish_cfg->tacacs[i].ip_addr, args->argv[3], 16)) {
				cish_cfg->tacacs[i].ip_addr[0] = 0;
				break;
			}
		} else
			cish_cfg->tacacs[i].ip_addr[0] = 0;
	}
	if (i == MAX_SERVERS && args->argc == 4) {
		printf("%% Server not found!\n");
		destroy_args(args);
		return;
	}
	if ((server = fopen(FILE_TACDB_SERVER, "w"))) {
		for (i = 0; i < MAX_SERVERS; i++) {
			if (cish_cfg->tacacs[i].ip_addr[0]) { /* server[:port] secret [timeout] */
				if (cish_cfg->tacacs[i].authkey[0])
					fprintf(server, "%s\t%s\t%d\n",
					                cish_cfg->tacacs[i].ip_addr,
					                cish_cfg->tacacs[i].authkey,
					                cish_cfg->tacacs[i].timeout);
				else
					fprintf(server, "%s\n", cish_cfg->tacacs[i].ip_addr);
			}
		}
		fclose(server);
	}
	destroy_args(args);
}
