/*
 * File : config_aaa.c
 * Comment : All CLI AAA functions must be inside this file
 * Author : PD3 Tecnologia
 * Created on : May 20, 2011
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h> /* fstat */

#include "commands.h"
#include "commandtree.h"


struct pam_types_t {
	char cish_name[32];
	char conf_filename[64];
} pam_types[] = {
		{ "cli", FILE_PAM_LOGIN },
		{ "ppp", FILE_PAM_PPP },
		{ "web", FILE_PAM_WEB },
		{ "enable", FILE_PAM_ENABLE },
		{ "login", FILE_PAM_LOGIN }
};
#define PAM_TYPES_SIZE 	sizeof(pam_types)/sizeof(struct pam_types_t)

static const char *pam_files[] = {FILE_PAM_LOGIN, FILE_PAM_ENABLE, FILE_PAM_CLI, FILE_PAM_WEB, NULL};



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

static int _check_tacacs_server(void)
{
	FILE *server;
	struct stat st;
	if (!(server = fopen(FILE_TACDB_SERVER, "r"))) {
		printf("%% Please configure TACACS+ server first\n");
		return -1;
	}
	fstat(fileno(server), &st);
	if (!st.st_size) { /* File exists but it is empty */
		printf("%% Please configure TACACS+ server first\n");
		fclose(server);
		return -1;
	}
	fclose(server);

	return 0;
}

static int _check_radius_server(void)
{
	FILE *server;
	struct stat st;
	if (!(server = fopen(FILE_RADDB_SERVER, "r"))) {
		printf("%% Please configure RADIUS server first\n");
		return -1;
	}
	fstat(fileno(server), &st);
	if (!st.st_size) { /* File exists but it is empty */
		printf("%% Please configure RADIUS server first\n");
		fclose(server);
		return -1;
	}
	fclose(server);

	return 0;
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
	int args_len;
	arg_list args = NULL;
	char *filename = NULL;
	char *service;
	int no = 0, none = 0;
	enum aaa_modes mode = AAA_AUTH_NONE;

	args_len = librouter_parse_args_din((char *) cmd, &args);

	if (args_len < 5) {
		librouter_destroy_args_din(&args);
		return;
	}

	if (!strcmp(args[0], "no"))
		no = 1;
	else if (!strcmp(args[4], "none"))
		none = 1;

	service = no ? args[3] : args[2];

	filename = get_pam_filename(service);

	if (filename == NULL) {
		printf("%% Authentication file for %s not found ....\n", service);
		return;
	}

	if (no || none)
		mode = AAA_AUTH_NONE;
	else if (!strcmp(args[4], "local")) {
		mode = AAA_AUTH_LOCAL;
	} else if (!strcmp(args[5], "radius")) {
		if (_check_radius_server() == 0)
			mode = (args_len == 7 ? AAA_AUTH_RADIUS_LOCAL : AAA_AUTH_RADIUS);
	} else if (!strcmp(args[5], "tacacs+")) {
		if (_check_tacacs_server() == 0)
			mode = (args_len == 7 ? AAA_AUTH_TACACS_LOCAL : AAA_AUTH_TACACS);
	}

	if (librouter_pam_config_mode(mode, filename) < 0)
		printf("%% Not possible to execute command with success\n");

	librouter_destroy_args_din(&args);
	return;
}



static void cmd_aaa_acct_exec(const char *cmd)
{
	int args_len;
	arg_list args = NULL;
	enum aaa_modes mode = AAA_ACCT_NONE;

	args_len = librouter_parse_args_din((char *) cmd, &args);

	/* [no] aaa accounting exec */
	if (args_len < 5) {
		librouter_destroy_args_din(&args);
		return;
	}

	if (!strcmp(args[0], "no") || !strcmp(args[4], "none")) {
		mode = AAA_ACCT_NONE;
	} else if (!strcmp(args[2], "exec")) {
		if (strstr(cmd, "tacacs") && (_check_tacacs_server() == 0))
			mode = AAA_ACCT_TACACS;
		else if (strstr(cmd, "radius") && (_check_radius_server() == 0))
			mode = AAA_ACCT_RADIUS;
	}

	if (librouter_pam_config_mode(mode, FILE_PAM_LOGIN) < 0)
		printf("%% Not possible to execute command with success\n");

	librouter_destroy_args_din(&args);
	return;
}


static void cmd_aaa_acct_commands(const char *cmd)
{
	int args_len;
	arg_list args = NULL;
	enum aaa_modes mode = AAA_ACCT_NONE;

	args_len = librouter_parse_args_din((char *) cmd, &args);

	/* [no] aaa accounting commands */
	if (args_len < 5) {
		librouter_destroy_args_din(&args);
		return;
	}

	if (!strcmp(args[0], "no") || !strcmp(args[4], "none")) {
		mode = AAA_ACCT_NONE;
	} else if (!strcmp(args[2],"commands")) {
		if (strstr(cmd, "tacacs") && (_check_tacacs_server() == 0))
			mode = AAA_ACCT_TACACS;
		else if (strstr(cmd, "radius") && (_check_radius_server() == 0))
			mode = AAA_ACCT_RADIUS;
	}


	if (librouter_pam_config_mode(mode, FILE_PAM_CLI) < 0)
		printf("%% Not possible to execute command with success\n");

	librouter_destroy_args_din(&args);
	return;
}

/* [no] aaa accounting exec default start-stop group tacacs+ */
/* [no] aaa accounting commands [1-15] default start-stop group tacacs+ */
void cmd_aaa_acct(const char *cmd)
{
	if (strstr(cmd, "commands"))
		cmd_aaa_acct_commands(cmd);
	else if (strstr(cmd, "exec"))
		cmd_aaa_acct_exec(cmd);
	else
		printf("Error in accounting command\n");
}

/*****************/
/* Authorization */
/*****************/

static void cmd_aaa_author_commands(const char *cmd)
{
	int args_len;
	arg_list args = NULL;
	enum aaa_modes mode = AAA_AUTHOR_NONE;

	args_len = librouter_parse_args_din((char *) cmd, &args);

	/* [no] aaa authorization commands */
	if (args_len < 5) {
		librouter_destroy_args_din(&args);
		return;
	}

	if (!strcmp(args[0], "no") || !strcmp(args[4], "none")) {
		mode = AAA_AUTHOR_NONE;
	} else if (!strcmp(args[2],"commands")) {
		if (strstr(cmd, "tacacs") && (_check_tacacs_server() == 0))
			mode = (args_len == 7) ? AAA_AUTHOR_TACACS_LOCAL : AAA_AUTHOR_TACACS;
		else if (strstr(cmd, "radius") && (_check_radius_server() == 0))
			mode = (args_len == 7) ? AAA_AUTHOR_RADIUS_LOCAL : AAA_AUTHOR_RADIUS;
	}

	if (librouter_pam_config_mode(mode, FILE_PAM_CLI) < 0)
		printf("%% Not possible to execute command with success\n");

	librouter_destroy_args_din(&args);
	return;
}

static void cmd_aaa_author_exec(const char *cmd)
{
	int args_len;
	arg_list args = NULL;
	enum aaa_modes mode = AAA_AUTHOR_NONE;

	args_len = librouter_parse_args_din((char *) cmd, &args);

	/* [no] aaa authorization exec */
	if (args_len < 5) {
		librouter_destroy_args_din(&args);
		return;
	}

	if (!strcmp(args[0], "no") || !strcmp(args[4], "none")) {
		mode = AAA_AUTHOR_NONE;
	} else if (!strcmp(args[2], "exec")) {
		if (strstr(cmd, "tacacs") && (_check_tacacs_server() == 0))
			mode = (args_len == 7) ? AAA_AUTHOR_TACACS_LOCAL : AAA_AUTHOR_TACACS;
		else if (strstr(cmd, "radius") && (_check_radius_server() == 0))
			mode = (args_len == 7) ? AAA_AUTHOR_RADIUS_LOCAL : AAA_AUTHOR_RADIUS;
	}

	if (librouter_pam_config_mode(mode, FILE_PAM_LOGIN) < 0)
		printf("%% Not possible to execute command with success\n");

	librouter_destroy_args_din(&args);
	return;
}

void cmd_aaa_author(const char *cmd)
{
	if (strstr(cmd, "commands"))
		cmd_aaa_author_commands(cmd);
	else if (strstr(cmd, "exec"))
		cmd_aaa_author_exec(cmd);
	else
		printf("Error in authorization command\n");
}

/**
 * add_radiusserver	Add RADIUS server to system config
 *
 * @param cmd
 */
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

/**
 * del_radiusserver	Delete RADIUS server from system config
 *
 * @param cmd
 */
void del_radiusserver(const char *cmd) /* no radius-server [host <ipaddr>] */
{
	arglist *args;
	struct auth_server server;
	int mode, i;

	memset(&server, 0, sizeof(server));

	/* Parse all PAM files to check if RADIUS is enabled anywhere */
	for (i = 0; pam_files[i] != NULL; i++) {
		mode = librouter_pam_get_current_mode((char *)pam_files[i]);
		if (mode == AAA_AUTH_RADIUS || mode == AAA_AUTH_RADIUS_LOCAL) {
			printf("%% please disable RADIUS authentication first\n");
			return;
		}
		mode = librouter_pam_get_current_author_mode((char *)pam_files[i]);
		if (mode == AAA_AUTHOR_RADIUS || mode == AAA_AUTHOR_RADIUS_LOCAL) {
			printf("%% please disable RADIUS authorization first\n");
			return;
		}

		mode = librouter_pam_get_current_acct_mode((char *)pam_files[i]);
		if (mode == AAA_ACCT_RADIUS) {
			printf("%% please disable RADIUS accounting first\n");
			return;
		}
	}

	args = librouter_make_args(cmd);

	if (args->argc == 4) {
		server.ipaddr = args->argv[3];
		librouter_pam_del_radius_server(&server);
	} else
		librouter_pam_del_radius_server(NULL); /* Delete all servers */

	librouter_destroy_args(args);
}

/**
 * add_tacacsserver	Add TACACS+ server to system config
 *
 * @param cmd
 */
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

/**
 * del_tacacsserver	Delete TACACS+ server from system config
 *
 * If any AAA method is active, issue a warning to user and exit
 *
 * @param cmd
 */
void del_tacacsserver(const char *cmd) /* no tacacs-server [host <ipaddr>] */
{
	arglist *args;
	struct auth_server server;
	int mode, i;

	memset(&server, 0, sizeof(server));

	args = librouter_make_args(cmd);


	/* Parse all PAM files to check if TACACS is enabled anywhere */
	for (i = 0; pam_files[i] != NULL; i++) {
		mode = librouter_pam_get_current_mode((char *)pam_files[i]);
		if (mode == AAA_AUTH_TACACS || mode == AAA_AUTH_TACACS_LOCAL) {
			printf("%% please disable TACACS+ authentication first\n");
			librouter_destroy_args(args);
			return;
		}
		mode = librouter_pam_get_current_author_mode((char *)pam_files[i]);
		if (mode == AAA_AUTHOR_TACACS || mode == AAA_AUTHOR_TACACS_LOCAL) {
			printf("%% please disable TACACS+ authorization first\n");
			librouter_destroy_args(args);
			return;
		}

		mode = librouter_pam_get_current_acct_mode((char *)pam_files[i]);
		if (mode == AAA_ACCT_TACACS) {
			printf("%% please disable TACACS+ accounting first\n");
			librouter_destroy_args(args);
			return;
		}
	}

	if (args->argc == 4) {
		server.ipaddr = args->argv[3];
		librouter_pam_del_tacacs_server(&server);
	} else
		librouter_pam_del_tacacs_server(NULL); /* Delete all servers */

	librouter_destroy_args(args);
}

/****************************************/
/* Command authorization and accounting */
/****************************************/

/**
 * authorize_cli_command
 *
 * Get authorization from PAM that this command can be run
 *
 * @param cmd
 * @return 0 if ok, -1 if not
 */
int authorize_cli_command(char *cmd)
{
#ifdef OPTION_AAA_AUTHORIZATION
	/* Exit commands are not accounted */
	if (!strcmp(cmd, "exit"))
		return 0;

	char cish_enable[2];
	snprintf(cish_enable,sizeof(cish_enable),"%d",_cish_enable);

	if (librouter_pam_authorize_command(cmd, cish_enable) != 0)
		return -1;
#endif
	return 0;
}

/**
 * account_cli_command	Account a CLI command via PAM
 *
 * @param cmd
 */
void account_cli_command(char *cmd)
{
#ifdef OPTION_AAA_ACCOUNTING
	librouter_pam_account_command(cmd);
#endif
}

/*********************/
/* User manipulation */
/*********************/

/**
 * add_user	Add a user to system and set its password and privileges
 *
 * @param cmd
 */
void add_user(const char *cmd) /* aaa username <user> password [hash] <pass> privilege <priv>*//* tinylogin */
{
	arglist *args;

	args = librouter_make_args(cmd);

	if (strstr(cmd, "hash")) {
		if (librouter_pam_cmds_del_user_from_group(args->argv[2]) < 0)
			goto errorG;

		if (librouter_pam_add_user_with_hash(args->argv[2], args->argv[5]) < 0)
			goto errorU;

		if (librouter_pam_cmds_add_user_to_group(args->argv[2], args->argv[7]) < 0)
			goto errorU;
	}
	else {
		if (librouter_pam_cmds_del_user_from_group(args->argv[2]) < 0 )
			goto errorG;

		if (librouter_pam_add_user(args->argv[2], args->argv[4]) < 0)
			goto errorU;

		if (librouter_pam_cmds_add_user_to_group(args->argv[2], args->argv[6]) < 0)
			goto errorU;
	}

	librouter_destroy_args(args);
	return;

errorG:
	printf("%% Problems retrieving user group\n");
errorU:
	printf("%% Not possible to execute command with success\n");
	librouter_destroy_args(args);
	return;
}

/**
 * del_user	Delete a user from system
 *
 * @param cmd
 */
void del_user(const char *cmd) /* no aaa username <user>*//* tinylogin */
{
	arglist *args;
	args = librouter_make_args(cmd);

	if (librouter_pam_cmds_del_user_from_group(args->argv[3]) < 0)
		goto errorG;

	if (librouter_pam_del_user(args->argv[3]) < 0)
		goto errorU;

	librouter_destroy_args(args);
	return;

errorG:
	printf("%% Problems retriving user group\n");
errorU:
	printf("%% Not possible to execute command with success\n");
	librouter_destroy_args(args);
	return;

}
