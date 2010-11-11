#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "commands.h"
#include "commandtree.h"
#include "commands.h"
#include "pprintf.h"


void snmp_community(const char *cmd)
{
	int ro;
	arglist *args;

	args = librouter_make_args(cmd);

	if ((args->argc >= 4) && (strcasecmp(args->argv[3], "rw") == 0))
		ro = 0;
	else
		ro = 1;

	librouter_snmp_set_community(args->argv[2], 1, ro);

	librouter_destroy_args(args);

	if (librouter_snmp_is_running())
		librouter_snmp_reload_config();
	/* This code is commented on Atlanta without any explanation */
#ifdef CONFIG_BERLIN_SATROUTER
	else
	librouter_snmp_start();
#endif
}

void snmp_no_community(const char *cmd)
{
	int ro;
	arglist *args;

	args = librouter_make_args(cmd);

	if ((args->argc >= 5) && (strcasecmp(args->argv[4], "rw") == 0))
		ro = 0;
	else
		ro = 1;

	librouter_snmp_set_community(args->argv[3], 0, ro);

	librouter_destroy_args(args);

	if (librouter_snmp_is_running())
		librouter_snmp_reload_config();
	/* This code is commented on Atlanta without any explanation */
#ifdef CONFIG_BERLIN_SATROUTER
	else
	librouter_snmp_start();
#endif
}

void snmp_text(const char *cmd) /* [no] snmp-server contact|location <text> */
{
	int i;
	char *p;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc < 2) {
		librouter_destroy_args(args);
		return;
	}
	if (!strcmp(args->argv[0], "no"))
		i = 2;
	else
		i = 1;
	if (!strcmp(args->argv[i], "contact")) {
		if (args->argc > i + 1) {
			if ((p = strstr((char *) cmd, args->argv[i + 1])))
				librouter_snmp_set_contact(p);
		} else
			librouter_snmp_set_contact(NULL);
	} else if (!strcmp(args->argv[i], "location")) {
		if (args->argc > i + 1) {
			if ((p = strstr((char *) cmd, args->argv[i + 1])))
				librouter_snmp_set_location(p);
		} else
			librouter_snmp_set_location(NULL);
	} else
		fprintf(stderr, "%% Syntax error\n");
	librouter_destroy_args(args);

	if (librouter_snmp_is_running())
		librouter_snmp_reload_config();
}

void snmp_no_server(const char *cmd)
{
	librouter_snmp_stop();
}

void snmp_trapsink(const char *cmd) /* snmp trapsink <ipaddress> <community> */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc >= 4)
		librouter_snmp_add_trapsink(args->argv[2], args->argv[3]);
	librouter_destroy_args(args);
}

void snmp_no_trapsink(const char *cmd) /* no snmp trapsink <ipaddress> */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 4)
		librouter_snmp_del_trapsink(args->argv[3]);
	librouter_destroy_args(args);
}

void snmp_user(const char *cmd) /* [no] snmp-server user <username> <rw | ro> <authpriv type> [authproto <md5 | sha>] [privproto <des | aes>] */
{
	arglist *args;
	char retype[32], authpasswd[32], privpasswd[32];

	args = librouter_make_args(cmd);
	switch (strcmp(args->argv[0], "no")) {
	case 0: /* Remocao de usuario */
		switch (args->argc) {
		case 3: {
			int i, n;
			char **list;

			if ((n = librouter_snmp_list_users(&list)) > 0) {
				for (i = (n - 1); i >= 0; i--) {
					if (list[i] != NULL) {
						if (librouter_snmp_remove_user(list[i]) < 0)
							printf(
							                "%% Not possible to remove user '%s'\n",
							                list[i]);
						free(list[i]);
					}
				}
				free(list);
			}
			break;
		}

		case 4:
			if (librouter_snmp_remove_user(args->argv[3]) < 0)
				printf("%% Not possible to remove user '%s'\n", args->argv[3]);
			break;
		}
		break;

	default: /* Adicao de usuario */
		switch (args->argc) {
		case 5:
			if (librouter_snmp_add_user(args->argv[2], ((strcmp(args->argv[3], "rw")
			                == 0) ? 1 : 0), args->argv[4], NULL, NULL, NULL, NULL) < 0)
				printf("%% Not possible to add user\n");
			break;

		case 7:
			printf("               Username: %s\n", args->argv[2]);
			printf("Authentication Password: ");
			fflush(stdout);
			librouter_str_read_password(1, authpasswd, 31);
			printf("\n");
			if (strlen(authpasswd) < 8) {
				printf("%% Password too short. (minimum 8 characters)!\n");
				librouter_destroy_args(args);
				return;
			}
			printf("                 Retype: ");
			fflush(stdout);
			librouter_str_read_password(1, retype, 31);
			printf("\n");
			if (strcmp(authpasswd, retype) != 0) {
				printf("%% Password do not match!\n");
				librouter_destroy_args(args);
				return;
			}
			if (librouter_snmp_add_user(args->argv[2], ((strcmp(args->argv[3], "rw")
			                == 0) ? 1 : 0), args->argv[4], args->argv[6], NULL,
			                authpasswd, NULL) < 0)
				printf("%% Not possible to add user\n");
			break;

			/* [no] snmp-server user <username> <rw | ro> <authpriv type> [authproto <md5 | sha>] [privproto <des | aes>] */
		case 9:
			printf("               Username: %s\n", args->argv[2]);
			printf("Authentication Password: ");
			fflush(stdout);
			librouter_str_read_password(1, authpasswd, 31);
			printf("\n");
			if (strlen(authpasswd) < 8) {
				printf("%% Password too short. (minimum 8 characters)!\n");
				librouter_destroy_args(args);
				return;
			}
			printf("                 Retype: ");
			fflush(stdout);
			librouter_str_read_password(1, retype, 31);
			printf("\n");
			if (strcmp(authpasswd, retype) != 0) {
				printf("%% Password do not match!\n");
				librouter_destroy_args(args);
				return;
			}

			printf("        Cipher Password: ");
			fflush(stdout);
			librouter_str_read_password(1, privpasswd, 31);
			printf("\n");
			if (strlen(privpasswd) < 8) {
				printf("%% Password too short. (minimum 8 characters)!\n");
				librouter_destroy_args(args);
				return;
			}
			printf("                 Retype: ");
			fflush(stdout);
			librouter_str_read_password(1, retype, 31);
			printf("\n");
			if (strcmp(privpasswd, retype) != 0) {
				printf("%% Password do not match!\n");
				librouter_destroy_args(args);
				return;
			}
			if (librouter_snmp_add_user(args->argv[2], ((strcmp(args->argv[3], "rw")
			                == 0) ? 1 : 0), args->argv[4], args->argv[6],
			                args->argv[8], authpasswd, privpasswd) < 0)
				printf("%% Not possible to add user\n");
			break;

		default:
			printf("%% Invalid command!\n");
			break;
		}
		break;
	}
	librouter_destroy_args(args);
}

void show_snmp_users(const char *cmd) /* show snmp users */
{
	FILE *f;
	char buf[256];
	int n, first = 0;
	arg_list argl = NULL;

	if ((f = fopen(SNMP_USERKEY_FILE, "r")) != NULL) {
		while (feof(f) == 0) {
			if (fgets(buf, 255, f) != NULL) {
				buf[255] = 0;
				if ((n = librouter_parse_args_din(buf, &argl)) >= 2) {
					if (strcmp(argl[0], "createUser") == 0) {
						if (first == 0) {
							printf("SNMP v3 users:\n");
							first = 1;
						}
						argl[n - 1][0] = ' ';
						printf("   '%s'%s", argl[1], argl[n - 1]);
						if (n >= 4) {
							if (strcasecmp(argl[2], "md5") == 0)
								printf(" Auth MD5");
							else if (strcasecmp(argl[2], "sha") == 0)
								printf(" Auth SHA");
						}
						if (n >= 6) {
							if (strcasecmp(argl[4], "DES") == 0)
								printf(" Privacy DES");
							else if (strcasecmp(argl[4], "AES") == 0)
								printf(" Privacy AES");
						}
						printf("\n");
					}
				}
				librouter_destroy_args_din(&argl);
			}
		}
		fclose(f);
		if (first == 1)
			printf("\n");
	}
}

#ifdef OPTION_SNMP_VERSION_SELECT
void snmp_version(const char *cmd)
{
	int i;
	char tp[16];
	arglist *args;

	if (librouter_snmp_is_running())
		librouter_snmp_stop();

	args = librouter_make_args(cmd);
	tp[0] = 0;
	for (i = 2; i < args->argc; i++) {
		if (strcmp(args->argv[i], "1") == 0)
			strcat(tp, "1");
		else if (strcmp(args->argv[i], "2") == 0)
			strcat(tp, "2c");
		else if (strcmp(args->argv[i], "3") == 0)
			strcat(tp, "3");
	}
	if (strlen(tp) > 0)
		librouter_exec_control_inittab_lineoptions(PROG_SNMPD, "-J", tp);
	librouter_destroy_args(args);

	/* De qualquer forma colocamos o agente SNMP em execucao */
	librouter_snmp_start();
}
#endif /* OPTION_SNMP_VERSION_SELECT */

void snmp_enable(const char *cmd)
{
	arglist *args;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0],"no"))
		librouter_snmp_stop();
	else
		librouter_snmp_start();

	librouter_destroy_args(args);
}
