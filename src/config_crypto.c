#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"


#ifdef OPTION_IPSEC

char dynamic_ipsec_menu_name[MAX_CONN_NAME + 1] = " ";

int ipsec_file_filter(const struct dirent *file)
{
	char *p1, *p2;

	if ((p1 = strstr(file->d_name, "ipsec.")) == NULL)
		return 0;
	if ((p2 = strstr(file->d_name, ".conf")) == NULL)
		return 0;
	if (p1 + 6 < p2)
		return 1; /* ipsec.[conname].conf */
	return 0;
}

/*  Create ipsec.[connectioname].conf
 *  Type:
 *     - 0,  manual
 *     - 1,  ike
 */
int create_conf_conn_file(char *name)
{
	int fd;
	char buf[MAX_CMD_LINE];

	sprintf(buf, FILE_IKE_CONN_CONF, name);

	if ((fd = open(buf, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
		printf("%% could not create connection file\n");
		return -1;
	}

	sprintf(buf, "#active= no\n"
		"conn %s\n"
		"\tauthby= \n"
		"\tauth= esp\n"
		"\tesp= \n"
		"\tleftid=\n"
		"\tleft=\n"
		"\tleftsubnet=\n"
		"\tleftnexthop=\n"
		"\tleftrsasigkey=\n"
		"\tleftprotoport=\n"
		"\trightid=\n"
		"\tright=\n"
		"\trightsubnet=\n"
		"\trightnexthop=\n"
		"\trightrsasigkey=\n"
		"\trightprotoport=\n"
		"\taggrmode=\n"
		"\tpfs=\n"
		"\tauto= ignore\n"
		"\tdpddelay= 30\n"
		"\tdpdtimeout= 120\n"
		"\tdpdaction= restart\n", name);

	write(fd, buf, strlen(buf));
	close(fd);
	return 0;
}

/*  Updade ipsec.conf
 *  0 -> para excluir
 *  1 -> para acrescentar
 */
int update_ipsec_conf(char *name, int action)
{
	int fd, ret;
	char filename[128], key[128];

	if ((fd = open(FILE_IPSEC_CONF, O_RDWR)) < 0) {
		if ((fd = librouter_ipsec_create_conf()) < 0) {
			printf("%% could not open file %s\n", FILE_IPSEC_CONF);
			return -1;
		}
	}
	snprintf(filename, 128, FILE_IKE_CONN_CONF, name);
	snprintf(key, 128, "include %s\n", filename);
	ret = librouter_ipsec_set_connection(action, key, fd);
	close(fd);
	return ret;
}

/*  Updade ipsec.secrets
 *  0 -> para excluir
 *  1 -> para acrescentar
 */
int update_ipsec_secrets(char *name, int action)
{
	int fd, ret;
	char filename[128], key[128];

	if ((fd = open(FILE_IPSEC_SECRETS, O_RDWR | O_CREAT, 0600)) < 0) {
		printf("%% could not open file %s\n", FILE_IPSEC_SECRETS);
		return -1;
	}
	snprintf(filename, 128, FILE_CONN_SECRETS, name);
	snprintf(key, 128, "include %s\n", filename);
	ret = librouter_ipsec_set_connection(action, key, fd);
	close(fd);
	return ret;
}

void cd_connection_dir(const char *cmd) /* ipsec connection [name] */
{
	arglist *args;

	dynamic_ipsec_menu_name[0] = '\0';
	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		strcpy(dynamic_ipsec_menu_name, args->argv[2]);
		command_root = CMD_IPSEC_CONNECTION_CHILDREN;
	}
	librouter_destroy_args(args);
}

void cd_crypto_dir(const char *cmd)
{
	check_initial_conn();
	command_root = CMD_CONFIG_CRYPTO;
}

static void refresh_dynamic_ipsec_menus(void)
{
	int i, j;

	for (i = CMDS_BEF_LIST; i < (MAX_CONN + CMDS_BEF_LIST); i++) {
		if (!CMD_IPSEC_CONNECTION_ADD[i].name
		                && CMD_IPSEC_CONNECTION_ADD[i + 1].name) {
			CMD_IPSEC_CONNECTION_ADD[i].name
			                = CMD_IPSEC_CONNECTION_ADD[i + 1].name;
			CMD_IPSEC_CONNECTION_ADD[i].children
			                = CMD_IPSEC_CONNECTION_ADD[i + 1].children;
			CMD_IPSEC_CONNECTION_ADD[i].func
			                = CMD_IPSEC_CONNECTION_ADD[i + 1].func;
			CMD_IPSEC_CONNECTION_ADD[i].privilege
			                = CMD_IPSEC_CONNECTION_ADD[i + 1].privilege;
			CMD_IPSEC_CONNECTION_ADD[i + 1].name = NULL;
			CMD_IPSEC_CONNECTION_ADD[i + 1].children = NULL;
			CMD_IPSEC_CONNECTION_ADD[i + 1].func = NULL;
			CMD_IPSEC_CONNECTION_ADD[i + 1].privilege = 1000;
			j = i - CMDS_BEF_LIST;
			CMD_CRYPTO_IPSEC_NO_CONN[j].name
			                = CMD_CRYPTO_IPSEC_NO_CONN[j + 1].name;
			CMD_CRYPTO_IPSEC_NO_CONN[j].children
			                = CMD_CRYPTO_IPSEC_NO_CONN[j + 1].children;
			CMD_CRYPTO_IPSEC_NO_CONN[j].func
			                = CMD_CRYPTO_IPSEC_NO_CONN[j + 1].func;
			CMD_CRYPTO_IPSEC_NO_CONN[j].privilege
			                = CMD_CRYPTO_IPSEC_NO_CONN[j + 1].privilege;
			CMD_CRYPTO_IPSEC_NO_CONN[j + 1].name = NULL;
			CMD_CRYPTO_IPSEC_NO_CONN[j + 1].children = NULL;
			CMD_CRYPTO_IPSEC_NO_CONN[j + 1].func = NULL;
			CMD_CRYPTO_IPSEC_NO_CONN[j + 1].privilege = 1000;
		}
	}
}

int eval_connections_menus(int add_del, char *name)
{
	int i;
	char *p;

	if (name == NULL)
		return -1;
	if (strlen(name) == 0)
		return -1;

	if (add_del) { // add name
		for (i = CMDS_BEF_LIST; i < (MAX_CONN + CMDS_BEF_LIST); i++) {
			if (CMD_IPSEC_CONNECTION_ADD[i].name == NULL)
				break;
		}
		if (i >= (MAX_CONN + CMDS_BEF_LIST))
			return -1;
		if ((p = malloc(strlen(name) + 1)) == NULL)
			return -1;
		strcpy(p, name);
		CMD_IPSEC_CONNECTION_ADD[i].name = p;
		CMD_IPSEC_CONNECTION_ADD[i].help = "User connection";
		CMD_IPSEC_CONNECTION_ADD[i].func = cd_connection_dir;
		CMD_IPSEC_CONNECTION_ADD[i].privilege = 1;
		// prepare del node
		CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].name = p;
		CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].help
		                = "User connection";
		CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].func
		                = del_ipsec_conn;
		CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].privilege = 1;
	} else { // del name
		for (i = CMDS_BEF_LIST; i < (MAX_CONN + CMDS_BEF_LIST); i++) {
			if (CMD_IPSEC_CONNECTION_ADD[i].name != NULL) {
				if (!strcmp(CMD_IPSEC_CONNECTION_ADD[i].name,
				                name)) {
					free(
					                (char *) CMD_IPSEC_CONNECTION_ADD[i].name);
					CMD_IPSEC_CONNECTION_ADD[i].name = NULL;
					CMD_IPSEC_CONNECTION_ADD[i].help = NULL;
					CMD_IPSEC_CONNECTION_ADD[i].func = NULL;
					CMD_IPSEC_CONNECTION_ADD[i].privilege
					                = 1000;
					// remove del node
					CMD_CRYPTO_IPSEC_NO_CONN[i
					                - CMDS_BEF_LIST].name
					                = NULL;
					CMD_CRYPTO_IPSEC_NO_CONN[i
					                - CMDS_BEF_LIST].help
					                = NULL;
					CMD_CRYPTO_IPSEC_NO_CONN[i
					                - CMDS_BEF_LIST].func
					                = NULL;
					CMD_CRYPTO_IPSEC_NO_CONN[i
					                - CMDS_BEF_LIST].privilege
					                = 1000;
					refresh_dynamic_ipsec_menus();
					return 0;
				}
			}
		}
		return -1;
	}
	return 0;
}

void ipsec_autoreload(const char *cmd) /* [no] auto-reload [60-3600] */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0)
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF,
		                STRING_IPSEC_AUTORELOAD, "0");
	else
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF,
		                STRING_IPSEC_AUTORELOAD, args->argv[1]);
	librouter_destroy_args(args);
}

void ipsec_nat_traversal(const char *cmd) /* [no] nat-traversal */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 2)
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF, STRING_IPSEC_NAT,
		                "no");
	else
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF, STRING_IPSEC_NAT,
		                "yes");
	librouter_destroy_args(args);
}

void ipsec_overridemtu(const char *cmd) /* [no] overridemtu [64-1460] */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0)
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF, STRING_IPSEC_OMTU,
		                "0");
	else
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF, STRING_IPSEC_OMTU,
		                args->argv[1]);
	librouter_destroy_args(args);
}

extern int _cish_booting;

void add_ipsec_conn(const char *cmd) /* ipsec connection add [name] */
{
	arglist *args;
	char **list = NULL, **list_ini = NULL;
	int i, go_out, count;

	args = librouter_make_args(cmd);
	if (args->argc == 4) {
		if (strlen(args->argv[3]) >= MAX_CONN_NAME) {
			printf("%% Connection name to long\n");
			goto free_args;
		}
		if (librouter_ipsec_list_all_names(&list) < 1) {
			printf("%% Not possible to add ipsec connection\n");
			goto free_args;
		}
		if (*list != NULL) {
			list_ini = list;
			for (i = 0, go_out = 0, count = 0; *list != NULL && i
			                < MAX_CONN; i++, list++, count++) {
				if (strcmp(args->argv[3], *list) == 0)
					go_out++;
				free(*list);
			}
			free(list_ini);
			if (go_out) {
				if (!_cish_booting)
					printf(
					                "%% Connection with name %s already exists!\n",
					                args->argv[3]);
				goto free_args;
			}
			// Teste do numero de conexoes
			if (count >= MAX_CONN) {
				printf(
				                "%% You have reached the max number of connections!\n");
				goto free_args;
			}
		}
		// Adicao da conexao
		if (create_conf_conn_file(args->argv[3]) < 0) {
			printf(
			                "%% Not possible to add ipsec connection name!\n");
			goto free_args;
		}
		// Atualizacao do arquivo /etc/ipsec.conf
		if (update_ipsec_conf(args->argv[3], 1) < 0) {
			printf(
			                "%% Not possible to add ipsec connection name!\n");
			goto free_args;
		}
		// Atualizacao do arquivo /etc/ipsec.secrets
		if (update_ipsec_secrets(args->argv[3], 1) < 0) {
			printf(
			                "%% Not possible to add ipsec connection name!\n");
			goto free_args;
		}
		if (eval_connections_menus(1, args->argv[3]) < 0) {
			remove_conn_files(args->argv[3]);
			goto free_args;
		}
	}
	free_args: librouter_destroy_args(args);
}

void del_ipsec_conn(const char *cmd) /* no ipsec connection [name] */
{
	arglist *args;
	int i, restart = 0;
	char **list = NULL, **list_ini = NULL;

	args = librouter_make_args(cmd);
	if (args->argc == 4) {
		if (librouter_ipsec_set_link(args->argv[3], 0) < 0) {
			printf("%% Not possible to del ipsec connection!\n");
			goto free_args;
		}
		if (remove_conn_files(args->argv[3]) < 0) {
			printf(
			                "%% Not possible to del ipsec connection files!\n");
			goto free_args;
		}
		if (eval_connections_menus(0, args->argv[3]) < 0)
			goto free_args;

		if (librouter_ipsec_list_all_names(&list) > 0) {
			if (*list != NULL) {
				list_ini = list;
				for (i = 0; i < MAX_CONN; i++, list++) {
					if (*list) {
						if (librouter_ipsec_get_link(*list))
							restart = 1;
						free(*list);
					}
				}
				free(list_ini);
			}
		}
		if (restart)
			librouter_ipsec_exec(RESTART);
		else
			librouter_ipsec_exec(STOP);
	}
	free_args: librouter_destroy_args(args);
}

void generate_rsa_key(const char *cmd)
{
	int i, ret;
	arglist *args;
	char **list = NULL, **list_ini = NULL, buf[100];

	args = librouter_make_args(cmd);
	if (args->argc == 4) {
		printf("%% Please wait... computation may take long time!\n");
		if (librouter_ipsec_create_rsakey(atoi(args->argv[3])) < 0) {
			printf("%% Not possible to generate RSA key!\n");
			goto free_args;
		}
		if (librouter_ipsec_list_all_names(&list) < 1) {
			goto free_args;
		}
		if (*list != NULL) {
			list_ini = list;
			for (i = 0; i < MAX_CONN; i++, list++) {
				if (*list) {
					ret = librouter_ipsec_get_auth(*list, buf);
					if (ret == RSA)
						librouter_ipsec_create_secrets_file(*list,
						                1, NULL);
					free(*list);
				}
			}
			free(list_ini);
		}
		librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void config_crypto_done(const char *cmd)
{
	int i;

	/* free memory */
	for (i = CMDS_BEF_LIST; i < (MAX_CONN + CMDS_BEF_LIST); i++) {
		if (CMD_IPSEC_CONNECTION_ADD[i].name) {
			free((char *) CMD_IPSEC_CONNECTION_ADD[i].name);
			CMD_IPSEC_CONNECTION_ADD[i].name = NULL;
			CMD_IPSEC_CONNECTION_ADD[i].children = NULL;
			CMD_IPSEC_CONNECTION_ADD[i].func = NULL;
			CMD_IPSEC_CONNECTION_ADD[i].privilege = 1000;
			// remove del node
			CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].name = NULL;
			CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].func = NULL;
			CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].privilege
			                = 1000;
		}
	}
	command_root = CMD_CONFIGURE;
}

void config_connection_done(const char *cmd)
{
	command_root = CMD_CONFIG_CRYPTO;
}

int remove_conn_files(char *name)
{
	char buf[128];
	struct stat st;

	snprintf(buf, 128, FILE_IKE_CONN_CONF, name);
	if (stat(buf, &st) == 0)
		remove(buf);
#if 0
	snprintf(buf, 128, FILE_MAN_CONN_CONF, name);
	if (stat(buf, &st) == 0) remove(buf);
#endif
	snprintf(buf, 128, FILE_CONN_SECRETS, name);
	if (stat(buf, &st) == 0)
		remove(buf);

	update_ipsec_conf(name, 0); // Atualizacao do arquivo /etc/ipsec.conf
	update_ipsec_secrets(name, 0); // Atualizacao do arquivo /etc/ipsec.secrets
	return 0;
}

void ipsec_set_secret_key(const char *cmd) /* authby secret password */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (librouter_ipsec_create_secrets_file(dynamic_ipsec_menu_name, 0,
		                args->argv[2]) < 0) {
			printf(
			                "%% Not possible to set secret authentication type\n");
			goto free_args;
		}
		if (librouter_ipsec_set_auth(dynamic_ipsec_menu_name, SECRET) < 0) {
			printf(
			                "%% Not possible to set secret authentication type\n");
			goto free_args;
		}
		// se o link estiver ativo, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf(
			                "%% Not possible to set secret authentication type\n");
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void ipsec_authby_rsa(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 2) {
		if (librouter_ipsec_create_secrets_file(dynamic_ipsec_menu_name, 1, NULL)
		                < 0) {
			printf(
			                "%% Not possible to set RSA authentication type\n");
			goto free_args;
		}
		if (librouter_ipsec_set_auth(dynamic_ipsec_menu_name, RSA) < 0) {
			printf(
			                "%% Not possible to set RSA authentication type\n");
			goto free_args;
		}
		// se o link estiver ativo, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf(
			                "%% Not possible to set RSA authentication type\n");
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void ipsec_authproto_esp(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 2) {
		if (librouter_ipsec_set_ike_authproto(dynamic_ipsec_menu_name, ESP) < 0) {
			printf("%% Not possible to set authproto to esp\n");
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set authproto to esp\n");
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void set_esp_hash(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	switch (args->argc) {
	case 1:
		if (librouter_ipsec_set_esp(dynamic_ipsec_menu_name, NULL, NULL) < 0) {
			printf("%% Not possible to reset esp\n");
			goto free_args;
		}
		break;
	case 2:
		if (librouter_ipsec_set_esp(dynamic_ipsec_menu_name, args->argv[1], NULL)
		                < 0) {
			printf("%% Not possible to set cypher to %s\n",
			                args->argv[1]);
			goto free_args;
		}
		break;
	case 3:
		if (librouter_ipsec_set_esp(dynamic_ipsec_menu_name, args->argv[1],
		                args->argv[2]) < 0) {
			printf("%% Not possible to set cypher to %s/%s\n",
			                args->argv[1], args->argv[2]);
			goto free_args;
		}
		break;
	default:
		goto free_args;
	}
	// se o link estiver up, entao provocamos um RESTART no starter
	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Not possible to set cypher\n");
		goto free_args;
	}
	if (ret > 0)
		librouter_ipsec_exec(RESTART);
	free_args: librouter_destroy_args(args);
}

void set_ipsec_id(const char *cmd)
{
	int ret;
	arglist *args;
	char tp[MAX_ID_LEN];

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (strlen(args->argv[2]) < MAX_ID_LEN)
			strcpy(tp, args->argv[2]);
		else {
			printf("%% ID to long\n");
			goto free_args;
		}
		if (strncmp(args->argv[0], "local", 5) == 0)
			ret = librouter_ipsec_set_local_id(dynamic_ipsec_menu_name, tp);
		else
			ret = librouter_ipsec_set_remote_id(dynamic_ipsec_menu_name, tp);
		if (ret < 0) {
			printf("%% Not possible to set %s id\n", args->argv[0]);
			goto free_args;
		}
		// se o link estiver ativo, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s id\n", args->argv[0]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void clear_ipsec_id(const char *cmd) /* no local/remote id */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (strncmp(args->argv[1], "local", 5) == 0)
			ret = librouter_ipsec_set_local_id(dynamic_ipsec_menu_name, "");
		else
			ret = librouter_ipsec_set_remote_id(dynamic_ipsec_menu_name, "");
		if (ret < 0) {
			printf("%% Not possible to clear %s id\n",
			                args->argv[1]);
			goto free_args;
		}
		// se o link estiver ativo, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s id\n",
			                args->argv[1]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void set_ipsec_addr(const char *cmd) /* local/remote address default-route/interface/ip/fqdn serial/x.x.x.x/www */
{
	int ret, local = 0;
	char tp[200];
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc >= 3) {
		if (!strncmp(args->argv[0], "local", 5))
			local = 1;
		if (local && !strncmp(args->argv[2], "default-route", 13)) {
			ret = librouter_ipsec_set_local_addr(dynamic_ipsec_menu_name,
			                STRING_DEFAULTROUTE);
			if (ret < 0) {
				printf(
				                "%% Not possible to set %s address to default-route\n",
				                args->argv[0]);
				goto free_args;
			}
		} else if (local && args->argc == 5 && !strncmp(args->argv[2],
		                "interface", 9)) {
			sprintf(tp, "%%%s%s", args->argv[3], args->argv[4]);
			ret = librouter_ipsec_set_local_addr(dynamic_ipsec_menu_name, tp);
			if (ret < 0) {
				printf(
				                "%% Not possible to set %s address to interface %s\n",
				                args->argv[0], args->argv[3]);
				goto free_args;
			}
		} else if (!local && !strncmp(args->argv[2], "any", 3)) {
			ret = librouter_ipsec_set_remote_addr(dynamic_ipsec_menu_name,
			                STRING_ANY);
			if (ret < 0) {
				printf(
				                "%% Not possible to set %s address to any\n",
				                args->argv[0]);
				goto free_args;
			}
		} else if (args->argc == 4 && (!strncmp(args->argv[2], "ip", 2)
		                || !strncmp(args->argv[2], "fqdn", 4))) {
			if (strlen(args->argv[3]) < 200)
				strcpy(tp, args->argv[3]);
			else {
				printf("%% Not possible to set %s address\n",
				                args->argv[0]);
				goto free_args;
			}
			if (local)
				ret = librouter_ipsec_set_local_addr(
				                dynamic_ipsec_menu_name, tp);
			else
				ret = librouter_ipsec_set_remote_addr(
				                dynamic_ipsec_menu_name, tp);
			if (ret < 0) {
				if (!strncmp(args->argv[2], "ip", 2))
					printf(
					                "%% Not possible to set %s ip address\n",
					                args->argv[0]);
				else
					printf(
					                "%% Not possible to set %s fqdn address\n",
					                args->argv[0]);
				goto free_args;
			}
		}

		// se o link estiver ativo, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s address\n",
			                args->argv[0]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void set_ipsec_nexthop(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (!strncmp(args->argv[0], "local", 5))
			ret = librouter_ipsec_set_nexthop_inf(LOCAL,
			                dynamic_ipsec_menu_name, args->argv[2]);
		else
			ret = librouter_ipsec_set_nexthop_inf(REMOTE,
			                dynamic_ipsec_menu_name, args->argv[2]);
		if (ret < 0) {
			printf("%% Not possible to set %s nexthop\n",
			                args->argv[0]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s nexthop\n",
			                args->argv[0]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void clear_ipsec_nexthop(const char *cmd) /* no local/remote nexthop */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (!strncmp(args->argv[1], "local", 5))
			ret = librouter_ipsec_set_nexthop_inf(LOCAL,
			                dynamic_ipsec_menu_name, "");
		else
			ret = librouter_ipsec_set_nexthop_inf(REMOTE,
			                dynamic_ipsec_menu_name, "");
		if (ret < 0) {
			printf("%% Not possible to clear %s nexthop\n",
			                args->argv[1]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s nexthop\n",
			                args->argv[1]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void set_ipsec_remote_rsakey(const char *cmd) /* remote rsakey [publickey] */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (librouter_ipsec_set_rsakey(dynamic_ipsec_menu_name,
		                STRING_IPSEC_R_RSAKEY, args->argv[2]) < 0) {
			printf("%% Not possible to set %s rsakey\n",
			                args->argv[0]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s rsakey\n",
			                args->argv[0]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void clear_ipsec_remote_rsakey(const char *cmd) /* no local/remote rsakey */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (librouter_ipsec_set_rsakey(dynamic_ipsec_menu_name,
		                STRING_IPSEC_R_RSAKEY, "") < 0) {
			printf("%% Not possible to clear %s rsakey\n",
			                args->argv[1]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s rsakey\n",
			                args->argv[1]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void set_ipsec_subnet(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 4) {
		if (!strncmp(args->argv[0], "local", 5))
			ret = librouter_ipsec_set_subnet_inf(LOCAL,
			                dynamic_ipsec_menu_name, args->argv[2],
			                args->argv[3]);
		else
			ret = librouter_ipsec_set_subnet_inf(REMOTE,
			                dynamic_ipsec_menu_name, args->argv[2],
			                args->argv[3]);
		if (ret < 0) {
			printf("%% Not possible to set %s subnet\n",
			                args->argv[0]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s subnet\n",
			                args->argv[0]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void clear_ipsec_subnet(const char *cmd) /* no local/remote subnet */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (!strncmp(args->argv[1], "local", 5))
			ret = librouter_ipsec_set_subnet_inf(LOCAL,
			                dynamic_ipsec_menu_name, "", "");
		else
			ret = librouter_ipsec_set_subnet_inf(REMOTE,
			                dynamic_ipsec_menu_name, "", "");
		if (ret < 0) {
			printf("%% Not possible to clear %s subnet\n",
			                args->argv[1]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s subnet\n",
			                args->argv[1]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void ipsec_link_up(const char *cmd)
{
	if (librouter_ipsec_set_link(dynamic_ipsec_menu_name, 1) < 0) {
		printf("%% Not possible to enable tunnel\n");
		return;
	}
	if (librouter_ipsec_is_running())
		librouter_ipsec_exec(RESTART);
	else
		librouter_ipsec_exec(START);
}

void ipsec_link_down(const char *cmd)
{
	int i, restart = 0;
	char **list = NULL, **list_ini = NULL;

	if (librouter_ipsec_set_link(dynamic_ipsec_menu_name, 0) < 0) {
		printf("%% Not possible to shutdown\n");
		return;
	}
	if (librouter_ipsec_list_all_names(&list) > 0) {
		if (*list != NULL) {
			list_ini = list;
			for (i = 0; i < MAX_CONN; i++, list++) {
				if (*list) {
					if (librouter_ipsec_get_link(*list))
						restart = 1;
					free(*list);
				}
			}
			free(list_ini);
		}
	}
	if (restart)
		librouter_ipsec_exec(RESTART);
	else
		librouter_ipsec_exec(STOP);
}

void set_ipsec_l2tp_protoport(const char *cmd) /* [no] l2tp protoport [SP1|SP2] */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (!strcmp(args->argv[0], "no"))
			librouter_ipsec_set_protoport(dynamic_ipsec_menu_name, NULL);
		else
			librouter_ipsec_set_protoport(dynamic_ipsec_menu_name,
			                args->argv[2]);
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set protoport\n");
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void ipsec_pfs(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	switch (args->argc) {
	case 1:
		if (librouter_ipsec_set_pfs(dynamic_ipsec_menu_name, 1) < 0) {
			printf("%% Not possible to turn on PFS\n");
			goto free_args;
		}
		break;
	case 2:
		if (librouter_ipsec_set_pfs(dynamic_ipsec_menu_name, 0) < 0) {
			printf("%% Not possible to turn off PFS\n");
			goto free_args;
		}
		break;
	default:
		goto free_args;
	}
	// se o link estiver up, entao provocamos um RESTART no starter
	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Not possible to turn on PFS\n");
		goto free_args;
	}
	if (ret > 0)
		librouter_ipsec_exec(RESTART);
	free_args: librouter_destroy_args(args);
}

void l2tp_dhcp_server(const char *cmd) /* l2tp <local|ethernet 0-1> pool s.s.s.s e.e.e.e ... */
{
	librouter_dhcp_set_server_local(1, (char*) cmd);
}

void l2tp_server(const char *cmd) /* [no] l2tp server */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3 && !strcmp(args->argv[0], "no"))
		librouter_l2tp_exec(STOP);
	else
		librouter_l2tp_exec(START);
	librouter_destroy_args(args);
}

void check_initial_conn(void)
{
	int i, j;
	char *p, **list = NULL, **list_ini = NULL;

	if (librouter_ipsec_list_all_names(&list) >= 0) {
		if (*list != NULL) {
			list_ini = list;
			for (i = 0; i < MAX_CONN; i++) {
				if (*list != NULL) {
					for (j = CMDS_BEF_LIST;; j++) {
						if (CMD_IPSEC_CONNECTION_ADD[j].name
						                == NULL) {
							if ((p = malloc(strlen(
							                *list)
							                + 1))
							                == NULL)
								break;
							strcpy(p, *list);
							list++;
							CMD_IPSEC_CONNECTION_ADD[j].name
							                = p;
							CMD_IPSEC_CONNECTION_ADD[j].help
							                = "User connection";
							CMD_IPSEC_CONNECTION_ADD[j].func
							                = cd_connection_dir;
							CMD_IPSEC_CONNECTION_ADD[j].privilege
							                = 1;
							// prepare del node
							CMD_CRYPTO_IPSEC_NO_CONN[j
							                - CMDS_BEF_LIST].name
							                = p;
							CMD_CRYPTO_IPSEC_NO_CONN[j
							                - CMDS_BEF_LIST].help
							                = "User connection";
							CMD_CRYPTO_IPSEC_NO_CONN[j
							                - CMDS_BEF_LIST].func
							                = del_ipsec_conn;
							CMD_CRYPTO_IPSEC_NO_CONN[j
							                - CMDS_BEF_LIST].privilege
							                = 1;
							break;
						}
					}
				}
			}
			// Libera memoria
			for (i = 0, list = list_ini; i < MAX_CONN; i++, list++)
				if (*list)
					free(*list);
			free(list_ini);
		}
	}
}


/*************************************** L2TP ********************************************/

void l2tp_peer(const char *cmd) /* [no] l2tp peer <ipaddress> <netmask> */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (strcmp(args->argv[0], "no") == 0) {
		cfg.peer_mask = -1; /* Disable peer! */
	} else {
		strncpy(cfg.peer, args->argv[2], 16);
		cfg.peer[15] = 0;
		cfg.peer_mask = librouter_quagga_netmask_to_cidr(args->argv[3]);
	}
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	librouter_destroy_args(args);
}

void l2tp_ppp_auth_pass(const char *cmd) /* l2tp ppp authentication pass [password] */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	strncpy(cfg.auth_pass, args->argv[4], MAX_PPP_PASS);
	cfg.auth_pass[MAX_PPP_PASS - 1] = 0;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	librouter_destroy_args(args);
}

void l2tp_ppp_auth_user(const char *cmd) /* l2tp ppp authentication user [username] */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	strncpy(cfg.auth_user, args->argv[4], MAX_PPP_USER);
	cfg.auth_user[MAX_PPP_USER - 1] = 0;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	librouter_destroy_args(args);
}

void l2tp_ppp_noauth(const char *cmd) /* no l2tp ppp authentication */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.auth_user[0] = cfg.auth_pass[0] = 0;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
}

void l2tp_ppp_ipaddr(const char *cmd) /* l2tp ppp ip address <ipaddress> */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	strncpy(cfg.ip_addr, args->argv[4], 16);
	cfg.ip_addr[15] = 0;
	cfg.ip_unnumbered = -1; /* Desativando a flag do IP UNNUMBERED */
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	librouter_destroy_args(args);
}

void l2tp_ppp_noipaddr(const char *cmd) /* no l2tp ppp ip address */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.ip_addr[0] = cfg.ip_mask[0] = 0;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
}

void l2tp_ppp_defaultroute(const char *cmd) /* l2tp ppp ip default-route */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (!cfg.default_route) {
		cfg.default_route = 1;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}

void l2tp_ppp_no_defaultroute(const char *cmd) /* no l2tp ppp ip default-route */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (cfg.default_route) {
		cfg.default_route = 0;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}

void l2tp_ppp_peeraddr(const char *cmd) /* l2tp ppp ip peer-address [pool|<ipaddress>] */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (strcmp(args->argv[4], "pool") == 0)
		cfg.ip_peer_addr[0] = 0;
	else {
		strncpy(cfg.ip_peer_addr, args->argv[4], 16);
		cfg.ip_peer_addr[15] = 0;
	}
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	librouter_destroy_args(args);
}

void l2tp_ppp_nopeeraddr(const char *cmd) /* no l2tp ppp ip peer-address */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.ip_peer_addr[0] = 0;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
}

void l2tp_ppp_unnumbered(const char *cmd) /* l2tp ppp ip unnumbered ethernet 0-x */
{
	arglist *args;
	char addr[32], mask[32];
	ppp_config cfg;
	char *dev;

	args = librouter_make_args(cmd);
	dev = librouter_device_convert(args->argv[4], atoi(args->argv[5]), -1);

	if (!strncmp(dev, "eth", strlen("eth")))
		librouter_ip_ethernet_ip_addr(dev, addr, mask);
	else
		librouter_ip_interface_get_ip_addr(dev, addr, mask);

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	strncpy(cfg.ip_addr, addr, 16);
	cfg.ip_addr[15] = 0;

	/* Quando for interface loopbackX, ip_unnumbered recebe X+2 */
	if (!strncmp(dev, "lo", strlen("lo")))
		cfg.ip_unnumbered = atoi(args->argv[5]) + 2;
	else
		cfg.ip_unnumbered = atoi(args->argv[5]);

	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	free(dev);
	librouter_destroy_args(args);
}

void l2tp_ppp_no_unnumbered(const char *cmd) /* no l2tp ppp ip unnumbered */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.ip_addr[0] = cfg.ip_mask[0] = 0;
	cfg.ip_unnumbered = -1;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
}

void l2tp_ppp_vj(const char *cmd) /* l2tp ppp ip vj */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (cfg.novj) {
		cfg.novj = 0;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}

void l2tp_ppp_no_vj(const char *cmd) /* no l2tp ppp ip vj */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (!cfg.novj) {
		cfg.novj = 1;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}

void l2tp_ppp_keepalive_interval(const char *cmd) /* l2tp ppp keepalive interval [seconds] */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.echo_interval = atoi(args->argv[4]);
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	librouter_destroy_args(args);
}

void l2tp_ppp_keepalive_timeout(const char *cmd) /* l2tp ppp keepalive timeout [seconds] */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.echo_failure = atoi(args->argv[4]);
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	librouter_destroy_args(args);
}

void l2tp_ppp_mtu(const char *cmd) /* l2tp ppp mtu [mtu] */
{
	arglist *args;
	int mtu;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	mtu = atoi(args->argv[3]);
	librouter_destroy_args(args);
	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (cfg.mtu != mtu) {
		cfg.mtu = mtu;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}

void l2tp_ppp_nomtu(const char *cmd) /* no l2tp ppp mtu */
{
	ppp_config cfg;

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (cfg.mtu) {
		cfg.mtu = 0;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}
#endif

