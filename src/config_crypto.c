#define _GNU_SOURCE
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

#include <readline/readline.h>
#include <readline/history.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"
#include "terminal_echo.h"

#ifdef OPTION_IPSEC

char dynamic_ipsec_menu_name[IPSEC_MAX_CONN_NAME + 1] = " ";

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

	for (i = CMDS_BEF_LIST; i < (IPSEC_MAX_CONN + CMDS_BEF_LIST); i++) {
		if (!CMD_IPSEC_CONNECTION_ADD[i].name && CMD_IPSEC_CONNECTION_ADD[i + 1].name) {
			CMD_IPSEC_CONNECTION_ADD[i].name = CMD_IPSEC_CONNECTION_ADD[i + 1].name;
			CMD_IPSEC_CONNECTION_ADD[i].children
			                = CMD_IPSEC_CONNECTION_ADD[i + 1].children;
			CMD_IPSEC_CONNECTION_ADD[i].func = CMD_IPSEC_CONNECTION_ADD[i + 1].func;
			CMD_IPSEC_CONNECTION_ADD[i].privilege
			                = CMD_IPSEC_CONNECTION_ADD[i + 1].privilege;
			CMD_IPSEC_CONNECTION_ADD[i + 1].name = NULL;
			CMD_IPSEC_CONNECTION_ADD[i + 1].children = NULL;
			CMD_IPSEC_CONNECTION_ADD[i + 1].func = NULL;
			CMD_IPSEC_CONNECTION_ADD[i + 1].privilege = 1000;
			j = i - CMDS_BEF_LIST;
			CMD_CRYPTO_IPSEC_NO_CONN[j].name = CMD_CRYPTO_IPSEC_NO_CONN[j + 1].name;
			CMD_CRYPTO_IPSEC_NO_CONN[j].children
			                = CMD_CRYPTO_IPSEC_NO_CONN[j + 1].children;
			CMD_CRYPTO_IPSEC_NO_CONN[j].func = CMD_CRYPTO_IPSEC_NO_CONN[j + 1].func;
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
		for (i = CMDS_BEF_LIST; i < (IPSEC_MAX_CONN + CMDS_BEF_LIST); i++) {
			if (CMD_IPSEC_CONNECTION_ADD[i].name == NULL)
				break;
		}
		if (i >= (IPSEC_MAX_CONN + CMDS_BEF_LIST))
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
		CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].help = "User connection";
		CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].func = del_ipsec_conn;
		CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].privilege = 1;
	} else { // del name
		for (i = CMDS_BEF_LIST; i < (IPSEC_MAX_CONN + CMDS_BEF_LIST); i++) {
			if (CMD_IPSEC_CONNECTION_ADD[i].name != NULL) {
				if (!strcmp(CMD_IPSEC_CONNECTION_ADD[i].name, name)) {
					free((char *) CMD_IPSEC_CONNECTION_ADD[i].name);
					CMD_IPSEC_CONNECTION_ADD[i].name = NULL;
					CMD_IPSEC_CONNECTION_ADD[i].help = NULL;
					CMD_IPSEC_CONNECTION_ADD[i].func = NULL;
					CMD_IPSEC_CONNECTION_ADD[i].privilege = 1000;
					// remove del node
					CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].name = NULL;
					CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].help = NULL;
					CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].func = NULL;
					CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].privilege
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

void ipsec_nat_traversal(const char *cmd) /* [no] nat-traversal */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 2)
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF, STRING_IPSEC_NAT, "no");
	else
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF, STRING_IPSEC_NAT, "yes");
	librouter_destroy_args(args);
}

void ipsec_overridemtu(const char *cmd) /* [no] overridemtu [64-1460] */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0)
		librouter_str_replace_string_in_file(FILE_IPSEC_CONF, STRING_IPSEC_OMTU, "0");
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

	if (args->argc != 4)
		goto free_args;

	if (strlen(args->argv[3]) >= IPSEC_MAX_CONN_NAME) {
		printf("%% Connection name to long\n");
		goto free_args;
	}

	if (librouter_ipsec_list_all_names(&list) < 1) {
		printf("%% Not possible to add ipsec connection\n");
		goto free_args;
	}

	if (*list != NULL) {
		list_ini = list;
		for (i = 0, go_out = 0, count = 0; *list != NULL && i < IPSEC_MAX_CONN;
		                i++, list++, count++) {
			if (strcmp(args->argv[3], *list) == 0)
				go_out++;
			free(*list);
		}
		free(list_ini);
		if (go_out) {
			if (!_cish_booting)
				printf("%% Connection with name %s already exists!\n",
				                args->argv[3]);
			goto free_args;
		}

		if (count >= IPSEC_MAX_CONN) {
			printf("%% You have reached the max number of connections!\n");
			goto free_args;
		}
	}

	if (librouter_ipsec_create_conn(args->argv[3])) {
		printf("%% Not possible to add ipsec connection %s\n", args->argv[3]);
		goto free_args;
	}

	if (eval_connections_menus(1, args->argv[3]) < 0) {
		librouter_ipsec_delete_conn(args->argv[3]);
		goto free_args;
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
			printf("%% Not possible to disable ipsec connection!\n");
			goto free_args;
		}
		if (librouter_ipsec_delete_conn(args->argv[3]) < 0) {
			printf("%% Not possible to delete ipsec connection !\n");
			goto free_args;
		}
		if (eval_connections_menus(0, args->argv[3]) < 0)
			goto free_args;

		if (librouter_ipsec_list_all_names(&list) > 0) {
			if (*list != NULL) {
				list_ini = list;
				for (i = 0; i < IPSEC_MAX_CONN; i++, list++) {
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

#ifdef IPSEC_SUPPORT_RSA_RAW
void generate_rsa_key(const char *cmd)
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 4) {
		printf("%% Please wait... computation may take long time!\n");
		if (librouter_ipsec_create_rsakey(atoi(args->argv[3])) < 0) {
			printf("%% Not possible to generate RSA key!\n");
			goto free_args;
		}

		if (librouter_ipsec_is_running())
			librouter_ipsec_exec(RESTART);
	}
free_args:
	librouter_destroy_args(args);
}
#endif /* IPSEC_SUPPORT_RSA_RAW */

#ifdef OPTION_PKI
void pki_no(const char *cmd)
{
	arglist *args;
	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[2], "csr"))
		librouter_pki_flush_csr();
	else if (!strcmp(args->argv[2], "cert"))
		librouter_pki_flush_cert();
	else if (!strcmp(args->argv[2], "cert"))
		librouter_pki_flush_privkey();
	else if (!strcmp(args->argv[2], "ca"))
		librouter_pki_del_cacert(args->argv[3]);

	librouter_destroy_args(args);
}

void pki_csr_show(const char *cmd)
{
	char buf[4096];

	memset(buf, 0, sizeof(buf));
	if (librouter_pki_get_csr(buf, sizeof(buf)) == 0)
		printf(buf);
}

static int _dn_prompt(struct pki_dn *dn)
{
	memset(dn, 0, sizeof(struct pki_dn));

	printf("You are about to be asked to enter information that will be incorporated\n"
			"into your certificate request.\n"
			"What you are about to enter is what is called a Distinguished Name or a DN.\n"
			"There are quite a few fields but you can leave some blank\n"
			"For some fields there will be a default value,\n");


	fflush(STDIN_FILENO);
	printf("Country Name (2 letter code):");
	dn->c = readline(NULL);
	printf("State or Province Name:");
	dn->state = readline(NULL);
	printf("Locality Name (eg, city):");
	dn->city = readline(NULL);
	printf("Organization Name (eg, company):");
	dn->org = readline(NULL);
	printf("Organizational Unit Name (eg, section):");
	dn->section = readline(NULL);
	printf("Common Name (eg, YOUR name):");
	dn->name = readline(NULL);
	printf("Email Address:");
	dn->email = readline(NULL);
	printf("Challenge Password:");
	dn->challenge = readline(NULL);

	return 0;
}

void pki_generate(const char *cmd)
{
	arglist *args;
	char buf[2048];
	args = librouter_make_args(cmd);
	char in;



	if (!strcmp(args->argv[1], "privkey")) {
		if (!librouter_pki_get_privkey(buf, sizeof(buf))) {
			printf("%% Private key already exists.\n"
					"%% Continuing will invalidate any "
					"certificate derived from the "
					"current key.\n"
					"%% Do you wish to continue?[y/N]\n");

			/* FIXME Do this in a library function ! */
			/* Wait for input in non-canonical mode */
			canon_off();
			echo_off();
			in = fgetc(stdin);
			canon_on();
			echo_on();
			cish_timeout = 0;
			printf("\n");

			if ((in != 'y') && (in != 'Y'))
				goto free_args;
			/* End of FIXME */
		}

		printf("%% Please wait... computation may take long time!\n");
		if (librouter_pki_gen_privkey(atoi(args->argv[2])) < 0) {
			printf("%% Not possible to generate private key!\n");
			goto free_args;
		}
	} else if (!strcmp(args->argv[1], "csr")) {
		struct pki_dn dn;

		_dn_prompt(&dn);

		if (librouter_pki_gen_csr(&dn) < 0) {
			printf("%% Not possible to generate csr!\n");
			goto free_args;
		}

		librouter_pki_dn_free(&dn);
	}

	if (librouter_ipsec_is_running())
		librouter_ipsec_exec(RESTART);
free_args:
	librouter_destroy_args(args);
}

#define X509_BEGIN_CERTIFICATE_STR	"-----BEGIN CERTIFICATE-----"
#define X509_BEGIN_CERTIFICATE_STR_LEN	strlen(X509_BEGIN_CERTIFICATE_STR)
#define X509_END_CERTIFICATE_STR	"-----END CERTIFICATE-----"
#define X509_END_CERTIFICATE_STR_LEN	strlen(X509_END_CERTIFICATE_STR)

static int _cert_add(char **buf)
{
	char *line, *cert;
	int spaceleft;

	cert = malloc(getpagesize());
	if (cert == NULL)
		return -1;

	spaceleft = getpagesize();

	printf("%% Paste the certificate signed by the Certificate Authority.\n");
	printf("%% (Type ENTER twice when finished)\n");

	while (1) {
		line = readline(NULL);
		if (line == NULL) {
			/* This will happend on abort (CTRL + D) */
			goto  cert_err;
		}

		if (strlen(line) == 0) {
			free(line);
			break;
		}

		strncat(cert, line, spaceleft);
		strcat(cert, "\n");
		spaceleft -= strlen(line) + 1;
		free(line);
	}

	/* Check if certificate is valid */
	if (strlen(cert) < (X509_BEGIN_CERTIFICATE_STR_LEN + X509_END_CERTIFICATE_STR_LEN)) {
		printf("%% Invalid certificate lenght: certificate will not be saved\n");
		goto  cert_err;
	}

	/* Try to find begin of certificate string */
	if (strncmp(cert, X509_BEGIN_CERTIFICATE_STR, X509_BEGIN_CERTIFICATE_STR_LEN)) {
		printf("%% Invalid syntax (begin): certificate will not be saved\n");
		goto  cert_err;
	}

	/* Try to find end of certificate string */
	line = cert + strlen(cert) - X509_END_CERTIFICATE_STR_LEN - 1;
	if (strncmp(line, X509_END_CERTIFICATE_STR, X509_END_CERTIFICATE_STR_LEN)) {
		printf("%% Invalid syntax (end): certificate will not be saved\n");
		goto  cert_err;
	}

	*buf = cert;
	return 0;
cert_err:
	free(cert);
	cert = NULL;

	return -1;
}

#ifdef IPSEC_SUPPORT_SCEP
void pki_ca_authenticate(const char *cmd)
{
	arglist *args;
	char buf[4096];
	char *url, *ca;

	args = librouter_make_args(cmd);

	ca = args->argv[3];
	url = args->argv[4];

	if (librouter_pki_get_privkey(buf, sizeof(buf)) < 0) {
		printf("%% Need to generate RSA Private-Key first\n");
		librouter_destroy_args(args);
		return;
	}

	librouter_pki_ca_authenticate(url, ca);

	librouter_destroy_args(args);
}

void pki_csr_enroll(const char *cmd)
{
	arglist *args;
	char buf[4096];
	char *url, *ca;

	args = librouter_make_args(cmd);

	ca = args->argv[3];
	url = args->argv[4];

	if (librouter_pki_get_privkey(buf, sizeof(buf)) < 0) {
		printf("%% Need to generate RSA Private-Key first\n");
		librouter_destroy_args(args);
		return;
	}

	if (librouter_pki_get_cacert(ca, buf, sizeof(buf)) < 0) {
		printf("%% Need to add %s CA certificate first\n", ca);
		librouter_destroy_args(args);
		return;
	}

	if (librouter_pki_get_csr(buf, sizeof(buf)) < 0) {
		printf("%% Need to generate Certificate request first\n");
		librouter_destroy_args(args);
		return;
	}

	librouter_pki_cert_enroll(url, ca);

	librouter_destroy_args(args);
}
#endif /* IPSEC_SUPPORT_SCEP */

void pki_cert_add(const char *cmd)
{
	char *c = NULL;

	if ((_cert_add(&c) <  0) || (c == NULL)) {
		printf("%% No certificate was added\n");
		return;
	}

	if (librouter_pki_set_cert(c, strlen(c)) < 0)
		printf("%% Could not add X.509 host certificate\n");

	free(c);
}

void pki_cacert_add(const char *cmd)
{
	arglist *args;
	char *c = NULL;

	if (librouter_pki_get_ca_num() == PKI_MAX_CA) {
		printf("%% Already reached maximum supported number of CAs\n");
		return;
	}

	args = librouter_make_args(cmd);

	if ((_cert_add(&c) < 0) || (c == NULL)) {
		printf("%% No certificate was added\n");
		return;
	}

	if (librouter_pki_set_cacert(args->argv[3], c, strlen(c)) < 0)
		printf("%% Could not add CA\n");

	free(c);
	librouter_destroy_args(args);
}

void pki_save(const char *cmd)
{
	librouter_pki_save();
}
#endif /* OPTION_PKI */

void config_crypto_done(const char *cmd)
{
	int i;

	/* free memory */
	for (i = CMDS_BEF_LIST; i < (IPSEC_MAX_CONN + CMDS_BEF_LIST); i++) {
		if (CMD_IPSEC_CONNECTION_ADD[i].name) {
			free((char *) CMD_IPSEC_CONNECTION_ADD[i].name);
			CMD_IPSEC_CONNECTION_ADD[i].name = NULL;
			CMD_IPSEC_CONNECTION_ADD[i].children = NULL;
			CMD_IPSEC_CONNECTION_ADD[i].func = NULL;
			CMD_IPSEC_CONNECTION_ADD[i].privilege = 1000;
			// remove del node
			CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].name = NULL;
			CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].func = NULL;
			CMD_CRYPTO_IPSEC_NO_CONN[i - CMDS_BEF_LIST].privilege = 1000;
		}
	}
	command_root = CMD_CONFIGURE;
}

void config_connection_done(const char *cmd)
{
	command_root = CMD_CONFIG_CRYPTO;
}

void ipsec_set_secret_key(const char *cmd) /* authby secret password */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (librouter_ipsec_set_auth(dynamic_ipsec_menu_name, SECRET) < 0) {
			printf("%% Not possible to set secret authentication type\n");
			goto free_args;
		}

		if (librouter_ipsec_set_secret(dynamic_ipsec_menu_name, args->argv[2]) < 0) {
			printf("%% Not possible to set secret\n");
			goto free_args;
		}

		/* If connection was enabled, we need to restart the service */
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set secret authentication type\n");
			goto free_args;
		}

		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

#ifdef OPTION_SUPPORT_RSA_RAW
void ipsec_authby_rsa(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 2) {
		if (librouter_ipsec_set_auth(dynamic_ipsec_menu_name, RSA) < 0) {
			printf("%% Not possible to set RSA authentication type:\n");
			goto free_args;
		}
		/* If connection was enabled, we need to restart the service */
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Could not get connection link status\n");
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}
#endif /* OPTION_SUPPORT_RSA_RAW */

void ipsec_authby_x509(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 2) {
		if (librouter_ipsec_set_auth(dynamic_ipsec_menu_name, X509) < 0) {
			printf("%% Not possible to set RSA authentication type:\n");
			goto free_args;
		}

		/* If connection was enabled, we need to restart the service */
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Could not get connection link status\n");
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

void ipsec_authproto_esp(const char *cmd)
{
	int ret, auth;
	arglist *args;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[2], "ah"))
		auth = AUTH_AH;
	else
		auth = AUTH_ESP;

	if (librouter_ipsec_set_ike_auth_type(dynamic_ipsec_menu_name, auth) < 0) {
		printf("%% Not possible to set authentication protocol\n");
		goto free_args;
	}

	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Failed to get IPSec status\n");
		goto free_args;
	}
	if (ret > 0)
		librouter_ipsec_exec(RESTART);

	free_args: librouter_destroy_args(args);
}

void ipsec_ipcomp(const char *cmd)
{
	int ret, ipcomp;
	arglist *args;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0], "no"))
		ipcomp = 0;
	else
		ipcomp = 1;

	if (librouter_ipsec_set_ipcomp(dynamic_ipsec_menu_name, ipcomp) < 0) {
		printf("%% Not possible to set IP compression\n");
		goto free_args;
	}

	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Failed to get IPSec status\n");
		goto free_args;
	}
	if (ret > 0)
		librouter_ipsec_exec(RESTART);

	free_args: librouter_destroy_args(args);
}

void set_esp_hash(const char *cmd)
{
	int ret;
	arglist *args;
	int cypher, hash;

	args = librouter_make_args(cmd);

	if (args->argc != 3)
		goto free_args;

	if (!strcmp(args->argv[1], "aes"))
		cypher = CYPHER_AES;
	else if (!strcmp(args->argv[1], "aes192"))
		cypher = CYPHER_AES192;
	else if (!strcmp(args->argv[1], "aes256"))
		cypher = CYPHER_AES256;
	else if (!strcmp(args->argv[1], "3des"))
		cypher = CYPHER_3DES;
	else if (!strcmp(args->argv[1], "null"))
		cypher = CYPHER_NULL;
	else
		cypher = CYPHER_DES;

	if (!strcmp(args->argv[2], "sha1"))
		hash = HASH_SHA1;
	else if (!strcmp(args->argv[2], "sha256"))
		hash = HASH_SHA256;
	else if (!strcmp(args->argv[2], "sha384"))
		hash = HASH_SHA384;
	else if (!strcmp(args->argv[2], "sha512"))
		hash = HASH_SHA512;
	else
		hash = HASH_MD5;

	if (librouter_ipsec_set_esp(dynamic_ipsec_menu_name, cypher, hash) < 0) {
		printf("%% Not possible to reset esp\n");
		goto free_args;
	}

	/* Restart link if it was already enabled */
	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Not possible to set cypher\n");
		goto free_args;
	}

	if (ret > 0)
		librouter_ipsec_exec(RESTART);
free_args:
	librouter_destroy_args(args);
}

void ipsec_set_ike_protocols(const char *cmd)
{
	int ret;
	arglist *args;
	int cypher, hash, dh;

	args = librouter_make_args(cmd);

	if (args->argc != 4)
		goto free_args;

	if (!strcmp(args->argv[1], "aes"))
		cypher = CYPHER_AES;
	else if (!strcmp(args->argv[1], "aes192"))
		cypher = CYPHER_AES192;
	else if (!strcmp(args->argv[1], "aes256"))
		cypher = CYPHER_AES256;
	else if (!strcmp(args->argv[1], "3des"))
		cypher = CYPHER_3DES;
	else if (!strcmp(args->argv[1], "null"))
		cypher = CYPHER_NULL;
	else
		cypher = CYPHER_DES;

	if (!strcmp(args->argv[2], "sha1"))
		hash = HASH_SHA1;
	else if (!strcmp(args->argv[2], "sha256"))
		hash = HASH_SHA256;
	else if (!strcmp(args->argv[2], "sha384"))
		hash = HASH_SHA384;
	else if (!strcmp(args->argv[2], "sha512"))
		hash = HASH_SHA512;
	else
		hash = HASH_MD5;

	if (!strcmp(args->argv[3], "1"))
		dh = DH_GROUP_1;
	else if (!strcmp(args->argv[3], "2"))
		dh = DH_GROUP_2;
	else if (!strcmp(args->argv[3], "5"))
		dh = DH_GROUP_5;
	else
		dh = DH_GROUP_14;


	if (librouter_ipsec_set_ike_algs(dynamic_ipsec_menu_name, cypher, hash, dh) < 0) {
		printf("%% Not possible to set IKE protocol\n");
		goto free_args;
	}

	/* Restart link if it was already enabled */
	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Not possible to get IPSec link status\n");
		goto free_args;
	}

	if (ret > 0)
		librouter_ipsec_exec(RESTART);
free_args:
	librouter_destroy_args(args);
}

void ipsec_conn_set_ike_version(const char *cmd)
{
	int ret;
	arglist *args;
	int version = IKEv1;

	args = librouter_make_args(cmd);

	if (strcmp(args->argv[1], "2") == 0)
		version = IKEv2;
	else
		version = IKEv1;

	if (librouter_ipsec_set_ike_version(dynamic_ipsec_menu_name, version) < 0) {
		printf("%% Not possible to reset esp\n");
		goto free_args;
	}

	/* Restart link if it was already enabled */
	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Not possible to set IKE version\n");
		goto free_args;
	}

	if (ret > 0)
		librouter_ipsec_exec(RESTART);
free_args:
	librouter_destroy_args(args);
}

void set_ipsec_id(const char *cmd)
{
	int ret;
	arglist *args;
	int local = 0;

	args = librouter_make_args(cmd);

	if (args->argc < 3)
		goto free_args;

	if (strncmp(args->argv[0], "local", 5) == 0)
		local = 1;

	if (args->argc == 3) {
		if (strlen(args->argv[2]) > MAX_ID_LEN) {
			printf("%% ERROR: ID too long!\n");
			goto free_args;
		}

		if (local)
			ret = librouter_ipsec_set_local_id(dynamic_ipsec_menu_name, args->argv[2]);
		else
			ret = librouter_ipsec_set_remote_id(dynamic_ipsec_menu_name, args->argv[2]);

	} else { /* DN for X.509 certificates */
		char *p;

		p = strstr(cmd, args->argv[2]); /* Get beggining of ID string */
		if (p == NULL) /* WTF! */
			goto free_args;

		if (local)
			ret = librouter_ipsec_set_local_id(dynamic_ipsec_menu_name, p);
		else
			ret = librouter_ipsec_set_remote_id(dynamic_ipsec_menu_name, p);
	}

	if (ret < 0) {
		printf("%% Not possible to set %s id\n", args->argv[0]);
		goto free_args;
	}

	/* Restart IPSec if it was active */
	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Not possible to set %s id\n", args->argv[0]);
		goto free_args;
	}

	if (ret > 0)
		librouter_ipsec_exec(RESTART);

free_args:
	librouter_destroy_args(args);
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
			printf("%% Not possible to clear %s id\n", args->argv[1]);
			goto free_args;
		}
		// se o link estiver ativo, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s id\n", args->argv[1]);
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
	char *ncmd;

	ncmd = librouter_device_to_linux_cmdline((char *)cmd);
	args = librouter_make_args(ncmd);

	if (args->argc < 2) {
		printf("%% Wrong number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	if (!strncmp(args->argv[0], "local", 5))
		local = 1;

	if (local && !strncmp(args->argv[2], "default-route", 13)) {
		ret = librouter_ipsec_set_local_addr(dynamic_ipsec_menu_name, STRING_DEFAULTROUTE);
		if (ret < 0) {
			printf("%% Not possible to set local address to default-route\n");
			goto free_args;
		}
	}
#ifdef IPSEC_SUPPORT_LOCAL_ADDRESS_INTERFACE
	else if (local && !strncmp(args->argv[2], "interface", 9)) {
		cish_dbg("Adding local as interface\n");

		sprintf(tp, "%%%s", args->argv[3]);

		ret = librouter_ipsec_set_local_addr(dynamic_ipsec_menu_name, tp);
		if (ret < 0) {
			printf("%% Not possible to set %s address to interface %s\n",
					args->argv[0], args->argv[3]);
			goto free_args;
		}
	}
#endif /* IPSEC_SUPPORT_LOCAL_ADDRESS_INTERFACE */
	else if (!local && !strncmp(args->argv[2], "any", 3)) {
		ret = librouter_ipsec_set_remote_addr(dynamic_ipsec_menu_name, STRING_ANY);
		if (ret < 0) {
			printf("%% Not possible to set %s address to any\n", args->argv[0]);
			goto free_args;
		}
	} else if (args->argc == 4 && (!strncmp(args->argv[2], "ip", 2) || !strncmp(
			args->argv[2], "fqdn", 4))) {
		if (strlen(args->argv[3]) < 200)
			strcpy(tp, args->argv[3]);
		else {
			printf("%% Not possible to set %s address\n", args->argv[0]);
			goto free_args;
		}

		if (local)
			ret = librouter_ipsec_set_local_addr(dynamic_ipsec_menu_name, tp);
		else
			ret = librouter_ipsec_set_remote_addr(dynamic_ipsec_menu_name, tp);
		if (ret < 0) {
			if (!strncmp(args->argv[2], "ip", 2))
				printf("%% Not possible to set %s ip address\n",
						args->argv[0]);
			else
				printf("%% Not possible to set %s fqdn address\n",
						args->argv[0]);
			goto free_args;
		}
	}

	/* If link was active, then restart the ipsec daemon */
	ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
	if (ret < 0) {
		printf("%% Not possible to set %s address\n", args->argv[0]);
		goto free_args;
	}
	if (ret > 0)
		librouter_ipsec_exec(RESTART);

free_args:
	librouter_destroy_args(args);
}

void set_ipsec_nexthop(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (!strncmp(args->argv[0], "local", 5))
			ret = librouter_ipsec_set_nexthop_inf(LOCAL, dynamic_ipsec_menu_name,
			                args->argv[2]);
		else
			ret = librouter_ipsec_set_nexthop_inf(REMOTE, dynamic_ipsec_menu_name,
			                args->argv[2]);
		if (ret < 0) {
			printf("%% Not possible to set %s nexthop\n", args->argv[0]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s nexthop\n", args->argv[0]);
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
			ret = librouter_ipsec_set_nexthop_inf(LOCAL, dynamic_ipsec_menu_name, "");
		else
			ret = librouter_ipsec_set_nexthop_inf(REMOTE, dynamic_ipsec_menu_name, "");
		if (ret < 0) {
			printf("%% Not possible to clear %s nexthop\n", args->argv[1]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s nexthop\n", args->argv[1]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}

#ifdef IPSEC_SUPPORT_RSA_RAW
void set_ipsec_remote_rsakey(const char *cmd) /* remote rsakey [publickey] */
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 3) {
		if (librouter_ipsec_set_remote_rsakey(dynamic_ipsec_menu_name, args->argv[2]) < 0) {
			printf("%% Not possible to set %s rsakey\n", args->argv[0]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s rsakey\n", args->argv[0]);
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
		if (librouter_ipsec_set_remote_rsakey(dynamic_ipsec_menu_name, "")
		                < 0) {
			printf("%% Not possible to clear %s rsakey\n", args->argv[1]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s rsakey\n", args->argv[1]);
			goto free_args;
		}
		if (ret > 0)
			librouter_ipsec_exec(RESTART);
	}
	free_args: librouter_destroy_args(args);
}
#endif /* IPSEC_SUPPORT_RSA_RAW */

void set_ipsec_subnet(const char *cmd)
{
	int ret;
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 4) {
		if (!strncmp(args->argv[0], "local", 5))
			ret = librouter_ipsec_set_subnet_inf(LOCAL, dynamic_ipsec_menu_name,
			                args->argv[2], args->argv[3]);
		else
			ret = librouter_ipsec_set_subnet_inf(REMOTE, dynamic_ipsec_menu_name,
			                args->argv[2], args->argv[3]);
		if (ret < 0) {
			printf("%% Not possible to set %s subnet\n", args->argv[0]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to set %s subnet\n", args->argv[0]);
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
			ret
			                = librouter_ipsec_set_subnet_inf(LOCAL,
			                                dynamic_ipsec_menu_name, "", "");
		else
			ret = librouter_ipsec_set_subnet_inf(REMOTE, dynamic_ipsec_menu_name, "",
			                "");
		if (ret < 0) {
			printf("%% Not possible to clear %s subnet\n", args->argv[1]);
			goto free_args;
		}
		// se o link estiver up, entao provocamos um RESTART no starter
		ret = librouter_ipsec_get_link(dynamic_ipsec_menu_name);
		if (ret < 0) {
			printf("%% Not possible to clear %s subnet\n", args->argv[1]);
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
			for (i = 0; i < IPSEC_MAX_CONN; i++, list++) {
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
			librouter_ipsec_set_protoport(dynamic_ipsec_menu_name, args->argv[2]);
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
			for (i = 0; i < IPSEC_MAX_CONN; i++) {
				if (*list != NULL) {
					for (j = CMDS_BEF_LIST;; j++) {
						if (CMD_IPSEC_CONNECTION_ADD[j].name == NULL) {
							if ((p = malloc(strlen(*list) + 1)) == NULL)
								break;
							strcpy(p, *list);
							list++;
							CMD_IPSEC_CONNECTION_ADD[j].name = p;
							CMD_IPSEC_CONNECTION_ADD[j].help
							                = "User connection";
							CMD_IPSEC_CONNECTION_ADD[j].func
							                = cd_connection_dir;
							CMD_IPSEC_CONNECTION_ADD[j].privilege = 1;
							// prepare del node
							CMD_CRYPTO_IPSEC_NO_CONN[j - CMDS_BEF_LIST].name
							                = p;
							CMD_CRYPTO_IPSEC_NO_CONN[j - CMDS_BEF_LIST].help
							                = "User connection";
							CMD_CRYPTO_IPSEC_NO_CONN[j - CMDS_BEF_LIST].func
							                = del_ipsec_conn;
							CMD_CRYPTO_IPSEC_NO_CONN[j - CMDS_BEF_LIST].privilege
							                = 1;
							break;
						}
					}
				}
			}
			// Libera memoria
			for (i = 0, list = list_ini; i < IPSEC_MAX_CONN; i++, list++)
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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.auth_user[0] = cfg.auth_pass[0] = 0;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
}

void l2tp_ppp_ipaddr(const char *cmd) /* l2tp ppp ip address <ipaddress> */
{
	arglist *args;
	ppp_config cfg;
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.ip_addr[0] = cfg.ip_mask[0] = 0;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
}

void l2tp_ppp_defaultroute(const char *cmd) /* l2tp ppp ip default-route */
{
	ppp_config cfg;
	memset(&cfg, 0, sizeof(ppp_config));

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (!cfg.default_route) {
		cfg.default_route = 1;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}

void l2tp_ppp_no_defaultroute(const char *cmd) /* no l2tp ppp ip default-route */
{
	ppp_config cfg;
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

	args = librouter_make_args(cmd);
	dev = librouter_device_cli_to_linux(args->argv[4], atoi(args->argv[5]), -1);

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
	memset(&cfg, 0, sizeof(ppp_config));

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	cfg.ip_addr[0] = cfg.ip_mask[0] = 0;
	cfg.ip_unnumbered = -1;
	librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
}

void l2tp_ppp_vj(const char *cmd) /* l2tp ppp ip vj */
{
	ppp_config cfg;
	memset(&cfg, 0, sizeof(ppp_config));

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (cfg.novj) {
		cfg.novj = 0;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}

void l2tp_ppp_no_vj(const char *cmd) /* no l2tp ppp ip vj */
{
	ppp_config cfg;
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

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
	memset(&cfg, 0, sizeof(ppp_config));

	librouter_ppp_l2tp_get_config(dynamic_ipsec_menu_name, &cfg);
	if (cfg.mtu) {
		cfg.mtu = 0;
		librouter_ppp_l2tp_set_config(dynamic_ipsec_menu_name, &cfg);
	}
}
#endif /* OPTION_IPSEC */

