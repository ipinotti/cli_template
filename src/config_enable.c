#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define __USE_XOPEN
#include <unistd.h>
#include <syslog.h>

#include <sys/time.h>


#include <readline/readline.h>
#include <readline/history.h>

#include "commands.h"
#include "commandtree.h"

#include "cish_main.h"
#include "terminal_echo.h"
#include "cish_main.h"

extern unsigned int readString(int echo_on, char *store, unsigned int max_len);

void enable(const char *cmdline)
{
	int authentication_pending = 1;
	int mode = librouter_pam_get_current_mode(FILE_PAM_ENABLE);

	if (mode != AAA_AUTH_NONE) {
		while (authentication_pending) {
				if (librouter_pam_enable_authenticate() == AUTH_NOK)
					authentication_pending++;
				else
					break;

				if (authentication_pending > 3) {
					syslog(LOG_WARNING, "excess failures on enable from %s",
					                _cish_source);
					fprintf(stderr, "%% Excess failures\n");
					return;
				} else {
					syslog(LOG_WARNING,
					                "enable authentication failure from %s",
					                _cish_source);
					sleep(2);
					fprintf(stderr, "%% Login failed\n");
				}
			}
			goto enable_ok;
	}

#if 0
	/* Should we try to authenticate even if no authentication is configured ? */
	else {
		char passwd[32];
		char secret[32];
		char *crypt_passwd;

		strncpy(secret, router_cfg->enable_secret, 16);
		if (!strlen(secret)) {
			fprintf(stderr, "%% WARNING: No enable secret set\n");
			goto enable_ok;
		}

		while (authentication_pending) {
			printf("Password: ");
			fflush(stdout);
			passwd[0] = 0;

			echo_off();
			cish_timeout = router_cfg->terminal_timeout;
			fgets(passwd, 16, stdin);
			cish_timeout = 0;
			echo_on();
			printf("\n");

			passwd[16] = 0;
			librouter_str_striplf(passwd);

			crypt_passwd = crypt(passwd, secret);
			if (strcmp(crypt_passwd, secret) == 0) {
				authentication_pending = 0;
				break;
			} else
				++authentication_pending;

			if (authentication_pending > 3) {
				syslog(LOG_WARNING, "excess failures on enable from %s",
				                _cish_source);
				fprintf(stderr, "%% Excess failures\n\n");
				return;
			} else if (authentication_pending) {
				syslog(LOG_WARNING, "enable authentication failure from %s",
				                _cish_source);
				sleep(2);
				fprintf(stderr, "%% Login failed\n\n");
			}
		}
	}
#endif
enable_ok:
	syslog(LOG_INFO, "raised privileges on session from %s", _cish_source);

	_cish_enable = 1;
	_cish_mask &= ~MSK_ENABLE; /* Hide enable command */
}

int is_safe(const char *passwd)
{
	int acnt, nacnt;
	const char *crsr;

	crsr = passwd;
	acnt = nacnt = 0;

	while (*crsr)
		isalpha(*(crsr++)) ? ++acnt : ++nacnt;

	if ((acnt + nacnt) < 6)
		return 0;
	if ((!acnt) || (!nacnt))
		return 0;

	return 1;
}

const char HASHVAL[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

void set_http_secret(char *secret)
{
	FILE *f;

	if (*secret) {
		f = fopen("/var/web/.htpasswd", "wt");
		if (!f)
			return;
		fprintf(f, "root:%s\n", secret);
		fclose(f);
		chown("/var/web/.htpasswd", 500, 254);
	} else
		unlink("/var/web/.htpasswd");
}

void set_admin_secret(char *secret) /* use login password! */
{
	char buffer[256];

	if (secret && strlen(secret))
		snprintf(buffer, 255, "/bin/passwd admin -c %s", secret);
	else
		snprintf(buffer, 255, "/bin/passwd admin -d >/dev/null 2>/dev/null");

	system(buffer);
}

void set_upload_secret(char *secret) /* use enable password! */
{
	char buffer[256];

	if (secret && strlen(secret))
		snprintf(buffer, 255, "/bin/passwd upload -c %s >/dev/null 2>/dev/null", secret);
	else
		snprintf(buffer, 255, "/bin/passwd upload -d >/dev/null 2>/dev/null");
	system(buffer);
}

void set_enable_secret(char *secret)
{
	char buffer[256];

	if (secret && strlen(secret))
		snprintf(buffer, 255, "/bin/passwd '$enable$' -c %s >/dev/null 2>/dev/null", secret);
	else
		snprintf(buffer, 255, "/bin/passwd '$enable$' -d >/dev/null 2>/dev/null");
	system(buffer);
}

void setsecret(const char *cmdline) /* secret enable|login [hash cryptedpassword] */
{
	char *crp;
	char in_passwd[32];
	char in_passwd_validate[32];
	char in_hash[4];
	struct timeval tv;
	struct timezone tz;
	time_t ti;
	int count;

	arglist *args = librouter_make_args(cmdline);

	if (args->argc == 4) { /* store hash! */
		if (strcmp(args->argv[1], "enable") == 0) {
			strncpy(router_cfg->enable_secret, args->argv[3], 15);
			router_cfg->enable_secret[14] = 0;
			set_http_secret(router_cfg->enable_secret);
			set_upload_secret(router_cfg->enable_secret);
			set_enable_secret(router_cfg->enable_secret);
		} else {
			strncpy(router_cfg->login_secret, args->argv[3], 15);
			router_cfg->login_secret[14] = 0;
			set_admin_secret(router_cfg->login_secret);
		}
	} else {
		for (count = 0; count < 3; count++) {
			printf("Enter new password  : ");
			fflush(stdout);
			echo_off();
			cish_timeout = router_cfg->terminal_timeout;
			fgets(in_passwd, 16, stdin);
			/* Descarta possivel lixo que tenha ficado no stdin */
			if (strchr(in_passwd, '\n') == NULL) {
				char durt[2];
				while (fgets(durt, 2, stdin) == durt) {
					if (durt[0] == '\n')
						break;
				}
			}
			cish_timeout = 0;
			echo_on();
			librouter_str_striplf(in_passwd);
			printf("\n");
			if (is_safe(in_passwd) != 0)
				break;
			printf("%% Password must be 6-8 characters with at least one non-alpha\n");
		}
		if (count >= 3) {
			printf("\n%% Excess failures - aborted\n");
			librouter_destroy_args(args);
			return;
		}

		printf("Enter password again: ");
		fflush(stdout);
		echo_off();
		cish_timeout = router_cfg->terminal_timeout;
		fgets(in_passwd_validate, 16, stdin);
		cish_timeout = 0;
		echo_on();
		librouter_str_striplf(in_passwd_validate);
		printf("\n");

		if (strcmp(in_passwd, in_passwd_validate)) /* different */
			printf("\n%% Password mismatch - aborted.\n");
		else {
			gettimeofday(&tv, &tz);
			ti = time(NULL);

			srand(
			                ((unsigned int) (ti & 0xff)) ^ ((unsigned int) tv.tv_usec
			                                & 0xffffffff));

			in_hash[0] = HASHVAL[rand() & 63];
			in_hash[1] = HASHVAL[rand() & 63];

			crp = crypt(in_passwd, in_hash);
			if (crp && strlen(crp)) {
				if (strcmp(args->argv[1], "enable") == 0) {
					strncpy(router_cfg->enable_secret, crp, 15);
					router_cfg->enable_secret[14] = 0;
					set_http_secret(router_cfg->enable_secret);
					set_upload_secret(router_cfg->enable_secret);
					set_enable_secret(router_cfg->enable_secret);
				} else {
					strncpy(router_cfg->login_secret, crp, 15);
					router_cfg->login_secret[14] = 0;
					set_admin_secret(router_cfg->login_secret);
				}
			} else
				printf("%% Unknown failure\n");
		}
	}
	librouter_destroy_args(args);
}

void set_nosecret(const char *cmdline) /* no secret enable|login */
{
	arglist *args = librouter_make_args(cmdline);

	if (strcmp(args->argv[2], "enable") == 0) {
		router_cfg->enable_secret[0] = 0;
		set_http_secret(router_cfg->enable_secret);
		set_upload_secret(NULL);
		set_enable_secret(NULL);
	} else {
		router_cfg->login_secret[0] = 0;
		set_admin_secret(NULL);
	}
	librouter_destroy_args(args);
}

void disable(const char *cmdline)
{
	_cish_enable = 0;
	_cish_mask |= MSK_ENABLE;
}
