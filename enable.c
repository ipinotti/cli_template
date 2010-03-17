#include <linux/config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>

#include <readline/readline.h>
#include <readline/history.h>

#define __USE_XOPEN
#include <unistd.h> 

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <libconfig/args.h>
#include <libconfig/cish_defines.h>
#include <libconfig/str.h>
#include <libconfig/pam.h>
#include <libconfig/defines.h>

#include "cish_config.h"
#include "commandtree.h"
#include "commands.h"
#include "cish_main.h"
#include "terminal_echo.h"
#include "cish_main.h"

extern cish_command CMD[];

extern unsigned int readString(int echo_on, char *store, unsigned int max_len);

void enable(const char *cmdline)
{
	char  passwd[32];
	char  secret[32];
	char *crypt_passwd;
	int   authentication_pending = 1;

#ifdef CONFIG_BERLIN_SATROUTER
	{
		int i, oktorun=0, mode=discover_pam_enable_current_mode();

		if( mode==AAA_AUTH_RADIUS || mode==AAA_AUTH_TACACS )
		{
			switch( mode )
			{
				case AAA_AUTH_RADIUS:
					for(i=0; i < MAX_SERVERS; i++)
					{
						if(cish_cfg->radius[i].ip_addr[0])
						{
							oktorun = 1;
							break;
						}
					}
					break;

				case AAA_AUTH_TACACS:
					for(i=0; i < MAX_SERVERS; i++)
					{
						if(cish_cfg->tacacs[i].ip_addr[0])
						{
							oktorun = 1;
							break;
						}
					}
					break;
			}
			if( oktorun )
			{
				while( authentication_pending )
				{
					if( proceed_third_authentication("$enable$", "enable") == AUTH_NOK )
						authentication_pending++;
					else
						break;

					if( authentication_pending > 3 )
					{
						syslog(LOG_WARNING, "excess failures on enable from %s", _cish_source);
						fprintf(stderr, "%% Excess failures\n");
						return;
					}
					else
					{
						syslog(LOG_WARNING, "enable authentication failure from %s", _cish_source);
						sleep(2);
						fprintf(stderr, "%% Login failed\n");
					}
				}
				goto enable_ok;
			}
			else
				fprintf (stderr, "%% No %s server configured! Doing local authentication.\n", 
					(mode==AAA_AUTH_RADIUS ? "radius" : (mode==AAA_AUTH_TACACS ? "Tacacs+" : "" )));
		}
	}
#endif
	
	strncpy (secret, cish_cfg->enable_secret, 16);
	if (!strlen (secret))
	{
		fprintf(stderr, "%% WARNING: No enable secret set\n");
		goto enable_ok;
	}

	while (authentication_pending)
	{
		printf("Password: ");
		fflush(stdout);
		passwd[0] = 0;

		echo_off();
		cish_timeout = cish_cfg->terminal_timeout;
		fgets(passwd, 16, stdin);
		cish_timeout = 0;
		echo_on();
		printf("\n");

		passwd[16] = 0;
		striplf(passwd);

		crypt_passwd = crypt(passwd, secret);
		if (strcmp(crypt_passwd, secret) == 0) {
			authentication_pending = 0;
			break;
		} else
			++authentication_pending;

		if (authentication_pending > 3)
		{
			syslog(LOG_WARNING, "excess failures on enable from %s", _cish_source);
			fprintf(stderr, "%% Excess failures\n\n");
			return;
		}
		else if (authentication_pending)
		{
			syslog(LOG_WARNING, "enable authentication failure from %s", _cish_source);
			sleep(2);
			fprintf(stderr, "%% Login failed\n\n");
		}
	}
enable_ok:
	syslog(LOG_INFO, "raised privileges on session from %s", _cish_source);
	_cish_enable = 1;
	CMD[6].privilege=2; /* �enable� hidden! */
}

int is_safe(const char *passwd)
{
	int acnt, nacnt;
	const char *crsr;

	crsr = passwd;
	acnt = nacnt = 0;

	while (*crsr)
		isalpha(*(crsr++)) ? ++acnt : ++nacnt;

	if ((acnt+nacnt) < 6) return 0;
	if ((!acnt)||(!nacnt)) return 0;

	return 1;
}

const char HASHVAL[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

void set_http_secret(char *secret)
{
	FILE *f;

	if (*secret)
	{
		f=fopen("/var/web/.htpasswd", "wt");
		if (!f) return;
		fprintf(f, "root:%s\n", secret);
		fclose(f);
		chown("/var/web/.htpasswd", 500, 254);
	}
	else unlink("/var/web/.htpasswd");
}

void set_admin_secret(char *secret) /* use login password! */
{
	char buffer[256];

	if (secret && strlen(secret)) snprintf(buffer, 255, "/bin/passwd admin -c %s", secret);
	else snprintf(buffer, 255, "/bin/passwd admin -d >/dev/null 2>/dev/null");

	system(buffer);
}

void set_upload_secret(char *secret) /* use enable password! */
{
	char buffer[256];

	if (secret && strlen(secret)) snprintf(buffer, 255, "/bin/passwd upload -c %s >/dev/null 2>/dev/null", secret);
	else snprintf(buffer, 255, "/bin/passwd upload -d >/dev/null 2>/dev/null");
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

	arglist	*args = make_args(cmdline);

	if (args->argc == 4) { /* store hash! */
		if (strcmp(args->argv[1], "enable") == 0) {
			strncpy(cish_cfg->enable_secret, args->argv[3], 15);
			cish_cfg->enable_secret[14] = 0;
			set_http_secret(cish_cfg->enable_secret);
			set_upload_secret(cish_cfg->enable_secret);
		}
		else {
			strncpy(cish_cfg->login_secret, args->argv[3], 15);
			cish_cfg->login_secret[14] = 0;
			set_admin_secret(cish_cfg->login_secret);
		}
	}
	else {
		for( count=0; count < 3; count++ ) {
			printf("Enter new password  : ");
			fflush(stdout);
			echo_off();
			cish_timeout = cish_cfg->terminal_timeout;
			fgets(in_passwd, 16, stdin);
			/* Descarta possivel lixo que tenha ficado no stdin */
			if( strchr(in_passwd, '\n') == NULL ) {
				char durt[2];
				while( fgets(durt, 2, stdin) == durt ) {
					if( durt[0] == '\n' )
						break;
				}
			}
			cish_timeout = 0;
			echo_on();
			striplf(in_passwd);
			printf("\n");
			if( is_safe(in_passwd) != 0 )
				break;
			printf ("%% Password must be 6-8 characters with at least one non-alpha\n");
		}
		if( count >= 3 ) {
			printf("\n%% Excess failures - aborted\n");
			destroy_args(args);
			return;
		}

		printf("Enter password again: ");
		fflush(stdout);
		echo_off();
		cish_timeout = cish_cfg->terminal_timeout;
		fgets(in_passwd_validate, 16, stdin);
		cish_timeout = 0;
		echo_on();
		striplf(in_passwd_validate);
		printf("\n");

		if (strcmp(in_passwd, in_passwd_validate)) /* different */
			printf("\n%% Password mismatch - aborted.\n");
		else {
			gettimeofday(&tv, &tz);
			ti = time(NULL);

			srand (((unsigned int) (ti & 0xff)) ^ ((unsigned int) tv.tv_usec & 0xffffffff));

			in_hash[0] = HASHVAL[rand()&63];
			in_hash[1] = HASHVAL[rand()&63];

			crp = crypt(in_passwd, in_hash);
			if (crp && strlen (crp)) {
				if (strcmp(args->argv[1], "enable") == 0) {
					strncpy(cish_cfg->enable_secret, crp, 15);
					cish_cfg->enable_secret[14] = 0;
					set_http_secret(cish_cfg->enable_secret);
					set_upload_secret(cish_cfg->enable_secret);
				}
				else {
					strncpy(cish_cfg->login_secret, crp, 15);
					cish_cfg->login_secret[14] = 0;
					set_admin_secret(cish_cfg->login_secret);
				}
			}
			else
				printf("%% Unknown failure\n");
		}
	}
	destroy_args(args);
}

void set_nosecret(const char *cmdline) /* no secret enable|login */
{
	arglist	*args = make_args(cmdline);

	if (strcmp(args->argv[2], "enable") == 0) {
		cish_cfg->enable_secret[0] = 0;
		set_http_secret(cish_cfg->enable_secret);
		set_upload_secret(NULL);
	} else {
		cish_cfg->login_secret[0] = 0;
		set_admin_secret(NULL);
	}
	destroy_args (args);
}

void disable(const char *cmdline)
{
	_cish_enable = 0;
	CMD[6].privilege=0; /* Enable �enable� */
}

#ifdef CONFIG_BERLIN_SATROUTER

void clear_enable_secret(const char *cmdline)	/* no enable secret */
{
	cish_cfg->enable_secret[0] = 0;
}

void set_enable_secret(const char *cmdline)	/* enable secret hash/cleartext <password> */
{
	time_t ti;
	struct timeval tv;
	struct timezone tz;
	char *crp, in_hash[4];

	arglist	*args = make_args(cmdline);
	if( !strcmp(args->argv[2], "hash") )
	{
		strncpy(cish_cfg->enable_secret, args->argv[3], 15);
		cish_cfg->enable_secret[14] = 0;
	}
	else if( !strcmp(args->argv[2], "cleartext") )
	{
		if( !is_safe(args->argv[3]) )
			printf("%% Password must be 6-8 characters with at least one non-alpha\n");
		else
		{
			gettimeofday(&tv, &tz);
			ti = time( NULL );

			srand( ((unsigned int) (ti & 0xff)) ^ ((unsigned int) tv.tv_usec & 0xffffffff) );

			in_hash[0] = HASHVAL[ rand()&63 ];
			in_hash[1] = HASHVAL[ rand()&63 ];
			crp = crypt(args->argv[3], in_hash);
			if(crp && strlen(crp))
			{
				strncpy(cish_cfg->enable_secret, crp, 15);
				cish_cfg->enable_secret[14] = 0;
			}
			else
				printf("%% Unknown failure\n");
		}
	}
	destroy_args (args);
}

void no_enable_tacrad(const char *cmdline)	/* no aaa authentication enable */
{
	conf_enable_pam_mode(cish_cfg, AAA_AUTH_NONE, 1);
}

void set_enable_tacrad(const char *cmdline)	/* aaa authentication enable group radius/tacacs */
{
	arglist	*args = make_args(cmdline);

	if( args->argc == 5 )
	{
		if( !conf_enable_pam_mode(cish_cfg, strcmp(args->argv[4], "radius")==0 ? AAA_AUTH_RADIUS : AAA_AUTH_TACACS, 1) )
			printf("%% Not possible to configure authentication method\n");
	}
	destroy_args (args);
}

#endif

