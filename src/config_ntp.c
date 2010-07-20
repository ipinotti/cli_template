#include <stdlib.h>

#include <ctype.h>
#include <stdio.h>
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

#ifdef OPTION_NTPD
#ifdef OPTION_NTPD_authenticate
void ntp_authenticate(const char *cmd)
{
	librouter_ntp_authenticate(1);
}
#endif

void ntp_generate_keys(const char *cmd)
{
#if 1 /* 4.2.0 */
	system("/bin/ntp-keygen -M > /dev/null 2> /dev/null");
#else /* 4.1.1 */
	system("/bin/ntp-genkeys > /dev/null 2> /dev/null");
#endif
	librouter_ntp_hup();
	librouter_nv_save_ntp_secret(NTP_KEY_FILE); /* save keys on flash! */
}

void ntp_restrict(const char *cmd) /* ntp restrict <ipaddr> <netmask> */
{
	arglist *args;

	args=librouter_make_args(cmd);
	if (args->argc == 4) librouter_ntp_restrict(args->argv[2], args->argv[3]);
	librouter_destroy_args(args);
}

void ntp_server(const char *cmd) /* ntp server <ipaddr> [key <1-16>] */
{
	arglist *args;

	args=librouter_make_args(cmd);

	if (args->argc == 3)
		librouter_ntp_server(args->argv[2], NULL);
	else if (args->argc == 5)
		librouter_ntp_server(args->argv[2], args->argv[4]);

	librouter_destroy_args(args);
}

void ntp_trust_on_key(const char *cmd) /* ntp trusted-key 1-16 */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if(args->argc == 3)	librouter_ntp_trust_on_key(args->argv[2]);
	librouter_destroy_args(args);
}

void ntp_set_key_value(const char *cmd) /* ntp authentication-key 1-16 md5 <hash> */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if(args->argc == 5)	librouter_ntp_set_key(args->argv[2], args->argv[4]);
	librouter_destroy_args(args);
}

#ifdef OPTION_NTPD_authenticate
void no_ntp_authenticate(const char *cmd)
{
	librouter_ntp_authenticate(0);
}
#endif

void no_ntp_restrict(const char *cmd) /* no ntp restrict [<ipaddr>] */
{
	arglist *args;

	args=librouter_make_args(cmd);
	if (args->argc == 4) librouter_ntp_exclude_restrict(args->argv[3]);
		else librouter_ntp_exclude_restrict(NULL);
	librouter_destroy_args(args);
}

void no_ntp_server(const char *cmd) /* no ntp server [<ipaddr>] */
{
	arglist *args;

	args = librouter_make_args(cmd);

	if (args->argc == 4)
		librouter_ntp_exclude_server(args->argv[3]);
	else
		librouter_ntp_exclude_server(NULL);

	librouter_destroy_args(args);
}

void ntp_enable(const char *cmd)
{
	arglist *args;

	args = librouter_make_args(cmd);

	if (args->argc == 3) /* no ntp enable */
		librouter_ntp_set_daemon(0);
	else
		librouter_ntp_set_daemon(1);

	librouter_destroy_args(args);
}

void no_ntp_trustedkeys(const char *cmd) /* no ntp trusted-key [<1-16>] */
{
	arglist *args;

	args=librouter_make_args(cmd);
	if (args->argc == 4) librouter_ntp_exclude_trustedkeys(args->argv[3]);
		else librouter_ntp_exclude_trustedkeys(NULL);
	librouter_destroy_args(args);
}

void ntp_update_calendar(const char *cmd)
{
	if (librouter_time_system_to_rtc() < 0)
		printf("%% Could not execute command\n");
}
#endif

