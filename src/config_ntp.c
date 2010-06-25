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
	libconfig_ntp_authenticate(1);
}
#endif

void ntp_generate_keys(const char *cmd)
{
#if 1 /* 4.2.0 */
	system("/bin/ntp-keygen -M > /dev/null 2> /dev/null");
#else /* 4.1.1 */
	system("/bin/ntp-genkeys > /dev/null 2> /dev/null");
#endif
	libconfig_ntp_hup();
	libconfig_nv_save_ntp_secret(NTP_KEY_FILE); /* save keys on flash! */
}

void ntp_restrict(const char *cmd) /* ntp restrict <ipaddr> <netmask> */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (args->argc == 4) libconfig_ntp_restrict(args->argv[2], args->argv[3]);
	libconfig_destroy_args(args);
}

void ntp_server(const char *cmd) /* ntp server <ipaddr> [key <1-16>] */
{
	arglist *args;

	args=libconfig_make_args(cmd);
#ifdef CONFIG_BERLIN_SATROUTER
	if( is_network_up() > 0 ) {
		if(args->argc == 3)
			libconfig_ntp_server(args->argv[2], NULL);
		else if(args->argc == 5)
			libconfig_ntp_server(args->argv[2], args->argv[4]);
	}
	else
		printf("** NTP is based on network access. Please configure and " 
			"enable network first. Check also cables.\n** Command '%s' ignored!\n\n", cmd);
#else
	if (args->argc == 3) libconfig_ntp_server(args->argv[2], NULL);
		else if (args->argc == 5) libconfig_ntp_server(args->argv[2], args->argv[4]);
#endif
	libconfig_destroy_args(args);
}

void ntp_trust_on_key(const char *cmd) /* ntp trusted-key 1-16 */
{
	arglist *args;

	args = libconfig_make_args(cmd);
	if(args->argc == 3)	libconfig_ntp_trust_on_key(args->argv[2]);
	libconfig_destroy_args(args);
}

void ntp_set_key_value(const char *cmd) /* ntp authentication-key 1-16 md5 <hash> */
{
	arglist *args;

	args = libconfig_make_args(cmd);
	if(args->argc == 5)	libconfig_ntp_set_key(args->argv[2], args->argv[4]);
	libconfig_destroy_args(args);
}

#ifdef OPTION_NTPD_authenticate
void no_ntp_authenticate(const char *cmd)
{
	libconfig_ntp_authenticate(0);
}
#endif

void no_ntp_restrict(const char *cmd) /* no ntp restrict [<ipaddr>] */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (args->argc == 4) libconfig_ntp_exclude_restrict(args->argv[3]);
		else libconfig_ntp_exclude_restrict(NULL);
	libconfig_destroy_args(args);
}

void no_ntp_server(const char *cmd) /* no ntp server [<ipaddr>] */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (args->argc == 4) libconfig_ntp_exclude_server(args->argv[3]);
		else libconfig_ntp_exclude_server(NULL);
	libconfig_destroy_args(args);
}

void no_ntp_trustedkeys(const char *cmd) /* no ntp trusted-key [<1-16>] */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (args->argc == 4) libconfig_ntp_exclude_trustedkeys(args->argv[3]);
		else libconfig_ntp_exclude_trustedkeys(NULL);
	libconfig_destroy_args(args);
}

void ntp_update_calendar(const char *cmd)
{
	if (set_rtc_with_system_date() < 0)
		printf("%% Could not execute command\n");
}
#endif

