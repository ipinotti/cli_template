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

#include <libconfig/options.h>
#include <libconfig/args.h>
#include <libconfig/ntp.h>
#include <libconfig/nv.h>
#include <libconfig/libtime.h>
#include <libconfig/quagga.h>

#ifdef OPTION_NTPD
#ifdef OPTION_NTPD_authenticate
void ntp_authenticate(const char *cmd)
{
	do_ntp_authenticate(1);
}
#endif

void ntp_generate_keys(const char *cmd)
{
#if 1 /* 4.2.0 */
	system("/bin/ntp-keygen -M > /dev/null 2> /dev/null");
#else /* 4.1.1 */
	system("/bin/ntp-genkeys > /dev/null 2> /dev/null");
#endif
	ntp_hup();
	save_ntp_secret(NTP_KEY_FILE); /* save keys on flash! */
}

void ntp_restrict(const char *cmd) /* ntp restrict <ipaddr> <netmask> */
{
	arglist *args;

	args=make_args(cmd);
	if (args->argc == 4) do_ntp_restrict(args->argv[2], args->argv[3]);
	destroy_args(args);
}

void ntp_server(const char *cmd) /* ntp server <ipaddr> [key <1-16>] */
{
	arglist *args;

	args=make_args(cmd);
#ifdef CONFIG_BERLIN_SATROUTER
	if( is_network_up() > 0 ) {
		if(args->argc == 3)
			do_ntp_server(args->argv[2], NULL);
		else if(args->argc == 5)
			do_ntp_server(args->argv[2], args->argv[4]);
	}
	else
		printf("** NTP is based on network access. Please configure and " 
			"enable network first. Check also cables.\n** Command '%s' ignored!\n\n", cmd);
#else
	if (args->argc == 3) do_ntp_server(args->argv[2], NULL);
		else if (args->argc == 5) do_ntp_server(args->argv[2], args->argv[4]);
#endif
	destroy_args(args);
}

void ntp_trust_on_key(const char *cmd) /* ntp trusted-key 1-16 */
{
	arglist *args;

	args = make_args(cmd);
	if(args->argc == 3)	do_ntp_trust_on_key(args->argv[2]);
	destroy_args(args);
}

void ntp_set_key_value(const char *cmd) /* ntp authentication-key 1-16 md5 <hash> */
{
	arglist *args;

	args = make_args(cmd);
	if(args->argc == 5)	do_ntp_key_set(args->argv[2], args->argv[4]);
	destroy_args(args);
}

#ifdef OPTION_NTPD_authenticate
void no_ntp_authenticate(const char *cmd)
{
	do_ntp_authenticate(0);
}
#endif

void no_ntp_restrict(const char *cmd) /* no ntp restrict [<ipaddr>] */
{
	arglist *args;

	args=make_args(cmd);
	if (args->argc == 4) do_exclude_ntp_restrict(args->argv[3]);
		else do_exclude_ntp_restrict(NULL);
	destroy_args(args);
}

void no_ntp_server(const char *cmd) /* no ntp server [<ipaddr>] */
{
	arglist *args;

	args=make_args(cmd);
	if (args->argc == 4) do_exclude_ntp_server(args->argv[3]);
		else do_exclude_ntp_server(NULL);
	destroy_args(args);
}

void no_ntp_trustedkeys(const char *cmd) /* no ntp trusted-key [<1-16>] */
{
	arglist *args;

	args=make_args(cmd);
	if (args->argc == 4) do_exclude_ntp_trustedkeys(args->argv[3]);
		else do_exclude_ntp_trustedkeys(NULL);
	destroy_args(args);
}

void ntp_update_calendar(const char *cmd)
{
	if (set_rtc_with_system_date() < 0)
		printf("%% Could not execute command\n");
}
#endif

