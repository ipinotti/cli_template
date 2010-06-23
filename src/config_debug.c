
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "commands.h"
#include "commandtree.h"

int _cish_debug;

void debug_all(const char *cmd) /* [no] debug all */
{
	arglist *args;
	char no_debug_ospf[]="no debug ospf event";
	char no_debug_rip[]="no debug rip events";
#ifdef OPTION_BGP
	char no_debug_bgp[]="no debug bgp events";
#endif

	args=libconfig_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {
		libconfig_debug_set_all(0);
		_cish_debug = 0;
		if (get_ospfd())
			ospf_execute_root_cmd(no_debug_ospf);
		if (get_ripd())
			rip_execute_root_cmd(no_debug_rip);
#ifdef OPTION_BGP
		if (get_bgpd())
			bgp_execute_root_cmd(no_debug_bgp);
#endif
	} else {
		libconfig_debug_set_all(1);
		_cish_debug = 1;
		if (get_ospfd())
			ospf_execute_root_cmd(&no_debug_ospf[3]);
		if (get_ripd())
			rip_execute_root_cmd(&no_debug_rip[3]);
#ifdef OPTION_BGP
		if (get_bgpd())
			bgp_execute_root_cmd(&no_debug_bgp[3]); /* debug bgp events */
#endif
	}
	libconfig_destroy_args(args);
}

void debug_one(const char *cmd) /* [no] debug <token> */
{
	arglist *args;
	char no_debug_ospf[]="no debug ospf event";
	char no_debug_rip[]="no debug rip events";
#ifdef OPTION_BGP
	char no_debug_bgp[]="no debug bgp events";
#endif
#ifdef OPTION_X25
	int vc = 0; /* x25 */
#endif

	args=libconfig_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {
#ifdef CONFIG_BERLIN_SATROUTER
		if (libconfig_debug_set_token(0, args->argv[2]) >= 0) _cish_debug = 0;
#else
		if (libconfig_debug_set_token(0, args->argv[2]) >= 0) _cish_debug = 0;
#endif
		if (strcmp(args->argv[2], "ospf") == 0) {
			if (get_ospfd())
				ospf_execute_root_cmd(no_debug_ospf);
		} else if (strcmp(args->argv[2], "rip") == 0) {
			if (get_ripd())
				rip_execute_root_cmd(no_debug_rip);
		}
#ifdef OPTION_BGP
		else if (strcmp(args->argv[2], "bgp") == 0) {
			if (get_bgpd())
				bgp_execute_root_cmd(no_debug_bgp);
		}
#endif
	} else {
#ifdef OPTION_X25
		if (args->argc > 2) /* x25 */
			vc = atoi(args->argv[2]);
#endif
		if (libconfig_debug_set_token(1, args->argv[1]) >= 0)
			_cish_debug = 1;
		if (strcmp(args->argv[1], "ospf") == 0) {
			if (get_ospfd()) ospf_execute_root_cmd(&no_debug_ospf[3]);
		} else if (strcmp(args->argv[1], "rip") == 0) {
			if (get_ripd()) rip_execute_root_cmd(&no_debug_rip[3]);
		}
#ifdef OPTION_BGP
		else if (strcmp(args->argv[1], "bgp") == 0) {
			if (get_bgpd())
				bgp_execute_root_cmd(&no_debug_bgp[3]); /* debug bgp events */
		}
#endif
	}
	libconfig_destroy_args(args);
}

void show_debug(const char *cmd)
{
	libconfig_debug_dump();
}

#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_LOG_CONSOLE)

#define TIOSERDEBUG		0x545E	/* enable/disable low level uart debug */

void debug_console(const char *cmd)
{
	int pf;
	arglist *args;
	unsigned int debug;

	args = libconfig_make_args(cmd);
	debug = (strcmp(args->argv[0], "no")==0 ? 0 : 1);
	if( (pf = open(TTS_AUX1, O_RDWR | O_NDELAY)) < 0 )
	{
		libconfig_destroy_args(args);
		printf("Not possible to enable/disable debug\n");
		return;
	}
	if( ioctl(pf, TIOSERDEBUG, &debug) != 0 )
	{
		close(pf);
		libconfig_destroy_args(args);
		printf("Not possible to enable/disable debug\n");
		return;
	}
	close(pf);
	libconfig_destroy_args(args);
}

#endif

