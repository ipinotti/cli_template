
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

	args=librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_debug_set_all(0);
		_cish_debug = 0;
		if (librouter_quagga_ospfd_is_running())
			ospf_execute_root_cmd(no_debug_ospf);
		if (librouter_quagga_ripd_is_running())
			rip_execute_root_cmd(no_debug_rip);
#ifdef OPTION_BGP
		if (librouter_quagga_bgpd_is_running())
			bgp_execute_root_cmd(no_debug_bgp);
#endif
	} else {
		librouter_debug_set_all(1);
		_cish_debug = 1;
		if (librouter_quagga_ospfd_is_running())
			ospf_execute_root_cmd(&no_debug_ospf[3]);
		if (librouter_quagga_ripd_is_running())
			rip_execute_root_cmd(&no_debug_rip[3]);
#ifdef OPTION_BGP
		if (librouter_quagga_bgpd_is_running())
			bgp_execute_root_cmd(&no_debug_bgp[3]); /* debug bgp events */
#endif
	}
	librouter_destroy_args(args);
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

	args=librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {
#ifdef CONFIG_BERLIN_SATROUTER
		if (librouter_debug_set_token(0, args->argv[2]) >= 0) _cish_debug = 0;
#else
		if (librouter_debug_set_token(0, args->argv[2]) >= 0) _cish_debug = 0;
#endif
		if (strcmp(args->argv[2], "ospf") == 0) {
			if (librouter_quagga_ospfd_is_running())
				ospf_execute_root_cmd(no_debug_ospf);
		} else if (strcmp(args->argv[2], "rip") == 0) {
			if (librouter_quagga_ripd_is_running())
				rip_execute_root_cmd(no_debug_rip);
		}
#ifdef OPTION_BGP
		else if (strcmp(args->argv[2], "bgp") == 0) {
			if (librouter_quagga_bgpd_is_running())
				bgp_execute_root_cmd(no_debug_bgp);
		}
#endif
	} else {
#ifdef OPTION_X25
		if (args->argc > 2) /* x25 */
			vc = atoi(args->argv[2]);
#endif
		if (librouter_debug_set_token(1, args->argv[1]) >= 0)
			_cish_debug = 1;
		if (strcmp(args->argv[1], "ospf") == 0) {
			if (librouter_quagga_ospfd_is_running()) ospf_execute_root_cmd(&no_debug_ospf[3]);
		} else if (strcmp(args->argv[1], "rip") == 0) {
			if (librouter_quagga_ripd_is_running()) rip_execute_root_cmd(&no_debug_rip[3]);
		}
#ifdef OPTION_BGP
		else if (strcmp(args->argv[1], "bgp") == 0) {
			if (librouter_quagga_bgpd_is_running())
				bgp_execute_root_cmd(&no_debug_bgp[3]); /* debug bgp events */
		}
#endif
	}
	librouter_destroy_args(args);
}

void show_debug(const char *cmd)
{
	librouter_debug_dump();
}

#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_LOG_CONSOLE)

#define TIOSERDEBUG		0x545E	/* enable/disable low level uart debug */

void debug_console(const char *cmd)
{
	int pf;
	arglist *args;
	unsigned int debug;

	args = librouter_make_args(cmd);
	debug = (strcmp(args->argv[0], "no")==0 ? 0 : 1);
	if( (pf = open(TTS_AUX1, O_RDWR | O_NDELAY)) < 0 )
	{
		librouter_destroy_args(args);
		printf("Not possible to enable/disable debug\n");
		return;
	}
	if( ioctl(pf, TIOSERDEBUG, &debug) != 0 )
	{
		close(pf);
		librouter_destroy_args(args);
		printf("Not possible to enable/disable debug\n");
		return;
	}
	close(pf);
	librouter_destroy_args(args);
}

#endif

