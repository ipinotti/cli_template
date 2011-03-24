
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
#ifdef OPTION_ROUTER
	char no_debug_ospf[]="no debug ospf event";
	char no_debug_rip[]="no debug rip events";
#ifdef OPTION_BGP
	char no_debug_bgp[]="no debug bgp events";
#endif
#endif

	args=librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_debug_set_all(0);
		_cish_debug = 0;
#ifdef OPTION_ROUTER
		if (librouter_quagga_ospfd_is_running())
			ospf_execute_root_cmd(no_debug_ospf);
		if (librouter_quagga_ripd_is_running())
			rip_execute_root_cmd(no_debug_rip);
#ifdef OPTION_BGP
		if (librouter_quagga_bgpd_is_running())
			bgp_execute_root_cmd(no_debug_bgp);
#endif
#endif /* OPTION_ROUTER */
	} else {
		librouter_debug_set_all(1);
		_cish_debug = 1;
#ifdef OPTION_ROUTER
		if (librouter_quagga_ospfd_is_running())
			ospf_execute_root_cmd(&no_debug_ospf[3]);
		if (librouter_quagga_ripd_is_running())
			rip_execute_root_cmd(&no_debug_rip[3]);
#ifdef OPTION_BGP
		if (librouter_quagga_bgpd_is_running())
			bgp_execute_root_cmd(&no_debug_bgp[3]); /* debug bgp events */
#endif
#endif /* OPTION_ROUTER */
	}
	librouter_destroy_args(args);
}

void debug_one(const char *cmd) /* [no] debug <token> */
{
	arglist *args;
#ifdef OPTION_ROUTER
	char no_debug_ospf[]="no debug ospf event";
	char no_debug_rip[]="no debug rip events";
#ifdef OPTION_BGP
	char no_debug_bgp[]="no debug bgp events";
#endif
#endif
#ifdef OPTION_X25
	int vc = 0; /* x25 */
#endif

	args=librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {

		if (librouter_debug_set_token(0, args->argv[2]) >= 0) _cish_debug = 0;
#ifdef OPTION_ROUTER
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
#endif /* OPTION_ROUTER */
	} else {
#ifdef OPTION_X25
		if (args->argc > 2) /* x25 */
			vc = atoi(args->argv[2]);
#endif
		if (librouter_debug_set_token(1, args->argv[1]) >= 0)
			_cish_debug = 1;
#ifdef OPTION_ROUTER
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
#endif /* OPTION_ROUTER */
	}
	librouter_destroy_args(args);
}

void show_debug(const char *cmd)
{
	librouter_debug_dump();
}

