
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <libconfig/defines.h>
#include <libconfig/args.h>
#include <libconfig/debug.h>
#include <libconfig/quagga.h>

#include "options.h"
#include "commands.h"
#include "commandtree.h"
#include "debug.h"

cish_command CMD_DEBUG_X25[] = {
	{"1-4095","VC number", NULL, debug_one, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_DEBUG[] = {
	{"acl","Access list events", NULL, debug_one, 1, MSK_NORMAL},
	{"all","All facilities", NULL, debug_all, 1, MSK_NORMAL},
#ifdef OPTION_BGP
	{"bgp","BGP events", NULL, debug_one, 1, MSK_BGP},
#endif
	{"bridge","Bridge connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"chat","Chat connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#endif
	{"config","System configuration events", NULL, debug_one, 1, MSK_NORMAL},
#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_LOG_CONSOLE)
	{"console","Dump console interface", NULL, debug_console, 1, MSK_NORMAL},
#endif
#ifdef OPTION_IPSEC
	{"crypto","VPN events", NULL, debug_one, 1, MSK_VPN},
#endif
#ifndef CONFIG_BERLIN_SATROUTER
	{"ethernet","Ethernet events", NULL, debug_one, 1, MSK_NORMAL},
#endif
	{"dhcp","DHCP events", NULL, debug_one, 1, MSK_NORMAL},
	{"frelay","Frame-relay connectivity events", NULL, debug_one, 1, MSK_NORMAL},
	{"hdlc","HDLC connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"lapb","LAPB events", NULL, debug_one, 1, MSK_X25MAP},
#endif
#ifdef OPTION_IPSEC
	{"l2tp","L2TP events", NULL, debug_one, 1, MSK_VPN},
#endif
#ifndef CONFIG_BERLIN_SATROUTER
	{"login","Login events", NULL, debug_one, 1, MSK_NORMAL},
#endif
#ifdef OPTION_NTPD
	{"ntp","NTP events", NULL, debug_one, 1, MSK_NORMAL},
#endif
	{"ospf","OSPF events", NULL, debug_one, 1, MSK_OSPF},
	{"ppp","PPP connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"rfc1356","RFC1356 connectivity events", NULL, debug_one, 1, MSK_X25},
#endif
	{"rip","RIP events", NULL, debug_one, 1, MSK_RIP},
	{"ssh","SSH events", NULL, debug_one, 1, MSK_NORMAL},
	{"systty","System control events", NULL, debug_one, 1, MSK_NORMAL},
#ifdef OPTION_X25MAP
	{"trace","Trace events", NULL, debug_one, 1, MSK_X25MAP},
#endif
#ifdef OPTION_VRRP
	{"vrrp","VRRP events", NULL, debug_one, 1, MSK_VRRP},
#endif
#ifdef OPTION_X25
	{"x25","X.25 layer 3 events", CMD_DEBUG_X25, debug_one, 1, MSK_X25MAP},
#ifdef OPTION_X25MAP
	{"x25map","x25 map events", NULL, debug_one, 1, MSK_X25MAP},
#endif
#ifdef OPTION_X25XOT
	{"xot","XOT events", NULL, debug_one, 1, MSK_X25XOT},
#endif
#endif
	{NULL,NULL,NULL,NULL,0}
};

int _cish_debug;

void debug_all(const char *cmd) /* [no] debug all */
{
	arglist *args;
	char no_debug_ospf[]="no debug ospf event";
	char no_debug_rip[]="no debug rip events";
#ifdef OPTION_BGP
	char no_debug_bgp[]="no debug bgp events";
#endif

	args=make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {
		set_debug_all(0);
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
		set_debug_all(1);
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
	destroy_args(args);
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

	args=make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) {
#ifdef CONFIG_BERLIN_SATROUTER
		if (set_debug_token(0, args->argv[2]) >= 0) _cish_debug = 0;
#else
		if (set_debug_token(0, args->argv[2]) >= 0) _cish_debug = 0;
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
		if (set_debug_token(1, args->argv[1]) >= 0)
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
	destroy_args(args);
}

void show_debug(const char *cmd)
{
	dump_debug();
}

#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_LOG_CONSOLE)

#define TIOSERDEBUG		0x545E	/* enable/disable low level uart debug */

void debug_console(const char *cmd)
{
	int pf;
	arglist *args;
	unsigned int debug;

	args = make_args(cmd);
	debug = (strcmp(args->argv[0], "no")==0 ? 0 : 1);
	if( (pf = open(TTS_AUX1, O_RDWR | O_NDELAY)) < 0 )
	{
		destroy_args(args);
		printf("Not possible to enable/disable debug\n");
		return;
	}
	if( ioctl(pf, TIOSERDEBUG, &debug) != 0 )
	{
		close(pf);
		destroy_args(args);
		printf("Not possible to enable/disable debug\n");
		return;
	}
	close(pf);
	destroy_args(args);
}

#endif

