#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#include "commands.h"
#include "commandtree.h"

cish_command CMD_DEBUG_X25[] = {
	{"1-4095","VC number", NULL, debug_one, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_DEBUG[] = {
#ifdef OPTION_FIREWALL
	{"acl","Access list events", NULL, debug_one, 1, MSK_NORMAL},
#endif
	{"all","All facilities", NULL, debug_all, 1, MSK_NORMAL},
#ifdef OPTION_BGP
	{"bgp","BGP events", NULL, debug_one, 1, MSK_BGP},
#endif
#ifdef OPTION_BRIDGE
	{"bridge","Bridge connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PPP
	{"chat","Chat connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#endif
	{"config","System configuration events", NULL, debug_one, 1, MSK_NORMAL},
#ifdef OPTION_IPSEC
	{"crypto","VPN events", NULL, debug_one, 1, MSK_VPN},
#endif
	{"ethernet","Ethernet events", NULL, debug_one, 1, MSK_NORMAL},
	{"dhcp","DHCP events", NULL, debug_one, 1, MSK_NORMAL},
#ifdef OPTION_FR
	{"frelay","Frame-relay connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#endif
#ifdef OPTION_HDLC
	{"hdlc","HDLC connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#endif
#if defined(OPTION_X25) && defined(CONFIG_DEVELOPMENT)
	{"lapb","LAPB events", NULL, debug_one, 1, MSK_X25MAP},
#endif
#ifdef OPTION_IPSEC
	{"l2tp","L2TP events", NULL, debug_one, 1, MSK_VPN},
#endif
	{"login","Login events", NULL, debug_one, 1, MSK_NORMAL},
#ifdef OPTION_NTPD
	{"ntp","NTP events", NULL, debug_one, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf","OSPF events", NULL, debug_one, 1, MSK_OSPF},
#endif
#ifdef OPTION_PPP
	{"ppp","PPP connectivity events", NULL, debug_one, 1, MSK_NORMAL},
#endif
#ifdef OPTION_X25
	{"rfc1356","RFC1356 connectivity events", NULL, debug_one, 1, MSK_X25},
#endif
#ifdef OPTION_ROUTER
	{"rip","RIP events", NULL, debug_one, 1, MSK_RIP},
	{"ssh","SSH events", NULL, debug_one, 1, MSK_NORMAL},
#endif
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
