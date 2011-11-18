/*
 * ipv6.c
 *
 *  Created on: Aug 22, 2011
 *      Author: ipinotti
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#include "commands.h"
#include "commandtree.h"

cish_command CMD_IPV6_ROUTE5[] = {
	{"1-255", "Distance metric for this route", NULL, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPV6_ROUTE4_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", CMD_IPV6_ROUTE5, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPV6_ROUTE4_LOOPBACK[] = {
	{"0-0", "Loopback interface number", CMD_IPV6_ROUTE5, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPV6_ROUTE4_TUNNEL[] = {
	{"0-0", "Tunnel interface number", CMD_IPV6_ROUTE5, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#ifdef OPTION_MODEM3G
cish_command CMD_IPV6_ROUTE4_3G[] = {
	{"0-2", "3G interface number", CMD_IPV6_ROUTE5, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IPV6_ROUTE4_PPTP[] = {
	{"0-0", "PPTP interface number", CMD_IPV6_ROUTE5, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPV6_ROUTE4_PPPOE[] = {
	{"0-0", "PPPoE interface number", CMD_IPV6_ROUTE5, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPV6_ROUTE3[] = {
	{"ethernet", "Ethernet interface", CMD_IPV6_ROUTE4_ETHERNET, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_IPV6_ROUTE4_LOOPBACK, NULL, 1, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_IPV6_ROUTE4_TUNNEL, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_MODEM3G
	{"m3G", "3G Interface", CMD_IPV6_ROUTE4_3G, NULL, 1, MSK_NORMAL},
#endif
	{"pptp", "PPTP Interface", CMD_IPV6_ROUTE4_PPTP, NULL, 1, MSK_NORMAL},
	{"pppoe", "PPPoE Interface", CMD_IPV6_ROUTE4_PPPOE, NULL, 1, MSK_NORMAL},
#endif
	{"<ipv6address>", "IPv6 Address - { X:X:X:X:X:X } - Forwarding router's address", CMD_IPV6_ROUTE5, zebra_execute_cmd_ipv6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPV6_ROUTE2[] = {
	{"<netmask_v6>", "IPv6 Netmask - <0-128> - Destination prefix mask", CMD_IPV6_ROUTE3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPV6_ROUTE1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X } - Destination prefix", CMD_IPV6_ROUTE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_NO_IPV6[] = {
	{"route", "Remove static routes", CMD_IPV6_ROUTE1, NULL, 1, MSK_NORMAL},
	{"routing", "Disable IPv6 routing", NULL, no_ipv6_param, 1, MSK_NORMAL},
	{"enable", "Disable IPv6 in all interfaces", NULL, no_ipv6_param, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
	{"auto-configuration", "Disable IPv6 address auto-configuration in all interfaces", NULL, no_ipv6_param, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPV6[] = {
	{"route", "Establish static routes", CMD_IPV6_ROUTE1, NULL, 1, MSK_NORMAL},
	{"routing", "Enable IPv6 routing", NULL, ipv6_param, 1, MSK_NORMAL},
	{"enable", "Enable IPv6 in all interfaces", NULL, ipv6_param, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
	{"auto-configuration", "Enable IPv6 address auto-configuration in all interfaces", NULL, ipv6_param, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};
