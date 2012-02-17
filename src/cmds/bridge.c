/*
 * bridge.c
 *
 *  Created on: Nov 11, 2010
 *      Author: Thomás Alimena Del Grande (tgrande@pd3.com.br)
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_BRIDGE
cish_command CMD_SHOW_BRIDGE[] = {
	{"0-15", "Bridge Group number", NULL, bridge_show, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_BRIDGE_AGING[] = {
	{"10-1000000", "Seconds", NULL, bridge_setaging, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_FD[] = {
	{"4-200", "Seconds", NULL, bridge_setfd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_HELLO[] = {
	{"1-10", "Seconds", NULL, bridge_sethello, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_MAXAGE[] = {
	{"6-200", "Seconds", NULL, bridge_setmaxage, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_PRIO[] = {
	{"0-65535", "Priority (low priority more likely to be root)", NULL, bridge_setprio, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_PROTO[] = {
	{"ieee", "IEEE 802.1 protocol", NULL, bridge_setproto, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_IPV4_MASK[] = {
	{"<netmask>", "IPv4 address mask", NULL, bridge_set_ipv4_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_IPV4_ADDRESS[] = {
	{"<ipaddress>", "IPv4 address", CMD_CONFIG_BRIDGE_IPV4_MASK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE2[] = {
	{"aging-time", "Set forwarding entry aging time", CMD_CONFIG_BRIDGE_AGING, NULL, 1, MSK_NORMAL},
	{"forward-time", "Set forwarding delay time", CMD_CONFIG_BRIDGE_FD, NULL, 1, MSK_NORMAL},
	{"hello-time", "Set interval between HELLOs", CMD_CONFIG_BRIDGE_HELLO, NULL, 1, MSK_NORMAL},
	{"ip-address", "Set bridge IPv4 address", CMD_CONFIG_BRIDGE_IPV4_ADDRESS, NULL, 1, MSK_NORMAL},
	{"max-age", "Maximum allowed message age of received Hello BPDUs", CMD_CONFIG_BRIDGE_MAXAGE, NULL, 1, MSK_NORMAL},
	{"priority", "Set bridge priority", CMD_CONFIG_BRIDGE_PRIO, NULL, 1, MSK_NORMAL},
	{"protocol", "Specify spanning tree protocol", CMD_CONFIG_BRIDGE_PROTO, NULL, 1, MSK_NORMAL},
	{"spanning-disabled", "Disable spanning tree", NULL, bridge_nostp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE[] = {
	{"0-15", "Bridge Group number for Bridging", CMD_CONFIG_BRIDGE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NO_BRIDGE2[] = {
	{"spanning-disabled", "Enable spanning tree", NULL, bridge_stp, 1, MSK_NORMAL},
	{"ip-address", "Remove bridge IPv4 address", NULL, bridge_set_no_ipv4_addr, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NO_BRIDGE[] = {
	{"0-15", "Bridge Group number for Bridging", CMD_CONFIG_NO_BRIDGE2, bridge_no, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#endif /* OPTION_BRIDGE */
