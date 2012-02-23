#include <stdio.h>
#include <stdlib.h>

#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_VRRP
cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_IP6[] = {
	{"<ipv6address>", "Virtual IPv6 address", NULL, interface_no_vrrp, 1, MSK_VRRP},
	{"<enter>", "", NULL, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_IP[] = {
	{"<ipaddress>", "Virtual IP address", NULL, interface_no_vrrp, 1, MSK_VRRP},
	{"<enter>", "", NULL, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_TIMERS[] = {
	{"advertise", "Unset the Advertisement timer", NULL, interface_no_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_OPTIONS[] = {
	{"authentication", "Clear authentication string", NULL, interface_no_vrrp, 1, MSK_VRRP},
	{"description", "Clear Group specific description", NULL, interface_no_vrrp, 1, MSK_VRRP},
	{"ip", "Disable VRRP for IP", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_IP, interface_no_vrrp, 1, MSK_VRRP},
	{"ipv6", "Disable VRRP for IPv6", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_IP6, interface_no_vrrp, 1, MSK_VRRP},
	{"preempt", "Disable preemption of lower priority Master", NULL, interface_no_vrrp, 1, MSK_VRRP},
	{"priority", "Unset priority of this VRRP group", NULL, interface_no_vrrp, 1, MSK_VRRP},
 	{"timers", "Unset the VRRP timers", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_TIMERS, NULL, 1, MSK_VRRP},
 	{"track-interface", "Unset VRRP interface tracking", NULL, interface_no_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP[] = {
	{"1-255", "Group number", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_OPTIONS, interface_no_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH_PASS[] = {
	{"<string>", "authentication string", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH[] = {
	{"ah", "AH authentication", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH_PASS, NULL, 1, MSK_VRRP},
	{"text", "TEXT authentication", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH_PASS, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_DESC[] = {
	{"<string>", "Up to 80 characters describing this group", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP_SECONDARY[] = {
	{"secondary", "Specify an additional VRRP address for this group", NULL, interface_vrrp, 1, MSK_VRRP},
	{"<enter>", "", NULL, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP[] = {
	{"<ipaddress>", "VRRP group IP address", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP_SECONDARY, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP6[] = {
	{"<ipv6address>", "VRRP group IPv6 address", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP_SECONDARY, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY_MINIMUM[] = {
	{"0-1000", "Seconds to delay", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY[] = {
	{"minimum", "Delay at least this long", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY_MINIMUM, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT[] = {
	{"delay", "Wait before preempting", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY, NULL, 1, MSK_VRRP},
	{"<enter>", "", NULL, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PRIO[] = {
	{"1-254", "Priority level", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS_ADVERTISE[] = {
	{"1-255", "Advertisement interval in seconds", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS[] = {
	{"advertise", "Set the Advertisement timer", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS_ADVERTISE, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

/* VRRP Interface tracking */
#ifdef OPTION_MODEM3G
cish_command CMD_VRRP_GROUP_TRACK_M3G[] = {
	{CLI_STRING_USB_PORTS, "Modem 3G interface number", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_TUNNEL
cish_command CMD_VRRP_GROUP_TRACK_TUNNEL[] = {
	{CLI_STRING_TUN_IFACES, "Tunnel interface number", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_EFM
cish_command CMD_VRRP_GROUP_TRACK_EFM[] = {
	{CLI_STRING_EFM_IFACES, "EFM interface number", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_VRRP_GROUP_TRACK_ETH[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", NULL, interface_vrrp, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TRACK[] = {
#ifdef OPTION_MODEM3G
	{"m3G", "Modem 3G interface", CMD_VRRP_GROUP_TRACK_M3G, NULL, 1, MSK_VRRP},
#endif
#ifdef OPTION_EFM
	{"efm", "EFM interface", CMD_VRRP_GROUP_TRACK_EFM, NULL, 1, MSK_VRRP},
#endif
	{"ethernet", "Ethernet interface", CMD_VRRP_GROUP_TRACK_ETH, NULL, 1, MSK_VRRP},
#ifdef OPTION_TUNNEL
	{"tunnel", "Tunnel interface", CMD_VRRP_GROUP_TRACK_TUNNEL, NULL, 1, MSK_VRRP},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_OPTIONS[] = {
	{"authentication", "Authentication string", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH, NULL, 1, MSK_VRRP},
	{"description", "Group specific description", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_DESC, NULL, 1, MSK_VRRP},
	{"ip", "Enable VRRP for IP", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP, NULL, 1, MSK_VRRP},
	{"ipv6", "Enable VRRP for IPv6", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP6, NULL, 1, MSK_VRRP},
	{"preempt", "Enable preemption of lower priority Master", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT, interface_vrrp, 1, MSK_VRRP},
	{"priority", "Priority of this VRRP group", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PRIO, NULL, 1, MSK_VRRP},
 	{"timers", "Set the VRRP timers", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS, NULL, 1, MSK_VRRP},
 	{"track-interface", "Set VRRP interface tracking", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TRACK, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP[] = {
	{"1-255", "Group number", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_OPTIONS, NULL, 1, MSK_VRRP},
	{NULL,NULL,NULL,NULL}
};

#endif
