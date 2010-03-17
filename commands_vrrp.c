#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "options.h"
#include "commandtree.h"
#include "commands_vrrp.h"

#include <libconfig/device.h>
#include <libconfig/defines.h>
#include <libconfig/args.h>
#include <libconfig/dev.h>
#include <libconfig/vrrp.h>

extern device_family *interface_edited;
extern int interface_major;
extern int interface_minor;

#ifdef OPTION_VRRP
/*
	Used: default off; enabled by set_model_qos_cmds
	CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP at:
		CMD_CONFIG_INTERFACE_ETHERNET_NO
		CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO
	CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP at:
		CMD_CONFIG_INTERFACE_ETHERNET
		CMD_CONFIG_INTERFACE_ETHERNET_VLAN
*/

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_IP[] = {
	{"<ipaddress>", "VRRP group IP address", NULL, interface_no_vrrp, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_TIMERS[] = {
	{"advertise", "Unset the Advertisement timer", NULL, interface_no_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_OPTIONS[] = {
	{"authentication", "Clear authentication string", NULL, interface_no_vrrp, 1},
	{"description", "Clear Group specific description", NULL, interface_no_vrrp, 1},
	{"ip", "Disable Virtual Router Redundancy Protocol (VRRP) for IP", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_IP, interface_no_vrrp, 1},
	{"preempt", "Disable preemption of lower priority Master", NULL, interface_no_vrrp, 1},
	{"priority", "Unset priority of this VRRP group", NULL, interface_no_vrrp, 1},
 	{"timers", "Unset the VRRP timers", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_TIMERS, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP[] = {
	{"1-255", "Group number", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP_OPTIONS, interface_no_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH_PASS[] = {
	{"<string>", "authentication string", NULL, interface_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH[] = {
	{"ah", "AH authentication", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH_PASS, NULL, 1},
	{"text", "TEXT authentication", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH_PASS, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_DESC[] = {
	{"<string>", "Up to 80 characters describing this group", NULL, interface_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP_SECONDARY[] = {
	{"secondary", "Specify an additional VRRP address for this group", NULL, interface_vrrp, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP[] = {
	{"<ipaddress>", "VRRP group IP address", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP_SECONDARY, interface_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY_MINIMUM[] = {
	{"0-1000", "Seconds to delay", NULL, interface_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY[] = {
	{"minimum", "Delay at least this long", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY_MINIMUM, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT[] = {
	{"delay", "Wait before preempting", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT_DELAY, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PRIO[] = {
	{"1-254", "Priority level", NULL, interface_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS_ADVERTISE[] = {
	{"1-255", "Advertisement interval in seconds", NULL, interface_vrrp, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS[] = {
	{"advertise", "Set the Advertisement timer", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS_ADVERTISE, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_OPTIONS[] = {
	{"authentication", "Authentication string", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_AUTH, NULL, 1},
	{"description", "Group specific description", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_DESC, NULL, 1},
	{"ip", "Enable Virtual Router Redundancy Protocol (VRRP) for IP", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_IP, NULL, 1},
	{"preempt", "Enable preemption of lower priority Master", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PREEMPT, interface_vrrp, 1},
	{"priority", "Priority of this VRRP group", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_PRIO, NULL, 1},
 	{"timers", "Set the VRRP timers", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_TIMERS, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP[] = {
	{"1-255", "Group number", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP_OPTIONS, NULL, 1},
	{NULL,NULL,NULL,NULL}
};

void interface_no_vrrp(const char *cmd) /* no vrrp <1-255> <option> <...> */
{
	arglist *args;
	int group;
	char *dev;

	args=make_args(cmd);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	group=atoi(args->argv[2]);
	if (args->argc == 3) {
		vrrp_no_group(dev, group);
	} else {
		if (strcmp(args->argv[3], "authentication") == 0) { /* authentication */
			vrrp_option_authenticate(dev, group, VRRP_AUTHENTICATION_NONE, NULL);
		} else if (strcmp(args->argv[3], "description") == 0) { /* description */
			vrrp_option_description(dev, group, NULL);
		} else if (strcmp(args->argv[3], "ip") == 0) { /* ip [<ipaddress>] */
			vrrp_option_ip(dev, group, 0, args->argc == 5 ? args->argv[4] : NULL, args->argc == 5);
		} else if (strcmp(args->argv[3], "preempt") == 0) {
			vrrp_option_preempt(dev, group, 0, 0);
		} else if (strcmp(args->argv[3], "priority") == 0) { /* priority */
			vrrp_option_priority(dev, group, 0);
		} else if (strcmp(args->argv[3], "timers") == 0) { /* timers advertise */
			vrrp_option_advertise_delay(dev, group, 0);
		}
	}
	free(dev);
	destroy_args(args);
}

void interface_vrrp(const char *cmd) /* vrrp <1-255> <option> <...> */
{
	arglist *args;
	int group;
	char *dev;

	args=make_args(cmd);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	group=atoi(args->argv[1]);
	if (strcmp(args->argv[2], "authentication") == 0) { /* authentication ah|text <string> */
		if (strcmp(args->argv[3], "ah") == 0) {
			vrrp_option_authenticate(dev, group, VRRP_AUTHENTICATION_AH, args->argv[4]);
		} else {
			vrrp_option_authenticate(dev, group, VRRP_AUTHENTICATION_TEXT, args->argv[4]);
		}
	} else if (strcmp(args->argv[2], "description") == 0) { /* description <string> */
		vrrp_option_description(dev, group, args->argv[3]);
	} else if (strcmp(args->argv[2], "ip") == 0) { /* ip <ipaddress> [secondary] */
		if (args->argc == 5 && strcmp(args->argv[4], "secondary") == 0) {
			vrrp_option_ip(dev, group, 1, args->argv[3], 1);
		}
			else vrrp_option_ip(dev, group, 1, args->argv[3], 0);
	} else if (strcmp(args->argv[2], "preempt") == 0) { /* preempt delay minimum <0-1000> */
		vrrp_option_preempt(dev, group, 1, args->argc == 6 ? atoi(args->argv[5]) : 0);
	} else if (strcmp(args->argv[2], "priority") == 0) { /* priority <1-254> */
		vrrp_option_priority(dev, group, atoi(args->argv[3]));
	} else if (strcmp(args->argv[2], "timers") == 0) { /* timers advertise <1-255> */
		vrrp_option_advertise_delay(dev, group, atoi(args->argv[4]));
	}
	free(dev);
	destroy_args(args);
}
#endif

