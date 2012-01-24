#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>

#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_VRRP
#include <librouter/device.h>
#include <librouter/defines.h>
#include <librouter/args.h>
#include <librouter/dev.h>
#include <librouter/vrrp.h>

extern dev_family *interface_edited;
extern int interface_major;
extern int interface_minor;

/*
 Used: default off; enabled by set_model_qos_cmds
 CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP at:
 CMD_CONFIG_INTERFACE_ETHERNET_NO
 CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO
 CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP at:
 CMD_CONFIG_INTERFACE_ETHERNET
 CMD_CONFIG_INTERFACE_ETHERNET_VLAN
 */

void interface_no_vrrp(const char *cmd) /* no vrrp <1-255> <option> <...> */
{
	arglist *args;
	int group;
	char *dev;

	args = librouter_make_args(cmd);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);

	group = atoi(args->argv[2]);
	if (args->argc == 3) {
		librouter_vrrp_no_group(dev, group);
	} else {
		if (strcmp(args->argv[3], "authentication") == 0) { /* authentication */
			librouter_vrrp_option_authenticate(dev, group, VRRP_AUTHENTICATION_NONE, NULL);
		} else if (strcmp(args->argv[3], "description") == 0) { /* description */
			librouter_vrrp_option_description(dev, group, NULL);
		} else if (strcmp(args->argv[3], "ip") == 0) { /* ip [<ipaddress>] */
			librouter_vrrp_option_ip(dev, group, 0, args->argc == 5 ? args->argv[4] : NULL, args->argc == 5);
		} else if (strcmp(args->argv[3], "preempt") == 0) {
			librouter_vrrp_option_preempt(dev, group, 0, 0);
		} else if (strcmp(args->argv[3], "priority") == 0) { /* priority */
			librouter_vrrp_option_priority(dev, group, 0);
		} else if (strcmp(args->argv[3], "timers") == 0) { /* timers advertise */
			librouter_vrrp_option_advertise_delay(dev, group, 0);
		}
	}
	free(dev);
	librouter_destroy_args(args);
}

void interface_vrrp(const char *cmd) /* vrrp <1-255> <option> <...> */
{
	arglist *args;
	int group;
	char *dev;

	args = librouter_make_args(cmd);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);

	group = atoi(args->argv[1]);
	if (strcmp(args->argv[2], "authentication") == 0) { /* authentication ah|text <string> */
		if (strcmp(args->argv[3], "ah") == 0) {
			librouter_vrrp_option_authenticate(dev, group, VRRP_AUTHENTICATION_AH, args->argv[4]);
		} else {
			librouter_vrrp_option_authenticate(dev, group, VRRP_AUTHENTICATION_TEXT,
			                args->argv[4]);
		}
	} else if (strcmp(args->argv[2], "description") == 0) { /* description <string> */
		librouter_vrrp_option_description(dev, group, args->argv[3]);
	} else if (strcmp(args->argv[2], "ip") == 0) { /* ip <ipaddress> [secondary] */
		if (args->argc == 5 && strcmp(args->argv[4], "secondary") == 0) {
			librouter_vrrp_option_ip(dev, group, 1, args->argv[3], 1);
		} else
			librouter_vrrp_option_ip(dev, group, 1, args->argv[3], 0);
	} else if (strcmp(args->argv[2], "preempt") == 0) { /* preempt delay minimum <0-1000> */
		librouter_vrrp_option_preempt(dev, group, 1, args->argc == 6 ? atoi(args->argv[5]) : 0);
	} else if (strcmp(args->argv[2], "priority") == 0) { /* priority <1-254> */
		librouter_vrrp_option_priority(dev, group, atoi(args->argv[3]));
	} else if (strcmp(args->argv[2], "timers") == 0) { /* timers advertise <1-255> */
		librouter_vrrp_option_advertise_delay(dev, group, atoi(args->argv[4]));
	}
	free(dev);
	librouter_destroy_args(args);
}
#endif /* OPTION_VRRP */

