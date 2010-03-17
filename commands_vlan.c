#include "commands.h"
#include "commandtree.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/hdlc.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig/typedefs.h>
#include <libconfig/vlan.h>
#include <libconfig/device.h>
#include <libconfig/defines.h>
#include <libconfig/args.h>
#include <libconfig/dev.h>

extern int interface_major;
extern int interface_minor;

void vlan_add(const char *cmd) /* vlan <id> */
{
	int vid;
	arglist *args;

	args=make_args(cmd);
	vid=atoi(args->argv[1]);
	if(vlan_exists(interface_major, vid)) {
		printf("%% vlan allready used\n");
	}
		else vlan_vid(interface_major, vid, 1, 0);
	destroy_args(args);
}

void vlan_del(const char *cmd) /* no vlan <id> */
{
	int vid;
	arglist *args;

	args=make_args(cmd);
	vid=atoi(args->argv[2]);
	if(!vlan_exists(interface_major, vid)) {
		printf("%% vlan not defined\n");
	}
		else vlan_vid(interface_major, vid, 0, 0);
	destroy_args(args);
}

void vlan_change_cos(const char *cmd) /* set cos [precedence|dscp] */
{
	arglist *args;
	args=make_args(cmd);

	if(!vlan_exists(interface_major, interface_minor)) {
		printf("%% vlan not defined\n");
	}

	if (!strcmp(args->argv[0],"no")) 
		set_vlan_cos(interface_major, interface_minor, NONE_TO_COS);
	else if (!strcmp(args->argv[2],"precedence"))
		set_vlan_cos(interface_major, interface_minor, IP_PRECEDENCE_TO_COS);
	else if (!strcmp(args->argv[2],"dscp"))
		set_vlan_cos(interface_major, interface_minor, IP_DSCP_TO_COS);

	destroy_args(args);
}

