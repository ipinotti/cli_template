#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/hdlc.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "commandtree.h"


void vlan_add(const char *cmd) /* vlan <id> */
{
	int vid;
	arglist *args;

	args=libconfig_make_args(cmd);
	vid=atoi(args->argv[1]);
	if(libconfig_vlan_exists(interface_major, vid)) {
		printf("%% vlan allready used\n");
	}
		else libconfig_vlan_vid(interface_major, vid, 1, 0);
	libconfig_destroy_args(args);
}

void vlan_del(const char *cmd) /* no vlan <id> */
{
	int vid;
	arglist *args;

	args=libconfig_make_args(cmd);
	vid=atoi(args->argv[2]);
	if(!libconfig_vlan_exists(interface_major, vid)) {
		printf("%% vlan not defined\n");
	}
		else libconfig_vlan_vid(interface_major, vid, 0, 0);
	libconfig_destroy_args(args);
}

#if 0
void vlan_change_cos(const char *cmd) /* set cos [precedence|dscp] */
{
	arglist *args;
	args=libconfig_make_args(cmd);

	if(!libconfig_vlan_exists(interface_major, interface_minor)) {
		printf("%% vlan not defined\n");
	}

	if (!strcmp(args->argv[0],"no")) 
		libconfig_vlan_set_cos(interface_major, interface_minor, NONE_TO_COS);
	else if (!strcmp(args->argv[2],"precedence"))
		libconfig_vlan_set_cos(interface_major, interface_minor, IP_PRECEDENCE_TO_COS);
	else if (!strcmp(args->argv[2],"dscp"))
		libconfig_vlan_set_cos(interface_major, interface_minor, IP_DSCP_TO_COS);

	libconfig_destroy_args(args);
}
#endif

