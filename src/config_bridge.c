#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <librouter/options.h> /* autoconf.h */

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/ipx.h>
#include <linux/route.h>
#include <linux/netdevice.h>

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"

#ifdef OPTION_BRIDGE

static int check_bridge(char *arg, char *brname)
{
	strcpy(brname, BRIDGE_NAME);
	strcat(brname, arg);
	if (!librouter_br_exists(brname)) {
		printf("%% protocol for bridge group %s has not been configured\n", arg);
		return 0;
	}
	return 1;
}

void bridge_setaging(const char *cmd)
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[1], brname))
		librouter_br_setageing(brname, atoi(args->argv[3]));

	librouter_destroy_args(args);
}

void bridge_setfd(const char *cmd)
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[1], brname))
		librouter_br_setfd(brname, atoi(args->argv[3]));

	librouter_destroy_args(args);
}

void bridge_sethello(const char *cmd)
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[1], brname))
		librouter_br_sethello(brname, atoi(args->argv[3]));

	librouter_destroy_args(args);
}

void bridge_setmaxage(const char *cmd)
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[1], brname))
		librouter_br_setmaxage(brname, atoi(args->argv[3]));

	librouter_destroy_args(args);
}

void bridge_setprio(const char *cmd)
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[1], brname))
		librouter_br_setbridgeprio(brname, atoi(args->argv[3]));

	librouter_destroy_args(args);
}

void bridge_nostp(const char *cmd) /* bridge 1 spanning-disabled */
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[1], brname))
		librouter_br_set_stp(brname, 0);

	librouter_destroy_args(args);
}

void bridge_stp(const char *cmd) /* no bridge 1 spanning-disabled */
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[2], brname))
		librouter_br_set_stp(brname, 1);

	librouter_destroy_args(args);
}

void bridge_setproto(const char *cmd) /* bridge 1 protocol ieee */
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[1]);

	if (!librouter_br_exists(brname)) {
		librouter_br_addbr(brname);
		librouter_dev_set_link_up(brname);
	}

	librouter_destroy_args(args);
}

void bridge_set_no_ipv4_addr(const char *cmd)
{
	arglist *args;
	char brname[32];
	char * dhcpd_intf = NULL;

	args = librouter_make_args(cmd);

	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[2]);

	/*Verify DHCP Server on intf and shut it down*/
	librouter_dhcp_server_get_iface(&dhcpd_intf);
	if (dhcpd_intf){
		if (!strcmp(brname, dhcpd_intf)){
			printf("%% bridge group %s has DHCP Server assigned.\n", args->argv[2]);
			printf("%% DHCP Server is going to be shut down.\n");
			librouter_dhcp_server_set_status(0);
		}
		free (dhcpd_intf);
	}

	librouter_ip_interface_set_no_addr(brname);

	librouter_destroy_args(args);
}


void bridge_set_ipv4_addr(const char *cmd)
{
	arglist *args;
	char brname[32];
	char *addr, *mask;

	args = librouter_make_args(cmd);

	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[1]);
	addr = args->argv[3];
	mask = args->argv[4];

	librouter_ip_interface_set_addr(brname, addr, mask);

	librouter_destroy_args(args);
}

void bridge_no(const char *cmd)
{
	arglist *args;
	char brname[32];
	char * dhcpd_intf = NULL;

	args = librouter_make_args(cmd);

	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[2]);
	if (librouter_br_exists(brname)) {
		if (librouter_br_hasifs(brname)) {
			printf("%% bridge group %s has assigned interface(s)\n", args->argv[2]);
		} else {
			/*Verify DHCP Server on intf and shut it down*/
			librouter_dhcp_server_get_iface(&dhcpd_intf);
			if (dhcpd_intf){
				if (!strcmp(brname, dhcpd_intf))
					librouter_dhcp_server_set_status(0);
				free (dhcpd_intf);
			}

			librouter_dev_set_link_down(brname);
			librouter_br_delbr(brname);
		}
	}

	librouter_destroy_args(args);
}

void bridge_show(const char *cmd) /* show bridge 1 */
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	if (check_bridge(args->argv[2], brname)) {
		librouter_br_dump_info(brname, stdout);
	}

	librouter_destroy_args(args);
}
#endif /* OPTION_BRIDGE */

