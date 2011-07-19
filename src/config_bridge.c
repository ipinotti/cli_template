#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

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

void bridge_no(const char *cmd)
{
	arglist *args;
	char brname[32];

	args = librouter_make_args(cmd);

	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[2]);
	if (librouter_br_exists(brname)) {
		if (librouter_br_hasifs(brname)) {
			printf("%% bridge group %s has assigned interface(s)\n", args->argv[2]);
		} else {
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

