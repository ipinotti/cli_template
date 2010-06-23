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

#ifdef OPTION_BRIDGE
#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"

static int check_bridge(char *arg, char *brname)
{
	strcpy(brname, BRIDGE_NAME);
	strcat(brname, arg);
	if (!br_exists(brname))
	{
		printf("%% protocol for bridge group %s has not been configured\n", arg);
		return 0;
	}
	return 1;
}

void bridge_setaging (const char *cmd)
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[1], brname))
		br_setageing(brname, atoi(args->argv[3]));
	
	libconfig_destroy_args (args);
}

void bridge_setfd (const char *cmd)
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[1], brname))
		br_setfd(brname, atoi(args->argv[3]));
	
	libconfig_destroy_args (args);
}

void bridge_sethello (const char *cmd)
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[1], brname))
		br_sethello(brname, atoi(args->argv[3]));
	
	libconfig_destroy_args (args);
}

void bridge_setmaxage (const char *cmd)
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[1], brname))
		br_setmaxage(brname, atoi(args->argv[3]));
	
	libconfig_destroy_args (args);
}

void bridge_setprio (const char *cmd)
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[1], brname))
		br_setbridgeprio(brname, atoi(args->argv[3]));
	
	libconfig_destroy_args (args);
}

void bridge_nostp (const char *cmd) /* bridge 1 spanning-disabled */
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[1], brname))
		br_set_stp(brname, 0);
	
	libconfig_destroy_args (args);
}

void bridge_stp (const char *cmd) /* no bridge 1 spanning-disabled */
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[2], brname))
		br_set_stp(brname, 1);
	
	libconfig_destroy_args (args);
}

void bridge_setproto (const char *cmd) /* bridge 1 protocol ieee */
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[1]);
	if (!br_exists(brname))
	{
		br_addbr(brname);
		br_set_stp(brname, 1); /* enable spanning-tree protocol */
		dev_set_link_up(brname);
	}
	
	libconfig_destroy_args (args);
}

void bridge_no (const char *cmd)
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[2]);
	if (br_exists(brname))
	{
		if (br_hasifs(brname))
		{
			printf("%% bridge group %s has assigned interface(s)\n", 
				args->argv[2]);
		}
		else
		{
			dev_set_link_down(brname);
			br_delbr(brname);
		}
	}
	
	libconfig_destroy_args (args);
}

void dump_bridge (FILE *out)
{
	int i, printed_something=0;
	char brname[32];
	
	for (i=1; i<=MAX_BRIDGE; i++)
	{
		sprintf(brname, "%s%d", BRIDGE_NAME, i);
		if (!br_exists(brname)) continue;
		printed_something = 1;	
		fprintf(out, "bridge %d protocol ieee\n", i);
		fprintf(out, "bridge %d aging-time %d\n", i, br_getageing(brname));
		fprintf(out, "bridge %d forward-time %d\n", i, br_getfd(brname));
		fprintf(out, "bridge %d hello-time %d\n", i, br_gethello(brname));
		fprintf(out, "bridge %d max-age %d\n", i, br_getmaxage(brname));
		fprintf(out, "bridge %d priority %d\n", i, br_getbridgeprio(brname));
		if (!br_get_stp(brname))
			fprintf(out, "bridge %d spanning-disabled\n", i);
	}	
	if (printed_something) fprintf(out, "!\n");
}

void bridge_show (const char *cmd) /* show bridge 1 */
{
	arglist *args;
	char brname[32];
	
	args = libconfig_make_args (cmd);
	
	if (check_bridge(args->argv[2], brname))
	{
		br_dump_info(brname, stdout);
	}
	
	libconfig_destroy_args (args);
}
#endif /* OPTION_BRIDGE */

