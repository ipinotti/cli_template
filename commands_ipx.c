/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */
   
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
#include "pprintf.h"
#include <libconfig/typedefs.h>
#include <libconfig/args.h>
#include <libconfig/exec.h>
#include <libconfig/ipx.h>

#define IPX_RIP_DAEMON "ipxd"

void ipx_routing (const char *cmd)
{
	exec_daemon(IPX_RIP_DAEMON);
}

void no_ipx_routing (const char *cmd)
{
	kill_daemon(IPX_RIP_DAEMON);
}

void dump_ipx(FILE *out, int conf_format)
{
	pfprintf(out, "%sipx routing\n", 
		is_daemon_running(IPX_RIP_DAEMON) ? "" : "no ");
	pfprintf (out, "!\n");
}

#if 0
void ipx_route (const char *cmd)
{
	arglist *args;
	u32 target_net, router_net, lo, hi;
	char *s;
	char router_node[IPX_NODE_LEN];
	int len;
	
	args = make_args (cmd);
	
	target_net = strtoul(args->argv[2], NULL, 16);
	router_net = strtoul(args->argv[3], NULL, 16);
	s = args->argv[4];
	len = strlen(s);
	if (len<=8)
	{
		hi = 0;
		lo = strtoul(s, NULL, 16);
	}
	else
	{
		lo = strtoul(s+len-8, NULL, 16);
		s[len-8] = 0;
		hi = strtoul(s, NULL, 16);
	}
	router_node[0] = hi >> 8;
	router_node[1] = hi;
	router_node[2] = lo >> 24;
	router_node[3] = lo >> 16;
	router_node[4] = lo >> 8;
	router_node[5] = lo;
	
	ipx_add_route(target_net, router_net, router_node);
	
	destroy_args (args);
}

void no_ipx_route (const char *cmd)
{
	arglist *args;
	u32 net;
	
	args = make_args (cmd);
	
	net = strtoul(args->argv[3], NULL, 16);
	
	ipx_del_route(net);
	
	destroy_args (args);
}
#endif

#define trimcolumn(x) tmp=strchr(x, ' '); if (tmp != NULL) *tmp=0;
#define trimnl(x) tmp=strchr(x, '\n'); if (tmp != NULL) *tmp=0;
void dump_ipx_routes (FILE *out, int conf_format)
{
	FILE *F;
	char *target_net, *router_net, *router_node, *tmp;
	char buf[100];
	int printed_something=0;
	
	target_net = buf;
	router_net = buf+11;
	router_node = buf+24;
	
	F = fopen ("/proc/net/ipx/route", "r");
	if (!F)
	{
		fprintf (stderr, "%% IPX subsystem not found\n");
		return;
	}
	
	if (!conf_format) pfprintf (out, "Target Network   Router Network   Router Node\n");
	
	fgets (buf, 100, F);
	
	while (!feof (F))
	{
		buf[0] = 0;
		fgets (buf, 100, F);
		if (strlen (buf)>24)
		{
			trimcolumn(target_net);
			trimcolumn(router_net);
			trimcolumn(router_node);
			trimnl(router_node);

			if (conf_format&&(strcasecmp(router_net, "Directly")==0)) continue;
			if (conf_format) pfprintf (out, "ipx route %s %s %s\n", target_net, router_net, router_node);
			else  pfprintf (out, "%-17s%-17s%-17s\n", target_net, router_net, router_node);
			printed_something = 1;
		}
	}
	fclose (F);
	if ((conf_format)&&printed_something) pfprintf(out, "!\n");
}

void show_ipx_routingtables (const char *cmdline)
{
	dump_ipx_routes (stdout, 0);
}


