#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "commands.h"
#include "commandtree.h"

#if 0
void ip_route (const char *cmdline)
{
	arglist *args;
	
	char *source_net;
	char *source_mask;
	char *destination;
	char *devicenr;
	char *minptr;
	char *dev;
	char  string[512];
	char  cmd[768];
	
	int   metric;
	int   major,minor;
	
	string[0] = 0;
	metric = 0;
	
	args = librouter_make_args (cmdline);
	
	source_net = args->argv[2];
	source_mask = args->argv[3];
	destination = args->argv[4];

	if (librouter_device_get_family_by_name(destination)) /* route to a device */
	{
		if (args->argc < 6)
		{
			major=0;
			minor=-1;
		}
		else
		{
			devicenr = strdup (args->argv[5]);
			minptr = strchr (devicenr, '.');
			if (minptr) *minptr = 0;
			major = atoi (devicenr);
			if (minptr) minor = atoi (minptr+1);
			else minor = -1;
			free (devicenr);
		}
		if (args->argc == 7) metric=atoi(args->argv[6]);
		
		dev = librouter_device_cli_to_linux (destination, major, minor);
		sprintf (string, "-net %s netmask %s dev %s", source_net, source_mask, dev);
		if (metric) sprintf (string+strlen(string), " %i", metric);
		free(dev);
	}
	else /* route to a gateway */
	{
		if (args->argc == 6) metric = atoi (args->argv[5]);
		if ( (strcmp (source_net, "0.0.0.0") == 0) &&
			 (strcmp (source_mask, "0.0.0.0") == 0) )
		{
			sprintf (string, "default gw %s", destination);
		}
		else
		{
			sprintf (string, "-net %s netmask %s gw %s", source_net, source_mask, destination);
			if (metric) sprintf (string+strlen(string), " %i", metric);
		}
	}
	if (strlen (string))
	{
		sprintf(cmd, "/bin/route add %s 2>&1 >/dev/null", string);
		system(cmd);
	}
	librouter_destroy_args (args);
}

void no_ip_route (const char *cmdline)
{
	arglist *args;
	
	char *source_net;
	char *source_mask;
	char *destination;
	char *devicenr;
	char *minptr;
	char *dev;
	char *tmp;
	char  string[512];
	char  cmd[768];
	
	int   metric;
	int   major,minor;
	
	string[0] = 0;
	metric = 0;
	
	tmp = (char *)cmdline;
	while (*tmp==' ') ++tmp;
	
	tmp = strchr (tmp, ' ');
	if (tmp) ++tmp;
	else tmp = (char *)cmdline;
	
	args = librouter_make_args (tmp);
	
	source_net = args->argv[2];
	source_mask = args->argv[3];
	destination = args->argv[4];
	if (librouter_device_get_family_by_name(destination)) /* route to a device */
	{
		if (args->argc < 6)
		{
			major=0;
			minor=-1;
		}
		else
		{
			devicenr = strdup (args->argv[5]);
			minptr = strchr (devicenr, '.');
			if (minptr) *minptr = 0;
			major = atoi (devicenr);
			if (minptr) minor = atoi (minptr+1);
			else minor = -1;
			free (devicenr);
		}
		if (args->argc == 7) metric=atoi(args->argv[6]);
		
		dev = librouter_device_cli_to_linux (destination, major, minor);
		sprintf (string, "-net %s netmask %s dev %s", source_net, source_mask, dev);
		if (metric) sprintf (string+strlen(string), " %i", metric);
		free(dev);
	}
	else /* route to a gateway */
	{
		if (args->argc == 6) metric = atoi (args->argv[5]);
		if ( (strcmp (source_net, "0.0.0.0") == 0) &&
			 (strcmp (source_mask, "0.0.0.0") == 0) )
		{
			sprintf (string, "default gw %s", destination);
		}
		else
		{
			sprintf (string, "-net %s netmask %s gw %s", source_net, source_mask, destination);
			if (metric) sprintf (string+strlen(string), " %i", metric);
		}
	}
	if (strlen (string))
	{
		sprintf(cmd, "/bin/route delete %s >/dev/null", string);
		system(cmd);
	}
	librouter_destroy_args (args);
}
#endif

#ifdef OPTION_SMCROUTE
void ip_mroute(const char *cmdline) /* [no] ip mroute <IPorigin> <McastGroup> in <InIntf> out <OutIntf> */
{
	char *new_cmdline;
	arglist *args;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	args = librouter_make_args(new_cmdline);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_smc_route(0, args->argv[3], args->argv[4], args->argv[6],
		                args->argv[8]);
	} else {
#ifdef OPTION_PIMD
		if (librouter_exec_check_daemon(PIMS_DAEMON) || librouter_exec_check_daemon(
		                PIMD_DAEMON)) {
			printf("%% Disable dynamic multicast routing first\n");
		} else
#endif
			librouter_smc_route(1, args->argv[2], args->argv[3],
			                args->argv[5], args->argv[7]);
	}
	librouter_destroy_args(args);
}
#endif

