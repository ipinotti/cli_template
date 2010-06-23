#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"

void ping (const char *cmdline)
{
	arglist *args;
	int argc;
	char count[32], size[32], addr[32];
	char *xargv[16];
	pid_t ping_pid;
	
	args = libconfig_make_args (cmdline);
	
	strncpy(addr, args->argv[1], 31); 
	addr[31] = 0;
	
	strcpy(count, "5");
	strcpy(size, "56");
			
	argc = 2;
	
	while (argc<args->argc)	
	{
		if (strcmp(args->argv[argc], "count")==0)
		{
			strncpy(count, args->argv[argc+1], 31); 
			count[31] = 0;
		}
		if (strcmp(args->argv[argc], "size")==0)
		{
			strncpy(size, args->argv[argc+1], 31); 
			size[31] = 0;
		}
		argc += 2;
	}
	
	libconfig_destroy_args (args);
	
	switch (ping_pid = fork())
	{
		case -1:
			fprintf (stderr, "%% No processes left\n");
			return;
			
		case 0:
			xargv[0] = "/bin/ping";
			xargv[1] = "-c";
			xargv[2] = count;
			xargv[3] = "-s";
			xargv[4] = size;
			xargv[5] = addr;
			xargv[6] = NULL;
			execv(xargv[0], xargv);
			
		default:
			waitpid (ping_pid, NULL, 0);
			break;
	}
}

void traceroute (const char *cmdline)
{
	const char *crsr;
	const char *tmp;
	char		cmd[64];
	
	buf[0] = 0;
	
	crsr = strchr (cmdline, ' ');
	if (crsr)
	{
		++crsr;
		tmp = strchr (crsr, ' ');
		if (tmp)
		{
			if ((tmp - crsr) < 18)
			{
				memcpy (buf, crsr, tmp-crsr);
				buf[tmp-crsr] = 0;
			}
		}
		else
		{
			if (strlen (crsr) < 18)
			{
				strcpy (buf, crsr);
			}
		}
	}
	if (strlen (buf))
	{
		sprintf (cmd, "/bin/traceroute -m 15 -w 2 %s", buf); /* -n (ip domain lookup) */
		system (cmd);
	}
}

#ifdef CONFIG_GIGA
void giga_script(const char *cmdline)
{
	char cmd[64];

	strcpy(cmd, "/mnt/giga/autocfg");
	system(cmd);
}

void giga_scriptplus(const char *cmdline)
{
	char cmd[64];

	strcpy(cmd, "/mnt/giga/autocfgplus");
	system(cmd);
}

void giga_terminal(const char *cmdline)
{
	char cmd[64];

	sprintf(cmd, "/bin/microcom -D%s", TTS_AUX0);
	system(cmd);
}
#endif
