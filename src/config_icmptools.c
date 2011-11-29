#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"

void ping (const char *cmdline)
{
	arglist *args;
	int argc;
	char count[32], size[32], addr[INET6_ADDRSTRLEN + 1];
	char *xargv[16];
	pid_t ping_pid;
	
	args = librouter_make_args (cmdline);
	
	memset(addr, 0, sizeof(addr));
	strncpy(addr, args->argv[1], sizeof(addr)-1);
	
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
	
	librouter_destroy_args (args);
	
	switch (ping_pid = fork())
	{
		case -1:
			fprintf (stderr, "%% No processes left\n");
			return;
			
		case 0:
			if (!strcmp(args->argv[0],"ping6"))
				xargv[0] = "/bin/ping6";
			else
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
	arglist *args;
	pid_t pid;
	char *xargv[16];
	char addr[INET6_ADDRSTRLEN + 1];

	args = librouter_make_args (cmdline);

	memset(addr, 0, sizeof(addr));
	strncpy(addr, args->argv[1], sizeof(addr)-1);

	switch (pid = fork())
	{
		case -1:
			fprintf (stderr, "%% No processes left\n");
			return;

		case 0:
			if (!strcmp(args->argv[0],"traceroute6"))
				xargv[0] = "/bin/traceroute6";
			else
				xargv[0] = "/bin/traceroute";
			xargv[1] = "-m";
			xargv[2] = "15";
			xargv[3] = "-w";
			xargv[4] = "2";
			xargv[5] = addr;
			xargv[6] = NULL;
			execv(xargv[0], xargv);

		default:
			waitpid (pid, NULL, 0);
			break;
	}

	librouter_destroy_args(args);
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
