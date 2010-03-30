#include "commands.h"
#include "cish_main.h"
#include "options.h"

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void ssh(const char *cmd) /* ssh <ipaddr> <username> <port> */
{
	int i;
	arglist *args;
	pid_t pid;
	char *xargv[7];

	args=make_args(cmd);
	switch (pid=fork())
	{
		case -1:
			fprintf (stderr, "%% No processes left\n");
			return;
			
		case 0:
			i=0;
#ifdef OPTION_OPENSSH
			xargv[i++] = "/bin/ssh";
#else
			xargv[i++] = "/bin/dbclient";
#endif
			if (args->argc == 4)
			{
				xargv[i++] = "-l";
				xargv[i++] = args->argv[2];
				xargv[i++] = "-p";
				xargv[i++] = args->argv[3];
			}
			else if (args->argc == 3)
			{
				xargv[i++] = "-l";
				xargv[i++] = args->argv[2];
			}
			xargv[i++] = args->argv[1];
			xargv[i++] = NULL;
			//signal (SIGINT, SIG_DFL);
			execv(xargv[0], xargv);
			//signal (SIGINT, SIG_IGN);
			fprintf(stderr, "%% execv error:%s\n", strerror(errno));
			
		default:
			waitpid(pid, NULL, 0);
			break;
	}
	destroy_args(args);
} 

void telnet (const char *cmdline)
{
	arglist *args;
	char addr[32];
	char port[32];
	char *xargv[4];
	pid_t pid;
	
	args = make_args (cmdline);
	strncpy(addr, args->argv[1], 31); 
	addr[31] = 0;
	if (args->argc>2)
	{
		strncpy(port, args->argv[2], 31); 
		port[31] = 0;
	}
	else
	{
		port[0] = 0;
	}
	destroy_args (args);
	
	switch (pid = fork())
	{
		case -1:
			fprintf (stderr, "%% No processes left\n");
			return;
			
		case 0:
			xargv[0] = "/bin/telnet";
			xargv[1] = addr;
			xargv[2] = port[0] ? port : NULL;
			xargv[3] = NULL;
			//signal (SIGINT, SIG_DFL);
			execv(xargv[0], xargv);
			//signal (SIGINT, SIG_IGN);
			fprintf(stderr, "%% execv error:%s\n", strerror(errno));
			
		default:
			waitpid (pid, NULL, 0);
			break;
	}
}
