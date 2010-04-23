#include "sys_exec.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

extern char **environ;
#if 0
int sys_exec (const char *cmd)
{
	int pid, status;
	char *argv[4];
	
	if (cmd == NULL)
		return 1;
	pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0)
	{
		argv[0] = (char *) "sh";
		argv[1] = (char *) "-c";
		argv[2] = (char *) cmd;
		argv[3] = (char *) NULL;
		execve ("/bin/sh", argv, environ);
		exit (127); 
	}
	while (1)
	{
		if (waitpid (pid, &status, 0) == -1)
		{
			if (errno != EINTR)
				return -1;
		}
		else
			return status;
	}
	return -1;
}
#endif

