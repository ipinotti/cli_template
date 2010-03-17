#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <stdlib.h>

int main (int argc, char *argv[])
{
	if (mount("/proc","/proc","proc",0,0)) {
	  fprintf (stderr, "%% Mounting /proc failed\n");
	}
	system ("/etc/router/rc/init.rc");
	execl ("/sbin/systtyd","systtyd", (char *) 0);
	return 0;
}
