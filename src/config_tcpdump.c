#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"

void tcpdump(const char *cmdline)
{
	pid_t pid;
	arglist *args;
	int i, n_args;
	arg_list argl = NULL;
	char *new_line, f_option[] = "-vv";

	if ((n_args = librouter_parse_args_din((char *)cmdline, &argl)) <= 0)
		return;
	if ((new_line = malloc(strlen(cmdline) + strlen(f_option) + 2)) == NULL) {
		fprintf(stderr, "%% tcpdump exec error!\n");
		librouter_destroy_args_din(&argl);
		return;
	}
	sprintf(new_line, "%s %s ", argl[0], f_option);
	for (i=1; i < n_args; i++) {
		strcat(new_line, argl[i]);
		strcat(new_line, " ");
	}
	new_line[strlen(new_line)-1] = 0;
	librouter_destroy_args_din(&argl);
	args = librouter_make_args(new_line);
	switch (pid = fork()) {
		case -1:
			fprintf(stderr, "%% No processes left\n");
			break;

		case 0:
			execv("/bin/tcpdump", args->argv);
			fprintf(stderr, "%% tcpdump exec error!\n");
			break;

		default:
			waitpid(pid, NULL, 0);
			break;
	}
	librouter_destroy_args(args);
	free(new_line);
}

