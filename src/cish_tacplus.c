
#include <stdio.h>
#include <sys/mman.h>	/*mmap*/
#include <dlfcn.h>	/*dlopen, dlsym*/

#include "cish_tacplus.h"

/* Accounting */
int tacacs_log(unsigned char *line, int priv_lvl)
{
	void *handle;
	int (*tacacs_send_log_command)(unsigned char *, int);
	char *error;

	handle = dlopen("/lib/security/pam_tacplus.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		return (-1);
	}

	dlerror(); /* Clear any existing error */
	tacacs_send_log_command = dlsym(handle, "tacacs_send_log_command");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "%s\n", error);
		return (-1);
	}
	(*tacacs_send_log_command)(line, priv_lvl);
	dlclose(handle);
	return 0;
}
