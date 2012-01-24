/*
 * config_apmanager.c
 *
 *  Created on: Jan 16, 2012
 *      Author: Igor Kramer Pinotti (ipinotti@pd3.com.br)
 */

#ifndef CONFIG_APMANAGER_C_
#define CONFIG_APMANAGER_C_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/types.h>

#include <librouter/options.h>
#include <librouter/args.h>

#ifdef OPTION_WIFI
#include <librouter/wifi.h>

void apmanager_ssid_set (const char *cmdline)
{
	arglist *args;
	int length=0;

	args = librouter_make_args(cmdline);

	length = strlen(args->argv[1]);

	if (length < 8 || length > 63){
		printf("%% Exceed the limit of SSID characters.\n");
		goto end;
	}

	if (librouter_wifi_ssid_set(args->argv[1]) < 0)
		printf("%% Error setting SSID name.\n");

end:
	librouter_destroy_args(args);

}



#endif
#endif /* CONFIG_APMANAGER_C_ */
