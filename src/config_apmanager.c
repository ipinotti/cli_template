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

static int need_shutdown_warning(void)
{
	if (librouter_wifi_interface_status()){
		printf("(WLAN) Interface must be shutdown first!\n");
		return 1;
	}

	return 0;
}

void apmanager_ssid_set (const char *cmdline)
{
	arglist *args;
	int length=0;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	length = strlen(args->argv[1]);

	if (length < 8 || length > 63){
		printf("%% Exceed the limit of SSID characters.\n");
		goto end;
	}

	if (librouter_wifi_ssid_set(args->argv[1], length) < 0)
		printf("%% Error setting SSID name.\n");

end:
	librouter_destroy_args(args);
}

void apmanager_ssid_broadcast_set (const char *cmdline)
{
	arglist *args;
	int length=0;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no")){
		if (librouter_wifi_ssid_broadcast_enable_set(0) < 0)
			printf("%% Error setting ssid broadcast.\n");
	}
	else {
		if (librouter_wifi_ssid_broadcast_enable_set(1) < 0)
			printf("%% Error setting ssid broadcast.\n");
	}

	librouter_destroy_args(args);
}


void apmanager_channel_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (librouter_wifi_channel_set(atoi(args->argv[1])) < 0)
		printf("%% Error setting channel.\n");

	librouter_destroy_args(args);
}

void apmanager_hw_mode_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (librouter_wifi_channel_set(atoi(args->argv[1])) < 0)
		printf("%% Error setting channel.\n");

	librouter_destroy_args(args);
}

void apmanager_max_num_station_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	librouter_destroy_args(args);

}

void apmanager_beacon_interval_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	librouter_destroy_args(args);
}

void apmanager_rts_threshold_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	librouter_destroy_args(args);
}

void apmanager_fragmentation_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	librouter_destroy_args(args);
}

void apmanager_dtim_interval_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	librouter_destroy_args(args);
}

void apmanager_preamble_type_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	librouter_destroy_args(args);
}

void apmanager_security_mode_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	librouter_destroy_args(args);
}

#endif
#endif /* CONFIG_APMANAGER_C_ */
