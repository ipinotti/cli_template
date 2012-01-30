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
	int ret = 0;
	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no")){
		if (librouter_wifi_ssid_broadcast_enable_set(0) < 0)
			ret = -1;
	}
	else {
		if (librouter_wifi_ssid_broadcast_enable_set(1) < 0)
			ret = -1;
	}

	if (ret < 0)
		printf("%% Error setting ssid broadcast.\n");

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
	int ret = 0;
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	switch (args->argv[1][0]) {
#ifdef NOT_YET_IMPLEMENTED
		case 'a':
			if (librouter_wifi_hw_mode_set(a_hw) < 0)
				ret = -1;
			break;
#endif
		case 'b':
			if (librouter_wifi_hw_mode_set(b_hw) < 0)
				ret = -1;
			break;
		case 'g':
			if (librouter_wifi_hw_mode_set(g_hw) < 0)
				ret = -1;
			break;
		case 'n':
			if (librouter_wifi_hw_mode_set(n_hw) < 0)
				ret = -1;
			break;
		default:
			ret = -1;
			break;
	}

	if (ret < 0)
		printf("%% Error setting wifi hardware mode.\n");

	librouter_destroy_args(args);
}

void apmanager_max_num_station_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (librouter_wifi_max_num_sta_set(atoi(args->argv[1])) < 0)
		printf("%% Error setting max number of stations connected.\n");

	librouter_destroy_args(args);
}

void apmanager_beacon_interval_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (librouter_wifi_beacon_inteval_set(atoi(args->argv[1])) < 0)
		printf("%% Error setting beacon interval.\n");

	librouter_destroy_args(args);
}

void apmanager_rts_threshold_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (librouter_wifi_rts_threshold_set(atoi(args->argv[1])) < 0)
		printf("%% Error setting rts threshold.\n");

	librouter_destroy_args(args);
}

void apmanager_fragmentation_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (librouter_wifi_fragm_threshold_set(atoi(args->argv[1])) < 0)
		printf("%% Error setting fragmentation threshold.\n");

	librouter_destroy_args(args);
}

void apmanager_dtim_interval_set (const char *cmdline)
{
	arglist *args;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (librouter_wifi_dtim_inter_set(atoi(args->argv[1])) < 0)
		printf("%% Error setting DTIM interval.\n");

	librouter_destroy_args(args);
}

void apmanager_preamble_type_set (const char *cmdline)
{
	arglist *args;
	int ret = 0;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[1], "long")){
		if (librouter_wifi_preamble_type_set(long_p) < 0)
			ret = -1;
	}
	else
		if (!strcmp(args->argv[1], "short")){
			if (librouter_wifi_preamble_type_set(short_p) < 0)
				ret = -1;
		}

	if (ret < 0)
		printf("%% Error setting preamble type.\n");

	librouter_destroy_args(args);
}

static int security_none_set(arglist * args)
{
	librouter_wifi_security_mode_struct security;
	memset(&security, 0, sizeof(security));

	security.security_mode = none_sec;

	return librouter_wifi_security_mode_set(&security);
}

static int security_wep_set(arglist * args)
{
	librouter_wifi_security_mode_struct security;
	memset(&security, 0, sizeof(security));

	security.security_mode = wep;

	if (!strcmp(args->argv[2], "open")){
		security.wep_auth = open_a;
		goto wep_end;
	}

	if (!strcmp(args->argv[2], "shared")){
		if (!strcmp(args->argv[3], "ascii")){
			if (!strcmp(args->argv[4], "64Bit")){
				if (strlen(args->argv[5]) != 5){
					printf("%% Error: Wrong WEP ASCII 64Bit Key size.\n");
					return -1;
				}
			}
			else {
				if (!strcmp(args->argv[4], "128Bit")){
					if (strlen(args->argv[5]) != 13){
						printf("%% Error: Wrong WEP ASCII 128Bit Key size.\n");
						return -1;
					}
				}
			}
		}
		else {
			if (!strcmp(args->argv[3], "hex")){
				if (!strcmp(args->argv[4], "64Bit")){
					if (strlen(args->argv[5]) != 10){
						printf("%% Error: Wrong WEP HEX 64Bit Key size.\n");
						return -1;
					}
				}
				else {
					if (!strcmp(args->argv[4], "128Bit")){
						if (strlen(args->argv[5]) != 26){
							printf("%% Error: Wrong WEP HEX 128Bit Key size.\n");
							return -1;
						}
					}
				}
			}
		}
	}

	security.wep_auth = shared;
	strcpy(security.wep_key, args->argv[5]);

wep_end:
	return librouter_wifi_security_mode_set(&security);
}

static int security_wpa_set(arglist * args)
{
	librouter_wifi_security_mode_struct security;
	memset(&security, 0, sizeof(security));

	if (!strcmp(args->argv[1], "wpa"))
		security.security_mode = wpa;
	else
		if (!strcmp(args->argv[1], "wpa2"))
			security.security_mode = wpa2;
		else
			if (!strcmp(args->argv[1], "wpa/wpa2"))
				security.security_mode = wpa_wpa2;

	if (!strcmp(args->argv[2], "psk")){
		if (strlen(args->argv[3]) != 64){
			printf("%% Error: Wrong WPA PSK Key size.\n");
			return -1;
		}
		strcpy(security.wpa_psk, args->argv[3]);
	}
	else
		if (!strcmp(args->argv[2], "phrase")){
			if (strlen(args->argv[3]) < 8 || strlen(args->argv[3]) > 63){
				printf("%% Error: Wrong WPA Phrase Key size.\n");
				return -1;
			}
			strcpy(security.wpa_phrase, args->argv[3]);
		}

	if (librouter_wifi_security_mode_set(&security) < 0)
		return -1;

	return 0;
}

void apmanager_security_mode_set (const char *cmdline)
{
	arglist *args;
	int ret = 0;

	if (need_shutdown_warning())
		return;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no")){
			if (security_none_set(args) < 0)
				ret = -1;
	}
	else {
		if (!strcmp(args->argv[1], "wep")){
			if (security_wep_set(args) < 0)
				ret = -1;
		}
		else {
			if (strstr(args->argv[1], "wpa")){
				if (security_wpa_set(args) < 0)
					ret = -1;
			}
		}
	}

	if (ret < 0)
		printf("%% Error setting Wifi security.\n");

	librouter_destroy_args(args);
}

#endif
#endif /* CONFIG_APMANAGER_C_ */
