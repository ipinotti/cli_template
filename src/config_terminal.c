#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/config.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <linux/hdlc.h>
#include <linux/if_arp.h>
#include <linux/mii.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"

extern int _cish_booting;

/* RIP key management */
char keychain_name[64];
int key_number;

device_family *interface_edited;
int interface_major, interface_minor;

void config_term(const char *cmdline)
{
	syslog(LOG_INFO, "entered configuration mode for session from %s",
	                _cish_source);
	command_root = CMD_CONFIGURE;
}

void config_term_done(const char *cmdline)
{
	syslog(LOG_INFO, "left configuration mode for session from %s",
	                _cish_source);
	command_root = CMD;
}

void config_keychain(const char *cmdline) /* [no] key chain <text> */
{
	arglist *args;

	args = make_args(cmdline);
	if (args->argc == 4 && strcmp(args->argv[0], "no") == 0) {
		rip_execute_root_cmd(cmdline);
	} else {
		strncpy(keychain_name, args->argv[2], 63); /* save keychain name */
		command_root = CMD_KEYCHAIN;
	}
	destroy_args(args);
}

void config_keychain_done(const char *cmdline)
{
	command_root = CMD_CONFIGURE;
}

void config_key(const char *cmdline) /* [no] key <0-2147483647> */
{
	arglist *args;

	args = make_args(cmdline);
	if (args->argc == 3 && strcmp(args->argv[0], "no") == 0) {
		rip_execute_keychain_cmd(cmdline);
	} else {
		key_number = atoi(args->argv[1]); /* save key number */
		command_root = CMD_KEY;
	}
	destroy_args(args);
}

void config_key_done(const char *cmdline)
{
	command_root = CMD_KEYCHAIN;
}

void config_key_string(const char *cmdline) /* key-string <text> */
{
	arglist *args;

	args = make_args(cmdline);
	rip_execute_key_cmd(cmdline);
	destroy_args(args);
}
