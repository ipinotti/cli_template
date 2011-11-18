#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_NTPD
cish_command CMD_NO_NTP_RESTRICT[] = {
	{"<ipaddress>","Exclude one rule", NULL, no_ntp_restrict, 1, MSK_NORMAL},
	{"<enter>", "Exclude all rules", NULL, NULL, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_NTP_SERVER[] = {
	{"<ipaddress>","Exclude one server", NULL, no_ntp_server, 1, MSK_NORMAL},
	{"<enter>", "Exclude all servers", NULL, NULL, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_NTP_TRUSTEDKEYS[] = {
	{"1-16","Exclude one key from trusted list", NULL, no_ntp_trustedkeys, 1, MSK_NORMAL},
	{"<enter>", "Exclude all keys from trusted list", NULL, NULL, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_NTP[] = {
#ifdef OPTION_NTPD_authenticate
	{"authenticate","Use of authentication", NULL, no_ntp_authenticate, 1, MSK_NORMAL},
#endif
	{"enable","Disable NTP synchronization", NULL, ntp_enable, 1, MSK_NORMAL},
	{"restrict","NTP restriction rules", CMD_NO_NTP_RESTRICT, no_ntp_restrict, 1, MSK_NORMAL},
	{"server","NTP servers", CMD_NO_NTP_SERVER, no_ntp_server, 1, MSK_NORMAL},
	{"trusted-key","Trusted keys", CMD_NO_NTP_TRUSTEDKEYS, no_ntp_trustedkeys, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_NTP_KEYS_VALUE[] = {
	{"<string>","Authentication key", NULL, ntp_set_key_value, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_KEYS_TYPE[] = {
	{"md5","MD5 authentication", CMD_CONFIG_NTP_KEYS_VALUE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_KEYS[] = {
	{"1-16","Key number", CMD_CONFIG_NTP_KEYS_TYPE, NULL, 1, MSK_NORMAL},
	{"generate","Generate new keys", NULL, ntp_generate_keys, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_RESTRICT_MASK[] = {
	{"<netmask>","Network mask to be restricted", NULL, ntp_restrict, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_RESTRICT_IP[] = {
	{"<ipaddress>","Address to be restricted", CMD_CONFIG_NTP_RESTRICT_MASK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_SERVER_IP_KEYNUM[] = {
	{"1-16","Key number", NULL, ntp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_SERVER_IP[] = {
	{"key","Configure key to use with server", CMD_CONFIG_NTP_SERVER_IP_KEYNUM, NULL, 1, MSK_NORMAL},
	{"<enter>", "Enter server", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_SERVER[] = {
	{"<ipaddress>","Address of the server", CMD_CONFIG_NTP_SERVER_IP, ntp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_TRUSTEDKEY[] = {
	{"1-16","Key number", NULL, ntp_trust_on_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP[] = {
#ifdef OPTION_NTPD_authenticate
	{"authenticate","Authenticate time sources", NULL, ntp_authenticate, 1, MSK_NORMAL},
#endif
	{"authentication-key","Authentication key for trusted time sources", CMD_CONFIG_NTP_KEYS, NULL, 1, MSK_NORMAL},
	{"enable","Enable NTP synchronization", NULL, ntp_enable, 1, MSK_NORMAL},
	{"restrict","NTP restriction rules", CMD_CONFIG_NTP_RESTRICT_IP, NULL, 1, MSK_NORMAL},
	{"server","Add time synchronization server", CMD_CONFIG_NTP_SERVER, NULL, 1, MSK_NORMAL},
	{"trusted-key","Configure trusted keys", CMD_CONFIG_NTP_TRUSTEDKEY, NULL, 1, MSK_NORMAL},
	{"update-calendar","Sync RTC with system clock", NULL, ntp_update_calendar, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#else

cish_command CMD_CONFIG_NTP_IP[] = {
	{"<ipaddress>","IP Address of NTP server host", NULL, ntp_sync, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP[] = {
	{"300-86400", "Query interval (seconds)", CMD_CONFIG_NTP_IP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif
