/*
 * snmp.c
 *
 *  Created on: Nov 11, 2010
 *      Author: Thomás Alimena Del Grande (tgrande@pd3.com.br)
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <linux/autoconf.h>

#include "commands.h"
#include "commandtree.h"

cish_command CMD_CONFIG_SNMP_TEXT[] = {
	{"<text>","", CMD_CONFIG_SNMP_TEXT, snmp_text, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_COM_2[] = {
	{"rw", "Read-write access with this community string", NULL, snmp_community, 1, MSK_NORMAL},
	{"ro", "Read-only access with this community string", NULL, snmp_community, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_COM[] = {
	{"<text>", "SNMP Community string", CMD_CONFIG_SNMP_COM_2, snmp_community, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_TRAPSINK_COMMUNITY[] = {
	{"<text>", "Traps manager community", NULL, snmp_trapsink, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_TRAPSINK[] = {
	{"<ipaddress>", "Traps destination host", CMD_CONFIG_SNMP_TRAPSINK_COMMUNITY, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_SECLEVEL_PRIVPROTO_TYPE[] = {
	{"des", "DES privacy", NULL, snmp_user, 1, MSK_NORMAL},
	{"aes", "AES privacy", NULL, snmp_user, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_SECLEVEL_PRIVPROTO[] = {
	{"privproto", "Privacy protocol", CMD_CONFIG_SNMP_USER_SECLEVEL_PRIVPROTO_TYPE, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO_TYPE[] = {
	{"md5", "MD5 authentication", CMD_CONFIG_SNMP_USER_SECLEVEL_PRIVPROTO, NULL, 1, MSK_NORMAL},
	{"sha", "SHA authentication", CMD_CONFIG_SNMP_USER_SECLEVEL_PRIVPROTO, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO[] = {
	{"authproto", "Authentication protocol", CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO_TYPE, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO_1_TYPE[] = {
	{"md5", "MD5 authentication", NULL, snmp_user, 1, MSK_NORMAL},
	{"sha", "SHA authentication", NULL, snmp_user, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO_1[] = {
	{"authproto", "Authentication protocol", CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO_1_TYPE, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_SECLEVEL[] = {
	{"noauthnopriv", "No authentication and no privacy", NULL, snmp_user, 1, MSK_NORMAL},
	{"authnopriv", "Authentication without privacy", CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO_1, NULL, 1, MSK_NORMAL},
	{"authpriv", "Authentication with privacy", CMD_CONFIG_SNMP_USER_SECLEVEL_AUTHPROTO, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER_RW[] = {
	{"rw", "Read-write access with this user", CMD_CONFIG_SNMP_USER_SECLEVEL, NULL, 1, MSK_NORMAL},
	{"ro", "Read-only access with this user", CMD_CONFIG_SNMP_USER_SECLEVEL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_USER[] = {
	{"<text>", "User name", CMD_CONFIG_SNMP_USER_RW, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

#ifdef OPTION_SNMP_VERSION_SELECT
cish_command CMD_CONFIG_SNMP_VERSION_2_1[] = {
	{"1", "Enable SNMP v1", NULL, snmp_version, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_VERSION_1_2[] = {
	{"2", "Enable SNMP v2c", NULL, snmp_version, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_VERSION_1_3[] = {
	{"3", "Enable SNMP v3", NULL, snmp_version, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_VERSION_1[] = {
	{"2", "Enable SNMP v2c", CMD_CONFIG_SNMP_VERSION_1_3, snmp_version, 1, MSK_NORMAL},
	{"3", "Enable SNMP v3", CMD_CONFIG_SNMP_VERSION_1_2, snmp_version, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_VERSION_2[] = {
	{"1", "Enable SNMP v1", CMD_CONFIG_SNMP_VERSION_1_3, snmp_version, 1, MSK_NORMAL},
	{"3", "Enable SNMP v3", CMD_CONFIG_SNMP_VERSION_2_1, snmp_version, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_VERSION_3[] = {
	{"1", "Enable SNMP v1", CMD_CONFIG_SNMP_VERSION_1_2, snmp_version, 1, MSK_NORMAL},
	{"2", "Enable SNMP v2c", CMD_CONFIG_SNMP_VERSION_2_1, snmp_version, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_SNMP_VERSION[] = {
	{"1", "Enable SNMP v1", CMD_CONFIG_SNMP_VERSION_1, snmp_version, 1, MSK_NORMAL},
	{"2", "Enable SNMP v2c", CMD_CONFIG_SNMP_VERSION_2, snmp_version, 1, MSK_NORMAL},
	{"3", "Enable SNMP v3", CMD_CONFIG_SNMP_VERSION_3, snmp_version, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif /* OPTION_SNMP_VERSION_SELECT */

cish_command CMD_CONFIG_SNMP[] = {
	{"community", "Set community string", CMD_CONFIG_SNMP_COM, NULL, 1, MSK_NORMAL},
	{"contact", "Set system contact information", CMD_CONFIG_SNMP_TEXT, snmp_text, 1, MSK_NORMAL},
	{"enable", "Enable SNMP Agent", NULL, snmp_enable, 1, MSK_NORMAL},
	{"location", "Set system location information", CMD_CONFIG_SNMP_TEXT, snmp_text, 1, MSK_NORMAL},
	{"trapsink", "Set trapsink addresses", CMD_CONFIG_SNMP_TRAPSINK, NULL, 1, MSK_NORMAL},
	{"user", "SNMP v3 users management", CMD_CONFIG_SNMP_USER, NULL, 1, MSK_NORMAL},
#ifdef OPTION_SNMP_VERSION_SELECT
	{"version", "Enable SNMP; SNMP protocol versions enable", CMD_CONFIG_SNMP_VERSION, NULL, 1, MSK_NORMAL},
#endif
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_NO_SNMP_COM_2[] = {
	{"rw", "Read-write access with this community string", NULL, snmp_no_community, 1, MSK_NORMAL},
	{"ro", "Read-only access with this community string", NULL, snmp_no_community, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_NO_SNMP_COM[] = {
	{"<text>", "SNMP Community string", CMD_CONFIG_NO_SNMP_COM_2, snmp_no_community, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_NO_SNMP_TRAPSINK[] = {
	{"<ipaddress>", "Traps destination host", NULL, snmp_no_trapsink, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_NO_SNMP_USER[] = {
	{"<text>", "User name", NULL, snmp_user, 1, MSK_NORMAL},
	{"<enter>", "Remove all SNMP v3 users", NULL, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_NO_SNMP[] = {
	{"community", "Remove a community", CMD_CONFIG_NO_SNMP_COM, NULL, 1, MSK_NORMAL},
	{"contact", "Unset system contact information", NULL, snmp_text, 1, MSK_NORMAL},
	{"location", "Unset system location information", NULL, snmp_text, 1, MSK_NORMAL},
	{"trapsink", "Remove trapsink addresses", CMD_CONFIG_NO_SNMP_TRAPSINK, NULL, 1, MSK_NORMAL},
	{"user", "Remove SNMP v3 user", CMD_CONFIG_NO_SNMP_USER, snmp_user, 1, MSK_NORMAL},
	{"<enter>", "Disable SNMP agent", NULL, snmp_enable, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
