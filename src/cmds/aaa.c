#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/autoconf.h>

#include "commands.h"
#include "commandtree.h"

cish_command CMD_CONFIG_NO_AAA_USERNAME_PRIVILEGE_DATA[] = {
	{"1", "Low Privilege", NULL, del_user, 1, MSK_AUTH},
	{"7", "Medium Privilege", NULL, del_user, 1, MSK_AUTH},
	{"15", "High Privilege (Master)", NULL, del_user, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_USERNAME_PRIVILEGE[] = {
	{"privilege", "Specify the privilege for the user", CMD_CONFIG_NO_AAA_USERNAME_PRIVILEGE_DATA, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT[] = {
	{"default", "The default authentication list", NULL, cmd_aaa_authen, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHENTICATION[] = {
	{"cli", "Set authentication lists for logins.", CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_AUTH},
	{"enable", "Set authentication lists for enable.", CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_AUTH},
	{"web", "Set authentication lists for web.", CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_USERNAME[] = {
	{"<text>", "User name", CMD_CONFIG_NO_AAA_USERNAME_PRIVILEGE, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHOR_DEFAULT[] = {
	{"default", "The default authorization list", NULL, cmd_aaa_author, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHOR[] = {
	{"exec", "For starting an exec (shell)", CMD_CONFIG_NO_AAA_AUTHOR_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_ACCT_DEFAULT[] = {
	{"default", "The default accounting list", NULL, cmd_aaa_acct, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_ACCT1[] = {
	{"0-15", "Enable Level", CMD_CONFIG_NO_AAA_ACCT_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_ACCT[] = {
	{"commands", "For exec (shell) commands", CMD_CONFIG_NO_AAA_ACCT1, NULL, 1, MSK_AUTH},
	{"exec", "For starting an exec (shell)", CMD_CONFIG_NO_AAA_ACCT_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA[] = {
	{"authentication", "Authentication configurations parameters", CMD_CONFIG_NO_AAA_AUTHENTICATION, NULL, 1, MSK_AUTH},
#ifdef OPTION_AAA_AUTHORIZATION
	{"authorization", "Authorization configurations parameters", CMD_CONFIG_NO_AAA_AUTHOR, NULL, 1, MSK_AUTH},
#endif
#ifdef OPTION_AAA_ACCOUNTING
	{"accounting", "Accounting configurations parameters", CMD_CONFIG_NO_AAA_ACCT, NULL, 1, MSK_AUTH},
#endif

	{"username", "Establish User Name Authentication", CMD_CONFIG_NO_AAA_USERNAME, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP_LOCAL[] = {
	{"local", "Use local username authentication.", NULL, cmd_aaa_authen, 1, MSK_AUTH},
	{"<enter>", "", NULL, NULL, 0, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP[] = {
	{"radius", "Use list of all Radius hosts.", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP_LOCAL, cmd_aaa_authen, 1, MSK_AUTH},
	{"tacacs+", "Use list of all Tacacs+ hosts.", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP_LOCAL, cmd_aaa_authen, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHENTICATION_LOGIN[] = {
	{"group", "Use Server-group", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP, NULL, 1, MSK_AUTH},
	{"local", "Use local username authentication.", NULL, cmd_aaa_authen, 1, MSK_AUTH},
	{"none", "NO authentication.", NULL, cmd_aaa_authen, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHEN_DEFAULT[] = {
	{"default", "The default accounting list", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

// cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH[] = {
// 	{"<string>", "Encrypted password", NULL, add_user, 1, MSK_AUTH},
// 	{NULL,NULL,NULL,NULL, 0}
// };

// cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA[] = {
// 	{"<text>", "The UNENCRYPTED (cleartext) user password", NULL, add_user, 1, MSK_AUTH},
// 	{"hash", "Encrypted password", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH, NULL, 2, MSK_AUTH}, /* needs especial privilege! (2) */
// 	{NULL,NULL,NULL,NULL, 0}
// };
//
// cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD[] = {
// 	{"password", "Specify the password for the user", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA, NULL, 1, MSK_AUTH},
// 	{NULL,NULL,NULL,NULL, 0}
// };


cish_command CMD_CONFIG_AAA_USERNAME_PRIVILEGE_DATA[] = {
	{"1", "Low Privilege", NULL, add_user, 1, MSK_AUTH},
	{"7", "Medium Privilege", NULL, add_user, 1, MSK_AUTH},
	{"15", "High Privilege (Master)", NULL, add_user, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME_PRIVILEGE[] = {
	{"privilege", "Specify the privilege for the user", CMD_CONFIG_AAA_USERNAME_PRIVILEGE_DATA, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHENTICATION[] = {
	{"cli", "Set authentication lists for logins.", CMD_CONFIG_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_AUTH},
	{"enable", "Set authentication lists for enable.", CMD_CONFIG_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_AUTH},
	{"web", "Set authentication lists for web.", CMD_CONFIG_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH[] = {
	{"<string>", "Encrypted password", CMD_CONFIG_AAA_USERNAME_PRIVILEGE, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA[] = {
	{"<text>", "The UNENCRYPTED (cleartext) user password", CMD_CONFIG_AAA_USERNAME_PRIVILEGE, NULL, 1, MSK_AUTH},
	{"hash", "Encrypted password", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH,
					NULL, 2, MSK_AUTH}, /* needs especial priviledge! (2) */
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD[] = {
	{"password", "Specify the password for the user", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME[] = {
	{"<text>", "User name", CMD_CONFIG_AAA_USERNAME_PASSWORD, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_TACACS[] = {
	{"radius", "Use list of all Radius hosts.", NULL, cmd_aaa_acct, 1, MSK_AUTH},
	{"tacacs+", "Use list of all Tacacs+ hosts.", NULL, cmd_aaa_acct, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_GROUP[] = {
	{"group", "Use Server-group", CMD_CONFIG_AAA_ACCT_TACACS, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_STARTSTOP[] = {
	{"start-stop", "Record start and stop without waiting", CMD_CONFIG_AAA_ACCT_GROUP, NULL, 1, MSK_AUTH},
	{"none", "no accounting", NULL, cmd_aaa_acct, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_DEFAULT[] = {
	{"default", "The default accounting list", CMD_CONFIG_AAA_ACCT_STARTSTOP, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT1[] = {
	{"0-15", "Enable Level", CMD_CONFIG_AAA_ACCT_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT[] = {
	{"commands", "For exec (shell) commands", CMD_CONFIG_AAA_ACCT1, NULL, 1, MSK_AUTH},
	{"exec", "For starting an exec (shell)", CMD_CONFIG_AAA_ACCT_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};
cish_command CMD_CONFIG_AAA_AUTHOR_LOCAL[] = {
	{"local", "Use local database", NULL, cmd_aaa_author, 1, MSK_AUTH},
	{"<enter>", "", NULL, NULL, 0, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR_GROUP1[] = {
	{"radius", "Use list of all Radius hosts.", CMD_CONFIG_AAA_AUTHOR_LOCAL, cmd_aaa_author, 1, MSK_AUTH},
	{"tacacs+", "Use list of all Tacacs+ hosts.", CMD_CONFIG_AAA_AUTHOR_LOCAL, cmd_aaa_author, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR_GROUP[] = {
	{"group", "Use Server-group", CMD_CONFIG_AAA_AUTHOR_GROUP1, NULL, 1, MSK_AUTH},
	{"none", "No authorization (always succeeds)", NULL, cmd_aaa_author, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR_DEFAULT[] = {
	{"default", "The default accounting list", CMD_CONFIG_AAA_AUTHOR_GROUP, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR[] = {
	{"exec", "For starting an exec (shell)", CMD_CONFIG_AAA_AUTHOR_DEFAULT, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA[] = {
#ifdef OPTION_AAA_ACCOUNTING
	{"accounting", "Accounting configurations parameters", CMD_CONFIG_AAA_ACCT, NULL, 1, MSK_AUTH},
#endif

	{"authentication", "Authentication configurations parameters", CMD_CONFIG_AAA_AUTHENTICATION, NULL, 1, MSK_AUTH},

#ifdef OPTION_AAA_AUTHORIZATION
	{"authorization", "Authorization configurations parameters", CMD_CONFIG_AAA_AUTHOR, NULL, 1, MSK_AUTH},
#endif

	{"username", "Establish User Name Authentication", CMD_CONFIG_AAA_USERNAME, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};


/***********************************************************/
/******** RADIUS SERVER CONFIG *****************************/
/***********************************************************/

cish_command CMD_CONFIG_RADIUSSERVER_TIMEOUTVALUE[] = {
	{"1-1000", "Timeout value in seconds to wait for server to reply", NULL, add_radiusserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_TIMEOUT[] = {
	{"timeout", "Time to wait for this RADIUS server to reply", CMD_CONFIG_RADIUSSERVER_TIMEOUTVALUE, NULL, 1, MSK_AUTH},
	{"<enter>", "", NULL, NULL, 0, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_KEYDATA[] = {
	{"<text>", "The UNENCRYPTED (cleartext) server key", CMD_CONFIG_RADIUSSERVER_TIMEOUT, add_radiusserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_KEY[] = {
	{"key", "per-server encryption key", CMD_CONFIG_RADIUSSERVER_KEYDATA, NULL, 1, MSK_AUTH},
	{"<enter>", "", NULL, NULL, 0, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of RADIUS server", CMD_CONFIG_RADIUSSERVER_KEY, add_radiusserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_HOST[] = {
	{"host", "Specify a RADIUS server", CMD_CONFIG_RADIUSSERVER_HOSTIP, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_RADIUSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of RADIUS server", NULL, del_radiusserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_RADIUSSERVER_HOST[] = {
	{"host", "Specify a RADIUS server", CMD_CONFIG_NO_RADIUSSERVER_HOSTIP, NULL, 1, MSK_AUTH},
	{"<enter>", "Clear RADIUS servers", NULL, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};


/***********************************************************/
/******** TACACS SERVER CONFIG *****************************/
/***********************************************************/
cish_command CMD_CONFIG_NO_TACACSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of TACACS server", NULL, del_tacacsserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_TACACSSERVER_HOST[] = {
	{"host", "Specify a TACACS server", CMD_CONFIG_NO_TACACSSERVER_HOSTIP, NULL, 1, MSK_AUTH},
	{"<enter>", "Clear TACACS servers", NULL, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_TIMEOUTVALUE[] = {
	{"1-1000", "Timeout value in seconds to wait for server to reply", NULL, add_tacacsserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_TIMEOUT[] = {
	{"timeout", "Time to wait for this TACACS server to reply", CMD_CONFIG_TACACSSERVER_TIMEOUTVALUE, NULL, 1, MSK_AUTH},
	{"<enter>", "", NULL, NULL, 0, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_KEYDATA[] = {
	{"<text>", "The UNENCRYPTED (cleartext) server key", CMD_CONFIG_TACACSSERVER_TIMEOUT, add_tacacsserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_KEY[] = {
	{"key", "per-server encryption key", CMD_CONFIG_TACACSSERVER_KEYDATA, NULL, 1, MSK_AUTH},
	{"<enter>", "", NULL, NULL, 0, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of TACACS server", CMD_CONFIG_TACACSSERVER_KEY, add_tacacsserver, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_HOST[] = {
	{"host", "Specify a TACACS server", CMD_CONFIG_TACACSSERVER_HOSTIP, NULL, 1, MSK_AUTH},
	{NULL,NULL,NULL,NULL, 0}
};
