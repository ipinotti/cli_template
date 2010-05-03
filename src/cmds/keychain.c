#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"

/* rip key chain entries */
cish_command CMD_KEY_STRING[] = {
	{"<text>", "The key", NULL, config_key_string, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_KEY[] = {
#if 0
	{"accept-lifetime", "Set accept lifetime of the key", CMD_KEY_ACCEPTLIFE, NULL, 1, MSK_RIP},
#endif
	{"exit", "Exit current mode and down to previous mode", NULL, config_key_done, 0, MSK_RIP},
	{"help", "Description of the interactive help system", NULL, help, 0, MSK_RIP},
#if 0
	{"key", "Configure a key", CMD_KEYCHAIN_KEY, NULL, 1, MSK_RIP},
#endif
	{"key-string", "Set key string", CMD_KEY_STRING, NULL, 1, MSK_RIP},
#if 0
	{"send-lifetime", "Set send lifetime of the key", CMD_KEY_SENDLIFE, NULL, 1, MSK_RIP},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_KEYCHAIN_KEY[] = {
	{"0-2147483647", "Key identifier number", NULL, config_key, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_KEYCHAIN_NO[] = {
	{"key", "Delete a key", CMD_KEYCHAIN_KEY, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_KEYCHAIN[] = {
	{"exit", "Exit current mode and down to previous mode", NULL, config_keychain_done, 0, MSK_RIP},
	{"help", "Description of the interactive help system", NULL, help, 0, MSK_RIP},
	{"key", "Configure a key", CMD_KEYCHAIN_KEY, NULL, 1, MSK_RIP},
	{"no", "Negate a command or set its defaults", CMD_KEYCHAIN_NO, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_KEY_CHAIN[] = {
	{"<text>", "Key-chain name", NULL, config_keychain, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_KEY[] = {
	{"chain", "Key-chain management", CMD_CONFIG_KEY_CHAIN, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};
