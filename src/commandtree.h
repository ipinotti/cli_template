/* ==============================================================================
 * cish - the cisco shell emulator for LPR
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#ifndef _COMMANDTREE_H
#define _COMMANDTREE_H

extern char EXTCMD[1024];
extern char EXTSCRIPT[1024];

extern int _cish_enable;
extern int _cish_mask;

typedef void cish_function(const char *);

typedef struct cish_command {
	const char *name;
	const char *help;
	struct cish_command *children;
	cish_function *func;
	int privilege;
	int mask;
} cish_command;

extern cish_command CMD[];
extern cish_command CEXT;

enum cish_mask {
	MSK_NORMAL = 0x00000001,
	MSK_FLASH = 0x00000002, /* running from flash */
	MSK_RAM = 0x00000004, /* running from ram */
	MSK_FEATURE = 0x00000008,
	MSK_RIP = 0x00000010,
	MSK_OSPF = 0x00000020,
	MSK_BGP = 0x00000040,
	MSK_AUX = 0x00000080,
	MSK_QOS = 0x00000100,
	MSK_VRRP = 0x00000200,
	MSK_VPN = 0x00000400,
	MSK_X25 = 0x00000800,
	MSK_X25XOT = 0x00001000,
	MSK_X25MAP = 0x00002000,
	MSK_V35 = 0x00004000, /* V35 specific commands */
	MSK_V28 = 0x00008000,
};

/* Global Commands */
extern cish_command CMD[];
extern cish_command CMD_CONFIGURE[];
extern cish_command CMD_KEYCHAIN[];
extern cish_command CMD_KEY[];
extern cish_command CMD_SHOW_LEVEL[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[];
extern cish_command CMD_CONFIG_INTERFACE_LOOPBACK[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL[];

#endif
