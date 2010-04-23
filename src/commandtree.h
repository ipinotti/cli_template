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

typedef void cish_function (const char *);

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

#define MSK_NORMAL  0x00000001
#define MSK_FLASH   0x00000002 /* running from flash */
#define MSK_RAM     0x00000004 /* running from ram */
#define MSK_FEATURE 0x00000008
#define MSK_RIP     0x00000010
#define MSK_OSPF    0x00000020
#define MSK_BGP     0x00000040
#define MSK_AUX     0x00000080
#define MSK_QOS     0x00000100
#define MSK_VRRP    0x00000200
#define MSK_VPN     0x00000400
#ifdef OPTION_X25
#define MSK_X25     MSK_NORMAL /* X.25 enabled! */
#else
#define MSK_X25     0x00000800
#endif
#define MSK_X25XOT  0x00001000
#define MSK_X25MAP  0x00002000
#define MSK_V35     0x00004000 /* V35 specific commands */
#define MSK_V28     0x00008000 /* V28 specific commands */

#endif
