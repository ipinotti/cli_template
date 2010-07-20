/* ==============================================================================
 * cish - the cisco shell emulator for LPR
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#ifndef _COMMANDTREE_H
#define _COMMANDTREE_H


/* Global variables (We should really get rid of them!) */
extern char EXTCMD[1024];
extern char EXTSCRIPT[1024];
extern cish_config *cish_cfg;
extern int _cish_enable;
extern int _cish_mask;
extern int _cish_debug;
extern int _cish_booting;
extern const char *_cish_source;
extern char buf[1024];
extern dev_family  *interface_edited;
extern int interface_major;
extern int interface_minor;

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
extern cish_command *command_root;

extern cish_command CMD[];
extern cish_command CMD_CONFIGURE[];

extern cish_command CMD_KEYCHAIN[];
extern cish_command CMD_KEY[];

/* Interfaces */
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[];
extern cish_command CMD_CONFIG_INTERFACE_LOOPBACK[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL[];
#ifdef OPTION_MODEM3G
extern cish_command CMD_CONFIG_INTERFACE_M3G[];
#endif

/* Routing Protocols */
extern cish_command CMD_CONFIG_ROUTER_RIP[];
extern cish_command CMD_CONFIG_ROUTER_OSPF[];
#ifdef OPTION_BGP
extern cish_command CMD_CONFIG_ROUTER_BGP[];
#endif

/* IPSec */
#ifdef OPTION_IPSEC
extern cish_command CMD_CONFIG_CRYPTO[];
extern cish_command CMD_IPSEC_CONNECTION_CHILDREN[];
extern cish_command CMD_IPSEC_CONNECTION_ADD[];
extern cish_command CMD_CRYPTO_IPSEC_NO_CONN[];
#endif

/* Show */
extern cish_command CMD_SHOW_OSPF[];
#ifdef OPTION_BGP
extern cish_command CMD_SHOW_BGP[];
#endif
extern cish_command CMD_SHOW_LEVEL[];

/* QoS */
extern cish_command CMD_POLICYMAP[];
extern cish_command CMD_POLICYMAP_MARKRULE[];


extern cish_command CMD_CONFIG_NO[];
extern cish_command CMD_CONFIG_ROUTER[];

/* Interface */
extern cish_command CMD_CONFIG_INTERFACE[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL_IP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_IP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IP[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[];
#ifdef OPTION_MODEM3G
extern cish_command CMD_CONFIG_INTERFACE_M3G[];
extern cish_command CMD_CONFIG_INTERFACE_M3G_NO[];
#endif

/* Show */
extern cish_command CMD_SHOW[];
extern cish_command CMD_SHOW_IP[];
extern cish_command CMD_SHOW_INTERFACES[];

/* IP */
extern cish_command CMD_IP[];
extern cish_command CMD_NO_IP[];
extern cish_command CMD_IP_DHCP_SERVER[];

extern cish_command CMD_CONFIG_NO_ROUTER[];
extern cish_command CMD_IP_ROUTE3[];
extern cish_command CMD_CLEAR_INTERFACE[];

extern cish_command CMD_SHOW_LEVEL[];

/* AAA */
extern cish_command CMD_CONFIG_AAA[];
extern cish_command CMD_CONFIG_NO_AAA[];
extern cish_command CMD_CONFIG_NO_TACACSSERVER_HOST[];
extern cish_command CMD_CONFIG_TACACSSERVER_HOST[];
extern cish_command CMD_CONFIG_NO_RADIUSSERVER_HOST[];
extern cish_command CMD_CONFIG_RADIUSSERVER_HOST[];
extern cish_command CMD_CONFIG_KEY[];

/* SNMP */
extern cish_command CMD_CONFIG_SNMP[];
extern cish_command CMD_CONFIG_NO_SNMP[];

/* Debug */
extern cish_command CMD_DEBUG[];

extern cish_command CMD_CONFACL1[];
extern cish_command CMD_CONFMANGLE[];
extern cish_command CMD_CONFNAT1[];

extern cish_command CMD_CONFIG_NTP[];

extern cish_command CMD_CONFIG_RMON[];

extern cish_command CMD_CONFIG_CLOCK[];
extern cish_command CMD_TERMINAL[];

/* Quagga */
extern cish_command CMD_ROUTER_RIP_INTERFACE_ETHERNET[];
extern cish_command CMD_ROUTER_OSPF_PASSIVE_INTERFACE_ETHERNET[];
extern cish_command CMD_SHOW_OSPF_INTERFACE_ETHERNET[];
extern cish_command CMD_BGP_INTERFACE_ETHERNET[];

/* Firmware */
extern cish_command CMD_FIRMWARE[];

/* NTP */
extern cish_command CMD_NO_NTP[];

#endif /* _COMMANDTREE_H */
