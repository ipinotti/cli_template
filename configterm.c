/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

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

#include "defines.h"
#include "commands.h"
#include "commandtree.h"
#include "nat.h"
#include "options.h"
#include "acl.h"
#include "commands_vrrp.h"

#include "cish_main.h"
#include "pprintf.h"
#include "mangle.h"

extern cish_command CMD[];
extern cish_command CMD_CONFIGURE[];
extern cish_command CMD_KEYCHAIN[];
extern cish_command CMD_KEY[];
extern cish_command CMD_SHOW_LEVEL[];
extern int _cish_booting;

/* RIP key management */
char keychain_name[64];
int key_number;

device_family *interface_edited;
int interface_major, interface_minor;

//#define DEBUG_CMD(x) printf("cmd = %s\n", x)
#define DEBUG_CMD(x)

void config_term(const char *cmdline)
{
	syslog(LOG_INFO, "entered configuration mode for session from %s", _cish_source);
	command_root=CMD_CONFIGURE;
}

void config_term_done(const char *cmdline)
{
	syslog(LOG_INFO, "left configuration mode for session from %s", _cish_source);
	command_root=CMD;
}

void config_keychain(const char *cmdline) /* [no] key chain <text> */
{
	arglist *args;

	args=make_args(cmdline);
	if (args->argc == 4 && strcmp(args->argv[0], "no") == 0) {
		rip_execute_root_cmd(cmdline);
	} else {
		strncpy(keychain_name, args->argv[2], 63); /* save keychain name */
		command_root=CMD_KEYCHAIN;
	}
	destroy_args(args);
}

void config_keychain_done(const char *cmdline)
{
	command_root=CMD_CONFIGURE;
}

void config_key(const char *cmdline) /* [no] key <0-2147483647> */
{
	arglist *args;

	args=make_args(cmdline);
	if (args->argc == 3 && strcmp(args->argv[0], "no") == 0) {
		rip_execute_keychain_cmd(cmdline);
	} else {
		key_number = atoi(args->argv[1]); /* save key number */
		command_root=CMD_KEY;
	}
	destroy_args(args);
}

void config_key_done(const char *cmdline)
{
	command_root=CMD_KEYCHAIN;
}

void config_key_string(const char *cmdline) /* key-string <text> */
{
	arglist *args;

	args=make_args(cmdline);
	rip_execute_key_cmd(cmdline);
	destroy_args(args);
}

#ifdef OPTION_NEW_QOS_CONFIG
void do_bandwidth(const char *cmdline)
{
	char *dev;
	arglist *args;
	unsigned int bw=0;
	
	args = make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		destroy_args(args);
		return;
	}

	/* Check if it is bps, kbps or mbps */
	bw = atoi(args->argv[1]);
	if (strcasestr(args->argv[1],"kbps")) bw *= 1024;
	else if (strcasestr(args->argv[1],"mbps")) bw *= 1048576;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	cfg_interface_bw(dev, bw);
	free(dev);
	destroy_args(args);
	return;
}

void do_max_reserved_bw(const char *cmdline)
{
	char *dev;
	arglist *args;
	unsigned char reserved_bw=0; 

	args = make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		destroy_args(args);
		return;
	}

	reserved_bw = atoi(args->argv[1]);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	cfg_interface_reserved_bw(dev, reserved_bw);
	free(dev);
	return;
}

void do_service_policy(const char *cmdline)
{
	char *dev;
	arglist *args;
	args = make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		destroy_args(args);
		return;
	}
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	apply_policy(dev,args->argv[1]); 
	free(dev);
	return;
}

void no_service_policy(const char *cmdline)
{
	char *dev;
	intf_qos_cfg_t *intf_cfg;
	
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	get_interface_qos_config (dev, &intf_cfg);
	if (intf_cfg)
		intf_cfg->pname[0] = 0; /* clean policy-map */
	release_qos_config(intf_cfg);
	tc_insert_all(dev);
	free(dev);
	return;
}

cish_command CMD_CONFIG_INTERFACE_BW[] = {
	{"<bandwidth>", "Set bandwidth in [k|m]bps", NULL, do_bandwidth, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_MAXBW[] = {
	{"1-100", "Max. reservable bandwidth as % of interface bandwidth", NULL, do_max_reserved_bw, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_SERV_POLICY[] = {
	{"<text>", "policy-map name", NULL, do_service_policy, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};
#else
cish_command CMD_CONFIG_INTERFACE_POLICY_NO[] = {
	{"1-2000000000", "Unset mark rule (as marked on mark-rule)", NULL, interface_policy_no, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY12[] = {
	{"1-4096", "WFQ hold-queue size", NULL, interface_policy, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY11[] = {
	{"1-2048", "FIFO packets size", NULL, interface_policy, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY10[] = {
	{"ecn", "Use early congestion notification", NULL, interface_policy, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY9[] = {
	{"1-100", "Drop probability (%)", CMD_CONFIG_INTERFACE_POLICY10, interface_policy, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY8[] = {
	{"10-5000", "Desired latency (ms)", CMD_CONFIG_INTERFACE_POLICY9, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY7[] = {
	{"1-120", "Perturb (s)", NULL, interface_policy, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY6[] = {
	{"fifo", "Standard first-in first-out", CMD_CONFIG_INTERFACE_POLICY11, interface_policy, 1, MSK_QOS},
	{"red", "Random Early Detection", CMD_CONFIG_INTERFACE_POLICY8, NULL, 1, MSK_QOS},
	{"sfq", "Stochastic Fairness Queue", CMD_CONFIG_INTERFACE_POLICY7, interface_policy, 1, MSK_QOS},
	{"wfq", "Weighted Fairness Queue", CMD_CONFIG_INTERFACE_POLICY12, interface_policy, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY5[] = {
	{"queue", "Set queue strategy", CMD_CONFIG_INTERFACE_POLICY6, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY4[] = {
	{"<burst>", "Set burst <1500-65536>[k]bytes", CMD_CONFIG_INTERFACE_POLICY5, interface_policy, 1, MSK_QOS},
	{"queue", "Set queue strategy", CMD_CONFIG_INTERFACE_POLICY6, NULL, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY3[] = {
	{"<bandwidth>", "Set bandwidth <1000-5056000>[k|m]bps or <1-100>% of remainder", CMD_CONFIG_INTERFACE_POLICY4, interface_policy, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_POLICY2[] = {
	{"0-2", "Set priority (0: high; 2:low)", CMD_CONFIG_INTERFACE_POLICY3, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};


cish_command CMD_CONFIG_INTERFACE_POLICY[] = {
	{"1-2000000000", "Set mark rule (as marked on mark-rule)", CMD_CONFIG_INTERFACE_POLICY2, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};
#endif /*OPTION_NEW_QOS_CONFIG*/

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF[] = {
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_NO_MDKEY[] = {
	{"1-255", "Key ID", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_NO[] = {
	{"authentication", "Enable authentication on this interface", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"authentication-key", "Authentication password (key)", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"cost", "Interface cost", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"dead-interval", "Interval after which a neighbor is declared dead", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"hello-interval", "Time between HELLO packets", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"message-digest-key", "Message digest authentication password (key)", CMD_CONFIG_INTERFACE_IP_OSPF_NO_MDKEY, NULL, 1, MSK_OSPF},
	{"network", "Network type", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"priority", "Router priority", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"retransmit-interval", "Time between retransmitting lost link state advertisements", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"transmit-delay", "Link state transmit delay", CMD_CONFIG_INTERFACE_IP_OSPF_NO_INTF, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_VERSION_12_NO[] = {
	{"1", "RIP version 1", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"2", "RIP version 2", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"<enter>", "", NULL, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_VERSION_NO[] = {
	{"version", "Version control", CMD_CONFIG_INTERFACE_IP_RIP_VERSION_12_NO, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH_STRING_NO[] = {
	{"<text>", "Authentication string (text)", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"<enter>", "", NULL, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH_MODE_NO[] = {
	{"md5", "Keyed message digest", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"text", "Clear text authentication", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"<enter>", "", NULL, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH_KEY_NO[] = {
	{"<text>", "name of key-chain (md5)", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"<enter>", "", NULL, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH_NO[] = {
	{"key-chain", "Authentication key-chain", CMD_CONFIG_INTERFACE_IP_RIP_AUTH_KEY_NO, rip_execute_interface_cmd, 1, MSK_RIP},
	{"mode", "Authentication mode", CMD_CONFIG_INTERFACE_IP_RIP_AUTH_MODE_NO, rip_execute_interface_cmd, 1, MSK_RIP},
	{"string", "Authentication string", CMD_CONFIG_INTERFACE_IP_RIP_AUTH_STRING_NO, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_NO[] = {
	{"authentication", "Authentication control", CMD_CONFIG_INTERFACE_IP_RIP_AUTH_NO, NULL, 1, MSK_RIP},
	{"receive", "Advertisement reception", CMD_CONFIG_INTERFACE_IP_RIP_VERSION_NO, NULL, 1, MSK_RIP},
	{"send", "Advertisement transmission", CMD_CONFIG_INTERFACE_IP_RIP_VERSION_NO, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_NO_ACL2[] = {
//	{"fwd","forward packets", NULL, interface_no_acl, 1, MSK_NORMAL},
	{"in","inbound packets", NULL, interface_no_acl, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_no_acl, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_ACL[] = {
	{"<acl>","Access list name", CMD_CONFIG_INTERFACE_NO_ACL2, interface_no_acl, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_MANGLE2[] = {
	{"in","inbound packets", NULL, interface_no_mangle, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_no_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_MANGLE[] = {
	{"<acl>","MARK rule name", CMD_CONFIG_INTERFACE_NO_MANGLE2, interface_no_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_NAT2[] = {
	{"in","inbound packets", NULL, interface_no_nat, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_no_nat, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_NAT[] = {
	{"<acl>","NAT rule name", CMD_CONFIG_INTERFACE_NO_NAT2, interface_no_nat, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_ethernet_no_ipaddr_secondary, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP2, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_PIMD
cish_command CMD_CONFIG_INTERFACE_IP_PIM[] = {
	{"dense-mode", "Enable PIM dense-mode operation", NULL, pim_dense_mode, 1, MSK_NORMAL},
	{"sparse-mode", "Enable PIM sparse-mode operation", NULL, pim_sparse_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP1, interface_ethernet_no_ipaddr, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Remove QoS policy", CMD_CONFIG_INTERFACE_POLICY_NO, interface_policy_no, 1, MSK_QOS},
#endif
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_PRIORITY2[] = {
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_PRIORITY[] = {
	{"0-255", "Priority", CMD_CONFIG_INTERFACE_IP_OSPF_PRIORITY2, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};


cish_command CMD_CONFIG_INTERFACE_IP_OSPF_NETWORK[] = {
	{"broadcast", "Specify OSPF broadcast multi-access network", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"non-broadcast", "Specify OSPF NBMA network", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"point-to-multipoint", "Specify OSPF point-to-multipoint network", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"point-to-point", "Specify OSPF point-to-point network", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_MKDEY4[] = {
	{"<ipaddress>", "", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_MKDEY3[] = {
	{"<text>", "The OSPF password (key)", CMD_CONFIG_INTERFACE_IP_OSPF_MKDEY4, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_MDKEY2[] = {
	{"md5", "Use MD5 algorithm", CMD_CONFIG_INTERFACE_IP_OSPF_MKDEY3, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_MDKEY[] = {
	{"1-255", "Key ID", CMD_CONFIG_INTERFACE_IP_OSPF_MDKEY2, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS_B2[] = {
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS_B[] = {
	{"3-65535", "Seconds", CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS_B2, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS2[] = {
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS[] = {
	{"1-65535", "Seconds", CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS2, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_COST2[] = {
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_COST[] = {
	{"1-65535", "Cost", CMD_CONFIG_INTERFACE_IP_OSPF_COST2, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_AUTH_KEY2[] = {
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_AUTH_KEY[] = {
	{"<text>", "The OSPF password (key)", CMD_CONFIG_INTERFACE_IP_OSPF_AUTH_KEY2, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_AUTH2[] = {
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF_AUTH[] = {
	{"message-digest", "Use message-digest authentication", CMD_CONFIG_INTERFACE_IP_OSPF_AUTH2, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"null", "Use null authentication", CMD_CONFIG_INTERFACE_IP_OSPF_AUTH2, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<ipaddress>", "Address of interface", NULL, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"<enter>", "", NULL, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_OSPF[] = {
	{"authentication", "Enable authentication on this interface", CMD_CONFIG_INTERFACE_IP_OSPF_AUTH, ospf_execute_interface_cmd, 1, MSK_OSPF},
	{"authentication-key", "Authentication password (key)", CMD_CONFIG_INTERFACE_IP_OSPF_AUTH_KEY, NULL, 1, MSK_OSPF},
	{"cost", "Interface cost", CMD_CONFIG_INTERFACE_IP_OSPF_COST, NULL, 1, MSK_OSPF},
	{"dead-interval", "Interval after which a neighbor is declared dead", CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS, NULL, 1, MSK_OSPF},
	{"hello-interval", "Time between HELLO packets", CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS, NULL, 1, MSK_OSPF},
	{"message-digest-key", "Message digest authentication password (key)", CMD_CONFIG_INTERFACE_IP_OSPF_MDKEY, NULL, 1, MSK_OSPF},
	{"network", "Network type", CMD_CONFIG_INTERFACE_IP_OSPF_NETWORK, NULL, 1, MSK_OSPF},
	{"priority", "Router priority", CMD_CONFIG_INTERFACE_IP_OSPF_PRIORITY, NULL, 1, MSK_OSPF},
	{"retransmit-interval", "Time between retransmitting lost link state advertisements", CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS_B, NULL, 1, MSK_OSPF},
	{"transmit-delay", "Link state transmit delay", CMD_CONFIG_INTERFACE_IP_OSPF_SECONDS, NULL, 1, MSK_OSPF},
	{NULL,NULL,NULL,NULL, 0}
};


cish_command CMD_CONFIG_INTERFACE_IP_RIP_VERSION_2[] = {
	{"2", "RIP version 2", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"<enter>", "", NULL, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_VERSION_1[] = {
	{"1", "RIP version 1", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"<enter>", "", NULL, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_VERSION_12[] = {
	{"1", "RIP version 1", CMD_CONFIG_INTERFACE_IP_RIP_VERSION_1, rip_execute_interface_cmd, 1, MSK_RIP},
	{"2", "RIP version 2", CMD_CONFIG_INTERFACE_IP_RIP_VERSION_2, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_VERSION[] = {
	{"version", "Version control", CMD_CONFIG_INTERFACE_IP_RIP_VERSION_12, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH_STRING[] = {
	{"<text>", "Authentication string (text)", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH_MODE[] = {
	{"md5", "Keyed message digest", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"text", "Clear text authentication", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH_KEY[] = {
	{"<text>", "name of key-chain (md5)", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP_AUTH[] = {
	{"key-chain", "Authentication key-chain", CMD_CONFIG_INTERFACE_IP_RIP_AUTH_KEY, NULL, 1, MSK_RIP},
	{"mode", "Authentication mode", CMD_CONFIG_INTERFACE_IP_RIP_AUTH_MODE, NULL, 1, MSK_RIP},
	{"string", "Authentication string", CMD_CONFIG_INTERFACE_IP_RIP_AUTH_STRING, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_IP_RIP[] = {
	{"authentication", "Authentication control", CMD_CONFIG_INTERFACE_IP_RIP_AUTH, NULL, 1, MSK_RIP},
	{"receive", "Advertisement reception", CMD_CONFIG_INTERFACE_IP_RIP_VERSION, NULL, 1, MSK_RIP},
	{"send", "Advertisement transmission", CMD_CONFIG_INTERFACE_IP_RIP_VERSION, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ACL2[] = {
//	{"fwd","forward packets", NULL, interface_acl, 1, MSK_NORMAL},
	{"in","inbound packets", NULL, interface_acl, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_acl, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ACL[] = {
	{"<acl>","Access list name", CMD_CONFIG_INTERFACE_ACL2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_MANGLE2[] = {
	{"in","inbound packets", NULL, interface_mangle, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_MANGLE[] = {
	{"<acl>","MARK rule name", CMD_CONFIG_INTERFACE_MANGLE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NAT2[] = {
	{"in","inbound packets", NULL, interface_nat, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_nat, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NAT[] = {
	{"<acl>","NAT rule name", CMD_CONFIG_INTERFACE_NAT2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_MTU[] = {
	{"68-1500", "Max Transfer Unit", NULL, interface_mtu, 1, MSK_NORMAL}, /* linux/drivers/net/net_init.c: eth_change_mtu() */
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_DESCRIPTION[] = {
	{"<text>", "Up to 240 characters describing this interface", NULL, interface_description, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_TXQUEUELEN[] = {
	{"10-4096", "Length of the transmit queue", NULL, interface_txqueue, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

// interface ethernet

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_ethernet_ipaddr_secondary, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_ETHERNET_IP3, interface_ethernet_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_ETHERNET_IP2, NULL, 1, MSK_NORMAL},
	{"dhcp", "IP Address negotiated via DHCP", NULL, interface_ethernet_ipaddr_dhcp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_ETHERNET_IP1, NULL, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Add QoS policy", CMD_CONFIG_INTERFACE_POLICY, NULL, 1, MSK_QOS},
#endif
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER[] = {
	{"2-4094", "VLAN number", NULL, vlan_add, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_VLAN_NUMBER[] = {
	{"2-4094", "VLAN number", NULL, vlan_del, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_NO_SNMPTRAP2[] = {
	{"link-status", "Allow SNMP LINKUP and LINKDOWN traps", NULL, interface_no_snmptrap, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_SNMPTRAP1[] = {
	{"trap", "Allow a specific SNMP trap", CMD_CONFIG_INTERFACE_NO_SNMPTRAP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO[] = {
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP, NULL, 1, MSK_NORMAL},
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"vlan", "Delete vlan", CMD_CONFIG_INTERFACE_ETHERNET_NO_VLAN_NUMBER, NULL, 1, MSK_QOS},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP, NULL, 1, MSK_VRRP},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SNMPTRAP2[] = {
	{"link-status", "Allow SNMP LINKUP and LINKDOWN traps", NULL, interface_snmptrap, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_SNMPTRAP1[] = {
	{"trap", "Allow a specific SNMP trap", CMD_CONFIG_INTERFACE_SNMPTRAP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

#ifdef CONFIG_DEVELOPMENT
cish_command CMD_CONFIG_INTERFACE_ETHERNET_RXRING[] = {
 	{"2-2048", "Set RX ring size", NULL, interface_rxring, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_TXRING[] = {
 	{"2-2048", "Set TX ring size", NULL, interface_txring, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_WEIGHT[] = {
 	{"2-1024", "Set max packets processing by poll", NULL, interface_weight, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};
#endif

cish_command CMD_CONFIG_INTERFACE_ETHERNET_SPEED1[] = {
	{"full", "Configure full-duplex mode", NULL, interface_fec_cfg, 1, MSK_NORMAL},
	{"half", "Configure half-duplex mode", NULL, interface_fec_cfg, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_SPEED[] = {
	{"auto", "Enable auto-negotiation mode", NULL, interface_fec_autonegotiation, 1, MSK_NORMAL},
	{"10", "Force 10 Mbps operation", CMD_CONFIG_INTERFACE_ETHERNET_SPEED1, NULL, 1, MSK_NORMAL},
	{"100", "Force 100 Mbps operation", CMD_CONFIG_INTERFACE_ETHERNET_SPEED1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET[] = {
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_IP, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"speed", "Configure speed and related commands", CMD_CONFIG_INTERFACE_ETHERNET_SPEED, NULL, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{"vlan", "Add vlan", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER, NULL, 1, MSK_QOS},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP, NULL, 1, MSK_VRRP},
#endif

#ifdef CONFIG_DEVELOPMENT
	{"rx-ring", "Configure RX ring size", CMD_CONFIG_INTERFACE_ETHERNET_RXRING, NULL, 1, MSK_NORMAL},
	{"tx-ring", "Configure TX ring size", CMD_CONFIG_INTERFACE_ETHERNET_TXRING, NULL, 1, MSK_NORMAL},
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL}
};

// interface ethernet VLAN

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_no_ipaddr_secondary, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP2, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP1, interface_no_ipaddr, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Remove QoS policy", CMD_CONFIG_INTERFACE_POLICY_NO, interface_policy_no, 1, MSK_QOS},
#endif
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_ipaddr_secondary, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP3, interface_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP1, NULL, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol",CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Add QoS policy", CMD_CONFIG_INTERFACE_POLICY, NULL, 1, MSK_QOS},
#endif
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL}
};

#ifdef CONFIG_VLAN_COS
cish_command CMD_CONFIG_VLAN_COS1[] = {
	{"dscp", "Set value from packet dscp", NULL, vlan_change_cos, 1, MSK_NORMAL},
	{"precedence", "Set value from packet precedence", NULL, vlan_change_cos, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_VLAN_COS[] = {
	{"cos", "Set IEEE 802.1Q class of service", CMD_CONFIG_VLAN_COS1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_VLAN_NO_COS[] = {
	{"cos", "Unset IEEE 802.1Q class of service", NULL, vlan_change_cos, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif /* CONFIG_VLAN_COS */

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO[] = {
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_VLAN_COS
	{"set", "Unset QoS values", CMD_CONFIG_VLAN_NO_COS, NULL, 0, MSK_NORMAL},
#endif
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP, NULL, 1, MSK_VRRP},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[] = {
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Interface IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP, NULL, 1, MSK_VRRP},
#endif
#ifdef CONFIG_VLAN_COS
	{"set", "Set QoS values", CMD_CONFIG_VLAN_COS, NULL, 0, MSK_NORMAL},
#endif
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

// interface loopback

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_no_ipaddr_secondary, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP2, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP1, interface_no_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_ipaddr_secondary, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_LOOPBACK_IP3, interface_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_LOOPBACK_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_LOOPBACK_IP1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO[] = {
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP, NULL, 1, MSK_NORMAL},
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK[] = {
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_LOOPBACK_IP, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_LOOPBACK_NO, NULL, 1, MSK_NORMAL},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

// interface tunnel

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_no_ipaddr_secondary, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_TUNNEL_NO_IP3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_TUNNEL_NO_IP2, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_TUNNEL_NO_IP1, interface_no_ipaddr, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_ipaddr_secondary, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IP2[] = {
	{"<netmask>", "IP Netmask", CMD_CONFIG_INTERFACE_TUNNEL_IP3, interface_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_TUNNEL_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_TUNNEL_IP1, NULL, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_MTU[] = {
	{"68-1600", "Max Transfer Unit", NULL, interface_mtu, 1, MSK_NORMAL}, /* linux/net/ipv4/ip_gre.c: ipgre_tunnel_change_mtu() */
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_DST[] = {
	{"<ipaddress>", "Destination IP address", NULL, tunnel_destination, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_KEY[] = {
	{"0-4294967295", "Key", NULL, tunnel_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_MODE[] = {
	{"gre", "Generic route encapsulation protocol", NULL, tunnel_mode, 1, MSK_NORMAL},
	{"ipip", "IP over IP encapsulation", NULL, tunnel_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_AUX[] = {
	{"0-1", "Aux interface number", NULL, tunnel_source_interface, 1, MSK_AUX},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_LOOPBACK[] = {
	{"0-4", "Loopback interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_SERIAL[] = {
	{"0-0", "Serial interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_TUNNEL[] = {
	{"0-9", "Tunnel interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC[] = {
	{"aux", "Aux interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_AUX, NULL, 1, MSK_AUX},
	{"ethernet", "Ethernet interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_LOOPBACK, NULL, 1, MSK_NORMAL},
	{"serial", "Serial interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_SERIAL, NULL, 1, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_TUNNEL, NULL, 1, MSK_NORMAL},
	{"<ipaddress>", "Source IP address", NULL, tunnel_source, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_TTL[] = {
	{"0-255", "Tunnel TTL setting", NULL, tunnel_ttl, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef CONFIG_NET_IPGRE_KEEPALIVE
cish_command CMD_CONFIG_INTERFACE_TUNNEL_KP1[] = {
	{"1-255", "Keepalive retries", NULL, tunnel_keepalive, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_KP[] = {
	{"1-255", "Keepalive period (default 10 seconds)", CMD_CONFIG_INTERFACE_TUNNEL_KP1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL[] = {
	{"checksum", "Enable end to end checksumming of packets", NULL, tunnel_checksum, 1, MSK_NORMAL},
	{"destination", "Destination of tunnel", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_DST, NULL, 1, MSK_NORMAL},
	{"key", "Security or selector key", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_KEY, NULL, 1, MSK_NORMAL},
	{"mode", "Tunnel encapsulation method", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_MODE, NULL, 1, MSK_NORMAL},
	{"path-mtu-discovery", "Enable Path MTU Discovery on tunnel", NULL, tunnel_pmtu, 1, MSK_NORMAL},
	{"sequence-datagrams", "Drop datagrams arriving out of order", NULL, tunnel_sequence, 1, MSK_NORMAL},
	{"source", "Source of tunnel packets", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC, NULL, 1, MSK_NORMAL},
	{"ttl", "Tunnel time-to-live", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_TTL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_TUNNEL[] = {
	{"checksum", "Enable end to end checksumming of packets", NULL, tunnel_checksum, 1, MSK_NORMAL},
	{"destination", "Destination of tunnel", NULL, tunnel_destination, 1, MSK_NORMAL},
	{"key", "Security or selector key", NULL, tunnel_key, 1, MSK_NORMAL},
	{"path-mtu-discovery", "Enable Path MTU Discovery on tunnel", NULL, tunnel_pmtu, 1, MSK_NORMAL},
	{"sequence-datagrams", "Drop datagrams arriving out of order", NULL, tunnel_sequence, 1, MSK_NORMAL},
	{"source", "Source of tunnel packets", NULL, tunnel_source, 1, MSK_NORMAL},
	{"ttl", "Tunnel time-to-live", NULL, tunnel_ttl, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO[] = {
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_TUNNEL_NO_IP, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_NET_IPGRE_KEEPALIVE
	{"keepalive", "Disable Keepalive", NULL, tunnel_keepalive, 1, MSK_NORMAL},
#endif
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"tunnel", "Protocol-over-protocol tunneling", CMD_CONFIG_INTERFACE_TUNNEL_NO_TUNNEL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL[] = {
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_TUNNEL_IP, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_NET_IPGRE_KEEPALIVE
	{"keepalive", "Enable Keepalive", CMD_CONFIG_INTERFACE_TUNNEL_KP, NULL, 1, MSK_NORMAL},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_TUNNEL_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_TUNNEL_NO, NULL, 1, MSK_NORMAL},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"tunnel", "Protocol-over-protocol tunneling", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

device_family *interface_edited;
int interface_major, interface_minor;

/* Valida a subinterface:
 * - verifica se o encapsulamento eh frame-relay/x25:
 *   - se nao for, retorna subinterface invalida;
 *   - se for, verifica se ja existe a subinterface:
 */
int validate_interface_minor(void)
{
	switch(interface_edited->type) {
		case ethernet:
			if(vlan_exists(interface_major, interface_minor))
				return 0; // ok
			break;
		default:
			break;
	}
	return -1; // subinterface invalida
}

void config_interface(const char *cmdline) /* [no] interface <device> <sub> */
{
	arglist *args;
	int no=0;
	char *major, *minor, *dev;
	char device[32], sub[16];

	args=make_args(cmdline);
	if (strcmp(args->argv[0], "no") == 0)
		no=1;
	strncpy(device, args->argv[no ? 2 : 1], 31);
	device[31]=0;
	strncpy(sub, args->argv[no ? 3 : 2], 15);
	sub[15]=0;
	destroy_args(args);

	if ((interface_edited=getfamily(device))) {
		major=sub;
		minor=strchr(major, '.');
		if (minor) *minor++ = 0;
		interface_major=atoi(major);
		if (minor)
		{
			interface_minor=atoi(minor);
			if (validate_interface_minor() < 0)
			{
				fprintf(stderr, "%% Invalid interface number.\n");
				return;
			}
		} else {
			interface_minor = -1;
		}

		switch(interface_edited->type) {
			case ethernet:
				if (interface_minor == -1) {
					command_root=CMD_CONFIG_INTERFACE_ETHERNET;
				} else {
					command_root=CMD_CONFIG_INTERFACE_ETHERNET_VLAN;
				}
				break;
			case loopback:
				command_root=CMD_CONFIG_INTERFACE_LOOPBACK;
				break;
			case tunnel:
				dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
				if (no) {
					del_tunnel(dev);
				} else {
					add_tunnel(dev);
					command_root=CMD_CONFIG_INTERFACE_TUNNEL;
				}
				free(dev);
				break;
			default:
				break;
		}
	} else {
		fprintf(stderr, "%% Unknown device type.\n");
	}
}

void config_interface_done(const char *cmdline)
{
	command_root=CMD_CONFIGURE;
}

void interface_ethernet_ipaddr_dhcp(const char *cmdline) /* ip address dhcp */
{
/*
Cisco1751(config-if)#ip address ?
  A.B.C.D  IP address
  dhcp     IP Address negotiated via DHCP
  pool     IP Address autoconfigured from a local DHCP pool
Cisco1751(config-if)#ip address dhcp ?
  client-id  Specify client-id to use
  hostname   Specify value for hostname option
  <cr>
Cisco1751(config-if)#ip address dhcp client-id ?
  FastEthernet  FastEthernet IEEE 802.3
Cisco1751(config-if)#ip address dhcp hostname ?
  WORD  hostname string
*/
	char *dev, daemon_dhcpc[32];

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	exec_daemon(daemon_dhcpc); /* inittab: #i:34:respawn:/bin/udhcpc -i ethernet0 >/dev/null 2>/dev/null */
	free(dev);
}

void interface_ethernet_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;
	ppp_config cfg;
	char daemon_dhcpc[32];

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (is_daemon_running(daemon_dhcpc))
		kill_daemon(daemon_dhcpc); /* !!! dhcp x ppp unumbered */

	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_ethernet_ip_addr(dev, addr, mask); /* preserve alias addresses */

	// Verifica se o ip unnumbered relaciona a ethernet com a serial
	ppp_get_config(0, &cfg); // Armazena em cfg a configuracao da serial
	if (cfg.ip_unnumbered == interface_major) {
		strncpy(cfg.ip_addr, addr, 16); // Atualiza cfg com os dados da ethernet
		cfg.ip_addr[15]=0;
		strncpy(cfg.ip_mask, mask, 16);
		cfg.ip_mask[15]=0;
		ppp_set_config(0, &cfg); // Atualiza as configuracoes da serial
	}
#if defined(CONFIG_BERLIN_MU0)
	ppp_get_config(1, &cfg); // Armazena em cfg a configuracao da serial
	if (cfg.ip_unnumbered == interface_major) {
		strncpy(cfg.ip_addr, addr, 16); // Atualiza cfg com os dados da ethernet
		cfg.ip_addr[15]=0;
		strncpy(cfg.ip_mask, mask, 16);
		cfg.ip_mask[15]=0;
		ppp_set_config(1, &cfg); // Atualiza as configuracoes da serial
	}
#elif defined(CONFIG_BERLIN_SATROUTER)
	switch( get_board_hw_id() )
	{
		case BOARD_HW_ID_1:
			break;
		case BOARD_HW_ID_0:
		case BOARD_HW_ID_2:
		case BOARD_HW_ID_3:
		case BOARD_HW_ID_4:
			ppp_get_config(1, &cfg); // Armazena em cfg a configuracao da serial
			if (cfg.ip_unnumbered == interface_major) {
				strncpy(cfg.ip_addr, addr, 16); // Atualiza cfg com os dados da ethernet
				cfg.ip_addr[15]=0;
				strncpy(cfg.ip_mask, mask, 16);
				cfg.ip_mask[15]=0;
				ppp_set_config(1, &cfg); // Atualiza as configuracoes da serial
			}
			break;
	}
#endif
	destroy_args(args);
	free(dev);
}

void interface_ethernet_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_ethernet_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[3];
	mask=args->argv[4];
	set_ethernet_no_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;
	char daemon_dhcpc[32];

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (is_daemon_running(daemon_dhcpc))
		kill_daemon(daemon_dhcpc);
	set_ethernet_no_ip_addr(dev);
	free(dev);
}


void interface_shutdown(const char *cmdline) /* shutdown */
{
	char *dev;

	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);

	tc_remove_all(dev);

	dev_set_link_down(dev);

	free(dev);
}

void interface_no_shutdown(const char *cmdline) /* no shutdown */
{
	char *dev;
	device_family *fam;

	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	fam = getfamily(interface_edited->cish_string);

	dev_set_link_up(dev); /* UP */

	if (fam) {
		switch(fam->type) {
			case ethernet:
				reload_udhcpd(interface_major); /* dhcp integration! force reload ethernet address */
				tc_insert_all(dev);
				break;
			default:
				break;
		}
	}

	free(dev);
#ifdef OPTION_SMCROUTE
	kick_smcroute();
#endif
}

void interface_mtu(const char *cmdline)
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);
	dev_set_mtu(dev, val);
	destroy_args(args);
	free(dev);
}

void interface_txqueue(const char *cmdline)
{
	arglist *args;
	int val;
	char *dev;

	args=make_args(cmdline);
	val = atoi(args->argv[1]);
#if 0 /* Use value from command definition! */
	if ((val<2) || (val>256))
	{
		destroy_args (args);
		fprintf (stderr, "%% Value way out of bounds\n");
		return;
	}
#endif
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	dev_set_qlen(dev, val);
	destroy_args(args);
	free(dev);
}

#ifdef CONFIG_DEVELOPMENT
void interface_rxring(const char *cmdline) /* rxring <2-2048> */
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	dev_set_rxring(dev, val);
	destroy_args(args);
	free(dev);
}

void interface_txring(const char *cmdline) /* txring <2-2048> */
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	dev_set_txring(dev, val);
	destroy_args(args);
	free(dev);
}

void interface_weight(const char *cmdline) /* weight <2-1024> */
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);

	if (wan_get_protocol(interface_major) == SCC_PROTO_MLPPP) {
		dev = (char *)malloc(2+1+1);
		sprintf(dev, "%s%d", SERIALDEV_PPP, interface_major); /* 'sx?' */
	} else

		dev_set_weight(dev, val);
	destroy_args(args);
	free(dev);
}
#endif

void interface_description(const char *cmd)
{
	char *description, *dev;
	
	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	description = (char *) cmd;
	while (*description == ' ') ++description;
	description = strchr (description, ' ');
	if (!description) return;
	while (*description == ' ') ++description;
	dev_add_description(dev, description);
	free(dev);
}

void interface_no_description(const char *cmd)
{
	char *dev;
	
	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	dev_del_description(dev);
	free(dev);
}

#ifndef OPTION_NEW_QOS_CONFIG
void interface_policy_no(const char *cmdline)
{
	char *dev;
	arglist *args;

	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline); /* no ip policy <mark> */
	if (args->argc < 4) del_qos_cfg(dev, -1); /* clear all! */
		else del_qos_cfg(dev, atoi(args->argv[3]));
	destroy_args(args);
	tc_insert_all(dev);
	free(dev);
}

void interface_policy(const char *cmdline)
{
	char *dev;
	int i;
	arglist *args;
	qos_cfg_t cfg;
	unsigned int bandwidth, burst, band_total_bps, band_total_perc, band_total_temp;
	char *endptr;

	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline); /* ip policy <mark> <priority> <bandwidth kbps> [[<burst kbytes>] [queue fifo|sfq 1-120|red 1-1000 1-100 ecn]] */
	cfg.mark=atoi(args->argv[2]);
	if (check_qos_cfg_mark(dev, cfg.mark))
	{
		fprintf(stderr, "%% Policy for mark %ld already set for this interface\n", cfg.mark);
		return;
	}
	cfg.prio=atoi(args->argv[3]);
	bandwidth=strtol(args->argv[4], &endptr, 10);
	cfg.bandwidth_bps=cfg.bandwidth_perc=cfg.bandwidth_temp=cfg.burst=0;
	cfg.queue=queue_fifo;
	cfg.fifo_limit=0;
	if (strcasecmp(endptr,"bps")==0) cfg.bandwidth_bps=bandwidth;
	else if (strcasecmp(endptr,"kbps")==0) cfg.bandwidth_bps=bandwidth*1024;
	else if (strcasecmp(endptr,"mbps")==0) cfg.bandwidth_bps=bandwidth*1048576;
	else if (strcasecmp(endptr,"%")==0) cfg.bandwidth_perc=bandwidth;
	if (check_qos_cfg_totals(dev, -1, &band_total_bps, &band_total_perc, &band_total_temp) < 0) return;
	if ((band_total_perc+cfg.bandwidth_perc) > 100)
	{
		fprintf(stderr, "%% Reserved bandwidth exceeds 100%% (%d%%)\n", band_total_perc+cfg.bandwidth_perc);
		return;
	}
	if (args->argc > 5)
	{
		i=5;
		if (strcmp(args->argv[i], "queue") != 0)
		{
			burst=strtol(args->argv[i], &endptr, 10);
			if (strcasecmp(endptr,"bytes") == 0) cfg.burst=burst;
			else if (strcasecmp(endptr,"kbytes")==0) cfg.burst=burst*1024;
			if (args->argc > 6) i++;
		}
		if (strcmp(args->argv[i], "queue") == 0)
		{
			i++;
			if (strcmp(args->argv[i], "fifo") == 0) {
				cfg.queue=queue_fifo;
				if (args->argc == i+2) {
					cfg.fifo_limit=atoi(args->argv[i+1]);
				}
					else cfg.fifo_limit=0;
			}
			else if (strcmp(args->argv[i], "sfq") == 0) {
				cfg.queue=queue_sfq;
				if (args->argc == i+2) {
					cfg.sfq_perturb=atoi(args->argv[i+1]);
				}
					else cfg.sfq_perturb=0;
			}
			else if (strcmp(args->argv[i], "wfq") == 0) {
				cfg.queue=queue_wfq;
				if (args->argc == i+2) {
					cfg.wfq_hold_queue=atoi(args->argv[i+1]);
				}
					else cfg.wfq_hold_queue=1024;
			}
			else if (strcmp(args->argv[i], "red") == 0) {
				cfg.queue=queue_red;
				cfg.red_latency=atoi(args->argv[i+1]);
				cfg.red_probability=atoi(args->argv[i+2]);
				if (args->argc == i+4) {
					if (strcmp(args->argv[i+3], "ecn") == 0) cfg.red_ecn=1;
						else cfg.red_ecn=0;
				}
					else cfg.red_ecn=0;
			}
		}
	}
	add_qos_cfg(dev, &cfg);
	destroy_args(args);
	tc_insert_all(dev);
	free(dev);
}
#endif

void interface_traffic_rate_no(const char *cmdline) /* no frame-relay traffic-rate */
{
	char *dev;

	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	del_frts_cfg(dev);
	tc_insert_all(dev);
	free(dev);
}

#ifdef CONFIG_NET_SCH_FRTBF
void interface_traffic_rate(const char *cmdline) /* frame-relay traffic-rate <CIR> [<EIR>] */
{
	char *dev;
	arglist *args;
	frts_cfg_t cfg;

	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	cfg.cir=atoi(args->argv[2]);
	if (args->argc > 3) cfg.eir=atoi(args->argv[3]);
		else cfg.eir=0;
	add_frts_cfg(dev, &cfg);
	destroy_args(args);
	tc_insert_all(dev);
	free(dev);
}
#endif

#ifdef CONFIG_HDLC_FR_FRAG
void interface_subfr_fragment(const char *cmdline) /* [no] frame-relay fragment [<16-1600>] */
{
	int frag;
	char *dev;
	arglist *args;

	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args = make_args(cmdline);
	if( strcmp(args->argv[0], "no") )
		frag = atoi(args->argv[2]);
	else
		frag = 0;
	destroy_args(args);
	fr_pvc_set_fragment(dev, frag);
	tc_insert_all(dev);
	free(dev);
}
#endif

void dev_add_snmptrap(char *itf)
{
	FILE *f;
	int fd, found=0;
	arg_list argl=NULL;
	char *p, line[100];

	if((fd = open(TRAPCONF, O_RDONLY | O_CREAT, 0600)) < 0)	return;
	close(fd);
	if((f = fopen(TRAPCONF, "r+")))
	{
		while(!found && fgets(line, 100, f))
		{
			if(parse_args_din(line, &argl) > 0)
			{
				if((p = strchr(argl[0], '#')))	*p = '\0';
				if(strlen(argl[0]))
				{
					if(!strcmp(itf, argl[0]))	found++;
				}
				free_args_din(&argl);
			}
		}
		if(!found)
		{
			fseek(f, 0, SEEK_END);
			fwrite(itf, 1, strlen(itf), f);
			fwrite("\n", 1, 1, f);
		}
		fclose(f);
	}
}

void dev_del_snmptrap(char *itf)
{
	int fd;
	FILE *f;
	struct stat st;
	char *p, *aux, *local, buf[100], buf_l[100];
	
	if((fd = open(TRAPCONF, O_RDONLY)) < 0)	return;
	if(fstat(fd, &st) < 0)
	{
		close(fd);
		return;
	}
	if(!(local = malloc(st.st_size+1))) 
	{
		close(fd);
		return;
	}
	local[0] = '\0';
	close(fd);
	
	if((f = fopen(TRAPCONF, "r")))
	{
		while(fgets(buf, 100, f))
		{
			strcpy(buf_l, buf);
			for(aux=buf_l; *aux == ' '; aux++);
			if((p = strchr(aux, ' ')))	*p = '\0';
			if((p = strchr(aux, '#')))	*p = '\0';
			if((p = strchr(aux, '\n')))	*p = '\0';
			if(strcmp(itf, aux))	strcat(local, buf);
		}
		fclose(f);
	}
	
	remove(TRAPCONF);
	if((fd = open(TRAPCONF, O_WRONLY|O_CREAT, st.st_mode)) < 0)
	{
		free(local);
		return;
	}
	write(fd, local, strlen(local));
	close(fd);
	free(local);
}

void interface_snmptrap(const char *cmd)
{
	char *dev;
	
	if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor)))
	{
		if (!strncmp(dev, "aux", 3) || !strncmp(dev, "ethernet", 8) || !strncmp(dev, "serial", 6))
			dev_add_snmptrap(dev);
		free(dev);
	}
}

void interface_no_snmptrap(const char *cmd)
{
	char *dev;

	if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor)))
	{
		if (!strncmp(dev, "aux", 3) || !strncmp(dev, "ethernet", 8) || !strncmp(dev, "serial", 6))
			dev_del_snmptrap(dev);
		free(dev);
	}
}

/* Interface generic ([no] ip address) */
void interface_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_interface_ip_addr(dev, addr, mask); /* preserve alias addresses */
	destroy_args(args);
	free(dev);
}

void interface_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_interface_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[3];
	mask=args->argv[4];
	set_interface_no_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	set_interface_no_ip_addr(dev);
	free(dev);
}

void interface_sppp_ipaddr(const char *cmdline) /* ip address [local] [remote] [mask] */
{
	arglist *args;
	char *local, *remote, *dev, *mask;

	args=make_args(cmdline);
	local=args->argv[2];
	remote=args->argv[3];
	if (args->argc > 4) mask=args->argv[4];
		else mask=NULL;
#ifdef CONFIG_BERLIN_SATROUTER
	{ /* Inclui enderecos da interface */
		IP addr;
		ppp_proto ppp;

		sppp_get_config(interface_major, &ppp);
		ppp.cfg_local = (inet_aton(local, &addr) != 0) ? addr.s_addr : 0;
		ppp.cfg_dest = (inet_aton(remote, &addr) != 0) ? addr.s_addr : 0;
		ppp.cfg_mask = (inet_aton(mask, &addr) != 0) ? addr.s_addr : 0;
		sppp_set_config(interface_major, &ppp);
	}
#endif
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	ip_addr_flush(dev);
	ip_addr_add(dev, local, remote, mask ? mask : "255.255.255.255");
	destroy_args(args);
	free(dev);
}

/* tunnel */
void tunnel_destination(const char *cmdline) /* [no] tunnel destination <ipaddress> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, destination, NULL);
	} else {
		change_tunnel(dev, destination, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_key(const char *cmdline) /* [no] tunnel key <key> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, key, NULL);
	} else {
		change_tunnel(dev, key, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_mode(const char *cmdline) /* tunnel mode gre|ipip */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[2], "gre") == 0) {
		mode_tunnel(dev, IPPROTO_GRE);
	} else if (strcmp(args->argv[2], "ipip") == 0) {
		mode_tunnel(dev, IPPROTO_IPIP);
	}
	/* TODO: pptp l2tp ipsec ipsec-l2tp */
	free(dev);
	destroy_args(args);
}

void tunnel_source_interface(const char *cmdline) /* tunnel source <intf> <sub> */
{
	arglist *args;
	char *dev, source[32];

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	strncpy(source, args->argv[2], 31);
	strncat(source, args->argv[3], 31);
	if (strcmp(dev, source) == 0) {
		fprintf(stderr, "%% Cannot use self\n");
	} else {
		change_tunnel(dev, source_interface, source);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_source(const char *cmdline) /* [no] tunnel source <ipaddress> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, source, NULL);
	} else {
		change_tunnel(dev, source, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_checksum(const char *cmdline) /* [no] tunnel checksum */
{
	arglist *args;
	char *dev;
	int i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, checksum, NULL);
	} else {
		change_tunnel(dev, checksum, &i);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_pmtu(const char *cmdline) /* [no] tunnel path-mtu-discovery */
{
	arglist *args;
	char *dev;
	int i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, pmtu, NULL);
	} else {
		change_tunnel(dev, pmtu, &i);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_sequence(const char *cmdline) /* [no] tunnel sequence-datagrams */
{
	arglist *args;
	char *dev;
	int i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, sequence, NULL);
	} else {
		change_tunnel(dev, sequence, &i);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_ttl(const char *cmdline) /* [no] tunnel ttl <0-255> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, ttl, NULL);
	} else {
		change_tunnel(dev, ttl, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

#ifdef CONFIG_NET_IPGRE_KEEPALIVE
void tunnel_keepalive(const char *cmdline) /* [no] keepalive <0-255> <0-255> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel_kp(dev, 0, 0);
	} else {
		change_tunnel_kp(dev, atoi(args->argv[1]), atoi(args->argv[2]));
	}
	free(dev);
	destroy_args(args);
}
#endif

void interface_fec_autonegotiation(const char *cmdline) /* speed auto */
{
	char *dev;

#ifdef CONFIG_ROOT_NFS
	if (_cish_booting)
		return;
#endif
	if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor))) {
		if (strncmp(dev, "ethernet", 8) == 0) {
			if(fec_autonegotiate_link(dev) < 0)
				printf("%% Not possible to set PHY parameters\n");
		}
		free(dev);
	}
}

void interface_fec_cfg(const char *cmdline) /* speed 10|100 half|full */
{
	char *dev;
	arglist *args;
	int speed100 = -1, duplex = -1;

	args = make_args(cmdline);
	if(args->argc == 3) {
		if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor))) {
			if (strncmp(dev, "ethernet", 8) == 0) {
				/* Speed */
				if(strcmp(args->argv[1], "10") == 0)
					speed100 = 0;
				else if(strcmp(args->argv[1], "100") == 0)
					speed100 = 1;
				/* Duplex */
				if(strcmp(args->argv[2], "half") == 0)
					duplex = 0;
				else if(strcmp(args->argv[2], "full") == 0)
					duplex = 1;
				if(speed100 < 0 || duplex < 0)
					printf("%% Sintax error!\n");
				else {
					if(fec_config_link(dev, speed100, duplex) < 0)
						printf("%% Not possible to set PHY parameters\n");
				}
			}
			free(dev);
		}
	}
	destroy_args(args);
}

