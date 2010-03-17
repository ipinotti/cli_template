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
#include <linux/ipx.h>
#include <netinet/in.h>
#include <linux/hdlc.h>
#include <linux/if_arp.h>
#include <linux/mii.h>
#include <asm/ucc_hdlc.h>

#include "defines.h"
#include "commands.h"
#include "commandtree.h"
#include "nat.h"
#include "options.h"
#include "acl.h"
#include "commands_vrrp.h"

#include <libconfig/acl.h>
#include <libconfig/device.h>
#include <libconfig/dhcp.h>
#include <libconfig/exec.h>
#include <libconfig/typedefs.h>
#include <libconfig/ip.h>
#include <libconfig/dev.h>
#include <libconfig/fr.h>
#include <libconfig/wan.h>
#include <libconfig/args.h>
#include <libconfig/bridge.h>
#include <libconfig/chdlc.h>
#include <libconfig/ipx.h>
#include <libconfig/ppp.h>
#include <libconfig/qos.h>
#include <libconfig/vlan.h>
#include <libconfig/x25.h>
#include <libconfig/pim.h>
#include <libconfig/smcroute.h>
#include <libconfig/tunnel.h>
#include <libconfig/lan.h>
#include <libconfig/ppcio.h>
#include <libconfig/sppp.h>

#include "cish_main.h"
#include "pprintf.h"
#include "mangle.h"

void interface_no_shutdown (const char *);
void interface_ethernet_ipaddr_dhcp(const char *);
void interface_ethernet_ipaddr (const char *);
void interface_ethernet_ipaddr_secondary (const char *);
void interface_ethernet_no_ipaddr (const char *);
void interface_ethernet_no_ipaddr_secondary (const char *);
void interface_fr_ipaddr (const char *);
void interface_subfr_ipaddr (const char *);
void interface_subfr_fragment(const char *);
void interface_subfr_bridgegroup (const char *);
void interface_subfr_no_bridgegroup (const char *);
void interface_ethernet_bridgegroup (const char *);
void interface_ethernet_no_bridgegroup (const char *);
void interface_chdlc_ipaddr (const char *);
void interface_chdlc_bridgegroup (const char *);
void interface_chdlc_no_bridgegroup (const char *);
void interface_sppp_ipaddr (const char *);
void interface_ipxnet (const char *);
void interface_no_ipxnet (const char *);
void interface_ethernet_ipxnet (const char *);
void interface_ethernet_no_ipxnet (const char *);
void interface_shutdown (const char *);
void interface_txqueue (const char *);
void config_interface_done (const char *);
void interface_mtu (const char *);
void interface_description (const char *);
void interface_no_description (const char *);
void interface_rxring(const char *);
void interface_txring(const char *);
void interface_weight(const char *);
void interface_x25_lapb_mode(const char *);
void interface_x25_lapb_n2(const char *);
void interface_x25_lapb_t1(const char *);
void interface_x25_lapb_t2(const char *);
void interface_x25_lapb_window(const char *);
void interface_x25_route_add(const char *);
void interface_x25_route_del(const char *);
void interface_x25_svc_add(const char *);
void interface_x25_svc_del(const char *);
void interface_subx25_ipaddr(const char *);
void interface_subx25_address(const char *);
void interface_subx25_ips(const char *);
void interface_subx25_map_ip(const char *);
void interface_subx25_ops(const char *);
void interface_subx25_win(const char *);
void interface_subx25_wout(const char *);
void interface_policy_no(const char *);
void interface_policy(const char *);
void interface_sppp_ipaddr(const char *cmdline);
void interface_traffic_rate_no(const char *);
void interface_traffic_rate(const char *);
void interface_subfr_fragment(const char *cmdline);
void interface_snmptrap(const char *);
void interface_no_snmptrap(const char *);
void interface_ipaddr(const char *);
void interface_ipaddr_secondary(const char *);
void interface_no_ipaddr(const char *);
void interface_no_ipaddr_secondary(const char *);
void tunnel_destination(const char *);
void tunnel_key(const char *);
void tunnel_mode(const char *);
void tunnel_source_interface(const char *);
void tunnel_source(const char *);
void tunnel_checksum(const char *);
void tunnel_pmtu(const char *);
void tunnel_sequence(const char *);
void tunnel_keepalive(const char *);
void tunnel_ttl(const char *);
void interface_fec_autonegotiation(const char *cmdline);
void interface_fec_cfg(const char *cmdline);



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

cish_command CMD_CONFIG_INTERFACE_NO_IPX[] = {
	{"network", "Unset IPX network", NULL, interface_no_ipxnet, 1, MSK_NORMAL},
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

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPX_NET3[] = {
	{"802.2", "IEEE 802.2", NULL, interface_ethernet_ipxnet, 1, MSK_NORMAL},
	{"802.3", "IEEE 802.3", NULL, interface_ethernet_ipxnet, 1, MSK_NORMAL},
	{"ethernet_II", "Ethernet II", NULL, interface_ethernet_ipxnet, 1, MSK_NORMAL},
	{"snap", "Sub Network Access Protocol", NULL, interface_ethernet_ipxnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPX_NET2[] = {
	{"encapsulation", "IPX Encapsulation", CMD_CONFIG_INTERFACE_ETHERNET_IPX_NET3, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPX_NET[] = {
	{"<ipx network>", "IPX Network number", CMD_CONFIG_INTERFACE_ETHERNET_IPX_NET2, interface_ethernet_ipxnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPX[] = {
	{"network", "Assing an IPX network and enable IPX routing", CMD_CONFIG_INTERFACE_ETHERNET_IPX_NET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_ethernet_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IPX[] = {
	{"network", "Unset IPX network", NULL, interface_no_ipxnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_ethernet_no_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
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
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPX, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
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
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_ETHERNET_IPX, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"speed", "Configure speed and related commands", CMD_CONFIG_INTERFACE_ETHERNET_SPEED, NULL, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
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

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO[] = {
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPX, NULL, 1, MSK_NORMAL},
	{"set", "Unset QoS values", CMD_CONFIG_VLAN_NO_COS, NULL, 0, MSK_NORMAL},
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP, NULL, 1, MSK_VRRP},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[] = {
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Interface IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Interface IPX parameters", CMD_CONFIG_INTERFACE_ETHERNET_IPX, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP, NULL, 1, MSK_VRRP},
#endif
	{"set", "Set QoS values", CMD_CONFIG_VLAN_COS, NULL, 0, MSK_NORMAL},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

// interface serial - comum a todos os encapsulamentos

cish_command CMD_CONFIG_INTERFACE_SERIAL_ENCAP[] = {
	{"frame-relay", "Frame Relay IETF RFC1490/RFC2427", NULL, serial_encap, 1, MSK_NORMAL},
	{"hdlc", "Cisco HDLC", NULL, serial_encap, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point protocol", NULL, serial_encap, 1, MSK_NORMAL},
	{"x25", "X.25 protocol", NULL, serial_encap, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL[] = {
	{"synchronous", "Synchronous (V.35)", NULL, serial_physical, 1, MSK_NORMAL},
#ifdef CONFIG_UCC_HDLC_ASSYNC
	{"asynchronous", "Asynchronous (V.28)", NULL, serial_physical, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CLOCK_RATE[] = {
#ifdef CONFIG_DEVELOPMENT
	{"64000-10240000", "Speed (bits per second)", NULL, serial_clock_rate, 1, MSK_V35},
#else
	{"64000-5056000", "Speed (bits per second)", NULL, serial_clock_rate, 1, MSK_V35},
#endif
	{"1200-230400", "Speed (bits per second)", NULL, serial_clock_rate, 1, MSK_V28},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CLOCK_TYPE[] = {
	{"external", "External clock (DTE)", NULL, serial_clock_type, 1, MSK_NORMAL},
	{"internal", "Internal clock (DCE)", NULL, serial_clock_type, 1, MSK_NORMAL},
	{"txint", "TX clock internal", NULL, serial_clock_type, 1, MSK_NORMAL},
	{"txfromrx", "TX clock from RX clock", NULL, serial_clock_type, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CLOCK[] = {
	{"rate", "Configure serial interface clock speed", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_RATE, NULL, 1, MSK_NORMAL},
	{"type", "Configure serial interface clock type", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_TYPE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CLOCK_NO[] = {
	{"rate", "Configure serial interface clock speed", NULL, serial_clock_rate_no, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

#ifdef CONFIG_DEVELOPMENT
cish_command CMD_CONFIG_INTERFACE_SERIAL_HDLC_NO[] = {
// 	{"fse", "Disable flag sharing", NULL, serial_hdlc_fse, 1, MSK_NORMAL},
// 	{"mff", "Disable multiple frames fifo", NULL, serial_hdlc_mff, 1, MSK_NORMAL},
// 	{"rtsm", "Idles between frames", NULL, serial_hdlc_rtsm, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_HDLC_NOF[] = {
// 	{"0-15", "Number of flags between frames", NULL, serial_hdlc_nof, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_HDLC[] = {
// 	{"fse", "Enable flag sharing", NULL, serial_hdlc_fse, 1, MSK_NORMAL},
// 	{"mff", "Enable multiple frames fifo", NULL, serial_hdlc_mff, 1, MSK_NORMAL},
// 	{"nof", "Change number of flags", CMD_CONFIG_INTERFACE_SERIAL_HDLC_NOF, NULL, 1, MSK_NORMAL},
// 	{"rtsm", "Flags between frames", NULL, serial_hdlc_rtsm, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_IGNORE[] = {
	{"cts", "Ignore CTS signal", NULL, serial_ignore, 1, MSK_NORMAL},
	{"dcd", "Ignore DCD signal", NULL, serial_ignore, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_INVERT[] = {
	{"txclock", "Invert transmit clock", NULL, serial_invert_tx_clock, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_INVERT_NO[] = {
	{"txclock", "Invert transmit clock", NULL, serial_invert_tx_clock_no, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_BACKUP3[] = {
	{"10-3600", "Deactivate delay", NULL, serial_backup, 1, MSK_AUX},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_BACKUP2[] = {
	{"10-3600", "Activate delay", CMD_CONFIG_INTERFACE_SERIAL_BACKUP3, NULL, 1, MSK_AUX},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_BACKUP1[] = {
	{"aux0", "Aux interface 0", CMD_CONFIG_INTERFACE_SERIAL_BACKUP2, NULL, 1, MSK_AUX},
	{"aux1", "Aux interface 1", CMD_CONFIG_INTERFACE_SERIAL_BACKUP2, NULL, 1, MSK_AUX},
	{NULL,NULL,NULL,NULL, 0}
};

// interface serial assincrona - comum a todos os encapsulamentos

cish_command CMD_CONFIG_INTERFACE_SERIAL_ENCAP_ASYNC[] = {
	{"ppp", "Point-to-Point protocol", NULL, serial_encap_async, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

// interface serial - sem encapsulamento

cish_command CMD_CONFIG_INTERFACE_SERIAL_NO[];

cish_command CMD_CONFIG_INTERFACE_SERIAL[] = {
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"physical-layer", "Select synchronous or asynchronous mode", CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL, NULL, 1, MSK_NORMAL},
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP, NULL, 1, MSK_NORMAL},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Set HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC, NULL, 1, MSK_NORMAL},
#endif
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER	
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT, NULL, 1, MSK_NORMAL},
	{"loopback", "Enable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_SERIAL_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// interface serial - encapsulamento PPP

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH_PASS[] = {
	{"<text>","Password", NULL, ppp_auth_pass, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH_USER[] = {
	{"<text>","Username", NULL, ppp_auth_user, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH[] = {
	{"pass","Set authentication password", CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH_PASS, NULL, 1, MSK_NORMAL},
	{"user","Set authentication username", CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH_USER, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset local address", NULL, ppp_noipaddr, 1, MSK_NORMAL},
	{"default-route", "Don't use default-route on this interface", NULL, ppp_no_defaultroute, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
	{"peer-address", "Unset peer address", NULL, ppp_nopeeraddr, 1, MSK_NORMAL},
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Remove QoS policy", CMD_CONFIG_INTERFACE_POLICY_NO, interface_policy_no, 1, MSK_QOS},
#endif
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"unnumbered", "Disable IP processing without an explicit address", NULL, ppp_no_unnumbered, 1, MSK_NORMAL},
	{"vj", "Disable Van Jacobson style TCP/IP header compression", NULL, ppp_no_vj, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP3[] = {
	{"<ipaddress>", "Address", NULL, ppp_peeraddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP2[] = {
	{"<netmask>", "Mask", NULL, ppp_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP1[] = {
	{"<ipaddress>", "Address", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_UNNUMBERED_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, ppp_unnumbered, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// Associa somente o IP da interface ethernet para serial IP UNNUMBERED
cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_UNNUMBERED[] = {
	{"ethernet", "Ethernet interface", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_UNNUMBERED_ETHERNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Set local address", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP1, NULL, 1, MSK_NORMAL},
	{"default-route", "Use default-route on this interface", NULL, ppp_defaultroute, 1, MSK_NORMAL},
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
	{"peer-address", "Set peer address", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP3, NULL, 1, MSK_NORMAL},
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Add QoS policy", CMD_CONFIG_INTERFACE_POLICY, NULL, 1, MSK_QOS},
#endif
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
	{"unnumbered", "Enable IP processing without an explicit address", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_UNNUMBERED, NULL, 1, MSK_NORMAL},
	{"vj", "Enable Van Jacobson style TCP/IP header compression", NULL, ppp_vj, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IPX_NET[] = {
	{"<ipx network>", "IPX Network number", NULL, ppp_ipxnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IPX[] = {
	{"network", "Assing an IPX network and enable IPX routing", CMD_CONFIG_INTERFACE_SERIAL_PPP_IPX_NET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IPX[] = {
	{"network", "Unset IPX network", NULL, ppp_no_ipxnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_CHATSCRIPT[] = {
	{"<text>","Chat script name", NULL, ppp_chat, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_FLOW[] = {
	{"rts-cts", "RTS/CTS hardware flowcontrol", NULL, ppp_flow_rtscts, 1, MSK_NORMAL},
	{"xon-xoff", "XON/XOFF software flowcontrol", NULL, ppp_flow_xonxoff, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_HOLDOFF[] = {
	{"1-86400", "Holdoff timeout (seconds)", NULL, ppp_holdoff, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IDLE[] = {
	{"1-86400", "Idle timeout (seconds)", NULL, ppp_idle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE_INTERVAL[] = {
	{"1-100", "seconds", NULL, ppp_keepalive_interval, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE_TIMEOUT[] = {
	{"2-100", "seconds", NULL, ppp_keepalive_timeout, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE[] = {
	{"interval", "Set interval between two keepalive commands", CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE_INTERVAL, NULL, 1, MSK_NORMAL},
	{"timeout", "Set keepalive failure timeout", CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE_TIMEOUT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_MTU[] = {
	{"128-16384", "Max Transfer Unit", NULL, ppp_mtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_SPEED[] = {
	{"300-115200", "Speed (bits per second)", NULL, ppp_speed, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

// PPP sync

cish_command PPP_AUTH_LOCAL_USER[] = {
        {"<text>", "Local hostname", NULL, ppp_server_auth_local_user, 1, MSK_NORMAL},
        {NULL,NULL,NULL,NULL, 0}
};

cish_command PPP_AUTH_LOCAL_PASS[] = {
        {"<text>", "Local password", NULL, ppp_server_auth_local_pass, 1, MSK_NORMAL},
        {NULL,NULL,NULL,NULL, 0}
};

cish_command PPP_AUTH_LOCAL_ALGO[] = {
	{"chap", "Require CHAP authentication", NULL, ppp_server_auth_local_algo, 1, MSK_NORMAL},
	{"pap", "Require PAP authentication", NULL, ppp_server_auth_local_algo, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_AUTH[] = {
	{"algorithm", "Set authentication algorithm",PPP_AUTH_LOCAL_ALGO, NULL, 1, MSK_NORMAL},
	{"hostname", "Set CHAP/PAP hostname", PPP_AUTH_LOCAL_USER, NULL, 1, MSK_NORMAL},
	{"password", "Set default CHAP/PAP password",PPP_AUTH_LOCAL_PASS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_AUTH[] = {
	{"algorithm", "No authentication algorithm",NULL, ppp_server_auth_local_algo, 1, MSK_NORMAL},
	{"hostname", "No CHAP/PAP hostname", NULL, ppp_server_auth_local_user, 1, MSK_NORMAL},
	{"password", "No default CHAP/PAP password",NULL, ppp_server_auth_local_pass, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_HDLC_SPPP_LFI

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI_FRAG[] = {
	{"16-1600", "Fragmentation size (bytes)", NULL, ppp_multilink, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI_INTLV_PRIOMARK[] = {
	{"1-2000000000", "Mark number", NULL, ppp_multilink, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI_INTLV[] = {
	{"priority-mark", "Configure mark as priority", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI_INTLV_PRIOMARK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI[] = {
	{"fragment", "Enable Fragmentation", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI_FRAG, NULL, 1, MSK_NORMAL},
	{"interleave", "Enable Interleaving", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI_INTLV, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_ML_INTLV_MARK[] = {
	{"1-2000000000", "Mark number", NULL, ppp_multilink, 1, MSK_NORMAL},
	{"<enter>", "Remove all marks", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_ML_INTLV[] = {
	{"priority-mark", "Remove mark", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_ML_INTLV_MARK, ppp_multilink, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_ML[] = {
	{"fragment", "Disable fragmentation", NULL, ppp_multilink, 1, MSK_NORMAL},
	{"interleave", "Disable interleaving marks", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_ML_INTLV, NULL, 1, MSK_NORMAL},
	{"<enter>", "Disable multilink and LFI", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO[] = {
	{"authentication", "Set CHAP/PAP authentication parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_AUTH, NULL, 1, MSK_NORMAL},
	{"debug", "Extra LCP debug log", NULL, ppp_debug, 1, MSK_NORMAL},
	{"multilink", "Make interface multilink capable", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_ML, ppp_multilink, 1, MSK_NORMAL},
	{"usepeerdns", "Request DNS servers from peer", NULL, ppp_usepeerdns, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#else
cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO[] = {
	{"authentication", "Set CHAP/PAP authentication parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO_AUTH, NULL, 1, MSK_NORMAL},
	{"debug", "Extra LCP debug log", NULL, ppp_debug, 1, MSK_NORMAL},
	{"multilink", "Make interface multilink capable", NULL, ppp_multilink, 1, MSK_NORMAL},
	{"usepeerdns", "Request DNS servers from peer", NULL, ppp_usepeerdns, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP[] = {
	{"authentication", "Set CHAP/PAP authentication parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_AUTH, NULL, 1, MSK_NORMAL},
	{"debug", "Extra LCP debug log", NULL, ppp_debug, 1, MSK_NORMAL},
#ifdef CONFIG_HDLC_SPPP_LFI
	{"multilink", "Make interface multilink capable", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_LFI, ppp_multilink, 1, MSK_NORMAL},
#else
	{"multilink", "Make interface multilink capable", NULL, ppp_multilink, 1, MSK_NORMAL},
#endif
	{"usepeerdns", "Request DNS servers from peer", NULL, ppp_usepeerdns, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_NO[] = {
	{"authentication", "Turn off authentication", NULL, ppp_noauth, 1, MSK_NORMAL},
	{"backup", "Unset backup interface", NULL, serial_no_backup, 1, MSK_AUX},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_NO, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT_NO, NULL, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IPX, NULL, 1, MSK_NORMAL},
	{"loopback", "Disable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
	{"mtu", "Default interface mtu", NULL, ppp_nomtu, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Turn device on", NULL, ppp_noshutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP[] = {
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"physical-layer", "Select synchronous or asynchronous mode", CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL, NULL, 1, MSK_NORMAL},
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP, NULL, 1, MSK_NORMAL},
	{"authentication", "Authentication settings", CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH, NULL, 1, MSK_NORMAL},
	{"backup", "Set backup interface", CMD_CONFIG_INTERFACE_SERIAL_BACKUP1, NULL, 1, MSK_AUX},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_IPX, NULL, 1, MSK_NORMAL},
	{"keepalive", "Set keepalive parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE, NULL, 1, MSK_NORMAL},
	{"loopback", "Enable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_SERIAL_PPP_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_PPP_NO, NULL, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"shutdown", "Shutdown interface", NULL, ppp_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

// ppp server

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL_ALGO[] = {
	{"chap", "Require CHAP authentication", NULL, ppp_server_auth_local_algo, 1, MSK_NORMAL},
	{"pap", "Require PAP authentication", NULL, ppp_server_auth_local_algo, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL_PASS[] = {
	{"<text>","Password", NULL, ppp_server_auth_local_pass, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL_USER[] = {
	{"<text>","Username", NULL, ppp_server_auth_local_user, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL[] = {
	{"algorithm","Set authentication algorithm", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL_ALGO, NULL, 1, MSK_NORMAL},
	{"pass","Set authentication password", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL_PASS, NULL, 1, MSK_NORMAL},
	{"user","Set authentication username", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL_USER, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_AUTHKEY[] = {
	{"<text>","key", NULL, ppp_server_auth_radius_authkey, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_RETRIES[] = {
	{"0-5","retries", NULL, ppp_server_auth_radius_retries, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_SERVERS[] = {
	{"<text>","host", NULL, ppp_server_auth_radius_servers, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_TIMEOUT[] = {
	{"0-300","timeout", NULL, ppp_server_auth_radius_timeout, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS[] = {
	{"auth_key","Authentication key on server", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_AUTHKEY, NULL, 1, MSK_NORMAL},
	{"retries","Max retransmissions on same server", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_RETRIES, NULL, 1, MSK_NORMAL},
	{"same_server","Authorization and accounting only on the authenticated server", NULL, ppp_server_auth_radius_sameserver, 1, MSK_NORMAL},
	{"servers","Radius servers", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_SERVERS, NULL, 1, MSK_NORMAL},
	{"timeout","Timeout on request for server", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_TIMEOUT, NULL, 1, MSK_NORMAL},
	{"try_next_on_reject","Try authentication on next server if current rejected", NULL, ppp_server_auth_radius_trynextonreset, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS_AUTHKEY[] = {
	{"<text>","key", NULL, ppp_server_auth_tacacs_authkey, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS_SERVERS[] = {
	{"<text>","host", NULL, ppp_server_auth_tacacs_servers, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS[] = {
	{"auth_key","Authentication key on server", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS_AUTHKEY, NULL, 1, MSK_NORMAL},
	{"same_server","Authorization and accounting only on the authenticated server", NULL, ppp_server_auth_tacacs_sameserver, 1, MSK_NORMAL},
	{"servers","Tacacs servers", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS_SERVERS, NULL, 1, MSK_NORMAL},
	{"try_next_on_reject","Try authentication on next server if current rejected", NULL, ppp_server_auth_tacacs_trynextonreset, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH[] = {
	{"local","Set local authentication parameters", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_LOCAL, NULL, 1, MSK_NORMAL},
	{"radius","Set radius authentication parameters", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS, NULL, 1, MSK_NORMAL},
	{"tacacs","Set tacacs authentication parameters", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_NO[] = {
	{"auth_key", "No radius authentication key", NULL, ppp_server_noauth_radius_authkey, 1, MSK_NORMAL},
	{"retries", "No radius retries", NULL, ppp_server_noauth_radius_retries, 1, MSK_NORMAL},
	{"same_server", "No radius same-server use", NULL, ppp_server_noauth_radius_sameserver, 1, MSK_NORMAL},
	{"servers", "No radius servers", NULL, ppp_server_noauth_radius_servers, 1, MSK_NORMAL},
	{"timeout", "No radius timeout", NULL, ppp_server_noauth_radius_timeout, 1, MSK_NORMAL},
	{"try_next_on_reject", "No radius try next on reject", NULL, ppp_server_noauth_radius_trynextonreject, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS_NO[] = {
	{"auth_key", "No tacacs authentication key", NULL, ppp_server_noauth_tacacs_authkey, 1, MSK_NORMAL},
	{"same_server", "No tacacs same-server use", NULL, ppp_server_noauth_tacacs_sameserver, 1, MSK_NORMAL},
	{"servers", "No tacacs servers", NULL, ppp_server_noauth_tacacs_servers, 1, MSK_NORMAL},
	{"try_next_on_reject", "No tacacs try next on reject", NULL, ppp_server_noauth_tacacs_trynextonreject, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_NOAUTH[] = {
	{"local", "No local authentication", NULL, ppp_server_noauth_local, 1, MSK_NORMAL},
	{"radius", "No radius authentication", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_RADIUS_NO, ppp_server_noauth_radius, 1, MSK_NORMAL},
	{"tacacs", "No tacacs authentication", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH_TACACS_NO, ppp_server_noauth_tacacs, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_NO_IP[] = {
	{"address", "Unset local address", NULL, ppp_server_noipaddr, 1, MSK_NORMAL},
	{"peer-address", "Unset peer address", NULL, ppp_server_nopeeraddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP3[] = {
	{"<ipaddress>", "Address", NULL, ppp_server_peeraddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP2[] = {
	{"<netmask>", "Mask", NULL, ppp_server_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP1[] = {
	{"<ipaddress>", "Address", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP[] = {
	{"address", "Set local address", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP1, NULL, 1, MSK_NORMAL},
	{"peer-address", "Set peer address", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_NO_SERVER[] = {
	{"authentication", "Turn off authentication", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_NOAUTH, ppp_server_noauth, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_NO_IP, NULL, 1, MSK_NORMAL},
	{"shutdown", "Turn ppp server on", NULL, ppp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER[] = {
	{"authentication", "Authentication settings", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_AUTH, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER_IP, NULL, 1, MSK_NORMAL},
	{"shutdown", "Disable ppp server", NULL, ppp_no_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// PPP async

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC_NO[] = {
	{"authentication", "Turn off authentication", NULL, ppp_noauth, 1, MSK_NORMAL},
	{"backup", "Unset backup interface", NULL, serial_no_backup, 1, MSK_AUX},
	{"chat-script", "Turn off chatscript on this interface", NULL, ppp_nochat, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"dial-on-demand", "Turn off dial-on-demand on this interface", NULL, ppp_no_dial_on_demand, 1, MSK_NORMAL},
	{"flow-control", "Turn off flow-control", NULL, ppp_no_flow, 1, MSK_NORMAL},
	{"holdoff", "Turn off holdoff on this interface", NULL, ppp_no_holdoff, 1, MSK_NORMAL},
	{"idle", "Turn off idle on this interface", NULL, ppp_no_idle, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IPX, NULL, 1, MSK_NORMAL},
	{"mtu", "Default interface mtu", NULL, ppp_nomtu, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP, NULL, 1, MSK_NORMAL},
	{"server", "Unset server parameters", CMD_CONFIG_INTERFACE_PPP_ASYNC_NO_SERVER, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Turn device on", NULL, ppp_noshutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"speed", "Default serial speed", NULL, ppp_nospeed, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC[] = {

	{"physical-layer", "Select synchronous or asynchronous mode", CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL, NULL, 1, MSK_NORMAL},
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP_ASYNC, NULL, 1, MSK_NORMAL},
	{"authentication", "Authentication settings", CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH, NULL, 1, MSK_NORMAL},
	{"backup", "Set backup interface", CMD_CONFIG_INTERFACE_SERIAL_BACKUP1, NULL, 1, MSK_AUX},
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"chat-script", "Set chatscript to use on this interface", CMD_CONFIG_INTERFACE_SERIAL_PPP_CHATSCRIPT, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"dial-on-demand", "Set dial-on-demand on this interface", NULL, ppp_dial_on_demand, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"flow-control", "Set flow-control", CMD_CONFIG_INTERFACE_SERIAL_PPP_FLOW, NULL, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"holdoff", "Set holdoff timeout on this interface", CMD_CONFIG_INTERFACE_SERIAL_PPP_HOLDOFF, NULL, 1, MSK_NORMAL},
	{"idle", "Set idle timeout on this interface", CMD_CONFIG_INTERFACE_SERIAL_PPP_IDLE, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_IPX, NULL, 1, MSK_NORMAL},
	{"keepalive", "Set keepalive parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_SERIAL_PPP_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC_NO, NULL, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP, NULL, 1, MSK_NORMAL},
	{"server", "Server settings", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"shutdown", "Shutdown interface", NULL, ppp_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"speed", "Set serial speed", CMD_CONFIG_INTERFACE_SERIAL_PPP_SPEED, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// interface aux - encapsulamento PPP

cish_command CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC_NO[] = {
	{"authentication", "Turn off authentication", NULL, ppp_noauth, 1, MSK_NORMAL},
	{"chat-script", "Turn off chatscript on this interface", NULL, ppp_nochat, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"dial-on-demand", "Turn off dial-on-demand on this interface", NULL, ppp_no_dial_on_demand, 1, MSK_NORMAL},
	{"flow-control", "Turn off flow-control", NULL, ppp_no_flow, 1, MSK_NORMAL},
	{"holdoff", "Turn off holdoff on this interface", NULL, ppp_no_holdoff, 1, MSK_NORMAL},
	{"idle", "Turn off idle on this interface", NULL, ppp_no_idle, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_NO_IPX, NULL, 1, MSK_NORMAL},
	{"mtu", "Default interface mtu", NULL, ppp_nomtu, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP, NULL, 1, MSK_NORMAL},
	{"server", "Unset server parameters", CMD_CONFIG_INTERFACE_PPP_ASYNC_NO_SERVER, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Turn device on", NULL, ppp_noshutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"speed", "Default serial speed", NULL, ppp_nospeed, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC[] = {
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP_ASYNC, NULL, 1, MSK_NORMAL},
	{"authentication", "Authentication settings", CMD_CONFIG_INTERFACE_SERIAL_PPP_AUTH, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"chat-script", "Set chatscript to use on this interface", CMD_CONFIG_INTERFACE_SERIAL_PPP_CHATSCRIPT, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"dial-on-demand", "Set dial-on-demand on this interface", NULL, ppp_dial_on_demand, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"flow-control", "Set flow-control", CMD_CONFIG_INTERFACE_SERIAL_PPP_FLOW, NULL, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"holdoff", "Set holdoff timeout on this interface", CMD_CONFIG_INTERFACE_SERIAL_PPP_HOLDOFF, NULL, 1, MSK_NORMAL},
	{"idle", "Set idle timeout on this interface", CMD_CONFIG_INTERFACE_SERIAL_PPP_IDLE, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_IPX, NULL, 1, MSK_NORMAL},
	{"keepalive", "Set keepalive parameters", CMD_CONFIG_INTERFACE_SERIAL_PPP_KEEPALIVE, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_SERIAL_PPP_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC_NO, NULL, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_PPP_LCP, NULL, 1, MSK_NORMAL},
	{"server", "Server settings", CMD_CONFIG_INTERFACE_PPP_ASYNC_SERVER, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"shutdown", "Shutdown interface", NULL, ppp_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"speed", "Set serial speed", CMD_CONFIG_INTERFACE_SERIAL_PPP_SPEED, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// interface serial - encapsulamento Frame Relay e Cisco HDLC (parte comum)

cish_command CMD_CONFIG_INTERFACE_SERIAL_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset IP address", NULL, interface_no_ipaddr, 1, MSK_NORMAL},
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

cish_command CMD_CONFIG_INTERFACE_SERIAL_IPX_NET[] = {
	{"<ipx network>", "IPX Network number", NULL, interface_ipxnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_IPX[] = {
	{"network", "Assing an IPX network and enable IPX routing", CMD_CONFIG_INTERFACE_SERIAL_IPX_NET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_NO_IPX[] = {
	{"network", "Unset IPX network", NULL, interface_no_ipxnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_NO[] = {
	{"backup", "Unset backup interface", NULL, serial_no_backup, 1, MSK_AUX},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_NO, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Unset HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC_NO, NULL, 1, MSK_NORMAL},
#endif
#ifndef CONFIG_BERLIN_SATROUTER
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT_NO, NULL, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IPX, NULL, 1, MSK_NORMAL},
	{"loopback", "Disable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"shutdown", "Turn device on", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_MTU[] = {
	{"68-1600", "Max Transfer Unit", NULL, interface_mtu, 1, MSK_NORMAL}, /* linux/drivers/net/wan/scc_hdlc.c: scc_hdlc_change_mtu() */
	{NULL,NULL,NULL,NULL}
};

// interface serial - encapsulamento Frame Relay

cish_command CMD_CONFIG_INTERFACE_FR_INTFTYPE[] = {
	{"dce", "Configure a FR DCE", NULL, fr_intftype_dce, 1, MSK_NORMAL},
	{"dte", "Configure a FR DTE", NULL, fr_intftype_dte, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_N391[] = {
	{"1-255", "Polling cycles", NULL, fr_lmi, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_N392[] = {
	{"1-10", "Errors", NULL, fr_lmi, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_N393[] = {
	{"1-10", "Events", NULL, fr_lmi, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_T391[] = {
	{"5-30", "Seconds", NULL, fr_lmi, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_T392[] = {
	{"5-30", "Seconds", NULL, fr_lmi, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_SIGNALLING[] = {
	{"ansi", "ANSI T1.617 Annex D signalling", NULL, fr_lmi_signalling_ansi, 1, MSK_NORMAL},
	{"auto", "Auto discovery LMI type", NULL, fr_lmi_signalling_auto, 1, MSK_NORMAL},
	{"cisco", "Cisco LMI signalling", NULL, fr_lmi_signalling_cisco, 1, MSK_NORMAL},
	{"none", "no LMI signalling", NULL, fr_lmi_signalling_none, 1, MSK_NORMAL},
	{"q933a", "ITU-T Q.933 Annex A signalling", NULL, fr_lmi_signalling_itu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_DLCI[] = {
	{"16-1022", "DLCI number", NULL, fr_dlci_add, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_HDLC_FR_LFI
cish_command CMD_CONFIG_INTERFACE_FR_INTLV_PRIOMARK[] = {
	{"1-2000000000", "Mark number", NULL, interface_fr_interleave, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_INTLV[] = {
	{"priority-mark", "Configure mark as priority", CMD_CONFIG_INTERFACE_FR_INTLV_PRIOMARK, NULL, 1, MSK_NORMAL},
	{"<enter>", "Only enable interleave", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_FR[] = {
	{"dlci", "Add DLCI", CMD_CONFIG_INTERFACE_FR_DLCI, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_HDLC_FR_LFI
	{"interleave", "Enable interleave on TX", CMD_CONFIG_INTERFACE_FR_INTLV, interface_fr_interleave, 1, MSK_NORMAL},
#endif
	{"intf-type", "Configure a FR DTE/DCE interface", CMD_CONFIG_INTERFACE_FR_INTFTYPE, NULL, 1, MSK_NORMAL},
	{"lmi-n391", "Set full status polling counter", CMD_CONFIG_INTERFACE_FR_N391, NULL, 1, MSK_NORMAL},
	{"lmi-n392", "Set error threshold", CMD_CONFIG_INTERFACE_FR_N392, NULL, 1, MSK_NORMAL},
	{"lmi-n393", "Set monitored events count", CMD_CONFIG_INTERFACE_FR_N393, NULL, 1, MSK_NORMAL},
	{"lmi-t391", "Set link integrity verification polling timer", CMD_CONFIG_INTERFACE_FR_T391, NULL, 1, MSK_NORMAL},
	{"lmi-t392", "Set polling verification timer", CMD_CONFIG_INTERFACE_FR_T392, NULL, 1, MSK_NORMAL},
	{"lmi-type", "Set signalling type", CMD_CONFIG_INTERFACE_FR_SIGNALLING, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_NO_FR_DLCI[] = {
	{"16-1007", "DLCI number", NULL, fr_dlci_del, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_HDLC_FR_LFI
cish_command CMD_CONFIG_INTERFACE_FR_NO_FR_INTLV_PRIOMARK[] = {
	{"1-2000000000", "Mark number to remove", NULL, interface_fr_no_interleave, 1, MSK_NORMAL},
	{"<enter>", "Remove all priority marks", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_FR_NO_FR_INTLV[] = {
	{"priority-mark", "Remove priority of marks", CMD_CONFIG_INTERFACE_FR_NO_FR_INTLV_PRIOMARK, interface_fr_no_interleave, 1, MSK_NORMAL},
	{"<enter>", "Disable interleave and remove all priority marks", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_FR_NO_FR[] = {
	{"dlci", "Delete DLCI", CMD_CONFIG_INTERFACE_FR_NO_FR_DLCI, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_HDLC_FR_LFI
	{"interleave", "Disable interleave on TX", CMD_CONFIG_INTERFACE_FR_NO_FR_INTLV, interface_fr_no_interleave, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_HDLC_FR_INVARP
cish_command CMD_CONFIG_INTERFACE_SERIAL_FR_IP2[] = {
	{"<netmask>", "Mask", NULL, interface_fr_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_FR_IP1[] = {
	{"<ipaddress>", "Local IP Address", CMD_CONFIG_INTERFACE_SERIAL_FR_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_FR_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Set IP address", CMD_CONFIG_INTERFACE_SERIAL_FR_IP1, NULL, 1, MSK_NORMAL},
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
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_FR_NO[] = {
	{"backup", "Unset backup interface", NULL, serial_no_backup, 1, MSK_AUX},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_NO, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"frame-relay", "Unset frame relay parameters", CMD_CONFIG_INTERFACE_FR_NO_FR, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Unset HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC_NO, NULL, 1, MSK_NORMAL},
#endif
#ifndef CONFIG_BERLIN_SATROUTER
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_HDLC_FR_INVARP
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IP, NULL, 1, MSK_NORMAL},
#endif
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT_NO, NULL, 1, MSK_NORMAL},
	{"loopback", "Disable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Turn device on", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_FR[] = {
	{"physical-layer", "Select synchronous or asynchronous mode", CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL, NULL, 1, MSK_NORMAL},
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP, NULL, 1, MSK_NORMAL},
	{"backup", "Set backup interface", CMD_CONFIG_INTERFACE_SERIAL_BACKUP1, NULL, 1, MSK_AUX},
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"frame-relay", "Set frame relay parameters", CMD_CONFIG_INTERFACE_FR, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Set HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC, NULL, 1, MSK_NORMAL},
#endif
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_HDLC_FR_INVARP
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_FR_IP, NULL, 1, MSK_NORMAL},
#endif
	{"loopback", "Enable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_FR_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// sub-interface serial - encapsulamento Frame Relay

#ifdef CONFIG_FR_IPHC
cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP_IPHC_RTP_MARK[] = {
	{"1-2000000000", "Mark number", NULL, subfr_iphc, 1, MSK_NORMAL},
	{"<enter>", "Disable all marks", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP_IPHC_RTP[] = {
	{"mark", "Mark to disable for header compression", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP_IPHC_RTP_MARK, subfr_iphc, 1, MSK_NORMAL},
	{"<enter>", "Disable RTP compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP_IPHC[] = {
	{"tcp", "Disable TCP compression", NULL, subfr_iphc, 1, MSK_NORMAL},
	{"udp", "Disable UDP compression", NULL, subfr_iphc, 1, MSK_NORMAL},
	{"rtp", "Disable RTP compression", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP_IPHC_RTP, subfr_iphc, 1, MSK_NORMAL},
	{"<enter>", "Disable all IPHC configurations", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset IP address", NULL, interface_no_ipaddr, 1, MSK_NORMAL},
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
#ifdef CONFIG_FR_IPHC
	{"header-compression", "IPHC configurations", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP_IPHC, subfr_iphc, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

// sub-interface serial - encapsulamento Frame Relay

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP3[] = {
	{"<netmask>", "Mask", NULL, interface_subfr_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP2[] = {
	{"<ipaddress>", "Remote IP Address", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP1[] = {
	{"<ipaddress>", "Local IP Address", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_FR_IPHC
cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_MP[] = {
	{"0-65535", "Number of compressed packets (0 disables packets counter, recommended 256)", NULL, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_MT[] = {
	{"0-255", "Time in seconds (0 disables time counter, recommended 5)", NULL, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_MH[] = {
	{"20-60", "Size in bytes", NULL, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_TCP_CONTEXT[] = {
	{"1-256", "Number of contexts", NULL, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_TCP[] = {
	{"contexts", "Maximum number of contexts for compression", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_TCP_CONTEXT, NULL, 1, MSK_NORMAL},
	{"passive", "Compress only for destinations which send compressed headers", NULL, subfr_iphc, 1, MSK_NORMAL},
	{"<enter>", "Enable TCP header compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_UDP_CONTEXT[] = {
	{"1-256", "Number of contexts", NULL, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_UDP_FORMAT[] = {
	{"contexts", "Maximum number of contexts for compression", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_UDP_CONTEXT, NULL, 1, MSK_NORMAL},
	{"passive", "Compress only for destinations which send compressed headers", NULL, subfr_iphc, 1, MSK_NORMAL},
	{"<enter>", "Enable UDP header compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_UDP[] = {
	{"ietf-format", "Compressing using IETF format", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_UDP_FORMAT, subfr_iphc, 1, MSK_NORMAL},
	{"iphc-format", "Compress using IPHC format", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_UDP_FORMAT, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_RTP_CHK[] = {
	{"1-64", "Number of decompressed packets (recommended 16)", NULL, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_RTP_MARK[] = {
	{"1-2000000000", "Mark number", NULL, subfr_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_RTP[] = {
	{"checksum-period", "Max number of decompressed packets before doing an UDP checksum", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_RTP_CHK, NULL, 1, MSK_NORMAL},
	{"mark", "Mark that identifies a traffic to apply compression", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_RTP_MARK, NULL, 1, MSK_NORMAL},
	{"passive", "Compress only for destinations which send compressed headers", NULL, subfr_iphc, 1, MSK_NORMAL},
	{"<enter>", "Enable RTP header compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC[] = {
	{"max-period", "Maximum number of compressed packets before sending FULL_HEADER packet", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_MP, NULL, 1, MSK_NORMAL},
	{"max-time", "Maximum amount of time before sending FULL_HEADER packet", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_MT, NULL, 1, MSK_NORMAL},
	{"max-header", "Maximum header size in octets that may be compressed", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_MH, NULL, 1, MSK_NORMAL},
	{"tcp", "TCP header compression parameters", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_TCP, subfr_iphc, 1, MSK_NORMAL},
	{"udp", "UDP header compression parameters", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_UDP, NULL, 1, MSK_NORMAL},
	{"rtp", "RTP header compression parameters (IP+UDP+RTP headers)", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC_RTP, subfr_iphc, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Set IP address", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP1, NULL, 1, MSK_NORMAL},
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
#ifdef CONFIG_FR_IPHC
	{"header-compression", "IPHC configurations", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP_IPHC, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_SERIAL_SUBFR_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_subfr_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_SERIAL_SUBFR_NO_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_subfr_no_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_NET_SCH_FRTBF
cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_TR2[] = {
	{"1024-5056000", "Excess Information Rate (EIR) bit/s", NULL, interface_traffic_rate, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_TR1[] = {
	{"1024-5056000", "Committed Information Rate (CIR) bit/s", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_TR2, interface_traffic_rate, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef CONFIG_HDLC_FR_FRAG
cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_FRAG_END2END[] = {
	{"end-to-end", "End-to-end fragmentation (FRF.12)", NULL, interface_subfr_fragment, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_FRAG[] = {
	{"16-1600", "Define payload fragment size", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_FRAG_END2END, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef CONFIG_HDLC_FR_EEK
cish_command CMD_CONFIG_EEK_EVENTS[] = {
	{"1-32", "counts", NULL, fr_eek_events, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_EEK_EVENT_WINDOW[] = {
	{"recv", "Event window for incoming end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_EVENTS, NULL, 1, MSK_NORMAL},
	{"send", "Event window for outgoing end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_EVENTS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_EEK_ERR[] = {
	{"recv", "Error threshold for incoming end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_EVENTS, NULL, 1, MSK_NORMAL},
	{"send", "Error threshold for outgoing end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_EVENTS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_EEK_SUCCESS[] = {
	{"recv", "Success events for incoming end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_EVENTS, NULL, 1, MSK_NORMAL},
	{"send", "Success events for outgoing end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_EVENTS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_EEK_TIMER1[] = {
	{"1-10000", "seconds", NULL, fr_eek_timer, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_EEK_TIMER[] = {
	{"recv", "Interval timer for incoming end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_TIMER1, NULL, 1, MSK_NORMAL},
	{"send", "Interval timer for outgoing end-to-end Keepalive REQUESTS", 
		CMD_CONFIG_EEK_TIMER1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_EEK_MODE[] = {
	{"bidirectional", "Set bidirectional mode", NULL, fr_eek_mode, 1, MSK_NORMAL},
	{"passive-reply", "Set passive-reply mode", NULL, fr_eek_mode, 1, MSK_NORMAL},
	{"reply", "Set unidirectional reply mode", NULL, fr_eek_mode, 1, MSK_NORMAL},
	{"request", "Set unidirectional request mode", NULL, fr_eek_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_FR_EEK1[] = {
	{"error-threshold", "End-to-end keepalive error threshold", 
		CMD_CONFIG_EEK_ERR, NULL, 1, MSK_NORMAL},
	{"event-window", "End-to-end keepalive event window", 
		CMD_CONFIG_EEK_EVENT_WINDOW, NULL, 1, MSK_NORMAL},
	{"mode", "End-to-end keepalive mode", CMD_CONFIG_EEK_MODE, NULL, 1, MSK_NORMAL},
	{"success-events", "End-to-end keepalive success events", 
		CMD_CONFIG_EEK_SUCCESS, NULL, 1, MSK_NORMAL},
	{"timer", "End-to-end keepalive timer", CMD_CONFIG_EEK_TIMER, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_FR_EEK[] = {
	{"keepalive", "Configure frame-relay end-to-end VC keepalive parameters", 
		CMD_CONFIG_INTERFACE_SERIAL_FR_EEK1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_FR_NO_EEK[] = {
	{"keepalive", "Disable frame-relay end-to-end VC keepalive parameters", 
		NULL, fr_eek_disable, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR[] = {
#ifdef CONFIG_HDLC_FR_EEK
	{"end-to-end", "Configure frame-relay end-to-end VC parameters", 
		CMD_CONFIG_INTERFACE_SERIAL_FR_EEK, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_HDLC_FR_FRAG
	{"fragment", "Enable end-to-end fragmentation", 
		CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_FRAG, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_NET_SCH_FRTBF
	{"traffic-rate", "VC traffic rate", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR_TR1, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_FR[] = {
#ifdef CONFIG_HDLC_FR_EEK
	{"end-to-end", "Disable frame-relay end-to-end VC parameters", 
		CMD_CONFIG_INTERFACE_SERIAL_FR_NO_EEK, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_HDLC_FR_FRAG
	{"fragment", "Disable end-to-end fragmentation", NULL, interface_subfr_fragment, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_NET_SCH_FRTBF
	{"traffic-rate", "VC traffic rate", NULL, interface_traffic_rate_no, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO[] = {
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_SERIAL_SUBFR_NO_BRIDGE, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"frame-relay", "Configure frame-relay parameters", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_FR, NULL, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IPX, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Turn device on", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR[] = {
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_SERIAL_SUBFR_BRIDGE, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"frame-relay", "Configure frame-relay parameters", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_FR, NULL, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_IPX, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_SERIAL_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_SUBFR_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// interface serial - encapsulamento Cisco HDLC

cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP3[] = {
	{"<netmask>", "Mask", NULL, interface_chdlc_ipaddr, 1, MSK_NORMAL},
#ifdef CONFIG_BERLIN_SATROUTER
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP2[] = {
#ifdef CONFIG_BERLIN_SATROUTER
	{"<ipaddress>", "Remote IP Address or Mask", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP3, interface_chdlc_ipaddr, 1, MSK_NORMAL},
#else
	{"<ipaddress>", "Remote IP Address", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP3, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP1[] = {
	{"<ipaddress>", "Local IP Address", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Set IP address", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP1, NULL, 1, MSK_NORMAL},
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
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_CHDLC_KEEPALIVE_INTERVAL[] = {
	{"1-100", "seconds", NULL, chdlc_keepalive_interval, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_CHDLC_KEEPALIVE_TIMEOUT[] = {
	{"2-100", "seconds", NULL, chdlc_keepalive_timeout, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_CHDLC_KEEPALIVE[] = {
	{"interval", "Set interval between two keepalive commands", CMD_CONFIG_INTERFACE_CHDLC_KEEPALIVE_INTERVAL, NULL, 1, MSK_NORMAL},
	{"timeout", "Set keepalive timeout", CMD_CONFIG_INTERFACE_CHDLC_KEEPALIVE_TIMEOUT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#define INTERFACE_SERIAL_CHDLC_BRIDGE

#ifdef INTERFACE_SERIAL_CHDLC_BRIDGE
cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_chdlc_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC_NO_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_chdlc_no_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC_NO[] = {
	{"backup", "Unset backup interface", NULL, serial_no_backup, 1, MSK_AUX},
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_NO_BRIDGE, NULL, 1, MSK_NORMAL},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_NO, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Unset HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC_NO, NULL, 1, MSK_NORMAL},
#endif
#ifndef CONFIG_BERLIN_SATROUTER
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT_NO, NULL, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IPX, NULL, 1, MSK_NORMAL},
	{"loopback", "Disable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Turn device on", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC[] = {
	{"physical-layer", "Select synchronous or asynchronous mode", CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL, NULL, 1, MSK_NORMAL},
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"backup", "Set backup interface", CMD_CONFIG_INTERFACE_SERIAL_BACKUP1, NULL, 1, MSK_AUX},
#ifdef INTERFACE_SERIAL_CHDLC_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Set HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC, NULL, 1, MSK_NORMAL},
#endif
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif	
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_IPX, NULL, 1, MSK_NORMAL},
	{"keepalive", "Set keepalive parameters", CMD_CONFIG_INTERFACE_CHDLC_KEEPALIVE, NULL, 1, MSK_NORMAL},
	{"loopback", "Enable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_SERIAL_MTU, NULL, 1, MSK_NORMAL},
#ifdef INTERFACE_SERIAL_CHDLC_BRIDGE
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_CHDLC_NO, NULL, 1, MSK_NORMAL},
#else
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_NO, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

// interface serial - encapsulamento SPPP

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP3[] = {
	{"<netmask>", "Mask", NULL, interface_sppp_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP2[] = {
	{"<ipaddress>", "Remote IP Address", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP1[] = {
	{"<ipaddress>", "Local IP Address", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_SPPP_IPHC
cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_MP[] = {
	{"0-65535", "Number of compressed packets (0 disables packets counter, recommended 256)", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_MT[] = {
	{"0-255", "Time in seconds (0 disables time counter, recommended 5)", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_MH[] = {
	{"20-60", "Size in bytes", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_TCP_CONTEXT[] = {
	{"1-256", "Number of contexts", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_TCP[] = {
	{"contexts", "Maximum number of contexts for compression", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_TCP_CONTEXT, NULL, 1, MSK_NORMAL},
	{"passive", "Compress only for destinations which send compressed headers", NULL, sppp_iphc, 1, MSK_NORMAL},
	{"<enter>", "Enable TCP header compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_UDP_CONTEXT[] = {
	{"1-256", "Number of contexts", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_UDP_FORMAT[] = {
	{"contexts", "Maximum number of contexts for compression", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_UDP_CONTEXT, NULL, 1, MSK_NORMAL},
	{"passive", "Compress only for destinations which send compressed headers", NULL, sppp_iphc, 1, MSK_NORMAL},
	{"<enter>", "Enable UDP header compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_UDP[] = {
	{"ietf-format", "Compressing using IETF format", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_UDP_FORMAT, sppp_iphc, 1, MSK_NORMAL},
	{"iphc-format", "Compress using IPHC format", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_UDP_FORMAT, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_RTP_CHK[] = {
	{"1-64", "Number of decompressed packets (recommended 16)", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_RTP_MARK[] = {
	{"1-2000000000", "Mark number", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_RTP[] = {
	{"checksum-period", "Max number of decompressed packets before doing an UDP checksum", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_RTP_CHK, NULL, 1, MSK_NORMAL},
	{"mark", "Mark that identifies a traffic to apply compression", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_RTP_MARK, NULL, 1, MSK_NORMAL},
	{"passive", "Compress only for destinations which send compressed headers", NULL, sppp_iphc, 1, MSK_NORMAL},
	{"<enter>", "Enable RTP header compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC[] = {
	{"max-period", "Maximum number of compressed packets before sending FULL_HEADER packet", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_MP, NULL, 1, MSK_NORMAL},
	{"max-time", "Maximum amount of time before sending FULL_HEADER packet", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_MT, NULL, 1, MSK_NORMAL},
	{"max-header", "Maximum header size in octets that may be compressed", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_MH, NULL, 1, MSK_NORMAL},
	{"tcp", "TCP header compression parameters", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_TCP, sppp_iphc, 1, MSK_NORMAL},
	{"udp", "UDP header compression parameters", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_UDP, NULL, 1, MSK_NORMAL},
	{"rtp", "RTP header compression parameters (IP+UDP+RTP headers)", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC_RTP, sppp_iphc, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Set IP address", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP1, NULL, 1, MSK_NORMAL},
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
#ifdef CONFIG_SPPP_IPHC
	{"header-compression", "IPHC configurations", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP_IPHC, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_SPPP_VJ
	{"vj", "Van Jacobson TCP/IP header compression", NULL, sppp_vj, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SPPP_KEEPALIVE_INTERVAL[] = {
	{"1-100", "seconds", NULL, sppp_keepalive_interval, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SPPP_KEEPALIVE_TIMEOUT[] = {
	{"2-100", "seconds", NULL, sppp_keepalive_timeout, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SPPP_KEEPALIVE[] = {
	{"interval", "Set interval between two keepalive commands", CMD_CONFIG_INTERFACE_SPPP_KEEPALIVE_INTERVAL, NULL, 1, MSK_NORMAL},
	{"timeout", "Set keepalive timeout", CMD_CONFIG_INTERFACE_SPPP_KEEPALIVE_TIMEOUT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_SPPP_MULTILINK
cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_FRAG[] = {
	{"16-1600", "Fragmentation size (bytes)", NULL, sppp_multilink, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_MRRU[] = {
	{"1024-1500", "Size inbytes", NULL, sppp_multilink, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_HDLC_SPPP_LFI
cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_INTLV_PRIOMARK[] = {
	{"1-2000000000", "Mark number", NULL, sppp_multilink, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_INTLV[] = {
	{"priority-mark", "Configure mark as priority", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_INTLV_PRIOMARK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_MLP_INTLV_MARK[] = {
	{"1-2000000000", "Mark number", NULL, sppp_multilink, 1, MSK_NORMAL},
	{"<enter>", "Remove all marks", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_MLP_INTLV[] = {
	{"priority-mark", "Remove mark", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_MLP_INTLV_MARK, sppp_multilink, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP[] = {
	{"fragment", "Enable Fragmentation", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_FRAG, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_HDLC_SPPP_LFI
	{"interleave", "Enable Interleaving", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_INTLV, NULL, 1, MSK_NORMAL},
#endif
	{"mrru", "Maximum Receive Reconstructed Unit", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP_MRRU, NULL, 1, MSK_NORMAL},
	{"<enter>", "Only enable multilink", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_MLP[] = {
	{"fragment", "Disable fragmentation", NULL, sppp_multilink, 1, MSK_NORMAL},
#ifdef CONFIG_HDLC_SPPP_LFI
	{"interleave", "Disable interleaving marks", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_MLP_INTLV, NULL, 1, MSK_NORMAL},
#endif
	{"<enter>", "Disable multilink and fragmentation", NULL, sppp_multilink, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef CONFIG_SPPP_NETLINK
cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP_PASSWD_VALUE[] = {
	{"<text>", "The UNENCRYPTED (cleartext) CHAP password", NULL, sppp_papchap, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP_PASSWD[] = {
	{"password", "Configure CHAP password", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP_PASSWD_VALUE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP_NAME[] = {
	{"<text>", "CHAP hostname", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP_PASSWD, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP[] = {
	{"sent-hostname", "Configure CHAP hostname to send when authenticating", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP_NAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP_PASSWD_VALUE[] = {
	{"<text>", "The UNENCRYPTED (cleartext) PAP password", NULL, sppp_papchap, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP_PASSWD[] = {
	{"password", "Configure PAP password", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP_PASSWD_VALUE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP_NAME[] = {
	{"<text>", "PAP username", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP_PASSWD, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP[] = {
	{"sent-username", "Configure PAP username to send when authenticating", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP_NAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP_NAME_PASS_VAL[] = {
	{"<text>", "Password", NULL, sppp_auth_algo, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP_NAME_PASS[] = {
	{"auth-pass", "Password to authenticate", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP_NAME_PASS_VAL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP_NAME[] = {
	{"<text>", "Name", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP_NAME_PASS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP[] = {
	{"auth-name", "Name to authenticate", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP_NAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO[] = {
	{"chap", "Require CHAP authentication", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO_CHAP, NULL, 1, MSK_NORMAL},
	{"pap", "Require PAP authentication", NULL, sppp_auth_algo, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH[] = {
	{"algorithm", "Set authentication algorithm", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH_ALGO, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_AUTH[] = {
	{"algorithm", "Disable authentication", NULL, sppp_auth_algo, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYDNS_SADDR[] = {
	{"<ipaddress>", "Secondary DNS server address to supply", NULL, sppp_supplypeerdns, 1, MSK_NORMAL},
	{"<enter>", "Configure only one DNS server address to supply", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYDNS[] = {
	{"dynamic", "Supply DNS server addresses configured in system", NULL, sppp_supplypeerdns, 1, MSK_NORMAL},
	{"<ipaddress>", "Primary DNS server address to supply", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYDNS_SADDR, sppp_supplypeerdns, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_SUPPLYDNS[] = {
	{"<ipaddress>", "DNS server address to remove", NULL, sppp_supplypeerdns, 1, MSK_NORMAL},
	{"<enter>", "Remove all DNS server addresses", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYNBNS_SADDR[] = {
	{"<ipaddress>", "Secondary Net-BIOS name server address to supply", NULL, sppp_supplypeernbns, 1, MSK_NORMAL},
	{"<enter>", "Configure only one Net-BIOS name server address to supply", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYNBNS[] = {
	{"<ipaddress>", "Primary Net-BIOS name server address to supply", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYNBNS_SADDR, sppp_supplypeernbns, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_SUPPLYNBNS[] = {
	{"<ipaddress>", "Net-BIOS server address to remove", NULL, sppp_supplypeernbns, 1, MSK_NORMAL},
	{"<enter>", "Remove all Net-BIOS name addresses", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP[] = {
	{"debug", "Disable LCP debug log", NULL, sppp_debug, 1, MSK_NORMAL},
#ifdef CONFIG_SPPP_PPPH_COMP
	{"header-compression", "Disable PPP header compression", NULL, sppp_header_compression, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_SPPP_MULTILINK
	{"multilink", "Disable multilink functions", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_MLP, sppp_multilink, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_SPPP_NETLINK
	{"authentication", "Configure authentication to use to authenticate peer", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_AUTH, NULL, 1, MSK_NORMAL},
	{"chap", "Disable CHAP authentication", NULL, sppp_papchap, 0, MSK_NORMAL},
	{"pap", "Disable PAP authentication", NULL, sppp_papchap, 0, MSK_NORMAL},
	{"usepeerdns", "Disable request for DNS servers", NULL, sppp_usepeerdns, 1, MSK_NORMAL},
	{"supplypeerdns", "Do not supply DNS servers", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_SUPPLYDNS, sppp_supplypeerdns, 1, MSK_NORMAL},
	{"supplypeernbns", "Do not supply Net-BIOS servers", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP_SUPPLYNBNS, sppp_supplypeernbns, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP[] = {
	{"debug", "Extra LCP debug log", NULL, sppp_debug, 1, MSK_NORMAL},
#ifdef CONFIG_SPPP_PPPH_COMP
	{"header-compression", "PPP header compression", NULL, sppp_header_compression, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_SPPP_MULTILINK
	{"multilink", "Make interface multilink capable", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_MLP, sppp_multilink, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_SPPP_NETLINK
	{"authentication", "Configure authentication to use to authenticate peer", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_REQAUTH, NULL, 1, MSK_NORMAL},
	{"chap", "Configure CHAP authentication parameters", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_CHAP, NULL, 1, MSK_NORMAL},
	{"pap", "Configure PAP authentication parameters", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_PAP, NULL, 1, MSK_NORMAL},
	{"usepeerdns", "Request DNS servers from peer", NULL, sppp_usepeerdns, 1, MSK_NORMAL},
	{"supplypeerdns", "Supply DNS servers to peer", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYDNS, NULL, 1, MSK_NORMAL},
	{"supplypeernbns", "Supply Net-BIOS name servers to peer", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP_SUPPLYNBNS, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_SPPP_IPHC
cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP_IPHC_RTP_MARK[] = {
	{"1-2000000000", "Mark number", NULL, sppp_iphc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP_IPHC_RTP[] = {
	{"mark", "Mark to disable for header compression", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP_IPHC_RTP_MARK, NULL, 1, MSK_NORMAL},
	{"<enter>", "Disable RTP compression", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP_IPHC[] = {
	{"tcp", "Disable TCP compression", NULL, sppp_iphc, 1, MSK_NORMAL},
	{"udp", "Disable UDP compression", NULL, sppp_iphc, 1, MSK_NORMAL},
	{"rtp", "Disable RTP compression", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP_IPHC_RTP, sppp_iphc, 1, MSK_NORMAL},
	{"<enter>", "Disable all IPHC configurations", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Unset IP address", NULL, interface_no_ipaddr, 1, MSK_NORMAL},
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
#ifdef CONFIG_SPPP_IPHC
	{"header-compression", "IPHC configurations", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP_IPHC, sppp_iphc, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_SPPP_VJ
	{"vj", "Van Jacobson TCP/IP header compression", NULL, sppp_vj, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO[] = {
	{"backup", "Unset backup interface", NULL, serial_no_backup, 1, MSK_AUX},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_NO, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT_NO, NULL, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IPX, NULL, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO_PPP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"shutdown", "Turn device on", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP[] = {
	{"physical-layer", "Select synchronous or asynchronous mode", CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL, NULL, 1, MSK_NORMAL},
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP, NULL, 1, MSK_NORMAL},
	{"backup", "Set backup interface", CMD_CONFIG_INTERFACE_SERIAL_BACKUP1, NULL, 1, MSK_AUX},
#ifdef OPTION_NEW_QOS_CONFIG
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Set HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC, NULL, 1, MSK_NORMAL},
#endif
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
#endif
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_SPPP_IP, NULL, 1, MSK_NORMAL},
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_IPX, NULL, 1, MSK_NORMAL},
	{"keepalive", "Set keepalive parameters", CMD_CONFIG_INTERFACE_SPPP_KEEPALIVE, NULL, 1, MSK_NORMAL},
	{"loopback", "Enable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_SERIAL_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_SPPP_NO, NULL, 1, MSK_NORMAL},
	{"ppp", "Point-to-Point Protocol", CMD_CONFIG_INTERFACE_SERIAL_SPPP_PPP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NEW_QOS_CONFIG
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_X25

#ifndef CONFIG_BERLIN_SATROUTER
// interface serial - encapsulamento X25

cish_command CMD_CONFIG_INTERFACE_X25_ADDRESS[] = {
	{"<x121>", "Local X.121 <address>", NULL, interface_x25_address, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT[] = {
	{"16", "Set output maximum size to 16 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"32", "Set output maximum size to 32 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"64", "Set output maximum size to 64 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"128", "Set output maximum size to 128 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"256", "Set output maximum size to 256 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"512", "Set output maximum size to 512 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"1024", "Set output maximum size to 1024 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"2048", "Set output maximum size to 2048 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"4096", "Set output maximum size to 4096 bytes", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_IN[] = {
	{"16", "Set input maximum size to 16 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"32", "Set input maximum size to 32 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"64", "Set input maximum size to 64 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"128", "Set input maximum size to 128 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"256", "Set input maximum size to 256 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"512", "Set input maximum size to 512 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"1024", "Set input maximum size to 1024 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"2048", "Set input maximum size to 2048 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{"4096", "Set input maximum size to 4096 bytes", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_OUT, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT[] = {
	{"75", "Set output throughput to 75bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"150", "Set output throughput to 150bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"300", "Set output throughput to 300bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"600", "Set output throughput to 600bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"1200", "Set output throughput to 1200bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"2400", "Set output throughput to 2400bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"4800", "Set output throughput to 4800bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"9600", "Set output throughput to 9600bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"19200", "Set output throughput to 19200bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"48000", "Set output throughput to 48000bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"64000", "Set output throughput to 64000bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
#if 0
	{"128000", "Set output throughput to 128000bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"192000", "Set output throughput to 192000bit/s", NULL, interface_x25_facility_throughput, 1, MSK_X25},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_IN[] = {
	{"75", "Set input throughput to 75bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"150", "Set input throughput to 150bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"300", "Set input throughput to 300bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"600", "Set input throughput to 600bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"1200", "Set input throughput to 1200bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"2400", "Set input throughput to 2400bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"4800", "Set input throughput to 4800bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"9600", "Set input throughput to 9600bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"19200", "Set input throughput to 19200bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"48000", "Set input throughput to 48000bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"64000", "Set input throughput to 64000bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
#if 0
	{"128000", "Set input throughput to 128000bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
	{"192000", "Set input throughput to 192000bit/s", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_OUT, NULL, 1, MSK_X25},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_OUT[] = {
	{"1-7", "Output window size", NULL, interface_x25_facility_windowsize, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_IN[] = {
	{"1-7", "Input window size", CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_OUT, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_NO[] = {
	{"called_ae", "Disable called address extension", NULL, interface_x25_facility_called_ae, 1, MSK_X25},
	{"calling_ae", "Disable calling address extension", NULL, interface_x25_facility_calling_ae, 1, MSK_X25},
	{"packetsize", "Disable packetsize negotiation", NULL, interface_x25_facility_packetsize, 1, MSK_X25},
	{"reverse", "Disable reverse negotiation", NULL, interface_x25_facility_reverse, 1, MSK_X25},
	{"throughput", "Disable throughput negotiation", NULL, interface_x25_facility_throughput, 1, MSK_X25},
	{"windowsize", "Disable windowsize negotiation", NULL, interface_x25_facility_windowsize, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_FACILITY[] = {
	{"called_ae", "Add called address extension", NULL, interface_x25_facility_called_ae, 1, MSK_X25},
	{"calling_ae", "Add calling address extension", NULL, interface_x25_facility_calling_ae, 1, MSK_X25},
	{"packetsize", "Proposes input/output maximum packet size", CMD_CONFIG_INTERFACE_X25_FACILITY_PACKETSIZE_IN, NULL, 1, MSK_X25},
	{"reverse", "Use reverse charging on calls", NULL, interface_x25_facility_reverse, 1, MSK_X25},
	{"throughput", "Sets the requested throughput class negotiation", CMD_CONFIG_INTERFACE_X25_FACILITY_THROUGHPUT_IN, NULL, 1, MSK_X25},
	{"windowsize", "Proposes the packet count for input/output windows", CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_IN, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_IDLE[] = {
	{"1-1440", "Idle timeout in minutes", NULL, interface_x25_idle, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_IPS[] = {
	{"16", "Set input maximum size to 16 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"32", "Set input maximum size to 32 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"64", "Set input maximum size to 64 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"128", "Set input maximum size to 128 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"256", "Set input maximum size to 256 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"512", "Set input maximum size to 512 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"1024", "Set input maximum size to 1024 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"2048", "Set input maximum size to 2048 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{"4096", "Set input maximum size to 4096 bytes", NULL, interface_x25_ips, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_X25MAP
cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_9[] = {
	{"multiconnection", "Accept multiple connections at same port", NULL, interface_x25_map, 1, MSK_X25MAP},
	{"<enter>", "", NULL, NULL, 0, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_8[] = {
	{"<port>", "Port number", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_9, interface_x25_map, 1, MSK_X25MAP}, /* 1024-65535 */
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_7[] = {
	{"port", "TCP port", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_8, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_6[] = {
	{"<ipaddress>", "IP number", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_7, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_5[] = {
	{"host", "TCP/IP address", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_6, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4[] = {
	{"local", "Local port for inbound TCP calls", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_7, NULL, 1, MSK_X25MAP}, /* skip address! */
	{"remote", "Remote host for outbound X.25 calls", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_5, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_3[] = {
	{"<cudhexstring>",	"Call User Data in hexadecimal string", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
#if 0
	{"C0000000",		"ACSP", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C0",				"Banrisul", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"F0000000",		"BigCard", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C0000000",		"CheckCheck", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C0000000",		"CheckExpress", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"00000001",		"HiperCard", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C0000001",		"PoliCard", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C0000000",		"Redecard", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C0000000",		"Serasa", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"0100000042493034","Softway", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C100000053",		"Tecban", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"C1C3",			"Teledata", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
	{"01000000",		"Visanet", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_4, NULL, 1, MSK_X25MAP},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_2[] = {
	{"cud", "Call User Data", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_3, NULL, 1, MSK_X25MAP},
	{"local", "Local port for inbound TCP calls", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_7, NULL, 1, MSK_X25MAP}, /* skip address! */
	{"remote", "Remote host for outbound X.25 calls", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_5, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE[] = {
	{"<x121>", "Remote X.121 <address>", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE_2, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_7[] = {
	{"multiconnection", "Accept multiple connections at same port", NULL, interface_x25_map, 1, MSK_X25MAP},
	{"<enter>", "", NULL, NULL, 0, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_6[] = {
	{"<port>", "Port number", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_7, interface_x25_map, 1, MSK_X25MAP}, /* 1024-65535 */
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_5[] = {
	{"port", "TCP port", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_6, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_4[] = {
	{"local", "Local port for inbound TCP calls", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_5, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_3[] = {
	{"<cudhexstring>", "Call User Data in hexadecimal string", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_4, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_2[] = {
	{"cud", "Call User Data", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_3, NULL, 1, MSK_X25MAP},
	{"local", "Local port for inbound TCP calls", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_5, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_LOCAL[] = {
	{"<x121>", "Remote X.121 <address>", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL_2, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP_NO[] = {
	{"api-auto", "X.25 Custom API options (auto mode)", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE, NULL, 1, MSK_X25MAP},
	{"api-manual", "X.25 Custom API options (manual mode)", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL, NULL, 1, MSK_X25MAP},
	{"raw", "X.25 Custom API options (raw mode)", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE, NULL, 1, MSK_X25MAP},
	{"rbp", "X.25 Record Boundary Preservation options", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE, NULL, 1, MSK_X25MAP},
	{"<enter>", "", NULL, NULL, 0, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MAP[] = {
	{"api-auto", "X.25 Custom API options (auto mode)", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE, NULL, 1, MSK_X25MAP},
	{"api-manual", "X.25 Custom API options (manual mode)", CMD_CONFIG_INTERFACE_X25_MAP_LOCAL, NULL, 1, MSK_X25MAP},
	{"raw", "X.25 Custom API options (raw mode)", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE, NULL, 1, MSK_X25MAP},
	{"rbp", "X.25 Record Boundary Preservation options", CMD_CONFIG_INTERFACE_X25_MAP_LOCALREMOTE, NULL, 1, MSK_X25MAP},
	{NULL,NULL,NULL,NULL, 0}
};
#endif /* OPTION_X25MAP */

cish_command CMD_CONFIG_INTERFACE_X25_VC[] = {
	{"0-4095", "VC number, or 0 to disable", NULL, interface_x25_vc, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_MODULO[] = {
	{"8", "Use window modulo 8", NULL, interface_x25_modulo, 1, MSK_X25},
	{"128", "Use window modulo 128", NULL, interface_x25_modulo, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_OPS[] = {
	{"16", "Set output maximum size to 16 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"32", "Set output maximum size to 32 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"64", "Set output maximum size to 64 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"128", "Set output maximum size to 128 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"256", "Set output maximum size to 256 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"512", "Set output maximum size to 512 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"1024", "Set output maximum size to 1024 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"2048", "Set output maximum size to 2048 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{"4096", "Set output maximum size to 4096 bytes", NULL, interface_x25_ops, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_ROUTE_NO[] = { /* !!! */
	{"<x121>", "X.121 route <address>[/<mask>]", NULL, interface_x25_route_del, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_ROUTE[] = { /* !!! */
	{"<x121>", "X.121 route <address>[/<mask>]", NULL, interface_x25_route_add, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_SVC_NO[] = {
	{"1-4095", "SVC number", NULL, interface_x25_svc_del, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_SVC[] = {
	{"1-4095", "SVC number", NULL, interface_x25_svc_add, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_WIN[] = {
	{"1-7", "Input window size", NULL, interface_x25_win, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_WOUT[] = {
	{"1-7", "Output window size", NULL, interface_x25_wout, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_NO[] = {
	{"address", "Unset X.121 local address", NULL, interface_x25_address, 1, MSK_X25},
	{"debug", "Disable connection extra debug", NULL, interface_x25_debug, 1, MSK_X25},
	{"facility", "Unset local facility", CMD_CONFIG_INTERFACE_X25_FACILITY_NO, NULL, 1, MSK_X25},
	{"idle", "Unset idle timeout", NULL, interface_x25_idle, 1, MSK_X25},
#ifdef OPTION_X25MAP
	{"map", "Unset map options", CMD_CONFIG_INTERFACE_X25_MAP_NO, interface_x25_map, 1, MSK_X25MAP},
#endif
	{"route", "Delete X.121 route", CMD_CONFIG_INTERFACE_X25_ROUTE_NO, NULL, 1, MSK_X25}, /* !!! */
	{"suppress-calling-address", "Send calling address on call request", NULL, interface_x25_suppresscallingaddress, 1, MSK_X25},
	{"svc", "Delete SVC (RFC1356)", CMD_CONFIG_INTERFACE_X25_SVC_NO, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25_DEBUG[] = {
	{"packet", "Enable packet dump", NULL, interface_x25_debug, 1, MSK_X25},
	{"<enter>", "", NULL, NULL, 0, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_X25[] = {
	{"address", "Set X.121 local address", CMD_CONFIG_INTERFACE_X25_ADDRESS, NULL, 1, MSK_X25},
	{"debug", "Enable connection extra debug", CMD_CONFIG_INTERFACE_X25_DEBUG, interface_x25_debug, 1, MSK_X25},
	{"facility", "Set local facility", CMD_CONFIG_INTERFACE_X25_FACILITY, NULL, 1, MSK_X25},
#if 0 /* !!! */
	{"hic", "Set the highest incoming-only VC number", CMD_CONFIG_INTERFACE_X25_VC, NULL, 1, MSK_X25},
	{"hoc", "Set the highest outgoing-only VC number", CMD_CONFIG_INTERFACE_X25_VC, NULL, 1, MSK_X25},
#endif
	{"htc", "Set the highest two-way VC number", CMD_CONFIG_INTERFACE_X25_VC, NULL, 1, MSK_X25},
	{"idle", "Set idle timeout", CMD_CONFIG_INTERFACE_X25_IDLE, NULL, 1, MSK_X25},
	{"ips", "Set input packet size", CMD_CONFIG_INTERFACE_X25_IPS, NULL, 1, MSK_X25},
#if 0 /* !!! */
	{"lic", "Set the lowest incoming-only VC number", CMD_CONFIG_INTERFACE_X25_VC, NULL, 1, MSK_X25},
	{"loc", "Set the lowest outgoing-only VC number", CMD_CONFIG_INTERFACE_X25_VC, NULL, 1, MSK_X25},
#endif
	{"ltc", "Set the lowest two-way VC number", CMD_CONFIG_INTERFACE_X25_VC, NULL, 1, MSK_X25},
#ifdef OPTION_X25MAP
	{"map", "Set map options", CMD_CONFIG_INTERFACE_X25_MAP, NULL, 1, MSK_X25MAP},
#endif
	{"modulo", "Set the window modulus", CMD_CONFIG_INTERFACE_X25_MODULO, NULL, 1, MSK_X25},
	{"ops", "Set output packet size", CMD_CONFIG_INTERFACE_X25_OPS, NULL, 1, MSK_X25},
	{"route", "Add X.121 route", CMD_CONFIG_INTERFACE_X25_ROUTE, NULL, 1, MSK_X25}, /* !!! */
	{"suppress-calling-address", "Suppress calling address on call request", NULL, interface_x25_suppresscallingaddress, 1, MSK_X25},
	{"svc", "Add SVC (RFC1356)", CMD_CONFIG_INTERFACE_X25_SVC, NULL, 1, MSK_X25},
	{"win", "Set input window size", CMD_CONFIG_INTERFACE_X25_WIN, NULL, 1, MSK_X25},
	{"wout", "Set output window size", CMD_CONFIG_INTERFACE_X25_WOUT, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_X25_NO[] = {
	{"backup", "Unset backup interface", NULL, serial_no_backup, 1, MSK_AUX},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK_NO, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Unset HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC_NO, NULL, 1, MSK_NORMAL},
#endif
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT_NO, NULL, 1, MSK_NORMAL},
	{"loopback", "Disable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
	{"shutdown", "Turn device on", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"x25", "Unset X.25 parameters", CMD_CONFIG_INTERFACE_X25_NO, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE2[] = {
	{"MLP", "LAPB MLP operation mode", NULL, interface_x25_lapb_mode, 1, MSK_X25},
	{"SLP", "LAPB Single Link Procedure operation mode", NULL, interface_x25_lapb_mode, 1, MSK_X25},
	{"<enter>", "", NULL, NULL, 0, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE1[] = {
	{"extended", "LAPB extended (modulo 128) operation mode (larger window sizes)", CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE2, interface_x25_lapb_mode, 1, MSK_X25},
	{"standard", "LAPB standard (modulo 8) operation mode", CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE2, interface_x25_lapb_mode, 1, MSK_X25},
	{"<enter>", "", NULL, NULL, 0, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE[] = {
	{"DCE", "LAPB DCE operation mode", CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE1, interface_x25_lapb_mode, 1, MSK_X25},
	{"DTE", "LAPB DTE operation mode", CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE1, interface_x25_lapb_mode, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB_N2[] = {
	{"1-60", "LAPB n2 couter", NULL, interface_x25_lapb_n2, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB_T1[] = {
	{"1-180", "LAPB t1 timeout", NULL, interface_x25_lapb_t1, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB_T2[] = {
	{"1-180", "LAPB t2 timeout", NULL, interface_x25_lapb_t2, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB_WINDOW[] = {
	{"1-7", "LAPB standard window size", NULL, interface_x25_lapb_window, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_LAPB[] = {
	{"mode", "LAPB operation mode", CMD_CONFIG_INTERFACE_SERIAL_LAPB_MODE, NULL, 1, MSK_X25},
	{"n2", "LAPB N2 counter: tries on the link before it is declared a failure", CMD_CONFIG_INTERFACE_SERIAL_LAPB_N2, NULL, 1, MSK_X25},
	{"t1", "LAPB T1 retry timeout", CMD_CONFIG_INTERFACE_SERIAL_LAPB_T1, NULL, 1, MSK_X25},
	{"t2", "LAPB T2 ack pending timeout", CMD_CONFIG_INTERFACE_SERIAL_LAPB_T2, NULL, 1, MSK_X25},
	{"window", "LAPB window size", CMD_CONFIG_INTERFACE_SERIAL_LAPB_WINDOW, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_X25[] = {
	{"physical-layer", "Select synchronous or asynchronous mode", CMD_CONFIG_INTERFACE_SERIAL_PHYSICAL, NULL, 1, MSK_NORMAL},
	{"encapsulation", "Set encapsulation type", CMD_CONFIG_INTERFACE_SERIAL_ENCAP, NULL, 1, MSK_NORMAL},
	{"backup", "Set backup interface", CMD_CONFIG_INTERFACE_SERIAL_BACKUP1, NULL, 1, MSK_AUX},
	{"clock", "Configure serial interface clock", CMD_CONFIG_INTERFACE_SERIAL_CLOCK, NULL, 1, MSK_NORMAL},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"hdlc", "Set HDLC parameters", CMD_CONFIG_INTERFACE_SERIAL_HDLC, NULL, 1, MSK_NORMAL},
#endif
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ignore", "Ignore serial signals", CMD_CONFIG_INTERFACE_SERIAL_IGNORE, NULL, 1, MSK_NORMAL},
	{"invert", "Serial invert modes", CMD_CONFIG_INTERFACE_SERIAL_INVERT, NULL, 1, MSK_NORMAL},
	{"lapb", "LAPB parameters", CMD_CONFIG_INTERFACE_SERIAL_LAPB, NULL, 1, MSK_NORMAL},
	{"loopback", "Enable loopback mode", NULL, serial_loopback, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_X25_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"x25", "Set X.25 parameters", CMD_CONFIG_INTERFACE_X25, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

// sub-interface serial - encapsulamento X25

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP3[] = {
	{"<netmask>", "Mask", NULL, interface_subx25_ipaddr, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP2[] = {
	{"<ipaddress>", "Remote IP Address", CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP3, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP1[] = {
	{"<ipaddress>", "Local IP Address", CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP2, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"address", "Set IP address", CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP1, NULL, 1, MSK_NORMAL},
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
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_ADDRESS[] = {
	{"<x121>", "Local X.121 <address>", NULL, interface_subx25_address, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_IPS[] = {
	{"16", "16 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"32", "32 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"64", "64 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"128", "128 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"256", "256 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"512", "512 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"1024", "1024 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"2048", "2048 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{"4096", "4096 bytes", NULL, interface_subx25_ips, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_MAP_IP_2[] = {
	{"<x121>", "Remote X.121 <address>", NULL, interface_subx25_map_ip, 1, MSK_X25},
	{"passive", "Wait for incoming call", NULL, interface_subx25_map_ip, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_MAP_IP[] = {
	{"<ipaddress>", "Remote IP Address", CMD_CONFIG_INTERFACE_SUBX25_MAP_IP_2, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_MAP_NO[] = {
	{"ip", "Unset map ip options", NULL, interface_subx25_map_ip, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_MAP[] = {
	{"ip", "Set map ip options", CMD_CONFIG_INTERFACE_SUBX25_MAP_IP, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_OPS[] = {
	{"16", "16 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"32", "32 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"64", "64 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"128", "128 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"256", "256 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"512", "512 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"1024", "1024 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"2048", "2048 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{"4096", "4096 bytes", NULL, interface_subx25_ops, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_WIN[] = {
	{"1-7", "Input window size", NULL, interface_subx25_win, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_WOUT[] = {
	{"1-7", "Output window size", NULL, interface_subx25_wout, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25_NO[] = {
	{"address", "Unset X.121 local address", NULL, interface_subx25_address, 1, MSK_X25},
	{"map", "Unset map options", CMD_CONFIG_INTERFACE_SUBX25_MAP_NO, NULL, 1, MSK_X25},
	{"route", "Delete X.121 route", CMD_CONFIG_INTERFACE_X25_ROUTE_NO, NULL, 1, MSK_X25}, /* !!! */
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SUBX25[] = {
	{"address", "Set X.121 local address", CMD_CONFIG_INTERFACE_SUBX25_ADDRESS, NULL, 1, MSK_X25},
	{"ips", "Set input packet size", CMD_CONFIG_INTERFACE_SUBX25_IPS, NULL, 1, MSK_X25},
	{"map", "Set map options", CMD_CONFIG_INTERFACE_SUBX25_MAP, NULL, 1, MSK_X25},
	{"ops", "Set output packet size", CMD_CONFIG_INTERFACE_SUBX25_OPS, NULL, 1, MSK_X25},
	{"route", "Add X.121 route", CMD_CONFIG_INTERFACE_X25_ROUTE, NULL, 1, MSK_X25}, /* !!! */
	{"win", "Set input window size", CMD_CONFIG_INTERFACE_SUBX25_WIN, NULL, 1, MSK_X25},
	{"wout", "Set output window size", CMD_CONFIG_INTERFACE_SUBX25_WOUT, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBX25_NO[] = {
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IP, NULL, 1, MSK_NORMAL},
#if 0
	{"ipx", "Unset IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_NO_IPX, NULL, 1, MSK_NORMAL},
#endif
	{"shutdown", "Turn device on", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"x25", "Unset X.25 parameters", CMD_CONFIG_INTERFACE_SUBX25_NO, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBX25[] = {
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_SERIAL_SUBX25_IP, NULL, 1, MSK_NORMAL},
#if 0 /* !!! */
	{"ipx", "Set IPX parameters", CMD_CONFIG_INTERFACE_SERIAL_IPX, NULL, 1, MSK_NORMAL},
#endif
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_SERIAL_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CONFIG_INTERFACE_SERIAL_SUBX25_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
	{"x25", "Set X.25 parameters", CMD_CONFIG_INTERFACE_SUBX25, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};
#endif /* OPTION_X25 */
#endif

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
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Remove QoS policy", CMD_CONFIG_INTERFACE_POLICY_NO, interface_policy_no, 1, MSK_QOS},
#endif
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
#ifndef OPTION_NEW_QOS_CONFIG
	{"policy", "Add QoS policy", CMD_CONFIG_INTERFACE_POLICY, NULL, 1, MSK_QOS},
#endif
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
		case serial:
			switch(wan_get_protocol(interface_major)) {
				case IF_PROTO_FR:
					if (fr_dlci_exists(interface_major, interface_minor))
						return 0; // ok
					break;
#ifdef OPTION_X25
				case IF_PROTO_X25:
					if (x25_svc_exists(interface_major, interface_minor))
						return 0; // ok
					break;
#endif
			}
			break;
		default:
			break;
	}
	return -1; // subinterface invalida
}

cish_command *get_wan_cmd_root(long protocol, int sync_nasync, int minor)
{
	if (sync_nasync) /* modo sincrono */
	{
		switch (protocol)
		{
			case IF_PROTO_CISCO:
				return CMD_CONFIG_INTERFACE_SERIAL_CHDLC;
			case IF_PROTO_FR:
				if (minor == -1) return CMD_CONFIG_INTERFACE_SERIAL_FR;
					else return CMD_CONFIG_INTERFACE_SERIAL_SUBFR;
			case IF_PROTO_PPP:
				return CMD_CONFIG_INTERFACE_SERIAL_SPPP;
#ifdef OPTION_X25
			case IF_PROTO_X25:
				if (minor == -1) return CMD_CONFIG_INTERFACE_SERIAL_X25;
					else return CMD_CONFIG_INTERFACE_SERIAL_SUBX25;
#endif
			case SCC_PROTO_MLPPP:
				return CMD_CONFIG_INTERFACE_SERIAL_PPP;
		}
		return CMD_CONFIG_INTERFACE_SERIAL;
	}
	else /* modo assincrono */
	{
		return CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC;
	}
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
			case aux:
				interface_major += MAX_WAN_INTF; /* Offset! 0-1:serial0-1; 2-3: aux0-1; */
				command_root=CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC;
				break;
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
			case serial:
			{
#ifndef CONFIG_BERLIN_SATROUTER
				int cabledetect, dte_ndce, v28_nv35, cablelogic;

				/* Switch clock rates according cable type! */
				wan_get_cable(interface_major, &cabledetect, &dte_ndce, &v28_nv35, &cablelogic);
				
				if (cabledetect && v28_nv35) {
					//CMD_CONFIG_INTERFACE_SERIAL_CLOCK_RATE[0].privilege=1000;
					//CMD_CONFIG_INTERFACE_SERIAL_CLOCK_RATE[1].privilege=1;
					_cish_mask &= ~MSK_V35;
					_cish_mask |= MSK_V28;
				} else {
					//CMD_CONFIG_INTERFACE_SERIAL_CLOCK_RATE[0].privilege=1;
					//CMD_CONFIG_INTERFACE_SERIAL_CLOCK_RATE[1].privilege=1000;
					_cish_mask &= ~MSK_V28;
					_cish_mask |= MSK_V35;
				}
#endif
				command_root=get_wan_cmd_root(wan_get_protocol(interface_major), wan_get_physical(interface_major), interface_minor);
#ifdef OPTION_X25
				if (command_root == CMD_CONFIG_INTERFACE_SERIAL_X25) {
					struct x25_intf_config conf;

					dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
					x25_get_devconfig(dev, &conf);
					if (conf.subscrip.extended) {
						CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_IN[0].name="1-127";
						CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_OUT[0].name="1-127";
						CMD_CONFIG_INTERFACE_X25_WIN[0].name="1-127";
						CMD_CONFIG_INTERFACE_X25_WOUT[0].name="1-127";
					} else {
						CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_IN[0].name="1-7";
						CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_OUT[0].name="1-7";
						CMD_CONFIG_INTERFACE_X25_WIN[0].name="1-7";
						CMD_CONFIG_INTERFACE_X25_WOUT[0].name="1-7";
					}
					free(dev);
				}
#endif
				break;
			}
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

void interface_fr_ipaddr(const char *cmdline) /* ip address [local] [mask] */
{
	arglist *args;
	char *local, *dev, *mask;

	args=make_args(cmdline);
	local=args->argv[2];
	if (args->argc == 4) mask=args->argv[3];
		else mask=NULL;
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	ip_addr_flush(dev);
	ip_addr_add(dev, local, NULL, mask ? mask : "255.255.255.255"); /* new address */
	destroy_args(args);
	free(dev);
}

void interface_subfr_ipaddr(const char *cmdline) /* ip address [local] [remote] [mask] */
{
	arglist *args;
	char *local, *remote, *dev, *mask;

	args=make_args(cmdline);
	local=args->argv[2];
	remote=args->argv[3];
	if (args->argc > 4) mask=args->argv[4];
		else mask=NULL;
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	ip_addr_flush(dev);
	ip_addr_add(dev, local, remote, mask ? mask : "255.255.255.255");
	destroy_args(args);
	free(dev);
}

void interface_subfr_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32];
	char *dev, *pdev;

	args = make_args(cmdline);
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);

	/* Teste 1: ja existe a bridge ? */
	strcpy(brname, BRIDGE_NAME); strcat(brname, args->argv[1]);
	if (!br_exists(brname))	{
		printf("%% bridge group %s does not exist\n", args->argv[1]);
		goto bridgegroup_done;
	}

	/* Teste 2: esta interface ja pertence a esta bridge ? */
	if (br_checkif(brname, dev)) {
		printf("%% interface already assigned to bridge group %s\n", args->argv[1]);
		goto bridgegroup_done;
	}

	/* Teste 3: esta interface ja pertence a alguma outra bridge ? TODO */
	

	/* Teste 4: este DLCI foi criado como bridge ? */
	if (!fr_dlci_is_bridge(interface_major, interface_minor))
	{
		// Nao - eh preciso deletar o DLCI e cria-lo novamente, agora como bridge.

		// Apaga a configuracao de IPX da interface (a configuracao de IP
		// sera automaticamente apagada quando o DLCI for recriado)
		ipx_del_intf_all(dev);

		fr_del_dlci(interface_major, interface_minor, 0);
		fr_add_dlci(interface_major, interface_minor, 1);
	}

	// Poe a interface em up (se ja nao estiver); mas primeiro
	// precisamos garantir que a interface 'serialn' tambem esteja 'up'.
	pdev = convert_device (interface_edited->cish_string, interface_major, -1);
	dev_set_link_up(pdev);
	free(pdev);
	dev_set_link_up(dev);

	// Finalmente, adiciona a interface `a bridge.	
	br_addif(brname, dev);

bridgegroup_done:
	destroy_args(args);
	free(dev);
}

void interface_subfr_no_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32];
	char *dev;

	args = make_args (cmdline);
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);

	// Teste 1: existe a bridge ?
	strcpy(brname, BRIDGE_NAME); strcat(brname, args->argv[2]);
	if (!br_exists(brname)) goto no_bridgegroup_done;

	// Teste 2: esta interface pertence a esta bridge ?
	if (!br_checkif(brname, dev)) goto no_bridgegroup_done;

	// Retira a interface da bridge.
	br_delif(brname, dev);

no_bridgegroup_done:
	// Este DLCI foi criado como bridge ?
	if (fr_dlci_is_bridge(interface_major, interface_minor))
	{
		// Sim - eh preciso deletar o DLCI e cria-lo novamente, 
		// agora nao como bridge.
		fr_del_dlci(interface_major, interface_minor, 1);
		fr_add_dlci(interface_major, interface_minor, 0);
	}

	destroy_args(args);
	free(dev);
}

void interface_ethernet_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32], addr[32], mask[32];
	char *dev;
	ipx_intf_t intf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);

	// Teste 1: ja existe a bridge ?
	strcpy(brname, BRIDGE_NAME); strcat(brname, args->argv[1]);
	if (!br_exists(brname))
	{
		printf("%% bridge group %s does not exist\n", args->argv[1]);
		return;
	}

	// Teste 2: a interface ethernet ja pertence a esta bridge ?
	if (br_checkif(brname, dev))
	{
		printf("%% interface already assigned to bridge group %s\n", args->argv[1]);
		goto bridgegroup_done;
	}

	// Teste 3: esta interface ja pertence a alguma outra bridge ?
	// TODO

	// Salva a configuracao de IP da ethernet
	get_interface_ip_addr(dev, addr, mask);

	// Salva a configuracao de IPX
	get_ethernet_ipx_network_br(dev, &intf);

	// Zera a configuracao de IP da ethernet
	set_interface_no_ip_addr(dev); /* flush */

	// Zera a configuracao de IPX
	set_ethernet_no_ipx_network_br(dev);

	// Adiciona a interface `a bridge.
	br_addif(brname, dev);

	// Restaura a configura IP da ethernet na bridge
	set_interface_ip_addr(brname, addr, mask); /* bridge use ethernet ip address */

	// Restaura a configura IPX da ethernet na bridge
	set_ethernet_ipx_network_br(brname, &intf); /* bridge use ethernet ipx address */

bridgegroup_done:	
	destroy_args(args);
	free(dev);
}

void interface_ethernet_no_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32], addr[32], mask[32];
	char *dev;
	ipx_intf_t intf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);

	// Teste 1: existe a bridge ?
	strcpy(brname, BRIDGE_NAME); strcat(brname, args->argv[2]);
	if (!br_exists(brname)) goto no_bridgegroup_done;

	// Teste 2: esta interface pertence a esta bridge ?
	if (!br_checkif(brname, dev)) goto no_bridgegroup_done;

	// Salva a configuracao de IP da bridge
	get_interface_ip_addr(brname, addr, mask);

	// Salva a configuracao de IPX da bridge
	get_ethernet_ipx_network_br(brname, &intf);

	// Zera a configuracao de IP da bridge
	set_interface_no_ip_addr(brname); /* flush */

	// Zera a configuracao de IPX da bridge
	set_ethernet_no_ipx_network_br(brname);

	// Retira a interface da bridge.
	br_delif(brname, dev);

	// Restaura a configura IP da ethernet
	set_interface_ip_addr(dev, addr, mask); /* Recover ip address from bridge */

	// Restaura a configura IPX da ethernet
	set_ethernet_ipx_network_br(dev, &intf); /* Recover ipx address from bridge */

no_bridgegroup_done:
	destroy_args(args);
	free(dev);
}

void interface_chdlc_ipaddr(const char *cmdline) /* ip address [local] [remote] [mask] */
{
	arglist *args;
	char *local, *remote, *dev, *mask;

	args=make_args(cmdline);
	if (args->argc < 4)
	{
		destroy_args(args);
		printf("%% incomplete command\n");
		return;
	}
	local=args->argv[2];
#ifdef CONFIG_BERLIN_SATROUTER
	if (args->argc > 4)
	{
		remote = args->argv[3];
		mask = args->argv[4];
	}
	else
	{
		remote = NULL;
		mask = args->argv[3];
	}
	if( !is_valid_netmask( mask ) )
	{
		printf("%% Invalid netmask\n");
		destroy_args(args);
		return;
	}
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	ip_addr_flush(dev);
	ip_addr_add(dev, local, remote ? remote : "0.0.0.0", mask ? mask : "255.255.255.255");
#else
	remote=args->argv[3];
	if (args->argc > 4) mask=args->argv[4];
		else mask=NULL;
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	ip_addr_flush(dev);
	ip_addr_add(dev, local, remote, mask ? mask : "255.255.255.255");
#endif
	destroy_args(args);
	free(dev);
}

#ifdef INTERFACE_SERIAL_CHDLC_BRIDGE
void interface_chdlc_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32];
	char *dev;
	cisco_proto cisco;

	args = make_args (cmdline);
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);

	/* Teste 1: ja existe a bridge ? */
	strcpy(brname, BRIDGE_NAME); strcat(brname, args->argv[1]);
	if (!br_exists(brname))
	{
		printf("%% bridge group %s does not exist\n", args->argv[1]);
		goto bridgegroup_done;
	}

	/* Teste 2: esta interface ja pertence a esta bridge ? */
	if (br_checkif(brname, dev)) {
		printf("%% interface already assigned to bridge group %s\n", args->argv[1]);
		goto bridgegroup_done;
	}

	ip_addr_flush(dev); /* clear interface address! */

	if (chdlc_get_config(interface_major, &cisco) < 0) {
		printf("%% error reading chdlc device configuration\n");
		goto bridgegroup_done;
	}

	cisco.bridge = 1; /* enable bridge! */

	if (chdlc_set_config(interface_major, &cisco) < 0) {
		printf("%% error setting chdlc device configuration\n");
		goto bridgegroup_done;
	}

	/* Finalmente, adiciona a interface a bridge. */
	br_addif(brname, dev);
	
bridgegroup_done:	
	destroy_args(args);
	free(dev);
}

void interface_chdlc_no_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32];
	char *dev;
	cisco_proto cisco;
	
	args = make_args (cmdline);
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);
	
	// Teste 1: existe a bridge ?
	strcpy(brname, BRIDGE_NAME); strcat(brname, args->argv[2]);
	if (!br_exists(brname)) goto no_bridgegroup_done;
	
	// Teste 2: esta interface pertence a esta bridge ?
	if (!br_checkif(brname, dev)) goto no_bridgegroup_done;
	
	// Retira a interface da bridge.
	br_delif(brname, dev);

	if (chdlc_get_config(interface_major, &cisco) < 0)
	{
		printf("%% error reading chdlc device configuration\n");
		goto no_bridgegroup_done;
	}
	cisco.bridge = 0; /* disable bridge! */
	if (chdlc_set_config(interface_major, &cisco) < 0) goto no_bridgegroup_done;
	
no_bridgegroup_done:
	destroy_args(args);
	free(dev);
}
#endif

void interface_clear_bridgegroup(void)
{
	char brname[32];
	char *dev;
	
	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);

	// Teste 1: existe a bridge ?
	strcpy(brname, BRIDGE_NAME); strcat(brname, "1");
	if (!br_exists(brname)) goto clear_bridgegroup_done;
	
	// Teste 2: esta interface pertence a esta bridge ?
	if (!br_checkif(brname, dev)) goto clear_bridgegroup_done;
	
	// Retira a interface da bridge.
	br_delif(brname, dev);

clear_bridgegroup_done:
	free(dev);
}

void interface_ipxnet(const char *cmdline)
{
	arglist *args;
	char *network;
	char *dev;
	unsigned char enc=IPX_FRAME_ETHERII;
	u32 net, old_net;

	args = make_args(cmdline);
	network = args->argv[2];
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);
	net = strtoul(network, NULL, 16);
	if (ipx_check_intf(dev, enc, &old_net))
	{
		printf("%% network number already set to (%08lX)\n", (long unsigned int)old_net);
	}
	else
	{
		ipx_add_intf(dev, enc, net);
	}
	destroy_args(args);
	free(dev);
}

void interface_no_ipxnet(const char *cmdline)
{
	char *dev;
	
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);
	ipx_del_intf_all(dev);
	free(dev);
}

void interface_ethernet_ipxnet(const char *cmdline)
{
	arglist *args;
	char *network, *dev;
	char *encapsulation = NULL;
	unsigned char enc=0;
	u32 net, old_net;

	args = make_args (cmdline);

	network = args->argv[2];
	if (args->argc==5)
		encapsulation = args->argv[4];

	if (encapsulation)
	{
		if (strcasecmp(encapsulation, "ethernet_II")==0) enc=IPX_FRAME_ETHERII;
		else if (strcasecmp(encapsulation, "802.3")==0) enc=IPX_FRAME_8023;
		else if (strcasecmp(encapsulation, "802.2")==0) enc=IPX_FRAME_8022;
		else if (strcasecmp(encapsulation, "snap")==0) enc=IPX_FRAME_SNAP;
	}
		else enc=IPX_FRAME_8023; // Default para ethernet eh 802.3

	net = strtoul(network, NULL, 16);
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);
	if (ipx_check_intf(dev, enc, &old_net))
	{
		printf("%% network number already set to (%08lX)\n", (long unsigned int)old_net);
	}
	else
	{
		ipx_add_intf(dev, enc, net);
	}
	destroy_args(args);
	free(dev);
}

#if 0
void interface_ethernet_no_ipxnet(const char *cmdline)
{
	 set_ethernet_no_ipx_network(); /* !!! */
}
#endif

void interface_shutdown(const char *cmdline) /* shutdown */
{
	char *dev;
	long protocol=0;
#ifdef OPTION_X25
	struct rfc1356_config cfg;
#endif
	device_family *fam;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if ((fam=getfamily(interface_edited->cish_string))) {
		switch(fam->type) {
			case serial:
				protocol=wan_get_protocol(interface_major);
				switch(protocol) {
#ifdef OPTION_X25
					case IF_PROTO_X25:
						if (interface_minor >= 0)
						{
							rfc1356_get_config(interface_major, interface_minor, &cfg);
							if (cfg.up)
							{
								cfg.up=0;
								rfc1356_set_config(interface_major, interface_minor, &cfg);
							}
						}
						else x25_shutdown_all(interface_major);
						break;
#endif
					case IF_PROTO_PPP:
						notify_driver_about_shutdown(dev);
						break;

					default:
						break;
				}
				break;
			default:
				break;
		}
	}
	tc_remove_all(dev);
#ifdef CONFIG_BERLIN_SATROUTER
	if(!strcmp(dev, "serial0"))
		system("gpio wan_status off");
#endif
	dev_set_link_down(dev);

#ifdef CONFIG_BERLIN_SATROUTER
	if( !strcmp(dev, "ethernet0") )
		reload_udhcpd(0);
	switch( get_board_hw_id() )
	{
		case BOARD_HW_ID_1:
			break;
		case BOARD_HW_ID_0:
		case BOARD_HW_ID_2:
		case BOARD_HW_ID_3:
		case BOARD_HW_ID_4:
			if( !strcmp(dev, "ethernet1") )
				reload_udhcpd(1);
			break;
	}
#endif
#ifdef OPTION_X25MAP
	if (fam) {
		if ( (fam_type == serial) && (protocol == IF_PROTO_X25) )
			write_x25mapd_conf(); /* verify x25mapd interfaces... */
	}
#endif
	free(dev);
}

void interface_no_shutdown(const char *cmdline) /* no shutdown */
{
	char *dev;
	long protocol=0;
#ifdef OPTION_X25
	struct rfc1356_config cfg;
#endif
	device_family *fam;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if ((fam=getfamily(interface_edited->cish_string))) {
		switch(fam->type) {
			case serial:
				protocol=wan_get_protocol(interface_major);
#ifdef CONFIG_BERLIN_SATROUTER
				if(protocol == 0xFFFF)
				{
					printf("%% No encapsulation defined\n");
					return;
				}
#endif
				if (interface_minor >= 0) // Verifica se eh uma subinterface
				{
					char *pdev;

					switch(protocol) {
#ifdef OPTION_X25
						case IF_PROTO_X25:
							pdev=convert_device(interface_edited->cish_string, interface_major, -1);
							dev_set_link_up(pdev);				
							x25_route_reconfigure(interface_major);
							free(pdev);
							break;
#endif
						case IF_PROTO_FR: // Sim - portanto precisamos garantir que a interface 'serialn' tambem esteja 'up'.
							pdev=convert_device(interface_edited->cish_string, interface_major, -1);
							dev_set_link_up(pdev);
							/*tc_insert_all(pdev);*//* !!! */
							free(pdev);
							break;
						default:
							break;
					}
				}
				break;
			default:
				break;
		}
	}
	dev_set_link_up(dev); /* UP */
	ipx_reconfigure_intf(dev); /* carrega network de /var/run/ipx/%s.%d.net e configura IPX de dev */
	if (fam) {
		switch(fam->type) {
			case ethernet:
				reload_udhcpd(interface_major); /* dhcp integration! force reload ethernet address */
				tc_insert_all(dev);
				break;
			case serial:
				switch(protocol) {
#ifdef OPTION_X25
					case IF_PROTO_X25:
						if (interface_minor == -1) /* serial0 */
						{
							x25_route_reconfigure(interface_major);
#ifdef OPTION_X25MAP
							write_x25mapd_conf(); /* wake-up x25mapd! */
#endif
						}
						else
						{
							rfc1356_get_config(interface_major, interface_minor, &cfg);
							if (!cfg.up)
							{
								cfg.up=1;
								rfc1356_set_config(interface_major, interface_minor, &cfg);
								tc_insert_all(dev);
							}
						}
						break;
#endif
					case IF_PROTO_FR:
#ifdef OPTION_NEW_QOS_CONFIG
						tc_insert_all(dev);
#else
						if (interface_minor >= 0)
							tc_insert_all(dev);
#endif
						break;
					case IF_PROTO_CISCO:
						tc_insert_all(dev);
						break;
					case IF_PROTO_PPP:
						tc_insert_all(dev);
						break;
					default:
						break;
				}
				break;
			default:
				break;
		}
	}
#ifdef CONFIG_BERLIN_SATROUTER
	if( !strcmp(dev, "ethernet0") || !strcmp(dev, "ethernet1") )
	{
		int k, result;
		unsigned short bmcr;

		switch( get_board_hw_id() )
		{
			case BOARD_HW_ID_0:
			case BOARD_HW_ID_1:
				if( (result = lan_get_phy_reg(dev, MII_BMCR)) >= 0 )
				{
					bmcr = (unsigned short) result;
					if( bmcr & BMCR_ANENABLE )
						fec_autonegotiate_link(dev);
					else
						fec_config_link(dev, (bmcr & BMCR_SPEED100) ? 1 : 0, (bmcr & BMCR_FULLDPLX) ? 1 : 0);
					for( k=0; k<2; k++ )
						sleep(1);
					if( bmcr & BMCR_ANENABLE )
						fec_autonegotiate_link(dev);
					else
						fec_config_link(dev, (bmcr & BMCR_SPEED100) ? 1 : 0, (bmcr & BMCR_FULLDPLX) ? 1 : 0);
				}
				break;
			case BOARD_HW_ID_2:
			case BOARD_HW_ID_3:
			case BOARD_HW_ID_4:
				if( !strcmp(dev, "ethernet0") )
				{
					if( (result = lan_get_phy_reg(dev, MII_BMCR)) >= 0 )
					{
						bmcr = (unsigned short) result;
						if( bmcr & BMCR_ANENABLE )
							fec_autonegotiate_link(dev);
						else
							fec_config_link(dev, (bmcr & BMCR_SPEED100) ? 1 : 0, (bmcr & BMCR_FULLDPLX) ? 1 : 0);
						for( k=0; k<2; k++ )
							sleep(1);
						if( bmcr & BMCR_ANENABLE )
							fec_autonegotiate_link(dev);
						else
							fec_config_link(dev, (bmcr & BMCR_SPEED100) ? 1 : 0, (bmcr & BMCR_FULLDPLX) ? 1 : 0);
					}
				}
				break;
		}
	}
	if( !strcmp(dev, "ethernet0") )
		reload_udhcpd(0);
	switch( get_board_hw_id() )
	{
		case BOARD_HW_ID_1:
			break;
		case BOARD_HW_ID_0:
		case BOARD_HW_ID_2:
		case BOARD_HW_ID_3:
		case BOARD_HW_ID_4:
			if( !strcmp(dev, "ethernet1") )
				reload_udhcpd(1);
			break;
	}
#endif

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

void serial_encap(const char *cmdline)
{
	long old_protocol, new_protocol;
	char *dev;
	arglist *args;

	args=make_args(cmdline);
	old_protocol=wan_get_protocol(interface_major);
	if (strcasecmp(args->argv[1], "frame-relay") == 0)
		new_protocol = IF_PROTO_FR;
	else if (strcasecmp(args->argv[1], "hdlc") == 0)
		new_protocol = IF_PROTO_CISCO;
	else if (strcasecmp(args->argv[1], "ppp") == 0)
		new_protocol = IF_PROTO_PPP;
#ifdef OPTION_X25
	else if (strcasecmp(args->argv[1], "x25") == 0)
		new_protocol = IF_PROTO_X25;
#endif
	else
	{
		destroy_args(args);
		return;
	}
	destroy_args(args);
	if (old_protocol == new_protocol)
		return;
#ifdef CONFIG_SPPP_NETLINK
	if( old_protocol == IF_PROTO_PPP )
		kill_daemon(SPPPD_DAEMON);
	if( new_protocol == IF_PROTO_PPP ) {
		exec_daemon(SPPPD_DAEMON);
		wait_spppd_daemon();
	}
#endif
	interface_clear_bridgegroup();
	dev=convert_device(interface_edited->cish_string, interface_major, -1);
	clean_iface_acls(dev);
	clean_iface_nat_rules(dev);
	clean_iface_mangle_rules(dev);
	ipx_del_intf_all(dev); /* clean ipx files! */
#ifdef OPTION_PIMD
	pimdd_phyint(0, dev);
	pimsd_phyint(0, dev);
#endif
	switch (old_protocol)
	{
		case IF_PROTO_FR:
			interface_shutdown(NULL);
			if (new_protocol == SCC_PROTO_MLPPP)
			{ /* na troca de frame-relay para ppp, passar antes
			     por cisco-hdlc para garantir que as interfaces
			     do frame-relay sejam destruidas */
				wan_set_protocol(interface_major, IF_PROTO_CISCO);
			}
			break;
		case IF_PROTO_CISCO:
			interface_shutdown(NULL);
			ip_addr_flush(dev); /* clear configured ip! */
			break;
		case IF_PROTO_PPP:
			interface_shutdown(NULL);
			ip_addr_flush(dev); /* clear configured ip! */
			break;
#ifdef OPTION_X25
		case IF_PROTO_X25:
			interface_shutdown(NULL);
			x25_clean_all(interface_major);
			break;
#endif
		case SCC_PROTO_MLPPP:
			ppp_shutdown(NULL);
			sleep(3); /* wait for pppd clean locks (for example!) */
			break;
	}
	wan_set_protocol(interface_major, new_protocol);
	/* serial0 QoS */
	clean_qos_cfg(dev); /* Limpa configuracao do QoS */
	free(dev);
	/* New command root */
	command_root=get_wan_cmd_root(new_protocol, wan_get_physical(interface_major), -1);
}

void serial_encap_async(const char *cmdline)
{
	/* no modo assincrono somente existe o encapsulamento: PPP (async) */
}

void serial_physical(const char *cmdline)
{
	int old_phy, new_phy;
	char *dev;
	arglist *args;

	args=make_args(cmdline);
	old_phy=wan_get_physical(interface_major);
	if (strcasecmp(args->argv[1], "synchronous")==0)
		new_phy=1;
	else if (strcasecmp(args->argv[1], "asynchronous")==0)
		new_phy=0;
	else
	{
		destroy_args(args);
		return;
	}
	destroy_args(args);
	if (old_phy == new_phy) return; /* se eh para mudar para o mesmo, retorna */
	if (old_phy == 0) /* estava no modo assincrono */
	{
		ppp_shutdown(NULL);
	}
	else /* estava no modo sincrono */
	{
		long proto=wan_get_protocol(interface_major);

		interface_clear_bridgegroup();
		switch(proto)
		{
			case SCC_PROTO_MLPPP:
				ppp_shutdown(NULL);
				break;
#ifdef OPTION_X25
			case IF_PROTO_X25:
				interface_shutdown(NULL);
				x25_clean_all(interface_major);
				break;
#endif
			default:
				interface_shutdown(NULL);
				break;
		}
		/* alterar o protocolo para cisco hdlc, para permitir que
		   o modulo seja descarregado */
		wan_set_protocol(interface_major, IF_PROTO_CISCO);
	}
#if 0
	sleep(3);
#endif
	wan_set_physical(interface_major, new_phy);
	/* serial0 QoS */
	dev=convert_device(interface_edited->cish_string, interface_major, -1);
	clean_qos_cfg(dev); /* Limpa configuracao do QoS */
	free(dev);
	/* New command root */
	command_root=get_wan_cmd_root(wan_get_protocol(interface_major), new_phy, -1);
}

/*
    64000
   128000
   256000
   512000
  1024000
  2048000
  4096000
  4160000 4468352
  4224000 4468352
  4288000 4468352
  4352000 4468352
  4416000 4468352
  4480000 4915200
  4544000
  4608000
  4672000
  4736000
  4800000
  4864000
  4928000
  4992000
  5056000
  8192000
*/
void serial_clock_rate(const char *cmdline)
{
	arglist *args;
	int new_rate, old_rate;
	char type, inv_tx;
	char *dev;
#ifndef CONFIG_BERLIN_SATROUTER
	int cabledetect, dte_ndce, v28_nv35, cablelogic;
#endif
	if (wan_get_physical(interface_major) == 0) return;

	args=make_args(cmdline);
	new_rate=atoi(args->argv[2]);
	destroy_args(args);

#ifndef CONFIG_BERLIN_SATROUTER
	wan_get_cable(interface_major, &cabledetect, &dte_ndce, &v28_nv35, &cablelogic);
	if (cabledetect && v28_nv35) {
		/* 1200, 2400, 4800, 9600, 19200, 38400 | 57600, 115200, 230400 */
		new_rate=(new_rate/1200)*1200; /* 1200 steps! */
	} else {
		new_rate=(new_rate/64000)*64000; /* 64K steps! */
	}
#else
	new_rate=(new_rate/64000)*64000;
#endif
	wan_get_clock(interface_major, &old_rate, &type, &inv_tx);
	wan_set_clock(interface_major, new_rate, type, inv_tx);

	/* serial0 QoS */
	dev=convert_device(interface_edited->cish_string, interface_major, -1);
	if (wan_get_protocol(interface_major) == IF_PROTO_FR)
	{
		int i;

		if (get_if_list() < 0) goto error;
		for (i=0; i < link_table_index; i++)
		{
			if (strncmp(link_table[i].ifname, dev, strlen(dev)) == 0 && link_table[i].type == ARPHRD_DLCI)
			{
				tc_insert_all(link_table[i].ifname);
			}
		}
	}
		else tc_insert_all(dev);
error:
	free(dev);
}

void serial_clock_rate_no(const char *cmdline)
{
	int rate;
	char type, inv_tx;

	if (wan_get_physical(interface_major) == 0) return;

	wan_get_clock(interface_major, &rate, &type, &inv_tx);
	wan_set_clock(interface_major, 0, type, inv_tx);
}

void serial_clock_type(const char *cmdline) /* clock type [external|internal|txint|txfromrx] */
{
	arglist *args;
	int rate;
	char type, inv_tx;

	if (wan_get_physical(interface_major) == 0) return;

	args=make_args(cmdline);
	wan_get_clock(interface_major, &rate, &type, &inv_tx);
	if (strcmp(args->argv[2], "external") == 0)
		wan_set_clock(interface_major, rate, CLOCK_EXT, inv_tx);
	else if (strcmp(args->argv[2], "internal") == 0)
		wan_set_clock(interface_major, rate, CLOCK_INT, inv_tx);
	else if (strcmp(args->argv[2], "txint") == 0)
		wan_set_clock(interface_major, rate, CLOCK_TXINT, inv_tx);
	else if (strcmp(args->argv[2], "txfromrx") == 0)
		wan_set_clock(interface_major, rate, CLOCK_TXFROMRX, inv_tx);
	destroy_args(args);
}

#ifndef CONFIG_BERLIN_SATROUTER
void serial_ignore(const char *cmdline) /* [no] ignore <cts|dcd> */
{
	arglist *args;
	int no=0, ignore;

	if (wan_get_physical(interface_major) == 0)
		return;

	args=make_args(cmdline);
	ignore=wan_get_ignore(interface_major);
	if (strcmp(args->argv[0], "no") == 0)
		no=1;
	if (strcmp(args->argv[no+1], "cts") == 0) {
		if (no) ignore &= ~UCC_IGNORE_CTS;
			else ignore |= UCC_IGNORE_CTS;
	} else if (strcmp(args->argv[no+1], "dcd") == 0) {
		if (no) ignore &= ~UCC_IGNORE_DCD;
			else ignore |= UCC_IGNORE_DCD;
	}
	wan_set_ignore(interface_major, ignore);
	destroy_args(args);
}
#endif

void serial_invert_tx_clock(const char *cmdline)
{
	int rate;
	char type, inv_tx;

	if (wan_get_physical(interface_major) == 0) return;

	wan_get_clock(interface_major, &rate, &type, &inv_tx);
	wan_set_clock(interface_major, rate, type, 1);
}

void serial_invert_tx_clock_no(const char *cmdline)
{
	int rate;
	char type, inv_tx;

	if (wan_get_physical(interface_major) == 0) return;

	wan_get_clock(interface_major, &rate, &type, &inv_tx);
	wan_set_clock(interface_major, rate, type, 0);
}

void serial_loopback(const char *cmdline) /* [no] loopback */
{
	sync_serial_settings sst;
	arglist *args;

	if (wan_get_physical(interface_major) == 0) return;

	args=make_args(cmdline);
	wan_get_sst(interface_major, &sst);
	if (args->argc == 2) sst.loopback=0;
		else sst.loopback=1;
	wan_set_sst(interface_major, &sst);
	destroy_args(args);
}

#ifdef CONFIG_DEVELOPMENT
void serial_hdlc_fse(const char *cmdline) /* [no] hdlc fse */
{
// 	sync_serial_settings sst;
// 	arglist *args;
// 
// 	if (wan_get_physical(interface_major) == 0)
// 		return;
// 	args=make_args(cmdline);
// 	wan_get_sst(interface_major, &sst);
// 	if (args->argc == 3) sst.fse = 0;
// 		else sst.fse = 1;
// 	wan_set_sst(interface_major, &sst);
// 	destroy_args(args);
}

void serial_hdlc_mff(const char *cmdline) /* [no] hdlc mff */
{
// 	sync_serial_settings sst;
// 	arglist *args;
// 
// 	if (wan_get_physical(interface_major) == 0)
// 		return;
// 	args=make_args(cmdline);
// 	wan_get_sst(interface_major, &sst);
// 	if (args->argc == 3) sst.mff = 0;
// 		else sst.mff= 1 ;
// 	wan_set_sst(interface_major, &sst);
// 	destroy_args(args);
}

void serial_hdlc_nof(const char *cmdline) /* hdlc nof <0-15> */
{
// 	sync_serial_settings sst;
// 	arglist *args;
// 
// 	if (wan_get_physical(interface_major) == 0)
// 		return;
// 	args=make_args(cmdline);
// 	wan_get_sst(interface_major, &sst);
// 	sst.nof=atoi(args->argv[2]);
// 	wan_set_sst(interface_major, &sst);
// 	destroy_args(args);
}

void serial_hdlc_rtsm(const char *cmdline) /* [no] hdlc rtsm */
{
// 	sync_serial_settings sst;
// 	arglist *args;
// 
// 	if (wan_get_physical(interface_major) == 0)
// 		return;
// 	args=make_args(cmdline);
// 	wan_get_sst(interface_major, &sst);
// 	if (args->argc == 3) sst.rtsm = 0;
// 		else sst.rtsm = 1;
// 	wan_set_sst(interface_major, &sst);
// 	destroy_args(args);
}
#endif

#ifdef OPTION_X25
void interface_x25_lapb_mode(const char *cmdline) /* lapb mode DCE|DTE [extended|standard] [MLP|SLP] */
{
	arglist *args;
	char dev[16];
	x25_proto x25;

	sprintf(dev, "%s%d", SERIALDEV, interface_major);
	if (dev_get_link(dev) > 0) {
		if (!_cish_booting) {
			printf("%% shutdown interface first\n");
			return;
		}
		dev_set_link_down(dev); /* ~UP */
	}
	args=make_args(cmdline);
	x25_get_config(interface_major, &x25);
	x25.lapb_mode = 0;
	if (args->argc >= 3 && strcmp(args->argv[2], "DCE") == 0)
		x25.lapb_mode |= LAPB_DCE;
	if (args->argc >= 4 && strcmp(args->argv[3], "extended") == 0) {
		x25.lapb_mode |= LAPB_EXTENDED;
		CMD_CONFIG_INTERFACE_SERIAL_LAPB_WINDOW[0].name="1-127";
		x25.lapb_window=127;
	} else {
		CMD_CONFIG_INTERFACE_SERIAL_LAPB_WINDOW[0].name="1-7";
		x25.lapb_window=7;
	}
	if (args->argc == 5 && strcmp(args->argv[4], "MLP") == 0)
		x25.lapb_mode |= LAPB_MLP;
	x25_set_config(interface_major, &x25);
	destroy_args(args);
}

void interface_x25_lapb_n2(const char *cmdline) /* lapb n2 <1-60> */
{
	arglist *args;
	char dev[16];
	x25_proto x25;

	sprintf(dev, "%s%d", SERIALDEV, interface_major);
	if (dev_get_link(dev) > 0) {
		if (!_cish_booting) {
			printf("%% shutdown interface first\n");
			return;
		}
		dev_set_link_down(dev); /* ~UP */
	}
	args=make_args(cmdline);
	x25_get_config(interface_major, &x25);
	x25.lapb_n2=atoi(args->argv[2]);
	x25_set_config(interface_major, &x25);
	destroy_args(args);
}

void interface_x25_lapb_t1(const char *cmdline) /* lapb t1 <1-180> */
{
	arglist *args;
	char dev[16];
	x25_proto x25;

	sprintf(dev, "%s%d", SERIALDEV, interface_major);
	if (dev_get_link(dev) > 0) {
		if (!_cish_booting) {
			printf("%% shutdown interface first\n");
			return;
		}
		dev_set_link_down(dev); /* ~UP */
	}
	args=make_args(cmdline);
	x25_get_config(interface_major, &x25);
	x25.lapb_t1=atoi(args->argv[2]);
	x25_set_config(interface_major, &x25);
	destroy_args(args);
}

void interface_x25_lapb_t2(const char *cmdline) /* lapb t2 <1-180> */
{
	arglist *args;
	char dev[16];
	x25_proto x25;

	sprintf(dev, "%s%d", SERIALDEV, interface_major);
	if (dev_get_link(dev) > 0) {
		if (!_cish_booting) {
			printf("%% shutdown interface first\n");
			return;
		}
		dev_set_link_down(dev); /* ~UP */
	}
	args=make_args(cmdline);
	x25_get_config(interface_major, &x25);
	x25.lapb_t2=atoi(args->argv[2]);
	x25_set_config(interface_major, &x25);
	destroy_args(args);
}

void interface_x25_lapb_window(const char *cmdline) /* lapb window <size> */
{
	arglist *args;
	char dev[16];
	x25_proto x25;

	sprintf(dev, "%s%d", SERIALDEV, interface_major);
	if (dev_get_link(dev) > 0) {
		if (!_cish_booting) {
			printf("%% shutdown interface first\n");
			return;
		}
		dev_set_link_down(dev); /* ~UP */
	}
	args=make_args(cmdline);
	x25_get_config(interface_major, &x25);
	x25.lapb_window=atoi(args->argv[2]);
	x25_set_config(interface_major, &x25);
	destroy_args(args);
}

void interface_x25_route_add(const char *cmdline)
{
	arglist *args;

	args=make_args(cmdline);
	x25_route(1, interface_major, args->argv[2]); /* x25 route <x121> */
	destroy_args(args);
}

void interface_x25_route_del(const char *cmdline)
{
	arglist *args;

	args=make_args(cmdline);
	x25_route(0, interface_major, args->argv[3]); /* no x25 route <x121> */
	destroy_args(args);
}

void interface_x25_svc_add(const char *cmdline)
{
	arglist *args;
	int val;

	args=make_args(cmdline);
	val=atoi(args->argv[2]); /* x25 svc <x> */
	x25_svc(1, interface_major, val);
	destroy_args(args);
}

void interface_x25_svc_del(const char *cmdline)
{
	arglist *args;
	int val;

	args=make_args(cmdline);
	val=atoi(args->argv[3]); /* no x25 svc <x> */
	x25_svc(0, interface_major, val);
	destroy_args(args);
}

void interface_subx25_ipaddr(const char *cmdline) /* ip address [local] [remote] [mask] */
{
	arglist *args;
	char *local, *remote, *dev, *mask;
	
	args=make_args(cmdline);
	local=args->argv[2];
	remote=args->argv[3];
	if (args->argc > 4) mask=args->argv[4];
		else mask=NULL;
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	ip_addr_flush(dev);
	ip_addr_add(dev, local, remote, mask ? mask : "255.255.255.255");
	destroy_args(args);
	free(dev);
}

void interface_subx25_address(const char *cmdline) /* [no] x25 address <x121> */
{
	arglist *args;
	struct rfc1356_config cfg;

	args=make_args(cmdline);
	rfc1356_get_config(interface_major, interface_minor, &cfg);
	if (!strcmp(args->argv[0], "no")) /* no x25 address */
	{
		memset(&cfg.local, 0, sizeof(struct x25_address));
	}
	else
	{
		strncpy(cfg.local.x25_addr, args->argv[2], sizeof(struct x25_address));
	}
	rfc1356_set_config(interface_major, interface_minor, &cfg);
	destroy_args(args);
}

/* 16 32 64 128 256 512 1024 2048 4096 */
void interface_subx25_ips(const char *cmdline) /* x25 ips <size> */
{
	arglist *args;
	struct rfc1356_config cfg;
	int ips, i;

	args=make_args(cmdline);
	ips=atoi(args->argv[2]);
	for (i=1; 1<<i != ips && i < 13; i++);
	if (i == 13) {
		printf("%% invalid packet size!\n");
		return;
	}
	rfc1356_get_config(interface_major, interface_minor, &cfg);
	cfg.facilities.pacsize_in = i; /* 4-12 */
	rfc1356_set_config(interface_major, interface_minor, &cfg);
	destroy_args(args);
}

void interface_subx25_map_ip(const char *cmdline) /* [no] x25 map ip */
{
	arglist *args;
	struct rfc1356_config cfg;

	args=make_args(cmdline);
	rfc1356_get_config(interface_major, interface_minor, &cfg);
	if (!strcmp(args->argv[0], "no"))
	{
		memset(&cfg.remote, 0, sizeof(struct x25_address));
		cfg.ip_peer_addr[0]=0;
	}
	else
	{
		if (strcmp("passive", args->argv[4]) != 0)
		{
			strncpy(cfg.remote.x25_addr, args->argv[4], sizeof(struct x25_address)); /* x25 map ip <IP> <x121> */
			x25_route(1, interface_major, args->argv[4]); /* auto add remote x.121 address route */
		}
			else memset(&cfg.remote, 0, sizeof(struct x25_address));
		strncpy(cfg.ip_peer_addr, args->argv[3], 16); cfg.ip_peer_addr[15]=0;
	}
	rfc1356_set_config(interface_major, interface_minor, &cfg);
	destroy_args(args);
}

/* 16 32 64 128 256 512 1024 2048 4096 */
void interface_subx25_ops(const char *cmdline) /* x25 ops <size> */
{
	arglist *args;
	struct rfc1356_config cfg;
	int ops, i;

	args=make_args(cmdline);
	ops=atoi(args->argv[2]);
	for (i=1; 1<<i != ops && i < 13; i++);
	if (i == 13) {
		printf("%% invalid packet size!\n");
		return;
	}
	rfc1356_get_config(interface_major, interface_minor, &cfg);
	cfg.facilities.pacsize_out = i; /* 4-12 */
	rfc1356_set_config(interface_major, interface_minor, &cfg);
	destroy_args(args);
}

void interface_subx25_win(const char *cmdline) /* x25 win <size> */
{
	arglist *args;
	struct rfc1356_config cfg;

	args=make_args(cmdline);
	rfc1356_get_config(interface_major, interface_minor, &cfg);
	cfg.facilities.winsize_in = atoi(args->argv[2]); /* 1-7 */
	rfc1356_set_config(interface_major, interface_minor, &cfg);
	destroy_args(args);
}

void interface_subx25_wout(const char *cmdline) /* x25 wout <size> */
{
	arglist *args;
	struct rfc1356_config cfg;

	args=make_args(cmdline);
	rfc1356_get_config(interface_major, interface_minor, &cfg);
	cfg.facilities.winsize_out = atoi(args->argv[2]); /* 1-7 */
	rfc1356_set_config(interface_major, interface_minor, &cfg);
	destroy_args(args);
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

