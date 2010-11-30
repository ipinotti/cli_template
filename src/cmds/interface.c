#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"


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

cish_command CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_METR[] = {
	{"1-5000", "Smaller is better", NULL, pim_sparse_mode_intf, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_2[] = {
	{"metric", "Set interface's value in an election", CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_METR, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_PREF[] = {
	{"1-5000", "Smaller is better", CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_1[] = {
	{"preference", "Set interface's value in an election", CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_PREF, NULL, 1, MSK_NORMAL},
	{"<enter>", "Default configuration for Preference and Metric ", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_IP_PIM[] = {
#ifdef OPTION_PIMD_DENSE
	{"dense-mode", "Enable PIM dense-mode operation", NULL, pim_dense_mode, 1, MSK_NORMAL},
#endif
	{"sparse-mode", "Enable PIM sparse-mode operation", CMD_CONFIG_INTERFACE_IP_PIM_CONFIG_1, pim_sparse_mode_intf, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_IP_PIM_NO[] = {
#ifdef OPTION_PIMD_DENSE
	{"dense-mode", "Enable PIM dense-mode operation", NULL, pim_dense_mode, 1, MSK_NORMAL},
#endif
	{"sparse-mode", "Enable PIM sparse-mode operation", NULL, pim_sparse_mode_intf, 1, MSK_NORMAL},
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
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM_NO, NULL, 1, MSK_NORMAL},
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
#ifdef OPTION_GIGAETHERNET
	{"68-9000", "Max Transfer Unit", NULL, interface_mtu, 1, MSK_NORMAL},
#else
	{"68-1500", "Max Transfer Unit", NULL, interface_mtu, 1, MSK_NORMAL},
#endif
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

/* 3G Interface */
#ifdef OPTION_MODEM3G

cish_command CMD_CONFIG_INTERFACE_M3G_NO_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};


cish_command CMD_CONFIG_INTERFACE_M3G_IP[] = {
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};


cish_command CMD_CONFIG_INTERFACE_M3G_USB_PASS_SET[] = {
	{"<text>", "Password for login on ISP", NULL, interface_modem3g_set_password, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_USB_PASS[] = {
	{"set", "Set access point name (address of ISP)", CMD_CONFIG_INTERFACE_M3G_USB_PASS_SET, NULL, 1, MSK_NORMAL},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show password of ISP (address of ISP)", NULL, show_modem3g_password, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_USB_USER_SET[] = {
	{"<text>", "Username for login on ISP", NULL, interface_modem3g_set_username, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_USB_USER[] = {
	{"set", "Set username for login on ISP", CMD_CONFIG_INTERFACE_M3G_USB_USER_SET, NULL, 1, MSK_NORMAL},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show username of login on ISP", NULL, show_modem3g_username, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_USB_APN_SET[] = {
	{"<text>", "APN(address of ISP)", NULL, interface_modem3g_set_apn, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_USB_APN[] = {
	{"set", "Set access point name (address of ISP)", CMD_CONFIG_INTERFACE_M3G_USB_APN_SET, NULL, 1, MSK_NORMAL},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show acess point name (address of ISP)", NULL, show_modem3g_apn, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_BACKUP_INTERFACE_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, backup_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BACKUP_INTERFACE [] = {
	{"ethernet", "Ethernet interface", CMD_BACKUP_INTERFACE_ETHERNET, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BACKUP_METHOD_PING [] = {
	{"<text>", "Address to ping", NULL, backup_method_set_ping, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BACKUP_METHOD [] = {
	{"ping", "Test method based on ping a given address", CMD_BACKUP_METHOD_PING, NULL, 0, MSK_NORMAL},
	{"link", "Test method based on the status of the interface", NULL, backup_method_set_link, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_NO[] = {
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"backup-interface", "Shutdown backup over a given interface", NULL, backup_interface_shutdown, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_M3G_NO_IP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_M3G_USB[] = {
	{"apn", "Access point name (address of ISP)", CMD_CONFIG_INTERFACE_M3G_USB_APN, NULL, 1, MSK_NORMAL},
	{"username", "Username for login on 3G connection through ISP", CMD_CONFIG_INTERFACE_M3G_USB_USER, NULL, 1, MSK_NORMAL},
	{"password", "Password for login on 3G connection through ISP", CMD_CONFIG_INTERFACE_M3G_USB_PASS, NULL, 1, MSK_NORMAL},
	{"backup-method", "Set test method for backup", CMD_BACKUP_METHOD, NULL, 1, MSK_NORMAL},
	{"backup-interface", "Allow backup over a given interface", CMD_BACKUP_INTERFACE, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_M3G_IP, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_M3G_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_APN_SET[] = {
	{"<text>", "APN(address of ISP)", NULL, interface_modem3g_btin_set_info, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_APN[] = {
	{"set", "Set access point name (address of ISP)", CMD_CONFIG_INTERFACE_M3G_BTIN_APN_SET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_USER_SET[] = {
	{"<text>", "Username for login on ISP", NULL, interface_modem3g_btin_set_info, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_USER[] = {
	{"set", "Set username for login on ISP", CMD_CONFIG_INTERFACE_M3G_BTIN_USER_SET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_PASS_SET[] = {
	{"<text>", "Password for login on ISP", NULL, interface_modem3g_btin_set_info, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_PASS[] = {
	{"set", "Set access point name (address of ISP)", CMD_CONFIG_INTERFACE_M3G_BTIN_PASS_SET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_CONF[] = {
	{"apn", "Access point name (address of ISP)", CMD_CONFIG_INTERFACE_M3G_BTIN_APN, NULL, 1, MSK_NORMAL},
	{"username", "Username for login on 3G connection through ISP", CMD_CONFIG_INTERFACE_M3G_BTIN_USER, NULL, 1, MSK_NORMAL},
	{"password", "Password for login on 3G connection through ISP", CMD_CONFIG_INTERFACE_M3G_BTIN_PASS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_SIM[] = {
	{"0-1", "SIM Card Number", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_CONF, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER_BACK[] = {
	{"0-1", "Set <backup> SIM card", NULL, interface_modem3g_sim_card_select, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER[] = {
	{"0-1", "Set <main> SIM card", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER_BACK, interface_modem3g_sim_card_select, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}

};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN[] = {
	{"sim", "Configure SIM Cards", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM, NULL, 1, MSK_NORMAL},
	{"sim-order", "Set order of SIM Cards for backup - <MAIN> <BACKUP>", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER, NULL, 1, MSK_NORMAL},
	{"backup-method", "Set test method for backup", CMD_BACKUP_METHOD, NULL, 1, MSK_NORMAL},
	{"backup-interface", "Allow backup over a given interface", CMD_BACKUP_INTERFACE, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_M3G_IP, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_M3G_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

#endif

/***********************/
/* Ethernet Interfaces */
/***********************/
cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_ethernet_no_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE[] = {
	{"1-1", "Assign an interface to a Bridge Group", NULL, interface_ethernet_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

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
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
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

#if 0 //#ifdef CONFIG_DEVELOPMENT
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

#ifdef OPTION_MANAGED_SWITCH
cish_command CMD_CONFIG_INTERFACE_ETHERNET_RATE_LIMIT[] = {
	{"32-65535", "Maximum RX rate in Kbps", NULL, interface_rate_limit, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_TRAFFIC_SHAPE[] = {
	{"32-65535", "Maximum TX rate in Kbps", NULL, interface_traffic_shape, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_DEFAULT_VID[] = {
	{"1-4095", "802.1q VID", NULL, interface_vlan_default, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};


cish_command CMD_CONFIG_INTERFACE_ETHERNET_SW_PORT[] = {
	{"exit", "Exit from interface configuration mode", NULL, config_interface_switch_port_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"rate-limit", "Storm control configuration", CMD_CONFIG_INTERFACE_ETHERNET_RATE_LIMIT, NULL, 1, MSK_MANAGED_SWITCH},
	//{"storm-control", "Storm control configuration", CMD_CONFIG_INTERFACE_ETHERNET_STORM, NULL, 1, MSK_MANAGED_SWITCH},
	{"traffic-shape", "Storm control configuration", CMD_CONFIG_INTERFACE_ETHERNET_TRAFFIC_SHAPE, NULL, 1, MSK_MANAGED_SWITCH},
	{"vlan-default", "Mark non-tagged packets with VLAN tag", CMD_CONFIG_INTERFACE_ETHERNET_DEFAULT_VID, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETH_SW_PORT_[] = {
	{"0-1", "External switch port", NULL, config_interface_switch_port, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

#endif
cish_command CMD_CONFIG_INTERFACE_ETHERNET[] = {
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_IP, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_MANAGED_SWITCH
	{"switch-port", "Configure advanced settings for an external switch port", CMD_CONFIG_INTERFACE_ETH_SW_PORT_, NULL, 1, MSK_MANAGED_SWITCH},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"speed", "Configure speed and related commands", CMD_CONFIG_INTERFACE_ETHERNET_SPEED, NULL, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"vlan", "Add vlan", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER, NULL, 1, MSK_QOS},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP, NULL, 1, MSK_VRRP},
#endif

#ifdef CONFIG_PPC_BD_CONFIG
	{"rx-ring", "Configure RX ring size", CMD_CONFIG_INTERFACE_ETHERNET_RXRING, NULL, 1, MSK_NORMAL},
	{"tx-ring", "Configure TX ring size", CMD_CONFIG_INTERFACE_ETHERNET_TXRING, NULL, 1, MSK_NORMAL},
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL}
};

/* EFM Interface */
#ifdef OPTION_EFM
cish_command CMD_CONFIG_INTERFACE_EFM_MODE[] = {
	{"co", "Central Office", NULL, interface_efm_set_mode, 1, MSK_NORMAL},
	{"cpe", "Customer-premise Equipment", NULL, interface_efm_set_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO[] = {
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP, NULL, 1, MSK_NORMAL},
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"vlan", "Delete vlan", CMD_CONFIG_INTERFACE_ETHERNET_NO_VLAN_NUMBER, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_EFM[] = {
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_IP, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
	{"mode", "Set SHDSL DSP as CO or CPE", CMD_CONFIG_INTERFACE_EFM_MODE, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"vlan", "Add vlan", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER, NULL, 1, MSK_QOS},
#ifdef CONFIG_PPC_BD_CONFIG
	{"rx-ring", "Configure RX ring size", CMD_CONFIG_INTERFACE_ETHERNET_RXRING, NULL, 1, MSK_NORMAL},
	{"tx-ring", "Configure TX ring size", CMD_CONFIG_INTERFACE_ETHERNET_TXRING, NULL, 1, MSK_NORMAL},
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL}
};
#endif /* OPTION_EFM */


/* VLAN Interface */

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
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
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
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
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
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
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
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

/* Tunnel Interface */

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
	{"1-1", "Ethernet interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_LOOPBACK[] = {
	{"0-0", "Loopback interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
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

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_M3G[] = {
	{"0-2", "Modem 3G interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC[] = {
	{"aux", "Aux interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_AUX, NULL, 1, MSK_AUX},
#ifdef OPTION_ETHERNET_WAN
	{"ethernet", "Ethernet interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET, NULL, 1, MSK_NORMAL},
#endif
	{"loopback", "Loopback interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_LOOPBACK, NULL, 1, MSK_NORMAL},
#ifdef OPTION_MODEM3G
	{"m3G", "Modem 3G interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_M3G, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_SERIAL
	{"serial", "Serial interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_SERIAL, NULL, 1, MSK_NORMAL},
#endif
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
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"tunnel", "Protocol-over-protocol tunneling", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};
