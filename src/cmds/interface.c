#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>



#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_QOS
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
#endif /* OPTION_QOS */

#ifdef OPTION_ROUTER
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
#endif /* OPTION_ROUTER */

#ifdef OPTION_FIREWALL
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
#endif

#ifdef OPTION_QOS
cish_command CMD_CONFIG_INTERFACE_NO_MANGLE2[] = {
	{"in","inbound packets", NULL, interface_no_mangle, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_no_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_MANGLE[] = {
	{"<acl>","MARK rule name", CMD_CONFIG_INTERFACE_NO_MANGLE2, interface_no_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

#ifdef OPTION_NAT
cish_command CMD_CONFIG_INTERFACE_NO_NAT2[] = {
	{"in","inbound packets", NULL, interface_no_nat, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_no_nat, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_NAT[] = {
	{"<acl>","NAT rule name", CMD_CONFIG_INTERFACE_NO_NAT2, interface_no_nat, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

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


cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6_2[] = {
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", NULL, interface_ethernet_no_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6_2, interface_ethernet_no_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "Unset IPv6 address", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6_1, interface_ethernet_flush_ipaddr_v6, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM_NO, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
#endif
	{NULL,NULL,NULL,NULL, 0}
};


cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IP[] = {
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP1, interface_ethernet_no_ipaddr, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM_NO, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_ROUTER
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
#endif /* OPTION_ROUTER */

#ifdef OPTION_FIREWALL
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
#endif /* OPTION_FIREWALL */

#ifdef OPTION_QOS
cish_command CMD_CONFIG_INTERFACE_MANGLE2[] = {
	{"in","inbound packets", NULL, interface_mangle, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_MANGLE[] = {
	{"<acl>","MARK rule name", CMD_CONFIG_INTERFACE_MANGLE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif /* OPTION_QOS */

#ifdef OPTION_NAT
cish_command CMD_CONFIG_INTERFACE_NAT2[] = {
	{"in","inbound packets", NULL, interface_nat, 1, MSK_NORMAL},
	{"out","outbound packets", NULL, interface_nat, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NAT[] = {
	{"<acl>","NAT rule name", CMD_CONFIG_INTERFACE_NAT2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif /* OPTION_NAT */

cish_command CMD_CONFIG_INTERFACE_ETHERNET_MTU[] = {
#ifdef OPTION_GIGAETHERNET
	{"68-9000", "Max Transfer Unit", NULL, interface_mtu, 1, MSK_NORMAL},
#else
	{"68-1600", "Max Transfer Unit", NULL, interface_mtu, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_DESCRIPTION[] = {
	{"<text>", "Up to 240 characters describing this interface", NULL, interface_description, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

#ifdef CONFIG_DEVELOPMENT
cish_command CMD_CONFIG_INTERFACE_TXQUEUELEN[] = {
	{"10-4096", "Length of the transmit queue", NULL, interface_txqueue, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};
#endif

/* PPTP Interface */
#ifdef OPTION_PPTP
cish_command CMD_CONFIG_PPTP_SERVER[] = {
	{"<ipaddress>", "PPTP Server IP Address", NULL, pptp_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_PPTP_DOMAIN[] = {
	{"<text>", "Authentication Domain Name", NULL, pptp_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_PPTP_USERNAME[] = {
	{"<text>", "Username for PPTP Connection", NULL, pptp_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_PPTP_PASSWORD[] = {
	{"<text>", "Password for PPTP Connection", NULL, pptp_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPTP[] = {
	{"server", "Set server IP address", CMD_CONFIG_PPTP_SERVER, NULL, 1, MSK_NORMAL},
	{"domain", "Set authentication domain name", CMD_CONFIG_PPTP_DOMAIN, NULL, 1, MSK_NORMAL},
	{"username", "Set username", CMD_CONFIG_PPTP_USERNAME, NULL, 1, MSK_NORMAL},
	{"password", "Set password", CMD_CONFIG_PPTP_PASSWORD, NULL, 1, MSK_NORMAL},
	{"mppe", "Set support for MPPE encryption", NULL, pptp_set_mppe, 1, MSK_NORMAL},
	{"client-mode", "Enable PPTP Client Mode", NULL, pptp_set_clientmode, 1, MSK_NORMAL},
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
	{"no", "Reverse a setting",CMD_CONFIG_INTERFACE_PPTP_NO, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPTP_NO[] = {
	{"domain", "Remove authentication domain name", NULL, pptp_set_no_info, 1, MSK_NORMAL},
	{"mppe", "Remove support for MPPE encryption", NULL, pptp_set_mppe, 1, MSK_NORMAL},
	{"client-mode", "Disable PPTP Client Mode", NULL, pptp_set_clientmode, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif /* OPTION_PPTP */

/* PPPOE Interface */
#ifdef OPTION_PPPOE
cish_command CMD_CONFIG_PPPOE_SERVICE_NAME[] = {
	{"<text>", "Service Name - Most ISPs do not require this", NULL, pppoe_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_PPPOE_AC_NAME[] = {
	{"<text>", "Access Contractor Name - Most ISPs do not require this", NULL, pppoe_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_PPPOE_USERNAME[] = {
	{"<text>", "Username for PPPoE Connection", NULL, pppoe_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_PPPOE_PASSWORD[] = {
	{"<text>", "Password for PPPoE Connection", NULL, pppoe_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_PPPOE_NETWORK[] = {
	{"<text>", "Domain Network Name", NULL, pppoe_set_info, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPPOE[] = {
	{"service-name", "Set service name", CMD_CONFIG_PPPOE_SERVICE_NAME, NULL, 1, MSK_NORMAL},
	{"ac-name", "Set access contractor name", CMD_CONFIG_PPPOE_AC_NAME, NULL, 1, MSK_NORMAL},
	{"username", "Set username", CMD_CONFIG_PPPOE_USERNAME, NULL, 1, MSK_NORMAL},
	{"password", "Set password", CMD_CONFIG_PPPOE_PASSWORD, NULL, 1, MSK_NORMAL},
	{"network", "Set authentication domain network name", CMD_CONFIG_PPPOE_NETWORK, NULL, 1, MSK_NORMAL},
	{"client-mode", "Enable PPPoE Client Mode", NULL, pppoe_set_clientmode, 1, MSK_NORMAL},
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
	{"no", "Reverse a setting",CMD_CONFIG_INTERFACE_PPPOE_NO, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPPOE_NO[] = {
	{"service-name", "Remove service name", NULL, pppoe_set_no_info, 1, MSK_NORMAL},
	{"ac-name", "Remove access contractor name", NULL, pppoe_set_no_info, 1, MSK_NORMAL},
	{"network", "Remove authentication domain network name", NULL, pppoe_set_no_info, 1, MSK_NORMAL},
	{"client-mode", "Disable PPPoE Client Mode", NULL, pppoe_set_clientmode, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

#endif /* OPTION_PPPOE  */

/* 3G Interface */
#ifdef OPTION_MODEM3G

cish_command CMD_CONFIG_INTERFACE_M3G_NO_IP[] = {
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};


cish_command CMD_CONFIG_INTERFACE_M3G_IP[] = {
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
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

#ifdef OPTION_EFM
cish_command CMD_BACKUP_INTERFACE_EFM[] = {
	{CLI_STRING_EFM_IFACES, "EFM interface number", NULL, backup_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_BACKUP_INTERFACE_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", NULL, backup_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_DIGISTAR_3G
cish_command CMD_BACKUP_INTERFACE_M3G[] = {
	{"1-2", "3G interface number -| 1 == USB1 | 2 == USB2", NULL, backup_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_BACKUP_INTERFACE [] = {
	{"ethernet", "Ethernet interface", CMD_BACKUP_INTERFACE_ETHERNET, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BACKUP_INTERFACE_USB [] = {
#ifdef OPTION_EFM
	{"efm", "EFM interface", CMD_BACKUP_INTERFACE_EFM, NULL, 0, MSK_NORMAL},
#endif
	{"ethernet", "Ethernet interface", CMD_BACKUP_INTERFACE_ETHERNET, NULL, 0, MSK_NORMAL},
#ifdef CONFIG_DIGISTAR_3G
	{"m3G", "3G interface - USB", CMD_BACKUP_INTERFACE_M3G, NULL, 0, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BACKUP_METHOD_PING [] = {
	{"<ipaddress>", "Address to ping", NULL, backup_method_set_ping, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BACKUP_METHOD [] = {
	{"ping", "Test method based on ping a given address", CMD_BACKUP_METHOD_PING, NULL, 0, MSK_NORMAL},
	{"link", "Test method based on the status of the interface", NULL, backup_method_set_link, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_3G_DEFAULT_GW [] = {
	{"1-255", "Distance of this route", NULL, interface_modem3g_default_gateway, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_NO[] = {
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{"backup-interface", "Shutdown backup over a given interface", NULL, backup_interface_shutdown, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_M3G_NO_IP, NULL, 1, MSK_NORMAL},
	{"default-gateway", "Install default-gateway using this interface when connected", NULL, interface_modem3g_default_gateway, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_M3G_USB[] = {
	{"apn", "Access point name (address of ISP)", CMD_CONFIG_INTERFACE_M3G_USB_APN, NULL, 1, MSK_NORMAL},
	{"username", "Username for login on 3G connection through ISP", CMD_CONFIG_INTERFACE_M3G_USB_USER, NULL, 1, MSK_NORMAL},
	{"password", "Password for login on 3G connection through ISP", CMD_CONFIG_INTERFACE_M3G_USB_PASS, NULL, 1, MSK_NORMAL},
	{"backup-method", "Set test method for backup", CMD_BACKUP_METHOD, NULL, 1, MSK_NORMAL},
	{"backup-interface", "Allow backup over a given interface", CMD_BACKUP_INTERFACE_USB, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"default-gateway", "Install default-gateway using this interface when connected", CMD_3G_DEFAULT_GW, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_M3G_IP, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_M3G_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
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
	{"1-2", "SIM Card Number", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_CONF, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER_BACK[] = {
	{"1-2", "Set <backup> SIM card", NULL, interface_modem3g_sim_card_select, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER[] = {
	{"1-2", "Set <main> SIM card", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER_BACK, interface_modem3g_sim_card_select, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}

};

cish_command CMD_CONFIG_INTERFACE_M3G_BTIN[] = {
	{"sim", "Configure SIM Cards", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM, NULL, 1, MSK_NORMAL},
	{"sim-order", "Set order of SIM Cards for backup - <MAIN> <BACKUP>", CMD_CONFIG_INTERFACE_M3G_BTIN_SIM_ORDER, NULL, 1, MSK_NORMAL},
	{"backup-method", "Set test method for backup", CMD_BACKUP_METHOD, NULL, 1, MSK_NORMAL},
	{"backup-interface", "Allow backup over a given interface", CMD_BACKUP_INTERFACE, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"default-gateway", "Install default-gateway using this interface when connected", CMD_3G_DEFAULT_GW, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_M3G_IP, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_M3G_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
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
	{"0-15", "Assign an interface to a Bridge Group", NULL, interface_ethernet_no_bridgegroup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE[] = {
	{"0-15", "Assign an interface to a Bridge Group", NULL, interface_ethernet_bridgegroup, 1, MSK_NORMAL},
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
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_ETHERNET_IP1, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPV6_PREFIX[] = {
	{"eui-64", "Use eui-64 interface identifier", NULL, interface_ethernet_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPV6_2[] = {
	{"link-local", "Use link-local address", NULL, interface_ethernet_ipaddr_v6, 1, MSK_NORMAL},
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", CMD_CONFIG_INTERFACE_ETHERNET_IPV6_PREFIX, interface_ethernet_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_ETHERNET_IPV6_2, NULL, 1, MSK_NORMAL},
#ifdef NOT_IMPLEMENTED_YET
	{"dhcp", "IPv6 Address negotiated via DHCPv6", NULL, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "IPv6 Address", CMD_CONFIG_INTERFACE_ETHERNET_IPV6_1, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
#endif
	{NULL,NULL,NULL,NULL}
};


cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER[] = {
	{"2-4094", "VLAN number", NULL, vlan_add, 1, MSK_VLAN},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_VLAN_NUMBER[] = {
	{"2-4094", "VLAN number", NULL, vlan_del, 1, MSK_VLAN},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_LINKSTATUS_TRAP
cish_command CMD_CONFIG_INTERFACE_NO_SNMPTRAP2[] = {
	{"link-status", "Allow SNMP LINKUP and LINKDOWN traps", NULL, interface_no_snmptrap, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_NO_SNMPTRAP1[] = {
	{"trap", "Allow a specific SNMP trap", CMD_CONFIG_INTERFACE_NO_SNMPTRAP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};
#endif

/* ETHERNET 0 */
cish_command CMD_CONFIG_INTERFACE_ETHERNET_LAN_NO[] = {
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Unset IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6, NULL, 1, MSK_IPV6},
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_MANAGED_SWITCH
	{"switch-config", "Configure switch advanced settings general to all ports", CMD_CONFIG_INTERFACE_ETH_SW_GENERAL_NO, NULL, 1, MSK_MANAGED_SWITCH},
#endif
	{"vlan", "Delete vlan", CMD_CONFIG_INTERFACE_ETHERNET_NO_VLAN_NUMBER, NULL, 1, MSK_VLAN},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP, NULL, 1, MSK_VRRP},
#endif
	{NULL,NULL,NULL,NULL}
};

/* ETHERNET 1 */
cish_command CMD_CONFIG_INTERFACE_ETHERNET_WAN_NO[] = {
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Unset IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6, NULL, 1, MSK_IPV6},
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
	{"vlan", "Delete vlan", CMD_CONFIG_INTERFACE_ETHERNET_NO_VLAN_NUMBER, NULL, 1, MSK_VLAN},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP, NULL, 1, MSK_VRRP},
#endif
	{NULL,NULL,NULL,NULL}
};

#ifdef OPTION_LINKSTATUS_TRAP
cish_command CMD_CONFIG_INTERFACE_SNMPTRAP2[] = {
	{"link-status", "Allow SNMP LINKUP and LINKDOWN traps", NULL, interface_snmptrap, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_SNMPTRAP1[] = {
	{"trap", "Allow a specific SNMP trap", CMD_CONFIG_INTERFACE_SNMPTRAP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};
#endif

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
#ifdef OPTION_GIGAETHERNET
	{"1000", "Force 1000 Mbps operation", CMD_CONFIG_INTERFACE_ETHERNET_SPEED1, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL}
};

/* ETHERNET 0 */
cish_command CMD_CONFIG_INTERFACE_ETHERNET_LAN[] = {
#ifdef OPTION_QOS
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_IPV6, NULL, 1, MSK_IPV6},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_MANAGED_SWITCH
	{"switch-config", "Configure switch advanced settings general to all ports", CMD_CONFIG_INTERFACE_ETH_SW_GENERAL, NULL, 1, MSK_MANAGED_SWITCH},
	{"switch-port", "Configure switch advanced settings specific to an external port", CMD_CONFIG_INTERFACE_ETH_SW_PORT_, NULL, 1, MSK_MANAGED_SWITCH},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
//TODO
#ifdef NOT_YET_IMPLEMENTED
	{"speed", "Configure speed and related commands", CMD_CONFIG_INTERFACE_ETHERNET_SPEED, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_DEVELOPMENT
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"vlan", "Add vlan", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER, NULL, 1, MSK_VLAN},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP, NULL, 1, MSK_VRRP},
#endif

#ifdef CONFIG_PPC_BD_CONFIG
	{"rx-ring", "Configure RX ring size", CMD_CONFIG_INTERFACE_ETHERNET_RXRING, NULL, 1, MSK_NORMAL},
	{"tx-ring", "Configure TX ring size", CMD_CONFIG_INTERFACE_ETHERNET_TXRING, NULL, 1, MSK_NORMAL},
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_LAN_NO, NULL, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

/* ETHERNET 1 */
cish_command CMD_CONFIG_INTERFACE_ETHERNET_WAN[] = {
#ifdef OPTION_QOS
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_IPV6, NULL, 1, MSK_IPV6},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"speed", "Configure speed and related commands", CMD_CONFIG_INTERFACE_ETHERNET_SPEED, NULL, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_DEVELOPMENT
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"vlan", "Add vlan", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER, NULL, 1, MSK_VLAN},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP, NULL, 1, MSK_VRRP},
#endif
#ifdef CONFIG_PPC_BD_CONFIG
	{"rx-ring", "Configure RX ring size", CMD_CONFIG_INTERFACE_ETHERNET_RXRING, NULL, 1, MSK_NORMAL},
	{"tx-ring", "Configure TX ring size", CMD_CONFIG_INTERFACE_ETHERNET_TXRING, NULL, 1, MSK_NORMAL},
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_WAN_NO, NULL, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

/* EFM Interface */
#ifdef OPTION_EFM

cish_command CMD_CONFIG_INTERFACE_EFM_MODE3[] = {
	{"768-5696", "Maximum Line Rate in Kbps", NULL, interface_efm_set_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_EFM_MODE2[] = {
	{"192-3840", "Maximum Line Rate in Kbps", NULL, interface_efm_set_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_EFM_MODE1[] = {
	{"TCPAM-16", "16-TCPAM Line Modulation", CMD_CONFIG_INTERFACE_EFM_MODE2, NULL, 1, MSK_NORMAL},
	{"TCPAM-32", "32-TCPAM Line Modulation", CMD_CONFIG_INTERFACE_EFM_MODE3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_EFM_MODE[] = {
	{"co", "Central Office", CMD_CONFIG_INTERFACE_EFM_MODE1, NULL, 1, MSK_NORMAL},
	{"cpe", "Customer-premise Equipment", NULL, interface_efm_set_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_EFM_NO[] = {
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Unset IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6, NULL, 1, MSK_IPV6},
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
	{"vlan", "Delete vlan", CMD_CONFIG_INTERFACE_ETHERNET_NO_VLAN_NUMBER, NULL, 1, MSK_VLAN},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_NO_GROUP, NULL, 1, MSK_VRRP},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_EFM[] = {
#ifdef OPTION_QOS
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_IPV6, NULL, 1, MSK_IPV6},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
#endif
	{"mode", "Set SHDSL DSP as CO or CPE", CMD_CONFIG_INTERFACE_EFM_MODE, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_EFM_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_DEVELOPMENT
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
#ifdef CONFIG_PPC_BD_CONFIG
	{"rx-ring", "Configure RX ring size", CMD_CONFIG_INTERFACE_ETHERNET_RXRING, NULL, 1, MSK_NORMAL},
	{"tx-ring", "Configure TX ring size", CMD_CONFIG_INTERFACE_ETHERNET_TXRING, NULL, 1, MSK_NORMAL},
	{"weight", "Configure interface weight", CMD_CONFIG_INTERFACE_WEIGHT, NULL, 1, MSK_NORMAL},
#endif
	{"vlan", "Add vlan", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NUMBER, NULL, 1, MSK_VLAN},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP Interface configuration commands", CMD_CONFIG_INTERFACE_ETHERNET_VRRP_GROUP, NULL, 1, MSK_VRRP},
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
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP1, interface_no_ipaddr, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
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
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP1, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol",CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
	{NULL,NULL,NULL,NULL}
};


/*################################### VLAN IPV6 ###################################*/

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6_PREFIX[] = {
	{"eui-64", "Use eui-64 interface identifier", NULL, interface_ethernet_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6_2[] = {
	{"link-local", "Use link-local address", NULL, interface_ethernet_ipaddr_v6, 1, MSK_NORMAL},
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6_PREFIX, interface_ethernet_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6_2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "Set IPv6 Address", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6_1, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol",CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IPV6_2[] = {
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", NULL, interface_ethernet_no_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IPV6_2, interface_ethernet_no_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "Unset IPv6 address", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IPV6_1, interface_flush_ipaddr_v6, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM interface commands", CMD_CONFIG_INTERFACE_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
#endif
	{NULL,NULL,NULL,NULL, 0}
};
/*================================= VLAN IPV6 =================================*/


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
	{"ipv6", "Unset IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IPV6, NULL, 1, MSK_IPV6},
#ifdef CONFIG_VLAN_COS
	{"set", "Unset QoS values", CMD_CONFIG_VLAN_NO_COS, NULL, 0, MSK_NORMAL},
#endif
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_NO_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
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
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IPV6, NULL, 1, MSK_IPV6},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_DEVELOPMENT
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#endif
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

cish_command CMD_CONFIG_INTERFACE_EFM_VLAN[] = {
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Interface IP parameters", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_IPV6, NULL, 1, MSK_IPV6},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
#ifdef OPTION_LINKSTATUS_TRAP
	{"snmp", "Modify SNMP interface parameters", CMD_CONFIG_INTERFACE_SNMPTRAP1, NULL, 1, MSK_NORMAL},
#endif
#ifdef CONFIG_DEVELOPMENT
	{"txqueuelen", "Length of the transmit queue", CMD_CONFIG_INTERFACE_TXQUEUELEN, NULL, 1, MSK_NORMAL},
#endif
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

/* Loopback Interface */

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

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IPV6_2[] = {
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", NULL, interface_no_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IPV6_2, interface_no_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP[] = {
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP1, interface_no_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "Unset IPv6 address", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IPV6_1, interface_flush_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP3[] = {
	{"secondary", "Make this IP address a secondary address", NULL, interface_ipaddr_secondary, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP2[] = {
	{"<netmask>", "IP Netmask", NULL, interface_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IPV6_PREFIX[] = {
	{"eui-64", "Use eui-64 interface identifier", NULL, interface_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IPV6_2[] = {
	{"link-local", "Use link-local address", NULL, interface_ipaddr_v6, 1, MSK_NORMAL},
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", CMD_CONFIG_INTERFACE_LOOPBACK_IPV6_PREFIX, interface_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_LOOPBACK_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_LOOPBACK_IPV6_2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IP[] = {
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_LOOPBACK_IP1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "Unset IPv6 Address", CMD_CONFIG_INTERFACE_LOOPBACK_IPV6_1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};



cish_command CMD_CONFIG_INTERFACE_LOOPBACK_NO[] = {
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Unset IPv6 parameters", CMD_CONFIG_INTERFACE_LOOPBACK_NO_IPV6, NULL, 1, MSK_IPV6},
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK[] = {
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_LOOPBACK_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_LOOPBACK_IPV6, NULL, 1, MSK_IPV6},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_LOOPBACK_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

/********************/
/* Tunnel Interface */
/********************/
#ifdef OPTION_TUNNEL
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
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_TUNNEL_NO_IP1, interface_no_ipaddr, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IPV6_2[] = {
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", NULL, interface_no_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_TUNNEL_NO_IPV6_2, interface_no_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "Unset IPv6 address", CMD_CONFIG_INTERFACE_TUNNEL_NO_IPV6_1, interface_flush_ipaddr_v6, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF_NO, NULL, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP_NO, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
#endif
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
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_TUNNEL_IP1, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
	{NULL,NULL,NULL,NULL}
};


cish_command CMD_CONFIG_INTERFACE_TUNNEL_IPV6_PREFIX[] = {
	{"eui-64", "Use eui-64 interface identifier", NULL, interface_ipaddr_v6, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IPV6_2[] = {
	{"link-local", "Use link-local address", NULL, interface_ipaddr_v6, 1, MSK_NORMAL},
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", CMD_CONFIG_INTERFACE_TUNNEL_IPV6_PREFIX, interface_ipaddr_v6, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IPV6_6TO4_MASKV6[] = {
	{"<netmask_v6>", "IPv6 Netmask - <0-128>", NULL, tunnel_ipv6_6to4_addr_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IPV6_6TO4[] = {
	{"<ipaddress>", "IPv4 Address Target", CMD_CONFIG_INTERFACE_TUNNEL_IPV6_6TO4_MASKV6, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IPV6_1[] = {
	{"<ipv6address>", "IPv6 Address - { X:X:X:X::X }", CMD_CONFIG_INTERFACE_TUNNEL_IPV6_2, NULL, 1, MSK_NORMAL},
	{"6to4", "IPv6 Address for 6to4 Tunneling mode", CMD_CONFIG_INTERFACE_TUNNEL_IPV6_6TO4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_IPV6[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "IPv6 Address", CMD_CONFIG_INTERFACE_TUNNEL_IPV6_1, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"ospf", "OSPF protocol", CMD_CONFIG_INTERFACE_IP_OSPF, NULL, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol", CMD_CONFIG_INTERFACE_IP_RIP, NULL, 1, MSK_RIP},
	{"split-horizon", "Perform split horizon", NULL, rip_execute_interface_cmd, 1, MSK_RIP},
#endif
#endif
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

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_MODE_IPV6IP[] = {
	{"6to4", "IPv6 automatic tunnelling using 6to4", NULL, tunnel_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_MODE[] = {
	{"gre", "Generic route encapsulation protocol", NULL, tunnel_mode, 1, MSK_NORMAL},
	{"ipip", "IP over IP encapsulation", NULL, tunnel_mode, 1, MSK_NORMAL},
	{"ipv6ip", "IPv6 over IP encapsulation (sit mode)", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_MODE_IPV6IP, NULL, 1, MSK_IPV6},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_AUX_RS232_INTERFACE
cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_AUX[] = {
	{"0-1", "Aux interface number", NULL, tunnel_source_interface, 1, MSK_AUX},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_LOOPBACK[] = {
	{"0-0", "Loopback interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_SERIAL
cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_SERIAL[] = {
	{"0-0", "Serial interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_TUNNEL[] = {
	{"0-0", "Tunnel interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_MODEM3G
cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_M3G[] = {
	{"0-2", "Modem 3G interface number", NULL, tunnel_source_interface, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC[] = {
#ifdef OPTION_AUX_RS232_INTERFACE
	{"aux", "Aux interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_AUX, NULL, 1, MSK_AUX},
#endif
#ifdef OPTION_ETHERNET_WAN
	{"ethernet", "Ethernet interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET, NULL, 1, MSK_NORMAL},
#endif
	{"loopback", "Loopback interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_LOOPBACK, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_MODEM3G
	{"m3G", "Modem 3G interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_M3G, NULL, 1, MSK_NORMAL},
#endif
#endif
#ifdef OPTION_SERIAL
	{"serial", "Serial interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_SERIAL, NULL, 1, MSK_NORMAL},
#endif
#ifdef NOT_YET_IMPLEMENTED
	{"tunnel", "Tunnel interface", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_TUNNEL, NULL, 1, MSK_NORMAL},
#endif
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
	{"destination", "Destination of tunnel", CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_DST, NULL, 1, MSK_TUNNEL_DEST},
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
	{"destination", "Destination of tunnel", NULL, tunnel_destination, 1, MSK_TUNNEL_DEST},
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
	{"ipv6", "Unset IPv6 parameters", CMD_CONFIG_INTERFACE_TUNNEL_NO_IPV6, NULL, 1, MSK_IPV6},
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
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_TUNNEL_IPV6, NULL, 1, MSK_IPV6},
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
#endif /* OPTION_TUNNEL */



/********************/
/* WLAN Interface */
/********************/
#ifdef OPTION_WIFI

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_NO[] = {
	{"security-mode", "Disable Wifi Security ", NULL, apmanager_security_mode_set, 1, MSK_NORMAL},
	{"ssid-broadcast", "Disable SSID Brodcast", NULL, apmanager_ssid_broadcast_set, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
	{"wmm","Disable WMM Function", NULL, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_HEX[] = {
	{"<hexstring>", "Set Key in HEX digits - (64Bit - 10 Digits / 128Bit - 26 Digits)", NULL, apmanager_security_mode_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_ASCII[] = {
	{"<text>", "Set Key in ASCII digits - (64Bit - 5 Characters / 128Bit - 13 Characters)", NULL, apmanager_security_mode_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_HEX_ENCRYPT[] = {
	{"64Bit", "Set 64Bit WEP Encryption", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_HEX, NULL, 1, MSK_NORMAL},
	{"128Bit", "Set 128Bit WEP Encryption", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_HEX, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_ASCII_ENCRYPT[] = {
	{"64Bit", "Set 64Bit WEP Encryption", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_ASCII, NULL, 1, MSK_NORMAL},
	{"128Bit", "Set 128Bit WEP Encryption", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_ASCII, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_TYPE[] = {
	{"hex", "Set WEP Encryption Key in HEX digits", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_HEX_ENCRYPT, NULL, 1, MSK_NORMAL},
	{"ascii", "Set WEP Encryption Key in ASCII digits", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_STRING_ASCII_ENCRYPT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_AUTH[] = {
	{"open", "Set Open WEP Authentication Type", NULL, apmanager_security_mode_set, 1, MSK_NORMAL},
	{"shared", "Set Shared Key WEP Authentication Type", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_KEY_TYPE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP_PSK_KEY[] = {
	{"<hexstring>", "HEX Digits Key - (64 HEX Digits)", NULL, apmanager_security_mode_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP_PHRASE_KEY[] = {
	{"<text>", "ASCII Phrase Key - (8~63 Characters)", NULL, apmanager_security_mode_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP[] = {
	{"psk", "Set WPA PSK Key Type", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP_PSK_KEY, NULL, 1, MSK_NORMAL},
	{"phrase", "Set WPA Phrase Key Type", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP_PHRASE_KEY, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE[] = {
	{"wep", "Enable WEP Wireless Security", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WEP_AUTH, NULL, 1, MSK_NORMAL},
	{"wpa", "Enable WPA Wireless Security", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP, NULL, 1, MSK_NORMAL},
	{"wpa2", "Enable WPA2 Wireless Security", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP, NULL, 1, MSK_NORMAL},
	{"wpa/wpa2", "Enable WPA/WPA2 Wireless Security", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE_WAP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SSID_SET[] = {
	{"<text>", "SSID Name - (8~63 Characters)", NULL, apmanager_ssid_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_CHANNEL_SET[] = {
	{"1-13", "Wifi Channel - (Range: 1~13)", NULL, apmanager_channel_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_HW_MODE_SET[] = {
#ifdef NOT_YET_IMPLEMENTED
	{"a", "802.11a Mode", NULL, apmanager_hw_mode_set, 1, MSK_NORMAL},
#endif
	{"b", "802.11b Mode", NULL, apmanager_hw_mode_set, 1, MSK_NORMAL},
	{"g", "802.11g Mode", NULL, apmanager_hw_mode_set, 1, MSK_NORMAL},
	{"n", "802.11n Mode", NULL, apmanager_hw_mode_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_MAX_NUM_STA_SET[] = {
	{"1-1500", "Number of Connected Station through WIFI - (Range: 1~1500, Default:255)", NULL, apmanager_max_num_station_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_BEACON_INTR_SET[] = {
	{"20-1000", "Beacon Interval Value - (msec, Range:20~1000, Default:100)", NULL, apmanager_beacon_interval_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_RTS_THRESHOLD_SET[] = {
	{"256-2347", "RTS Threshold Value - (Range: 256~2347, Default:2347)", NULL, apmanager_rts_threshold_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_FRAGM_THRESHOLD_SET[] = {
	{"1500-2346", "Fragmentation Threshold Value - (Range: 1500~2346, Default:2346)", NULL, apmanager_fragmentation_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_DTIM_INTR_SET[] = {
	{"1-255", "DTIM Interval Value - (Range: 1~255, Default:1)", NULL, apmanager_dtim_interval_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER_PREAMBLE_TYPE_SET[] = {
	{"long", "Long Preamble Type - (Default)", NULL, apmanager_preamble_type_set, 1, MSK_NORMAL},
	{"short", "Short Preamble Type", NULL, apmanager_preamble_type_set, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_APMANAGER[] = {
	{"ssid", "Set SSID - Wireless Network Name", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SSID_SET, NULL, 1, MSK_NORMAL},
	{"ssid-broadcast", "Enable SSID Brodcast", NULL, apmanager_ssid_broadcast_set, 1, MSK_NORMAL},
	{"channel", "Set Wireless Channel", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_CHANNEL_SET, NULL, 1, MSK_NORMAL},
	{"hw-mode", "Set Wireless Mode", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_HW_MODE_SET, NULL, 1, MSK_NORMAL},
	{"max-num-station", "Set Maximum Number of Stations Connected", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_MAX_NUM_STA_SET, NULL, 1, MSK_NORMAL},
	{"beacon-interval", "Set Beacon Interval", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_BEACON_INTR_SET, NULL, 1, MSK_NORMAL},
	{"rts-threshold", "Set RTS Threshold", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_RTS_THRESHOLD_SET, NULL, 1, MSK_NORMAL},
	{"fragmentation", "Set Fragmentation Threshold", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_FRAGM_THRESHOLD_SET, NULL, 1, MSK_NORMAL},
	{"dtim-interval", "Set DTIM Interval", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_DTIM_INTR_SET, NULL, 1, MSK_NORMAL},
	{"preamble-type","Set Preamble Type", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_PREAMBLE_TYPE_SET, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
	{"wmm","Enable WMM Function", NULL, NULL, 1, MSK_NORMAL},
#endif
	{"security-mode", "Configure Security Mode Parameters", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_SECURITY_MODE, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_WLAN_APMANAGER_NO, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from Access Point configuration mode", NULL, config_interface_wlan_ap_manager_done, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_IP1[] = {
	{"<ipaddress>", "IP Address", CMD_CONFIG_INTERFACE_ETHERNET_IP2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_IP[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "IP Address and Netmask", CMD_CONFIG_INTERFACE_WLAN_IP1, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_MANGLE, NULL, 1, MSK_QOS},
#endif
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NAT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_NO_IP[] = {
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_FIREWALL
	{"access-group", "Specify access control for packets", CMD_CONFIG_INTERFACE_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
#endif
	{"address", "Unset local address", CMD_CONFIG_INTERFACE_ETHERNET_NO_IP1, interface_ethernet_no_ipaddr, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_QOS
	{"mark", "Specify MARK rule for packets", CMD_CONFIG_INTERFACE_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#endif
#ifdef OPTION_NAT
	{"nat", "Specify NAT rule for packets", CMD_CONFIG_INTERFACE_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_WLAN_NO[] = {
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
#ifdef NOT_YET_IMPLEMENTED
	{"description", "Interface specific description", NULL, interface_no_description, 1, MSK_NORMAL},
#endif
	{"ip", "Unset IP parameters", CMD_CONFIG_INTERFACE_WLAN_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Unset IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_NO_IPV6, NULL, 1, MSK_IPV6},
#ifdef OPTION_QOS
	{"service-policy", "Configure QoS Service Policy", NULL, no_service_policy, 1, MSK_QOS},
#endif
	{"shutdown", "Bring the interface up", NULL, interface_no_shutdown, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_WLAN[] = {
	{"ap-manager", "Access Point configuration mode", NULL, config_interface_wlan_ap_manager, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"bandwidth", "Set bandwidth informational parameter", CMD_CONFIG_INTERFACE_BW, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_BRIDGE
	{"bridge-group", "Transparent bridging interface parameters", CMD_CONFIG_INTERFACE_ETHERNET_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
#ifdef NOT_YET_IMPLEMENTED
	{"description", "Interface specific description", CMD_CONFIG_INTERFACE_DESCRIPTION, NULL, 1, MSK_NORMAL},
#endif
	{"ip", "Set IP parameters", CMD_CONFIG_INTERFACE_WLAN_IP, NULL, 1, MSK_NORMAL},
	{"ipv6", "Set IPv6 parameters", CMD_CONFIG_INTERFACE_ETHERNET_IPV6, NULL, 1, MSK_IPV6},
	{"mtu", "Set interface mtu", CMD_CONFIG_INTERFACE_ETHERNET_MTU, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"max-reserved-bandwidth","Maximum Reservable Bandwidth on an Interface", CMD_CONFIG_INTERFACE_MAXBW, NULL, 1, MSK_QOS},
	{"service-policy", "Configure QoS Service Policy", CMD_CONFIG_SERV_POLICY, NULL, 1, MSK_QOS},
#endif
	{"shutdown", "Shutdown interface", NULL, interface_shutdown, 1, MSK_NORMAL},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_WLAN_NO, NULL, 1, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_done, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

#endif
