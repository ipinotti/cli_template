/*
 * switch.c
 *
 *  Created on: Dec 6, 2010
 *      Author: Thomás Alimena Del Grande (tgrande@pd3.com.br)
 */
#include <librouter/options.h>

#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_MANAGED_SWITCH

/***************************************************/
/* VLAN table commands */

#if defined(OPTION_SWITCH_MICREL)

#if 0
cish_command CMD_CONFIG_SW_VLAN_ENTRY6[] = {
	{"port-1", "Add port 1 to this VLAN", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"<enter>", "", NULL, NULL, 0, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY5[] = {
	{"port-2", "Add port 2 to this VLAN", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"<enter>", "", NULL, NULL, 0, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY4[] = {
	{"internal", "Add internal port to this VLAN", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"<enter>", "", NULL, NULL, 0, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY3[] = {
	{"port-1", "Add port 1 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY5, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"port-2", "Add port 2 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY6, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY2[] = {
	{"port-1", "Add port 1 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY4, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"internal", "Add internal port to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY6, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY1[] = {
	{"port-2", "Add port 2 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY4, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"internal", "Add internal port to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY5, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};
#endif


cish_command CMD_CONFIG_SW_VLAN_ENTRY0[] = {
	{"port-1", "Add port 1 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY0, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"port-2", "Add port 2 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY0, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
#if OPTION_SWITCH_PORT_NUM == 4
	{"port-3", "Add port 3 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY0, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"port-4", "Add port 4 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY0, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
#endif
	{"internal", "Add internal port to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY0, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

#elif defined(OPTION_SWITCH_BROADCOM)

cish_command CMD_CONFIG_SW_VLAN_ENTRY4[] = {
	{"p4", "Add port 4 to this VLAN", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"0", "Ignore port 4 to this VLAN", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY3[] = {
	{"p3", "Add port 3 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY4, NULL, 1, MSK_MANAGED_SWITCH},
	{"0", "Ignore port 3 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY4, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY2[] = {
	{"p2", "Add port 2 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY3, NULL, 1, MSK_MANAGED_SWITCH},
	{"0", "Ignore port 2 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY3, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY1[] = {
	{"p1", "Add port 1 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY2, NULL, 1, MSK_MANAGED_SWITCH},
	{"0", "Ignore port 1 to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY2, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY0[] = {
	{"pI", "Add internal port to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY1, NULL, 1, MSK_MANAGED_SWITCH},
	{"0", "Ignore internal port to this VLAN", CMD_CONFIG_SW_VLAN_ENTRY1, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

#endif

cish_command CMD_CONFIG_SW_VLAN_ENTRY[] = {
#if defined(OPTION_SWITCH_MICREL)
	{"1-4095", "802.1q VID", CMD_CONFIG_SW_VLAN_ENTRY0, NULL, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"0-4094", "802.1q VID", CMD_CONFIG_SW_VLAN_ENTRY0, NULL, 1, MSK_MANAGED_SWITCH},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_SW_VLAN_ENTRY_NO[] = {
#if defined(OPTION_SWITCH_MICREL)
	{"1-4095", "802.1q VID", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"0-4094", "802.1q VID", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
	{"all-entries", "Erase all entries 802.1q VID", NULL, sw_vlan_entry, 1, MSK_MANAGED_SWITCH},
#endif
	{NULL,NULL,NULL,NULL}
};

/* End of VLAN commands */
/***********************************************/


cish_command CMD_CONFIG_STORM_CTRL[] = {
#if defined(OPTION_SWITCH_MICREL)
	{"1-20", "Bandwidth percentage allowed to broadcast/multicast traffic", NULL, sw_broadcast_storm_protect_rate, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"1-125", "Bandwidth allowed to broadcast/multicast traffic in 0.8% increments", NULL, sw_broadcast_storm_protect_rate, 1, MSK_MANAGED_SWITCH},
#endif
	{NULL,NULL,NULL,NULL}
};

#ifdef OPTION_SWITCH_MICREL
cish_command CMD_CONFIG_RATE_LIMIT1[] = {
	{"64-100000000", "Maximum RX rate in Kbps", NULL, sw_ingress_rate_limit, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_RATE_LIMIT[] = {
	{"0-3", "Priority queue", CMD_CONFIG_RATE_LIMIT1, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_RATE_LIMIT_NO[] = {
	{"0-3", "Priority queue", NULL, sw_ingress_rate_limit, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_TRAFFIC_SHAPE1[] = {
	{"64-100000000", "Maximum TX rate in Kbps", NULL, sw_egress_traffic_shape, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_TRAFFIC_SHAPE[] = {
	{"0-3", "Priority queue", CMD_CONFIG_TRAFFIC_SHAPE1, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_TRAFFIC_SHAPE_NO[] = {
	{"0-3", "Priority queue", NULL, sw_egress_traffic_shape, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};
#endif

cish_command CMD_CONFIG_DEFAULT_VID[] = {
	{"1-4095", "802.1q VID", NULL, sw_vlan_default, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_COS_PRIO1[] = {
#if defined(OPTION_SWITCH_MICREL)
	{"0-3", "Priority (0 - Lowest, 3 - Highest)", NULL, sw_8021p_prio, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"0-7", "Priority (0 - Lowest, 7 - Highest)", NULL, sw_8021p_prio, 1, MSK_MANAGED_SWITCH},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_COS_PRIO[] = {
	{"0-7", "CoS (802.1p) value", CMD_CONFIG_COS_PRIO1, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_DSCP_PRIO1[] = {
#if defined(OPTION_SWITCH_MICREL)
	{"0-3", "Priority (0 - Lowest, 3 - Highest)", NULL, sw_dscp_prio, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"0-7", "Priority (0 - Lowest, 7 - Highest)", NULL, sw_dscp_prio, 1, MSK_MANAGED_SWITCH},
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_DSCP_PRIO[] = {
	{"0-63", "DSCP value", CMD_CONFIG_DSCP_PRIO1, NULL, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

/********************/
/** Exported menus **/
/********************/


cish_command CMD_CONFIG_INTERFACE_ETHERNET_SW_PORT_NO[] = {
#if defined(OPTION_SWITCH_MICREL)
	{"rate-limit", "Storm control configuration", CMD_CONFIG_RATE_LIMIT_NO, NULL, 1, MSK_MANAGED_SWITCH},
	{"traffic-shape", "Storm control configuration", CMD_CONFIG_TRAFFIC_SHAPE_NO, NULL, 1, MSK_MANAGED_SWITCH},
	{"txqueue-split", "Split transmission into 4 queues", NULL, sw_txqueue_split, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"drop-untagged", "Do not drop packets without IEEE 802.1Q tag", NULL, sw_drop_untagged, 1, MSK_MANAGED_SWITCH},
	{"multicast-storm-protect", "Exclude multicast in storm-control", NULL, sw_multicast_storm_protect, 1, MSK_MANAGED_SWITCH},
#endif
	{"802.1p", "Enable 802.1p packet classification", NULL, sw_8021p, 1, MSK_MANAGED_SWITCH},
	{"diffserv", "Enable DiffServ packet classification", NULL, sw_dscp, 1, MSK_MANAGED_SWITCH},
	{"storm-control", "Disable broadcast storm control", NULL, sw_broadcast_storm_protect, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETHERNET_SW_PORT[] = {
	{"802.1p", "Enable 802.1p packet classification", NULL, sw_8021p, 1, MSK_MANAGED_SWITCH},
	{"diffserv", "Enable DiffServ packet classification", NULL, sw_dscp, 1, MSK_MANAGED_SWITCH},
	{"exit", "Exit from interface configuration mode", NULL, config_interface_switch_port_done, 1, MSK_MANAGED_SWITCH},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_MANAGED_SWITCH},
	{"no", "Reverse a setting", CMD_CONFIG_INTERFACE_ETHERNET_SW_PORT_NO, NULL, 1, MSK_MANAGED_SWITCH},
	{"storm-control", "Enable broadcast storm control", NULL, sw_broadcast_storm_protect, 1, MSK_MANAGED_SWITCH},
#if defined(OPTION_SWITCH_MICREL)
	{"rate-limit", "Rate limit (RX) configuration", CMD_CONFIG_RATE_LIMIT, NULL, 1, MSK_MANAGED_SWITCH},
	{"traffic-shape", "Traffic shape (TX) configuration", CMD_CONFIG_TRAFFIC_SHAPE, NULL, 1, MSK_MANAGED_SWITCH},
	{"txqueue-split", "Split transmission into 4 queues", NULL, sw_txqueue_split, 1, MSK_MANAGED_SWITCH},
	{"vlan-default", "Mark non-tagged packets with VLAN tag", CMD_CONFIG_DEFAULT_VID, NULL, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"drop-untagged", "Drop packets without IEEE 802.1Q tag", NULL, sw_drop_untagged, 1, MSK_MANAGED_SWITCH},
	{"multicast-storm-protect", "Include multicast in storm-control", NULL, sw_multicast_storm_protect, 1, MSK_MANAGED_SWITCH},
	{"storm-protect-rate", "Set rate limit for broadcast packets", CMD_CONFIG_STORM_CTRL, NULL, 1, MSK_MANAGED_SWITCH},
	/*
	 * It is not clear how to configure tagging of untagged packet, perhaps at the
	 * untag map in each VLAN table entry. Leave it disabled until that's figured out.
	 *
	 * {"vlan-default", "Mark non-tagged packets with VLAN tag", CMD_CONFIG_DEFAULT_VID, NULL, 1, MSK_MANAGED_SWITCH},
	 *
	 */
#endif
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETH_SW_PORT_[] = {
	{CLI_STRING_SWITCH_PORTS, "External switch port", NULL, config_interface_switch_port, 1, MSK_MANAGED_SWITCH},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETH_SW_GENERAL_NO[] = {
	{"802.1q", "Disable 802.1q protocol in the switch", NULL, sw_8021q, 1, MSK_MANAGED_SWITCH},
	{"vlan", "Remove a VLAN entry", CMD_CONFIG_SW_VLAN_ENTRY_NO, NULL, 1, MSK_MANAGED_SWITCH},
#if defined(OPTION_SWITCH_MICREL)
	{"multicast-storm-protect", "Exclude multicast in storm-control", NULL, sw_multicast_storm_protect, 1, MSK_MANAGED_SWITCH},
	{"replace-null-vid", "Replace packet Null VID for port's default VID", NULL, sw_replace_null_vid, 1, MSK_MANAGED_SWITCH},
	{"wfq", "Disable WFQ scheme for TX queues", NULL, sw_enable_wfq, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"wrr", "Disable WRR scheme for TX queues", NULL, sw_enable_wrr, 1, MSK_MANAGED_SWITCH},
#endif
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_CONFIG_INTERFACE_ETH_SW_GENERAL[] = {
	{"802.1q", "Enable 802.1q protocol in the switch", NULL, sw_8021q, 1, MSK_MANAGED_SWITCH},
	{"cos-prio", "Class of Service (802.1p) priority configuration", CMD_CONFIG_COS_PRIO, NULL, 1, MSK_MANAGED_SWITCH},
	{"dscp-prio", "DSCP priority configuration", CMD_CONFIG_DSCP_PRIO, NULL, 1, MSK_MANAGED_SWITCH},
	{"vlan", "Configure a VLAN entry", CMD_CONFIG_SW_VLAN_ENTRY, NULL, 1, MSK_MANAGED_SWITCH},
#if defined(OPTION_SWITCH_MICREL)
	{"storm-protect-rate", "Set rate limit for broadcast packets", CMD_CONFIG_STORM_CTRL, NULL, 1, MSK_MANAGED_SWITCH},
	{"multicast-storm-protect", "Include multicast in storm-control", NULL, sw_multicast_storm_protect, 1, MSK_MANAGED_SWITCH},
	{"replace-null-vid", "Replace packet Null VID for port's default VID", NULL, sw_replace_null_vid, 1, MSK_MANAGED_SWITCH},
	{"wfq", "Enable WFQ scheme for TX queues", NULL, sw_enable_wfq, 1, MSK_MANAGED_SWITCH},
#elif defined(OPTION_SWITCH_BROADCOM)
	{"wrr", "Enable WRR scheme for TX queues", NULL, sw_enable_wrr, 1, MSK_MANAGED_SWITCH},
#endif
	{NULL, NULL, NULL, NULL}
};
#endif /* MANAGED_SWITCH */
