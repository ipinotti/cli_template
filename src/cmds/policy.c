#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/autoconf.h>

#include "commands.h"
#include "commandtree.h"

/* POLICY ROUTE - PBR */

cish_command CMD_POLICYROUTE_RULE_TABLENUM[] = {
	{"0-9", "Table for policy route", NULL, policyroute_rule_set_info, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_RULE_TABLE[] = {
	{"table", "Table for policy route", CMD_POLICYROUTE_RULE_TABLENUM, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_RULE_MRKNUM[] = {
	{"1-2000000000", "Mark-Rule Number for policy route", CMD_POLICYROUTE_RULE_TABLE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_TABLE_NAME[] = {
	{"0-9", "Route Table Number", NULL, policyroute_route_set_info, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_TABLE[] = {
	{"table", "Route Table", CMD_POLICYROUTE_ROUTE_TABLE_NAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_DEV_ETHERNET[] = {
	{"0-1", "Ethernet interface number", CMD_POLICYROUTE_ROUTE_TABLE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_ALL_INTF
cish_command CMD_POLICYROUTE_ROUTE_DEV_LOOPBACK[] = {
	{"0-0", "Loopback interface number", CMD_POLICYROUTE_ROUTE_TABLE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_POLICYROUTE_ROUTE_DEV_TUNNEL[] = {
	{"0-9", "Tunnel interface number", CMD_POLICYROUTE_ROUTE_TABLE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#ifdef OPTION_MODEM3G
cish_command CMD_POLICYROUTE_ROUTE_DEV_3G[] = {
	{"0-2", "3G interface number", CMD_POLICYROUTE_ROUTE_TABLE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_POLICYROUTE_ROUTE_DEV_PPTP[] = {
	{"0-0", "PPTP interface number", CMD_POLICYROUTE_ROUTE_TABLE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_POLICYROUTE_ROUTE_DEV_PPPOE[] = {
	{"0-0", "PPPoE interface number", CMD_POLICYROUTE_ROUTE_TABLE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#endif

cish_command CMD_POLICYROUTE_ROUTE_DEV_NAME[] = {
	{"ethernet", "Ethernet interface", CMD_POLICYROUTE_ROUTE_DEV_ETHERNET , NULL, 1, MSK_NORMAL},
#ifdef OPTION_ALL_INTF
	{"loopback", "Loopback interface", CMD_POLICYROUTE_ROUTE_DEV_LOOPBACK, NULL, 1, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_POLICYROUTE_ROUTE_DEV_TUNNEL, NULL, 1, MSK_NORMAL},
#ifdef OPTION_MODEM3G
	{"m3G", "3G Interface", CMD_POLICYROUTE_ROUTE_DEV_3G, NULL, 1, MSK_NORMAL},
#endif
	{"pptp", "PPTP Interface", CMD_POLICYROUTE_ROUTE_DEV_PPTP, NULL, 1, MSK_NORMAL},
	{"pppoe", "PPPoE Interface", CMD_POLICYROUTE_ROUTE_DEV_PPPOE, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_POLICYROUTE_ROUTE_DEV[] = {
	{"dev", "Device output", CMD_POLICYROUTE_ROUTE_DEV_NAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_VIA_OPT[] = {
	{"dev", "Device output", CMD_POLICYROUTE_ROUTE_DEV_NAME, NULL, 1, MSK_NORMAL},
	{"table", "Route Table", CMD_POLICYROUTE_ROUTE_TABLE_NAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_VIA[] = {
	{"<ipaddress>", "Target IP Address", CMD_POLICYROUTE_ROUTE_VIA_OPT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_OPT[] = {
	{"dev", "Device output", CMD_POLICYROUTE_ROUTE_DEV_NAME, NULL, 1, MSK_NORMAL},
	{"via", "Address of the nexthop router", CMD_POLICYROUTE_ROUTE_VIA, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_MASK[] = {
	{"<netmask>", "IP Network Mask", CMD_POLICYROUTE_ROUTE_OPT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_FLUSH_TABLE_NUM[] = {
	{"0-9", "Route Table Number", NULL, policyroute_route_flush_table, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_FLUSH_TABLE[] = {
	{"table", "Route Table", CMD_POLICYROUTE_ROUTE_FLUSH_TABLE_NUM, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYROUTE_ROUTE_NET[] = {
	{"<ipaddress>", "Network", CMD_POLICYROUTE_ROUTE_MASK, NULL, 1, MSK_NORMAL},
	{"default", "Default Path", CMD_POLICYROUTE_ROUTE_OPT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICY_ROUTE_NO[] = {
	{"rule", "Remove rule for policy route", CMD_POLICYROUTE_RULE_MRKNUM, NULL, 1, MSK_NORMAL},
	{"route", "Remove route for policy route", CMD_POLICYROUTE_ROUTE_NET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICY_ROUTE[] = {
	{"rule", "Add rule for policy route", CMD_POLICYROUTE_RULE_MRKNUM, NULL, 1, MSK_NORMAL},
	{"route", "Add route for policy route", CMD_POLICYROUTE_ROUTE_NET, NULL, 1, MSK_NORMAL},
	{"flush", "Empties a routing table", CMD_POLICYROUTE_ROUTE_FLUSH_TABLE, NULL, 1, MSK_NORMAL},
	{"no","Reverse settings", CMD_POLICY_ROUTE_NO, NULL, 1, MSK_NORMAL},
	{"exit","Exit from Policy Route (PBR) configuration mode", NULL, policyroute_done, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};



/* POLICY MAP */

cish_command CMD_POLICYMAP_WFQ[] = {
	{"1-4096", "WFQ hold-queue size", NULL, config_policy_queue, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_FIFO[] = {
	{"1-2048", "FIFO packets size", NULL, config_policy_queue, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_RED2[] = {
	{"ecn", "Use early congestion notification", NULL, config_policy_queue, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_RED1[] = {
	{"1-100", "Drop probability (%)", CMD_POLICYMAP_RED2, config_policy_queue, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_RED[] = {
	{"10-5000", "Desired latency (ms)", CMD_POLICYMAP_RED1, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_SFQ[] = {
	{"1-120", "Perturb (s)", NULL, config_policy_queue, 1, MSK_QOS},
	{"<enter>", "", NULL, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_QUEUE[] = {
	{"fifo", "Standard first-in first-out", CMD_POLICYMAP_FIFO, config_policy_queue, 1, MSK_QOS},
	{"red", "Random Early Detection", CMD_POLICYMAP_RED, NULL, 1, MSK_QOS},
	{"sfq", "Stochastic Fairness Queue", CMD_POLICYMAP_SFQ, config_policy_queue, 1, MSK_QOS},
	{"wfq", "Weighted Fairness Queue", CMD_POLICYMAP_WFQ, config_policy_queue, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_BW_PERC[] = {
	{"1-100", "Percentage", NULL, config_policy_bw, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_BW_REMAIN[] = {
	{"percent", "% of the remaining bandwidth", CMD_POLICYMAP_MARK_BW_PERC, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_BW[] = {
	{"<bandwidth>", "Set bandwidth in [k|m]bps", NULL, config_policy_bw, 1, MSK_QOS},
	{"percent", "% of total Bandwidth", CMD_POLICYMAP_MARK_BW_PERC, NULL, 1, MSK_QOS},
	{"remaining", "% of the remaining bandwidth", CMD_POLICYMAP_MARK_BW_REMAIN, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_CEIL_PERC[] = {
	{"1-100", "Percentage", NULL, config_policy_ceil, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_CEIL[] = {
	{"<bandwidth>", "Set bandwidth in [k|m]bps", NULL, config_policy_ceil, 1, MSK_QOS},
	{"percent", "% of total Bandwidth", CMD_POLICYMAP_MARK_CEIL_PERC, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_RT2[] = {
	{"64-1500","Maximum packet size for this traffic", NULL, config_policy_realtime, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK_RT1[] = {
	{"10-500","Maximum latency accepted in miliseconds", CMD_POLICYMAP_MARK_RT2, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARKRULE_NO[] = {
	{"bandwidth","Minimum bandwidth guaranteed for this traffic", NULL, config_policy_bw, 1, MSK_QOS},
	{"ceil","Maximum bandwidth allowed for this traffic", NULL, config_policy_ceil, 1, MSK_QOS},
	{"queue","Set queue strategy", NULL, config_policy_queue, 1, MSK_QOS},
	{"real-time","Set type of traffic as Real-Time (low latency)", NULL, config_policy_realtime, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARKRULE[] = {
	{"bandwidth","Minimum bandwidth guaranteed for this traffic", CMD_POLICYMAP_MARK_BW, NULL, 1, MSK_QOS},
	{"ceil","Maximum bandwidth allowed for this traffic", CMD_POLICYMAP_MARK_CEIL, NULL, 1, MSK_QOS},
	{"exit","Exit Mark configuration", NULL, quit_mark_config, 1, MSK_QOS},
	{"no","Negate or set default values of a command", CMD_POLICYMAP_MARKRULE_NO, NULL, 1, MSK_QOS},
	{"queue","Set queue strategy", CMD_POLICYMAP_MARK_QUEUE, NULL, 1, MSK_QOS},
	{"real-time","Set type of traffic as Real-Time (low latency)", CMD_POLICYMAP_MARK_RT1, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_DESC[] = {
	{"<text>","Up to 255 characters describing this policy-map", NULL, do_policy_description, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_MARK[] = {
	{"1-2000000000", "Mark number as configured in mark-rule", NULL, do_policy_mark, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP_NO[] = {
	{"description","Delete Policy-Map description", NULL, do_policy_description, 1, MSK_QOS},
	{"mark","Delete policy of a mark", CMD_POLICYMAP_MARK, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_POLICYMAP[] = {
	{"description","Policy-Map description", CMD_POLICYMAP_DESC, NULL, 1, MSK_QOS},
	{"exit","Exit from QoS policy-map configuration mode", NULL, policymap_done, 1, MSK_QOS},
	{"mark","Specify policy to a mark", CMD_POLICYMAP_MARK, NULL, 1, MSK_QOS},
	{"no","Negate or set default values of a command", CMD_POLICYMAP_NO, NULL, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};
