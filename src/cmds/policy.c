#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/autoconf.h>

#include "commands.h"
#include "commandtree.h"

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
