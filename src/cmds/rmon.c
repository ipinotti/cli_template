#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_RMON
cish_command RMON_EVENT_TRAP_VALUE[] = {
	{"<text>", "Community", NULL, rmon_event, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_EVENT_OWNERCHLD[] = {
	{"trap", "Trap community", RMON_EVENT_TRAP_VALUE, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_EVENT_OWNER_VALUE[] = {
	{"<text>", "Owner", RMON_EVENT_OWNERCHLD, rmon_event, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_EVENT_LOGCHLD[] = {
	{"owner", "Event owner", RMON_EVENT_OWNER_VALUE, NULL, 1, MSK_NORMAL},
	{"trap", "Trap community", RMON_EVENT_TRAP_VALUE, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_EVENT_DESCRCHLD[] = {
	{"log", "Log event when triggered", RMON_EVENT_LOGCHLD, rmon_event, 1, MSK_NORMAL},
	{"owner", "Event owner", RMON_EVENT_OWNER_VALUE, NULL, 1, MSK_NORMAL},
	{"trap", "Trap community", RMON_EVENT_TRAP_VALUE, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_EVENT_DESCR_VALUE[] = {
	{"<text>", "Description", RMON_EVENT_DESCRCHLD, rmon_event, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_EVENT_CHILDS[] = {
	{"description", "Event description", RMON_EVENT_DESCR_VALUE, NULL, 1, MSK_NORMAL},
	{"log", "Log event when triggered", RMON_EVENT_LOGCHLD, rmon_event, 1, MSK_NORMAL},
	{"owner", "Event owner", RMON_EVENT_OWNER_VALUE, NULL, 1, MSK_NORMAL},
	{"trap", "Trap community", RMON_EVENT_TRAP_VALUE, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_EVENT[] = {
	{"1-25", "Event number", RMON_EVENT_CHILDS, rmon_event, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_OWNER[] = {
	{"<text>", "Owner", NULL, rmon_alarm, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_FALLINGTH_EVENT_VAL[] = {
	{"owner", "Alarm owner", RMON_ALARM_OWNER, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_FALLINGTH_EVENT[] = {
	{"1-25", "Event number", RMON_ALARM_FALLINGTH_EVENT_VAL, rmon_alarm, 1, MSK_NORMAL},
	{"owner", "Alarm owner", RMON_ALARM_OWNER, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_FALLINGTH[] = {
	{"<text>", "Threshold value", RMON_ALARM_FALLINGTH_EVENT, rmon_alarm, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_RISINGTH_EVENT_VAL[] = {
	{"falling-threshold", "Falling threshold", RMON_ALARM_FALLINGTH, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_RISINGTH_EVENT[] = {
	{"1-25", "Event number", RMON_ALARM_RISINGTH_EVENT_VAL, NULL, 1, MSK_NORMAL},
	{"falling-threshold", "Falling threshold", RMON_ALARM_FALLINGTH, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_RISINGTH[] = {
	{"<text>", "Threshold value", RMON_ALARM_RISINGTH_EVENT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_RIS[] = {
	{"rising-threshold", "Rising threshold", RMON_ALARM_RISINGTH, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_DATATYPE[] = {
	{"absolute", "Absolute data type", RMON_ALARM_RIS, NULL, 1, MSK_NORMAL},
	{"delta", "Delta between the last get and the current", RMON_ALARM_RIS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_INTERVAL[] = {
	{"3-3600", "Interval in seconds", RMON_ALARM_DATATYPE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM_VAROID[] = {
	{"<text>", "Variable OID", RMON_ALARM_INTERVAL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_ALARM[] = {
	{"1-25", "Alarm number", RMON_ALARM_VAROID, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command RMON_VERSION[] = {
	{"1", "SNMPv1", NULL, rmon_snmp_version, 1, MSK_NORMAL},
	{"2c", "SNMPv2c", NULL, rmon_snmp_version, 1, MSK_NORMAL},
	{"3", "SNMPv3", NULL, rmon_snmp_version, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RMON[] = {
	{"agent", "Start RMON agent", NULL, rmon_agent, 1, MSK_NORMAL},
	{"event", "Configure event", RMON_EVENT, NULL, 1, MSK_NORMAL},
	{"alarm", "Configure alarm", RMON_ALARM, NULL, 1, MSK_NORMAL},
	{"snmp-version", "Configure SNMP version for traps", RMON_VERSION, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif
