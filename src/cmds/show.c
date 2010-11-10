#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"

cish_command CMD_SHOW_INTERFACE_ETHERNET[] = {
	{"0-1", "Ethernet interface number", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_INTERFACE_LOOPBACK[] = {
	{"0-4", "Loopback interface number", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_INTERFACE_TUNNEL[] = {
	{"0-9", "Tunnel interface number", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_MODEM3G
cish_command CMD_SHOW_INTERFACE_M3G[] = {
	{"0-2", "3G interface number -| 0 == Built-in | 1 == USB1 | 2 == USB2", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_SHOW_INTERFACES[] = {
	{"ethernet", "Ethernet interface", CMD_SHOW_INTERFACE_ETHERNET, NULL, 0, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_SHOW_INTERFACE_LOOPBACK, NULL, 0, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_SHOW_INTERFACE_TUNNEL, NULL, 0, MSK_NORMAL},
#ifdef OPTION_MODEM3G
	{"m3G", "3G interface", CMD_SHOW_INTERFACE_M3G, NULL, 0, MSK_NORMAL},
#endif
	{"<enter>", "", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_ACL[] = {
	{"<acl>", "Access list name", NULL, show_accesslists, 1, MSK_NORMAL},
	{"<enter>", "", NULL, show_accesslists, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_MANGLE[] = {
	{"<acl>", "MARK rule name", NULL, show_manglerules, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_NAT[] = {
	{"<acl>", "NAT rule name", NULL, show_natrules, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_IP[] = {
	{"arp", "ARP table", NULL, show_arp, 0, MSK_NORMAL},
#ifdef OPTION_BGP
	{"bgp", "BGP information", CMD_SHOW_BGP, show_ip_bgp, 1, MSK_BGP},
#endif
	{"dns", "DNS information", NULL, show_ip_dns, 0, MSK_NORMAL},
#ifdef OPTION_SMCROUTE
	{"mroute", "Show multicast route statistics", NULL, show_mroute, 1, MSK_NORMAL},
#endif
	{"ospf", "OSPF information", CMD_SHOW_OSPF, show_ip_ospf, 1, MSK_OSPF},
	{"rip", "RIP information", NULL, show_ip_rip, 1, MSK_RIP},
	{"route", "Routing information", NULL, show_routingtables, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_SNMP[] = {
	{"users", "Show SNMP v3 users", NULL, show_snmp_users, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_IPSEC
cish_command CMD_SHOW_CRYPTO[] = {
	{"<text>", "Specific tunnel information", NULL, show_crypto, 1, MSK_VPN},
	{"<enter>", "", NULL, NULL, 0, MSK_VPN},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_SHOW_LOGGING3[] = {
	{"1970-2037", "Year", NULL, show_logging, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_LOGGING2[] = {
	{"1-12", "Month of the year", CMD_SHOW_LOGGING3, show_logging, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_LOGGING1[] = {
	{"1-31", "Day of the month", CMD_SHOW_LOGGING2, show_logging, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_LOGGING[] = {
	{"hh:mm:ss", "Show after time", CMD_SHOW_LOGGING1, show_logging, 0, MSK_NORMAL},
	{"tail", "Show the tail of logging buffers", NULL, show_logging, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_NTPD
cish_command CMD_SHOW_NTP[] = {
	{"associations", "Show NTP associations", NULL, show_ntpassociations, 1, MSK_NORMAL},
	{"keys", "List NTP keys", NULL, show_ntpkeys, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_RMON
cish_command CMD_SHOW_RMON_EVENT[] = {
	{"1-25", "Show specific event", NULL, show_rmon_events, 1, MSK_NORMAL},
	{"<enter>", "Show all events", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_RMON_ALARM[] = {
	{"1-25", "Show specific alarm", NULL, show_rmon_alarms, 1, MSK_NORMAL},
	{"<enter>", "Show all alarms", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_RMON[] = {
	{"agent-state", "Show RMON agent state", NULL, show_rmon_agent, 1, MSK_NORMAL},
	{"alarms", "Show configured RMON alarms", CMD_SHOW_RMON_ALARM, show_rmon_alarms, 1, MSK_NORMAL},
	{"events", "Show configured RMON events", CMD_SHOW_RMON_EVENT, show_rmon_events, 1, MSK_NORMAL},
	{"mibs", "Show MIBs supported by RMON", NULL, show_rmon_mibs, 1, MSK_NORMAL},
	{"mibtree", "Show MIB tree supported by RMON", NULL, show_rmon_mibtree, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_SHOW[] = {
	{"access-lists", "List access lists", CMD_SHOW_ACL, show_accesslists, 1, MSK_NORMAL},
	{"arp", "ARP table", NULL, show_arp, 0, MSK_NORMAL},
	{"clock", "System clock", NULL, show_clock, 0, MSK_NORMAL},
#ifdef OPTION_IPSEC
	{"crypto", "VPN tunnels", CMD_SHOW_CRYPTO, show_crypto, 1, MSK_VPN},
#endif
	{"cpu", "CPU Information", NULL, show_cpu, 0, MSK_NORMAL},
	{"debugging", "State of each debugging option", NULL, show_debug, 0, MSK_NORMAL},
	{"dhcp", "Show DHCP leases", NULL, show_dumpleases, 0, MSK_NORMAL},
	{"interfaces", "Network interfaces", CMD_SHOW_INTERFACES, show_interfaces, 0, MSK_NORMAL},
	{"ip", "IP system information", CMD_SHOW_IP, NULL, 0, MSK_NORMAL},
#ifdef OPTION_IPSEC
	{"l2tp", "L2TP tunnels", NULL, show_l2tp, 1, MSK_VPN},
#endif
	{"logging", "Show the contents of logging buffers", CMD_SHOW_LOGGING, show_logging, 0, MSK_NORMAL},
	{"memory", "Memory statistics", NULL, show_memory, 0, MSK_NORMAL},
	{"mark-rules", "List MARK rules", CMD_SHOW_MANGLE, show_manglerules, 1, MSK_QOS},
	{"nat-rules", "List NAT rules", CMD_SHOW_NAT, show_natrules, 1, MSK_NORMAL},
#ifdef OPTION_NTPD
	{"ntp", "Show NTP info", CMD_SHOW_NTP, NULL, 1, MSK_NORMAL},
#endif
	{"performance", "Show current system resources", NULL, show_performance, 1, MSK_NORMAL},
	{"previous-config", "Contents of previous configuration", NULL, show_previous_config, 1, MSK_NORMAL},
	{"privilege", "Show current privilege level", NULL, show_privilege, 0, MSK_NORMAL},
	{"processes", "Active process statistics", NULL, show_processes, 1, MSK_NORMAL},
	{"qos", "Show QoS statistics", NULL, show_qos, 1, MSK_QOS},
#ifdef CONFIG_DEVELOPMENT
#ifdef CONFIG_KMALLOC_ACCOUNTING
	{"kmalloc-account", "Show kmalloc stats", NULL, show_kmalloc, 1, MSK_NORMAL},
#endif
#if defined(CONFIG_NET_SKB_RECYCLING) && defined(CONFIG_DEVELOPMENT)
	{"recycle", "Show recycle stats", NULL, show_recycle, 1, MSK_NORMAL},
#endif
#endif
	{"reload", "Show reload timeout", NULL, show_reload, 1, MSK_NORMAL},
#ifdef OPTION_RMON
	{"rmon", "Show RMON events and alarms", CMD_SHOW_RMON, NULL, 1, MSK_NORMAL},
#endif
	{"running-config", "Current operating configuration", NULL, show_running_config, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"softnet_stat", "Show cpu RX stats", NULL, show_softnet, 1, MSK_NORMAL},
#endif
	{"startup-config", "Contents of startup configuration", NULL, show_startup_config, 1, MSK_NORMAL},
	{"tech-support", "Show system information for Tech-Support ", NULL, show_techsupport, 1, MSK_NORMAL},
	{"uptime", "System uptime and load", NULL, show_uptime, 0, MSK_NORMAL},
	{"version", "System version information", NULL, show_version, 0, MSK_NORMAL},
#ifdef OPTION_VRRP
	{"vrrp", "VRRP information", NULL, show_vrrp, 1, MSK_VRRP},
#endif	
	{"snmp", "Show SNMP informations", CMD_SHOW_SNMP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
