/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/config.h>

#include <libconfig/defines.h>
#include "options.h"
#include "commandtree.h"
#include "commands.h"
#include "debug.h"
#include "mangle.h"
#include "interface_snmp.h"
#include "acl.h"
#include "mangle.h"
#include "nat.h"
#include "policymap.h"

char EXTCMD[1024];
char EXTSCRIPT[1024];
cish_command CEXT = {EXTCMD, EXTSCRIPT, NULL, NULL, 0};

extern cish_command CMD_SHOW_OSPF[];

cish_command CMD_CONFIG_KEY[];

cish_command CMD_SHOW_INTERFACE_AUX[] = {
	{"0-1", "Aux interface number", NULL, show_interfaces, 0, MSK_AUX},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_INTERFACE_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_INTERFACE_LOOPBACK[] = {
	{"0-4", "Loopback interface number", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_INTERFACE_SERIAL[] = {
	{"0-0", "Serial interface number", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_INTERFACE_TUNNEL[] = {
	{"0-9", "Tunnel interface number", NULL, show_interfaces, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_INTERFACES[] = {
	{"aux", "Aux interface", CMD_SHOW_INTERFACE_AUX, NULL, 0, MSK_AUX},
	{"ethernet", "Ethernet interface", CMD_SHOW_INTERFACE_ETHERNET, NULL, 0, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_SHOW_INTERFACE_LOOPBACK, NULL, 0, MSK_NORMAL},
	{"serial", "Serial interface", CMD_SHOW_INTERFACE_SERIAL, NULL, 0, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_SHOW_INTERFACE_TUNNEL, NULL, 0, MSK_NORMAL},
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

cish_command CMD_SHOW_BRIDGE[] = {
	{"1-1", "Bridge Group number", NULL, bridge_show, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_BGP
extern cish_command CMD_SHOW_BGP[];
#endif

#ifdef CONFIG_IPHC
cish_command CMD_SHOW_IP_IPHC_SERIAL[] = {
	{"0-0", "Interface number", NULL, show_iphc_stats, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_SHOW_IP_IPHC[] = {
	{"serial", "Serial interface", CMD_SHOW_IP_IPHC_SERIAL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

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
#ifdef CONFIG_IPHC
	{"header-compression", "IPHC header-compression statistics", CMD_SHOW_IP_IPHC, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_IPX[] = {
	{"route", "Routing information", NULL, show_ipx_routingtables, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_X25
cish_command CMD_SHOW_X25[] = {
#ifdef OPTION_X25XOT
	{"forward", "Forwarding information", NULL, show_x25_forward, 1, MSK_X25XOT},
#endif
#ifdef OPTION_X25MAP
	{"map", "Map information", NULL, show_x25_map, 1, MSK_X25MAP},
#endif
	{"route", "Routing information", NULL, show_x25_routes, 0, MSK_X25},
	{"svc", "SVC information", NULL, show_x25_svc, 0, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

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

cish_command CMD_SHOW_FR[] = {
	{"pvc", "show frame relay pvc statistics", NULL, show_fr_pvc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW[] = {
	{"access-lists", "List access lists", CMD_SHOW_ACL, show_accesslists, 1, MSK_NORMAL},
	{"arp", "ARP table", NULL, show_arp, 0, MSK_NORMAL},
	{"bridge", "Bridge Forwarding/Filtering Database", CMD_SHOW_BRIDGE, NULL, 1, MSK_NORMAL},
	{"clock", "System clock", NULL, show_clock, 0, MSK_NORMAL},
#ifdef OPTION_IPSEC
	{"crypto", "VPN tunnels", CMD_SHOW_CRYPTO, show_crypto, 1, MSK_VPN},
#endif
	{"cpu", "CPU Information", NULL, show_cpu, 0, MSK_NORMAL},
	{"debugging", "State of each debugging option", NULL, show_debug, 0, MSK_NORMAL},
	{"dhcp", "Show DHCP leases", NULL, show_dumpleases, 0, MSK_NORMAL},
#ifdef OPTION_FEATURE
	{"features", "Features", NULL, show_features, 1, MSK_FEATURE},
#endif
	{"frame-relay", "Frame-Relay information", CMD_SHOW_FR, NULL, 0, MSK_NORMAL},
	{"interfaces", "Network interfaces", CMD_SHOW_INTERFACES, show_interfaces, 0, MSK_NORMAL},
	{"ip", "IP system information", CMD_SHOW_IP, NULL, 0, MSK_NORMAL},
	{"ipx", "IPX system information", CMD_SHOW_IPX, NULL, 0, MSK_NORMAL},
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
	/* Verificar SatRouter para implementar essas funções */
// 	{"slot0-config", "Contents of slot0 configuration", NULL, show_slot_config, 1, MSK_NORMAL},
// 	{"slot1-config", "Contents of slot1 configuration", NULL, show_slot_config, 1, MSK_NORMAL},
// 	{"slot2-config", "Contents of slot2 configuration", NULL, show_slot_config, 1, MSK_NORMAL},
// 	{"slot3-config", "Contents of slot3 configuration", NULL, show_slot_config, 1, MSK_NORMAL},
// 	{"slot4-config", "Contents of slot4 configuration", NULL, show_slot_config, 1, MSK_NORMAL},
#endif
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
#ifdef OPTION_X25
	{"x25", "X.25 system information", CMD_SHOW_X25, NULL, 1, MSK_X25},
#endif
	{"snmp", "Show SNMP informations", CMD_SHOW_SNMP, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_BERLIN_SATROUTER
	{"manufacturer", "Manufacturer", NULL, show_motherboard_info, 1, MSK_NORMAL},
	{"serial-number", "Shows modem serial number", NULL, show_satrouter_info, 1, MSK_NORMAL},
	{"serial-number-router", "Shows router serial number", NULL, show_satrouter_info, 1, MSK_NORMAL},
	{"release-date", "Shows release date", NULL, show_release_date, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_NO_IP_ICMP_IGNORE[] = {
	{"all", "Stop ignoring all traffic", NULL, no_ip_param, 1, MSK_NORMAL},
	{"bogus", "Stop ignoring bogus error responses", NULL, no_ip_param, 1, MSK_NORMAL},
	{"broadcasts", "Stop ignoring broadcast traffic", NULL, no_ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,0}
};
cish_command CMD_NO_IP_ICMP[] = {
	{"ignore", "Set ignore parameters", CMD_NO_IP_ICMP_IGNORE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_HTTP
cish_command CMD_NO_IP_HTTP[] = {
	{"server", "Disable HTTP server", NULL, no_http_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_NO_IP_SSH[] = {
	{"server", "Disable SSH server", NULL, no_ssh_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_NO_IP_TELNET[] = {
	{"server", "Disable Telnet server", NULL, no_telnet_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_NO_IP_DHCP[] = {
	{"relay", "Disable DHCP relay", NULL, no_dhcp_relay, 1, MSK_NORMAL},
	{"server", "Disable DHCP server", NULL, no_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#if 0
cish_command CMD_NO_IPX_ROUTE[] = {
	{"<ipx network>", "Destination network", NULL, no_ipx_route, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_NO_IPX[] = {
#if 0
	{"route", "Unset routing information", CMD_NO_IPX_ROUTE, NULL, 1, MSK_NORMAL},
#endif
	{"routing", "Disable IPX routing", NULL, no_ipx_routing, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_FRAG_HIGH[] = {
	{"1-2000000000", "High IP fragment memory threshold (bytes)", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_FRAG_LOW[] = {
	{"1-2000000000", "Low IP fragment threshold (bytes)", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_FRAG_TIME[] = {
	{"1-2000000000", "Time to keep an IP fragment in memory (hundreths of a second)", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_FRAG[] = {
	{"high", "Set high threshold", CMD_IP_FRAG_HIGH, NULL, 1, MSK_NORMAL},
	{"low", "Set low threshold", CMD_IP_FRAG_LOW, NULL, 1, MSK_NORMAL},
	{"time", "Set time to keep an IP fragment in memory.", CMD_IP_FRAG_TIME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifndef CONFIG_BERLIN
cish_command CMD_IP_ICMP_RATE2[] = {
	{"0-1000", "Rate (hundreths of a second)", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ICMP_RATE[] = {
	{"dest-unreachable", "Destination unreachable messages rate", CMD_IP_ICMP_RATE2, NULL, 1, MSK_NORMAL},
	{"echo-reply", "Echo reply messages rate", CMD_IP_ICMP_RATE2, NULL, 1, MSK_NORMAL},
	{"param-prob", "Parameter probe messages rate", CMD_IP_ICMP_RATE2, NULL, 1, MSK_NORMAL},
	{"time-exceed", "Time exceeded messages rate", CMD_IP_ICMP_RATE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IP_ICMP_IGNORE[] = {
	{"all", "Ignore all icmp traffic", NULL, ip_param, 1, MSK_NORMAL},
	{"bogus", "Ignore bogus error responses", NULL, ip_param, 1, MSK_NORMAL},
	{"broadcasts", "Ignore broadcast traffic", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,0}
};

cish_command CMD_IP_ICMP[] = {
	{"ignore", "Set ignore parameters", CMD_IP_ICMP_IGNORE, NULL, 1, MSK_NORMAL},
#ifndef CONFIG_BERLIN
	{"rate", "Set icmp rates", CMD_IP_ICMP_RATE, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_SMCROUTE
cish_command CMD_IP_MROUTE8_ETHERNET[] = {
	{"0-0", "Interface number", NULL, ip_mroute, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE8_SERIAL[] = {
	{"0-0", "Interface number", NULL, ip_mroute, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE7[] = {
	{"ethernet", "Ethernet interface", CMD_IP_MROUTE8_ETHERNET, NULL, 1, MSK_NORMAL},
	{"serial", "Serial interface", CMD_IP_MROUTE8_SERIAL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE6[] = {
	{"out", "Output interface", CMD_IP_MROUTE7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE5_ETHERNET[] = {
	{"0-0", "Interface number", CMD_IP_MROUTE6, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE5_SERIAL[] = {
	{"0-0", "Interface number", CMD_IP_MROUTE6, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE4[] = {
	{"ethernet", "Ethernet interface", CMD_IP_MROUTE5_ETHERNET, NULL, 1, MSK_NORMAL},
	{"serial", "Serial interface", CMD_IP_MROUTE5_SERIAL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE3[] = {
	{"in", "Input interface", CMD_IP_MROUTE4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE2[] = {
	{"<ipaddress>", "Multicast group address", CMD_IP_MROUTE3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE1[] = {
	{"<ipaddress>", "Origin IP address", CMD_IP_MROUTE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IP_ROUTE5[] = {
	{"1-255", "Distance metric for this route", NULL, zebra_execute_cmd, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_AUX[] = {
	{"0-1", "Aux interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_AUX},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_ETHERNET[] = {
	{"0-0", "Ethernet interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_LOOPBACK[] = {
	{"0-4", "Loopback interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_SERIAL[] = {
	{"0-0", "Serial interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_TUNNEL[] = {
	{"0-9", "Tunnel interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE3[] = {
	{"aux", "Aux interface", CMD_IP_ROUTE4_AUX, NULL, 1, MSK_AUX},
	{"ethernet", "Ethernet interface", CMD_IP_ROUTE4_ETHERNET, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_IP_ROUTE4_LOOPBACK, NULL, 1, MSK_NORMAL},
	{"serial", "Serial interface", CMD_IP_ROUTE4_SERIAL, NULL, 1, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_IP_ROUTE4_TUNNEL, NULL, 1, MSK_NORMAL},
	{"<ipaddress>", "Forwarding router's address", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE2[] = {
	{"<netmask>", "Destination prefix mask", CMD_IP_ROUTE3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE1[] = {
	{"<ipaddress>", "Destination prefix", CMD_IP_ROUTE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_DEFAULT_TTL[] = {
	{"0-255", "Default TTL value", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_HTTP
cish_command CMD_IP_HTTP[] = {
	{"server", "Enable HTTP server", NULL, http_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_IP_SSH_KEY_RSA[] = {
	{"512-2048", "Length in bits (multiple of 8)", NULL, ssh_generate_rsa_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_SSH_KEY[] = {
	{"rsa", "RSA key for SSH server", CMD_IP_SSH_KEY_RSA, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_SSH[] = {
	{"key", "Generate new key", CMD_IP_SSH_KEY, NULL, 1, MSK_NORMAL},
	{"server", "Enable SSH server", NULL, ssh_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_TELNET[] = {
	{"server", "Enable Telnet server", NULL, telnet_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

extern cish_command CMD_IP_DHCP_SERVER5[]; /* Loop! */

cish_command CMD_IP_DHCP_SERVER10[] = {
	{"<ipaddress>", "IP address of a DNS server", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER20[] = {
	{"<ipaddress>", "IP address of the default router", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER30[] = {
	{"<text>", "Domain name for the client", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER43[] = {
	{"0-59", "seconds", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER42[] = {
	{"0-59", "minutes", CMD_IP_DHCP_SERVER43, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER41[] = {
	{"0-23", "hours", CMD_IP_DHCP_SERVER42, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER40[] = {
	{"0-20000", "days", CMD_IP_DHCP_SERVER41, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER50[] = {
	{"<ipaddress>", "IP address of a NetBIOS name server WINS (NBNS)", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER60[] = {
	{"<ipaddress>", "IP address of a NetBIOS datagram distribution server (NBDD)", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER70[] = {
	{"B", "NetBIOS B-node (Broadcast - no WINS)", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{"P", "NetBIOS P-node (Peer - WINS only)", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{"M", "NetBIOS M-node (Mixed - broadcast, then WINS)", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{"H", "NetBIOS H-node (Hybrid - WINS, then broadcast)", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER5[] = {
	{"default-lease-time", "Specify default lease time", CMD_IP_DHCP_SERVER40, NULL, 1, MSK_NORMAL},
	{"domain-name", "Specify the domain name for the client", CMD_IP_DHCP_SERVER30, NULL, 1, MSK_NORMAL},
	{"dns-server", "Specify the IP address of a DNS server", CMD_IP_DHCP_SERVER10, NULL, 1, MSK_NORMAL},
	{"max-lease-time", "Specify maximum lease time", CMD_IP_DHCP_SERVER40, NULL, 1, MSK_NORMAL},
	{"netbios-name-server", "Specify the IP address of the NetBIOS name server WINS (NBNS)", CMD_IP_DHCP_SERVER50, NULL, 1, MSK_NORMAL},
	{"netbios-dd-server", "Specify the IP address of the NetBIOS datagram distribution server (NBDD)", CMD_IP_DHCP_SERVER60, NULL, 1, MSK_NORMAL},
	{"netbios-node-type", "Specify the NetBIOS node type of the client", CMD_IP_DHCP_SERVER70, NULL, 1, MSK_NORMAL},
	{"router", "Specify the IP address of the default router", CMD_IP_DHCP_SERVER20, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER4[] = {
	{"<ipaddress>", "Pool end", CMD_IP_DHCP_SERVER5, dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER3[] = {
	{"<ipaddress>", "Pool begin", CMD_IP_DHCP_SERVER4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER2[] = {
	{"<netmask>", "Network mask of the DHCP pool", CMD_IP_DHCP_SERVER3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER[] = {
	{"<ipaddress>", "Network number of the DHCP pool", CMD_IP_DHCP_SERVER2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_RELAY_SERVER2[] = {
	{"<ipaddress>", "DHCP server address", NULL, dhcp_relay, 1, MSK_NORMAL},
	{"<enter>", "Enable DHCP relay", NULL, dhcp_relay, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
	
cish_command CMD_IP_DHCP_RELAY_SERVER1[] = {
	{"<ipaddress>", "DHCP server address", CMD_IP_DHCP_RELAY_SERVER2, dhcp_relay, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP[] = {
	{"relay", "Enable DHCP relay", CMD_IP_DHCP_RELAY_SERVER1, NULL, 1, MSK_NORMAL},
	{"server", "Enable DHCP server", CMD_IP_DHCP_SERVER, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DNS[] = {
	{"relay", "DNS relay service", NULL, ip_dnsrelay, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DOMAIN[] = {
	{"lookup", "DNS lookup service", NULL, ip_domainlookup, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAMESERVER_3[] = {
	{"<ipaddress>", "Domain server IP address", NULL, ip_nameserver, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAMESERVER_2[] = {
	{"<ipaddress>", "Domain server IP address", CMD_IP_NAMESERVER_3, ip_nameserver, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAMESERVER[] = {
	{"<ipaddress>", "Domain server IP address (maximum of 3)", CMD_IP_NAMESERVER_2, ip_nameserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT_HELPER_FTP_PORTS[] = {
	{"<ports>", "comma-separated list of ports(max 8)", NULL, ip_nat_ftp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT_HELPER_FTP[] = {
	{"ports", "comma-separated list of ports(max 8)", CMD_IP_NAT_HELPER_FTP_PORTS, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT_HELPER_IRC_PORTS[] = {
	{"<ports>", "comma-separated list of ports(max 8)", NULL, ip_nat_irc, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT_HELPER_IRC[] = {
	{"ports", "comma-separated list of ports(max 8)", CMD_IP_NAT_HELPER_IRC_PORTS, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT_HELPER_TFTP_PORTS[] = {
	{"<ports>", "comma-separated list of ports(max 8)", NULL, ip_nat_tftp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT_HELPER_TFTP[] = {
	{"ports", "comma-separated list of ports(max 8)", CMD_IP_NAT_HELPER_TFTP_PORTS, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT_HELPER[] = {
	{"ftp", "ftp NAT helper", CMD_IP_NAT_HELPER_FTP, ip_nat_ftp, 1, MSK_NORMAL},
	{"irc", "irc NAT helper", CMD_IP_NAT_HELPER_IRC, ip_nat_irc, 1, MSK_NORMAL},
	{"tftp", "tftp NAT helper", CMD_IP_NAT_HELPER_TFTP, ip_nat_tftp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_NAT[] = {
	{"helper", "NAT protocol helper", CMD_IP_NAT_HELPER, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_PIMD
cish_command CMD_NO_IP_PIM[] = {
	{"bsr-candidate", "Candidate bootstrap router (candidate BSR)", NULL, pim_bsr_candidate, 1, MSK_NORMAL},
#if 0
	{"register-rate-limit", "Rate limit for PIM data registers", CMD_NO_IP_PIM_RRL, NULL, 1, MSK_NORMAL},
#endif
	{"rp-address", "PIM RP-address (Rendezvous Point)", NULL, pim_rp_address, 1, MSK_NORMAL},
	{"rp-candidate", "To be a PIMv2 RP candidate", NULL, pim_rp_candidate, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_NO_IP_TCP[] = {
	{"ecn", "Disable Explicit Congestion Notification", NULL, no_ip_param, 1, MSK_NORMAL},
	{"syncookies", "Disable syn cookies", NULL, no_ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_NO_IP[] = {
	{"dhcp", "Disable DHCP server/relay", CMD_NO_IP_DHCP, NULL, 1, MSK_NORMAL},
	{"dns", "Configure DNS relay", CMD_IP_DNS, NULL, 1, MSK_NORMAL},
	{"domain", "Disable name lookup", CMD_IP_DOMAIN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_NET_FASTROUTE
	{"fastroute", "Enable interfaces fastroute (bypass firewall)", NULL, no_ip_param, 1, MSK_NORMAL},
#endif
#if 1 /* !!! */
	{"forwarding", "Disable IP forwarding", NULL, no_ip_param, 1, MSK_NORMAL},
#endif
#ifdef OPTION_HTTP
	{"http", "HTTP server configuration", CMD_NO_IP_HTTP, NULL, 1, MSK_NORMAL},
#endif
	{"icmp", "Unset icmp parameters", CMD_NO_IP_ICMP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_PIMD
	{"multicast-routing", "Disable IP multicast forwarding", NULL, no_ip_param, 1, MSK_NORMAL},
#endif
#ifdef OPTION_SMCROUTE
	{"mroute", "Establish multicast static routes", CMD_IP_MROUTE1, NULL, 1, MSK_NORMAL},
#endif
	{"name-server", "Specify address of name server to remove", CMD_IP_NAMESERVER, NULL, 1, MSK_NORMAL},
	{"nat", "NAT helper configuration", CMD_IP_NAT, NULL, 1, MSK_NORMAL},
#ifdef OPTION_PIMD
	{"pim", "PIM global commands", CMD_NO_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
	{"pmtu-discovery", "Disable Path MTU discovery", NULL, no_ip_param, 1, MSK_NORMAL},
	{"route", "Establish static routes", CMD_IP_ROUTE1, NULL, 1, MSK_NORMAL},
	{"routing", "Disable IP routing", NULL, no_ip_param, 1, MSK_NORMAL},
	{"rp-filter", "Disable reverse path filter", NULL, no_ip_param, 1, MSK_NORMAL},
	{"ssh", "SSH server configuration", CMD_NO_IP_SSH, NULL, 1, MSK_NORMAL},
	{"tcp", "Unset tcp parameters", CMD_NO_IP_TCP, NULL, 1, MSK_NORMAL},
	{"telnet", "Telnet server configuration", CMD_NO_IP_TELNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_PIMD
cish_command CMD_IP_PIM_CAND_BSR_PRIORITY_VALUE[] = {
	{"0-255", "Bigger value means higher priority", NULL, pim_bsr_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_BSR_PRIORITY[] = {
	{"priority", "BSR candidate priority", CMD_IP_PIM_CAND_BSR_PRIORITY_VALUE, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_BSR_INTF_ETHERNET[] = {
	{"0-0", "Ethernet interface number", CMD_IP_PIM_CAND_BSR_PRIORITY, pim_bsr_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_BSR_INTF_SERIAL[] = {
	{"0-0", "Serial interface number", CMD_IP_PIM_CAND_BSR_PRIORITY, pim_bsr_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_BSR_INTF[] = {
	{"ethernet", "Ethernet interface", CMD_IP_PIM_CAND_BSR_INTF_ETHERNET, NULL, 0, MSK_NORMAL},
	{"serial", "Serial interface", CMD_IP_PIM_CAND_BSR_INTF_SERIAL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_RP_ADDRESS[] = {
	{"<ipaddress>", "IP address of Rendezvous-point for group", NULL, pim_rp_address, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_INTERVAL_VALUE[] = {
	{"5-16383", "Number of seconds", NULL, pim_rp_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_INTERVAL[] = {
	{"interval", "RP candidate advertisement interval", CMD_IP_PIM_CAND_RP_INTERVAL_VALUE, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_PRIORITY_VALUE[] = {
	{"0-255", "Smaller value means higher priority", CMD_IP_PIM_CAND_RP_INTERVAL, pim_rp_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_PRIORITY[] = {
	{"priority", "RP candidate priority", CMD_IP_PIM_CAND_RP_PRIORITY_VALUE, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_INTF_ETHERNET[] = {
	{"0-0", "Ethernet interface number", CMD_IP_PIM_CAND_RP_PRIORITY, pim_rp_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_INTF_SERIAL[] = {
	{"0-0", "Serial interface number", CMD_IP_PIM_CAND_RP_PRIORITY, pim_rp_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_INTF[] = {
	{"ethernet", "Ethernet interface", CMD_IP_PIM_CAND_RP_INTF_ETHERNET, NULL, 0, MSK_NORMAL},
	{"serial", "Serial interface", CMD_IP_PIM_CAND_RP_INTF_SERIAL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM[] = {
	{"bsr-candidate", "Candidate bootstrap router (candidate BSR)", CMD_IP_PIM_CAND_BSR_INTF, NULL, 1, MSK_NORMAL},
#if 0
	{"register-rate-limit", "Rate limit for PIM data registers", CMD_IP_PIM_RRL, NULL, 1, MSK_NORMAL},
#endif
	{"rp-address", "PIM RP-address (Rendezvous Point)", CMD_IP_PIM_RP_ADDRESS, NULL, 1, MSK_NORMAL},
	{"rp-candidate", "To be a PIMv2 RP candidate", CMD_IP_PIM_CAND_RP_INTF, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef CONFIG_DEVELOPMENT
cish_command CMD_IP_MAXBACKLOG[] = {
	{"10-4096", "Max RX backlog size", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#if defined(CONFIG_NET_SKB_RECYCLING) && defined(CONFIG_DEVELOPMENT)
cish_command CMD_IP_RECYCLE_SIZE[] = {
	{"0-4096", "Set recycle pool size", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_RECYCLE[] = {
	{"max", "Recycle maximal pool size", CMD_IP_RECYCLE_SIZE, NULL, 1, MSK_NORMAL},
	{"min", "Recycle minimal pool size", CMD_IP_RECYCLE_SIZE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_IP_TCP_KEEPALIVE_INTVL[] = {
	{"1-32767", "Keepalive probe interval time (s)", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_TCP_KEEPALIVE_PROBES[] = {
	{"1-127", "Keepalive probe retries", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_TCP_KEEPALIVE_IDLE[] = {
	{"1-32767", "Keepalive idle timer (s)", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_TCP[] = {
	{"ecn", "Enable Explicit Congestion Notification", NULL, ip_param, 1, MSK_NORMAL},
	{"keepalive_intvl", "Keepalive probe interval time", CMD_IP_TCP_KEEPALIVE_INTVL, NULL, 1, MSK_NORMAL},
	{"keepalive_probes", "Keepalive probe retries", CMD_IP_TCP_KEEPALIVE_PROBES, NULL, 1, MSK_NORMAL},
	{"keepalive_time", "Keepalive idle timer", CMD_IP_TCP_KEEPALIVE_IDLE, NULL, 1, MSK_NORMAL},
	{"syncookies", "Enable syn cookies", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_BGP
cish_command CMD_IP_AS_PATH3[] = {
	{"<text>", "A regular-expression to match BGP AS paths."
	"Use \"ctrl-v ?\" to enter \"?\"", NULL, bgp_execute_root_cmd, 1, MSK_BGP},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_AS_PATH2[] = {
	{"deny", "Specify packets to reject", CMD_IP_AS_PATH3, NULL, 1, MSK_BGP},
	{"permit", "Specify packets to forward", CMD_IP_AS_PATH3, NULL, 1, MSK_BGP},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_AS_PATH1[] = {
	{"<text>", "Regular expression access list name", CMD_IP_AS_PATH2, NULL, 1, MSK_BGP},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_AS_PATH[] = {
	{"access-list", "Specify an access list name", CMD_IP_AS_PATH1, NULL, 1, MSK_BGP},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IP[] = {
#ifdef OPTION_BGP
	{"as-path", "BGP autonomous system path filter", CMD_IP_AS_PATH, NULL, 1, MSK_BGP},
#endif
	{"cache-flush", "Routing cache flush", NULL, ip_param, 1, MSK_NORMAL},
	{"default-ttl", "Default TTL value", CMD_IP_DEFAULT_TTL, NULL, 1, MSK_NORMAL},
	{"dhcp", "Enable DHCP server/relay", CMD_IP_DHCP, NULL, 1, MSK_NORMAL},
	{"dns", "Configure DNS relay", CMD_IP_DNS, NULL, 1, MSK_NORMAL},
	{"domain", "Enable name lookup", CMD_IP_DOMAIN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_NET_FASTROUTE
	{"fastroute", "Enable interfaces fastroute (bypass firewall)", NULL, ip_param, 1, MSK_NORMAL},
#endif
#if 1 /* Old compatibility! */
	{"forwarding", "Enable IP forwarding", NULL, ip_param, 1, MSK_NORMAL},
#endif
	{"fragment", "Set fragmenting parameters", CMD_IP_FRAG, NULL, 1, MSK_NORMAL},
#ifdef OPTION_HTTP
	{"http", "HTTP server configuration", CMD_IP_HTTP, NULL, 1, MSK_NORMAL},
#endif
	{"icmp", "Set icmp parameters", CMD_IP_ICMP, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"max_backlog", "Set maximum RX packets backlog", CMD_IP_MAXBACKLOG, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PIMD
	{"multicast-routing", "Enable IP multicast forwarding", NULL, ip_param, 1, MSK_NORMAL},
#endif
#ifdef OPTION_SMCROUTE
	{"mroute", "Establish multicast static routes", CMD_IP_MROUTE1, NULL, 1, MSK_NORMAL},
#endif
	{"name-server", "Specify address of name server to add", CMD_IP_NAMESERVER, NULL, 1, MSK_NORMAL},
	{"nat", "NAT helper configuration", CMD_IP_NAT, NULL, 1, MSK_NORMAL},
#ifdef OPTION_PIMD
	{"pim", "PIM global commands", CMD_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
	{"pmtu-discovery", "Enable Path MTU discovery", NULL, ip_param, 1, MSK_NORMAL},
#if defined(CONFIG_NET_SKB_RECYCLING) && defined(CONFIG_DEVELOPMENT)
	{"recycle", "Packet recycle options", CMD_IP_RECYCLE, NULL, 1, MSK_NORMAL},
#endif
	{"route", "Establish static routes", CMD_IP_ROUTE1, NULL, 1, MSK_NORMAL},
	{"routing", "Enable IP routing", NULL, ip_param, 1, MSK_NORMAL},
	{"rp-filter", "Enable reverse path filter", NULL, ip_param, 1, MSK_NORMAL},
	{"ssh", "SSH server configuration", CMD_IP_SSH, NULL, 1, MSK_NORMAL},
	{"tcp", "Set tcp parameters", CMD_IP_TCP, NULL, 1, MSK_NORMAL},
	{"telnet", "Telnet server configuration", CMD_IP_TELNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#if 0
cish_command CMD_IPX_ROUTE3[] = {
	{"<ipx node>", "Router node", NULL, ipx_route, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPX_ROUTE2[] = {
	{"<ipx network>", "Router network", CMD_IPX_ROUTE3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IPX_ROUTE1[] = {
	{"<ipx network>", "Destination network", CMD_IPX_ROUTE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IPX[] = {
#if 0
	{"route", "Set an IPX static routing table entry", CMD_IPX_ROUTE1, ip_route, 1, MSK_NORMAL},
#endif
	{"routing", "Enable IPX routing", NULL, ipx_routing, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_AUX_[] = {
	{"0-1", "Aux interface number", NULL, config_interface, 0, MSK_AUX},
	{NULL,NULL,NULL,NULL, 0}
};

#if 0
cish_command CMD_CONFIG_INTERFACE_BRIDGE_[] = {
	{"1-1", "Bridge number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_ETHERNET_[] = {
	{"0-0", "Ethernet interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_[] = {
	{"0-4", "Loopback interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_[] = {
	{"0-0", "Serial interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_[] = {
	{"0-9", "Tunnel interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE[] = {
	{"aux", "Aux interface", CMD_CONFIG_INTERFACE_AUX_, NULL, 0, MSK_AUX},
	{"ethernet", "Ethernet interface", CMD_CONFIG_INTERFACE_ETHERNET_, NULL, 0, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_CONFIG_INTERFACE_LOOPBACK_, NULL, 0, MSK_NORMAL},
	{"serial", "Serial interface", CMD_CONFIG_INTERFACE_SERIAL_, NULL, 0, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_CONFIG_INTERFACE_TUNNEL_, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_INTERFACE[] = {
	{"tunnel", "Tunnel interface", CMD_CONFIG_INTERFACE_TUNNEL_, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_NO_ACL[] = {
	{"<acl>","Access lists name", NULL, no_accesslist, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_MANGLE[] = {
	{"<acl>","MARK rule name", NULL, no_mangle_rule, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_NAT[] = {
	{"<acl>","NAT rule name", NULL, no_nat_rule, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

#ifdef OPTION_NTPD
cish_command CMD_NO_NTP_RESTRICT[] = {
	{"<ipaddress>","Exclude one rule", NULL, no_ntp_restrict, 1, MSK_NORMAL},
	{"<enter>", "Exclude all rules", NULL, NULL, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_NTP_SERVER[] = {
	{"<ipaddress>","Exclude one server", NULL, no_ntp_server, 1, MSK_NORMAL},
	{"<enter>", "Exclude all servers", NULL, NULL, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_NTP_TRUSTEDKEYS[] = {
	{"1-16","Exclude one key from trusted list", NULL, no_ntp_trustedkeys, 1, MSK_NORMAL},
	{"<enter>", "Exclude all keys from trusted list", NULL, NULL, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};

cish_command CMD_NO_NTP[] = {
#ifdef OPTION_NTPD_authenticate
	{"authenticate","Use of authentication", NULL, no_ntp_authenticate, 1, MSK_NORMAL},
#endif
	{"restrict","NTP restriction rules", CMD_NO_NTP_RESTRICT, no_ntp_restrict, 1, MSK_NORMAL},
	{"server","NTP servers", CMD_NO_NTP_SERVER, no_ntp_server, 1, MSK_NORMAL},
	{"trusted-key","Trusted keys", CMD_NO_NTP_TRUSTEDKEYS, no_ntp_trustedkeys, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif

cish_command CMD_CONFIG_NO_CHATSCRIPT[] = {
	{"<text>","Chatscript name", NULL, ppp_nochatscript, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NO_LOG[] = {
	{"remote","Disable remote logging", NULL, no_log_remote, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NO_BRIDGE2[] = {
	{"spanning-disabled", "Enable spanning tree", NULL, bridge_stp, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NO_BRIDGE[] = {
	{"1-1", "Bridge Group number for Bridging", CMD_CONFIG_NO_BRIDGE2, bridge_no, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_NO_SECRET[] = {
	{"login", "Disable login password", NULL, set_nosecret, 1, MSK_NORMAL},
	{"enable", "Disable privileged password", NULL, set_nosecret, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_BGP
cish_command CMD_CONFIG_NO_ROUTER_BGP[] = {
	{"1-65535", "AS number", NULL, config_no_router, 1, MSK_BGP},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_NO_ROUTER[] = {
#ifdef OPTION_BGP
	{"bgp", "Border Gateway Protocol (BGP)", CMD_CONFIG_NO_ROUTER_BGP, NULL, 1, MSK_BGP},
#endif
	{"ospf", "Open Shortest Path First (OSPF)", NULL, config_no_router, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol (RIP)", NULL, config_no_router, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT[] = {
	{"default", "The default authentication list", NULL, cmd_aaa_authen, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHENTICATION[] = {
#ifdef CONFIG_BERLIN_SATROUTER
	{"enable", "Set authentication list for enable.", CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_NORMAL},
#endif
	{"login", "Set authentication lists for logins.", CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_SPPP_NETLINK
	{"ppp", "Set authentication lists for ppp.", CMD_CONFIG_NO_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_USERNAME[] = {
	{"<text>", "User name", NULL, del_user, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHOR_DEFAULT[] = {
	{"default", "The default authorization list", NULL, cmd_aaa_author, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_AUTHOR[] = {
	{"exec", "For starting an exec (shell)", CMD_CONFIG_NO_AAA_AUTHOR_DEFAULT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_ACCT_DEFAULT[] = {
	{"default", "The default accounting list", NULL, cmd_aaa_acct, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_ACCT1[] = {
	{"0-15", "Enable Level", CMD_CONFIG_NO_AAA_ACCT_DEFAULT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA_ACCT[] = {
	{"commands", "For exec (shell) commands", CMD_CONFIG_NO_AAA_ACCT1, NULL, 1, MSK_NORMAL},
	{"exec", "For starting an exec (shell)", CMD_CONFIG_NO_AAA_ACCT_DEFAULT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_AAA[] = {
	{"authentication", "Authentication configurations parameters", CMD_CONFIG_NO_AAA_AUTHENTICATION, NULL, 1, MSK_NORMAL},
	{"authorization", "Authorization configurations parameters", CMD_CONFIG_NO_AAA_AUTHOR, NULL, 1, MSK_NORMAL},
	{"accounting", "Accounting configurations parameters", CMD_CONFIG_NO_AAA_ACCT, NULL, 1, MSK_NORMAL},
	{"username", "Establish User Name Authentication", CMD_CONFIG_NO_AAA_USERNAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_RADIUSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of RADIUS server", NULL, del_radiusserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_RADIUSSERVER_HOST[] = {
	{"host", "Specify a RADIUS server", CMD_CONFIG_NO_RADIUSSERVER_HOSTIP, NULL, 1, MSK_NORMAL},
	{"<enter>", "Clear RADIUS servers", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_TACACSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of TACACS server", NULL, del_tacacsserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_TACACSSERVER_HOST[] = {
	{"host", "Specify a TACACS server", CMD_CONFIG_NO_TACACSSERVER_HOSTIP, NULL, 1, MSK_NORMAL},
	{"<enter>", "Clear TACACS servers", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_RMON
cish_command CMD_CONFIG_NO_RMON_ALARM[] = {
	{"1-25", "Alarm number", NULL, no_rmon_alarm, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_RMON_EVENT[] = {
	{"1-25", "Event number", NULL, no_rmon_event, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_RMON[] = {
	{"agent", "Stop RMON agent", NULL, no_rmon_agent, 1, MSK_NORMAL},
	{"event", "Remove event", CMD_CONFIG_NO_RMON_EVENT, no_rmon_event, 1, MSK_NORMAL},
	{"alarm", "Remove alarm", CMD_CONFIG_NO_RMON_ALARM, no_rmon_alarm, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_NO_ARP_IP[] = {
	{"<ipaddress>", "IP address of ARP entry", NULL, arp_entry, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_X25XOT
cish_command CMD_X25_ROUTE5[] = {
	{"<ipaddress>", "Address of remote XOT host", NULL, x25_route_xot, 1, MSK_X25XOT},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_X25
cish_command CMD_X25_ROUTE4[] = {
	{"0-0", "Serial interface number", NULL, x25_route_interface, 0, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_X25_ROUTE3[] = {
	{"serial", "Serial interface", CMD_X25_ROUTE4, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_X25_ROUTE2[] = {
	{"interface", "Route to a local interface", CMD_X25_ROUTE3, NULL, 1, MSK_X25},
#ifdef OPTION_X25XOT
	{"xot", "Route to a remote host using XOT (X.25-Over-TCP)", CMD_X25_ROUTE5, NULL, 1, MSK_X25XOT},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_X25_ROUTE1[] = {
	{"<x121>", "Destination X.121 route to match <address>[/<mask>]", CMD_X25_ROUTE2, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_X25_NO[] = {
	{"route","Add an entry to the X.25 routing table", CMD_X25_ROUTE1, NULL, 1, MSK_X25},
#ifdef OPTION_X25XOT
	{"routing","Enable X.25 switching", NULL, x25_param, 1, MSK_X25XOT},
#endif
	{NULL,NULL,NULL,NULL, 0}
};
#endif /* OPTION_X25 */

#ifdef CONFIG_BERLIN_SATROUTER
cish_command CMD_CONFIG_NO_ENABLESECRET[] = {
	{"secret", "No secret required for privileged level", NULL, clear_enable_secret, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_NEW_QOS_CONFIG
cish_command CMD_CONFIG_POLICYMAP[] = {
	{"<text>","policy-map name", NULL, do_policymap, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_NO[] = {
	{"aaa","Authentication, Authorization and Accounting.", CMD_CONFIG_NO_AAA, NULL, 1, MSK_NORMAL},
	{"access-list","Remove access-list", CMD_NO_ACL, NULL, 1, MSK_NORMAL},
	{"arp", "Unset a static ARP entry", CMD_NO_ARP_IP, NULL, 1, MSK_NORMAL},
	{"bridge", "Bridging Group", CMD_CONFIG_NO_BRIDGE, NULL, 1, MSK_NORMAL},
	{"chatscript", "Reset a chatscript", CMD_CONFIG_NO_CHATSCRIPT, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_BERLIN_SATROUTER
	{"enable", "Modify enable secret parameters", CMD_CONFIG_NO_ENABLESECRET, NULL, 1, MSK_NORMAL},
#endif
	{"interface","Interface Configuration", CMD_CONFIG_NO_INTERFACE, NULL, 1, MSK_NORMAL},
	{"ip","IPv4 Configuration", CMD_NO_IP, NULL, 1, MSK_NORMAL},
	{"ipx","IPX Configuration", CMD_NO_IPX, NULL, 1, MSK_NORMAL},
	{"key","Authentication key management (RIP)", CMD_CONFIG_KEY, NULL, 1, MSK_RIP},
	{"logging", "Unset a logging target", CMD_CONFIG_NO_LOG, NULL, 1, MSK_NORMAL},
	{"mark-rule","Remove MARK rule", CMD_NO_MANGLE, NULL, 1, MSK_QOS},
	{"nat-rule","Remove NAT rule", CMD_NO_NAT, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NTPD
	{"ntp", "NTP Configuration", CMD_NO_NTP, NULL, 1, MSK_NORMAL},
#else
	{"ntp-sync", "Disable NTP synchronization", NULL, no_ntp_sync, 1, MSK_NORMAL},
#endif
#ifdef OPTION_NEW_QOS_CONFIG
	{"policy-map", "Configure QoS Policy Map", CMD_CONFIG_POLICYMAP, NULL, 1, MSK_QOS},
#endif
	{"radius-server", "Modify RADIUS query parameters", CMD_CONFIG_NO_RADIUSSERVER_HOST, 
								del_radiusserver, 1, MSK_NORMAL},
#ifdef OPTION_RMON
	{"rmon", "Modify RMON settings", CMD_CONFIG_NO_RMON, NULL, 1, MSK_NORMAL},
#endif
	{"router", "Disable a routing process", CMD_CONFIG_NO_ROUTER, NULL, 1, MSK_NORMAL},
	{"secret", "Disable authentication secrets", CMD_NO_SECRET, NULL, 1, MSK_NORMAL},
	{"snmp-server", "Remove SNMP settings", CMD_CONFIG_NO_SNMP, snmp_no_server, 1, MSK_NORMAL},
	{"tacacs-server", "Modify TACACS query parameters", CMD_CONFIG_NO_TACACSSERVER_HOST, 
								del_tacacsserver, 1, MSK_NORMAL},
#ifdef OPTION_X25
	{"x25","X.25 Level 3", CMD_X25_NO, NULL, 1, MSK_X25},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

/* BEGIN OF ACCESS-LIST CONFIGURATION */

cish_command CMD_CONFACL_LENGTH_1[] = {
	{"<min:max>", "Length range", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#define CMD_CONFACL_TCP_101_LOOP CMD_CONFACL_TCP_101
cish_command CMD_CONFACL_TCP_101[] = {
	{"established","Match packets associated with established connections", CMD_CONFACL_TCP_101_LOOP, do_accesslist, 1, MSK_NORMAL},
	{"new","Match packets starting new connections", CMD_CONFACL_TCP_101_LOOP, do_accesslist, 1, MSK_NORMAL},
	{"related","Match packets starting new connections associated with existing connections", CMD_CONFACL_TCP_101_LOOP, do_accesslist, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};	

cish_command CMD_CONFACL_TCP_100_FLAGS[] = {
	{"<flags>", "mask/comp flags: FIN(0x01),SYN(0x02),RST(0x04),PSH(0x08),ACK(0x10),URG(0x20),ALL(0x3F)", CMD_CONFACL_TCP_101, do_accesslist, 1, MSK_NORMAL},
	{"syn","Match only tcp packets with SYN bit set (SYN,RST,ACK/SYN)", CMD_CONFACL_TCP_101, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_TCP_100_TOS[] = {
	{"16","Minimize-Delay", CMD_CONFACL_TCP_101, do_accesslist, 1, MSK_NORMAL},
	{"8", "Maximize-Throughput", CMD_CONFACL_TCP_101, do_accesslist, 1, MSK_NORMAL},
	{"4", "Maximize-Reliability", CMD_CONFACL_TCP_101, do_accesslist, 1, MSK_NORMAL},
	{"2", "Minimize-Cost", CMD_CONFACL_TCP_101, do_accesslist, 1, MSK_NORMAL},
	{"0", "Normal-Service", CMD_CONFACL_TCP_101, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_UDP_100_TOS[] = {
	{"16","Minimize-Delay", NULL, do_accesslist, 1, MSK_NORMAL},
	{"8", "Maximize-Throughput", NULL, do_accesslist, 1, MSK_NORMAL},
	{"4", "Maximize-Reliability", NULL, do_accesslist, 1, MSK_NORMAL},
	{"2", "Minimize-Cost", NULL, do_accesslist, 1, MSK_NORMAL},
	{"0", "Normal-Service", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

#define CMD_CONFACL_TCP_99_LOOP CMD_CONFACL_TCP_99
cish_command CMD_CONFACL_TCP_99[] = {
	{"established","Match packets associated with established connections", CMD_CONFACL_TCP_99_LOOP, do_accesslist, 1, MSK_NORMAL},
	{"flags","Match only tcp packets when TCP flags & mask == comp", CMD_CONFACL_TCP_100_FLAGS, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_accesslist, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFACL_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"new","Match packets starting new connections", CMD_CONFACL_TCP_99_LOOP, do_accesslist, 1, MSK_NORMAL},
	{"related","Match packets starting new connections associated with existing connections", CMD_CONFACL_TCP_99_LOOP, do_accesslist, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFACL_TCP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_UDP_99[] = {
	{"fragments", "Match packets with fragment bit set", NULL, do_accesslist, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFACL_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFACL_UDP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_TCP_41[] = {
	{"<port>","Port number or service name", CMD_CONFACL_TCP_99, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_UDP_41[] = {
	{"<port>","Port number or service name", CMD_CONFACL_UDP_99, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_TCP_41B[] = {
	{"<port>","Port number or service name", CMD_CONFACL_TCP_41, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_UDP_41B[] = {
	{"<port>","Port number or service name", CMD_CONFACL_UDP_41, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_ANY_40[] = {
	{"fragments", "Match packets with fragment bit set", NULL, do_accesslist, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFACL_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFACL_UDP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_TCP_40[] = {
	{"eq","Match only packets on a given port", CMD_CONFACL_TCP_41, NULL, 1, MSK_NORMAL},
	{"established","Match packets associated with established connections", CMD_CONFACL_TCP_99, do_accesslist, 1, MSK_NORMAL},
	{"flags","Match only tcp packets when TCP flags & mask == comp", CMD_CONFACL_TCP_100_FLAGS, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_accesslist, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFACL_TCP_41, NULL, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFACL_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFACL_TCP_41, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFACL_TCP_41, NULL, 1, MSK_NORMAL},
	{"new","Match packets starting new connections", CMD_CONFACL_TCP_99, do_accesslist, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFACL_TCP_41B, NULL, 1, MSK_NORMAL},
	{"related","Match packets starting new connections associated with existing connections", CMD_CONFACL_TCP_99, do_accesslist, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFACL_TCP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_UDP_40[] = {
	{"eq","Match only packets on a given port", CMD_CONFACL_UDP_41, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_accesslist, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFACL_UDP_41, NULL, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFACL_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFACL_UDP_41, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFACL_UDP_41, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFACL_UDP_41B, NULL, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFACL_UDP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFACL_ANY_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFACL_ANY_40, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_TCP_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFACL_TCP_40, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_UDP_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFACL_UDP_40, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_ANY_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFACL_ANY_40, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_TCP_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFACL_TCP_40, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_UDP_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFACL_UDP_40, do_accesslist, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_TCP_22[] = {
	{"any","Any destination host", CMD_CONFACL_TCP_40, do_accesslist, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFACL_TCP_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFACL_TCP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFACL_UDP_22[] = {
	{"any","Any destination host", CMD_CONFACL_UDP_40, do_accesslist, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFACL_UDP_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFACL_UDP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFACL_TCP_21[] = {
	{"<port>","Port number or service name", CMD_CONFACL_TCP_22, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFACL_UDP_21[] = {
	{"<port>","Port number or service name", CMD_CONFACL_UDP_22, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFACL_TCP_21B[] = {
	{"<port>","Port number or service name", CMD_CONFACL_TCP_21, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFACL_UDP_21B[] = {
	{"<port>","Port number or service name", CMD_CONFACL_UDP_21, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFACL_ANY_20[] = {
	{"any","Any destination host", CMD_CONFACL_ANY_40, do_accesslist, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFACL_ANY_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFACL_ANY_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFACL_TCP_20[] = {
	{"any","Any destination host", CMD_CONFACL_TCP_40, do_accesslist, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFACL_TCP_21, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFACL_TCP_21, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFACL_TCP_26, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFACL_TCP_21, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFACL_TCP_21, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFACL_TCP_21B, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFACL_TCP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFACL_UDP_20[] = {
	{"any","Any destination host", CMD_CONFACL_UDP_40, do_accesslist, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFACL_UDP_21, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFACL_UDP_21, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFACL_UDP_26, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFACL_UDP_21, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFACL_UDP_21, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFACL_UDP_21B, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFACL_UDP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFACL_ANY_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFACL_ANY_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_TCP_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFACL_TCP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_UDP_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFACL_UDP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_ANY_6[] = {
	{"<ipaddress>","Source address", CMD_CONFACL_ANY_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_TCP_6[] = {
	{"<ipaddress>","Source address", CMD_CONFACL_TCP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_UDP_6[] = {
	{"<ipaddress>","Source address", CMD_CONFACL_UDP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_ANY_4[] = {
	{"any","Any source host", CMD_CONFACL_ANY_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFACL_ANY_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFACL_ANY_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_MAC_4[] = {
	{"<mac>","MAC address (xx:xx:xx:xx:xx:xx)", NULL, do_accesslist_mac, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_ICMP_TYPE_3_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-unreachable","network-unreachable ICMP type code (0)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-unreachable","host-unreachable ICMP type code (1)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"protocol-unreachable","protocol-unreachable ICMP type code (2)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"port-unreachable","port-unreachable ICMP type code (3)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"fragmentation-needed","fragmentation-needed ICMP type code (4)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"source-route-failed","source-route-failed ICMP type code (5)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-unknown","network-unknown ICMP type code (6)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-unknown","host-unknown ICMP type code (7)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-prohibited","network-prohibited ICMP type code (9)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-prohibited","host-prohibited ICMP type code (10)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-network-unreachable","TOS-network-unreachable ICMP type code (11)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-host-unreachable","TOS-host-unreachable ICMP type code (12)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"communication-prohibited","communication-prohibited ICMP type code (13)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-precedence-violation","host-precedence-violation ICMP type code (14)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"precedence-cutoff","precedence-cutoff ICMP type code (15)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_ICMP_TYPE_5_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-redirect","network-redirect ICMP type code (0)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-redirect","host-redirect ICMP type code (1)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-network-redirect","TOS-network-redirect ICMP type code (2)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-host-redirect","TOS-host-redirect ICMP type code (3)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_ICMP_TYPE_11_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"ttl-zero-during-transit","ttl-zero-during-transit ICMP type code (0)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"ttl-zero-during-reassembly","ttl-zero-during-reassembly ICMP type code (1)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_ICMP_TYPE_12_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"ip-header-bad","ip-header-bad ICMP type code (0)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"required-option-missing","required-option-missing ICMP type code (1)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_ICMP_TYPE[] = {
	{"any","Any ICMP type (255)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"echo-reply","echo-reply (pong) ICMP type (0)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"destination-unreachable","destination-unreachable ICMP type (3)", CMD_CONFACL_ICMP_TYPE_3_CODE, NULL, 1, MSK_NORMAL},
	{"source-quench","source-quench ICMP type (4)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"redirect","redirect ICMP type (5)", CMD_CONFACL_ICMP_TYPE_5_CODE, NULL, 1, MSK_NORMAL},
	{"echo-request","echo-request (ping) ICMP type (8)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"router-advertisement","router-advertisement ICMP type (9)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"router-solicitation","router-solicitation ICMP type (10)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"time-exceeded","time-exceeded (ttl-exceeded) ICMP type (11)", CMD_CONFACL_ICMP_TYPE_11_CODE, NULL, 1, MSK_NORMAL},
	{"parameter-problem","parameter-problem ICMP type (12)", CMD_CONFACL_ICMP_TYPE_12_CODE, NULL, 1, MSK_NORMAL},
	{"timestamp-request","timestamp-request ICMP type (13)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"timestamp-reply","timestamp-reply ICMP type (14)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"address-mask-request","address-mask-request ICMP type (17)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"address-mask-reply","address-mask-reply ICMP type (18)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_ICMP_4[] = {
	{"any","Any source host", CMD_CONFACL_ANY_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFACL_ANY_6, NULL, 1, MSK_NORMAL},
	{"type","ICMP type", CMD_CONFACL_ICMP_TYPE, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFACL_ANY_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_TCP_4[] = {
	{"any","Any source host", CMD_CONFACL_TCP_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFACL_TCP_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFACL_TCP_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL_UDP_4[] = {
	{"any","Any source host", CMD_CONFACL_UDP_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFACL_UDP_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFACL_UDP_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL3_TCPMSS_TCP[] = {
	{"tcp","Transmission Control Protocol", CMD_CONFACL_TCP_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFACL3_TCPMSS[] = {
	{"64-1500","Explicitly set MSS option to specified value", CMD_CONFACL3_TCPMSS_TCP, NULL, 1, MSK_NORMAL},
	{"pmtu", "Automatically clamp MSS value to (path_MTU - 40)", CMD_CONFACL3_TCPMSS_TCP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

/* Layer 7 support*/
cish_command CMD_CONFACL_LAYER7_NEWENTRY[] = {
	{"<text>","A regular expression for matching patterns", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL_LAYER7_1[] = {
	{"bgp", "The Border Gateway Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"bittorrent", "The Bittorrent Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"cvs", "The Concurrent Versioning System", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"dhcp", "The Dynamic Host Configuration Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"dns", "The Domain Name Server Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"fasttrack", "The Fasttrack Protocol (P2P)", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"ftp", "The File Transfer Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"http", "The Hypertext Transfer Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"http-rtsp", "The Real Time Streaming Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"msnmessenger", "The MSN Messenger Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"netbios", "The netBIOS Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"ntp", "The Network Time Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"pop3", "The Post Office Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"rtp", "The Real-time Transfer Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"skypeout", "The Skypeout Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"skypetoskype", "The Skype Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"smb", "The Samba protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"smtp", "The Simple Mail Transfer Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"snmp", "The Simple Network Management Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"ssh", "The Secure Shell Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"ssl", "The Secure Sockets Layer Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"subversion", "The Subversion Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"telnet", "The Telecommunication Network Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"tftp", "The Trivial File Transfer Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"<text>", "Name of a new entry", CMD_CONFACL_LAYER7_NEWENTRY, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
/* End of Layer 7 support */


cish_command CMD_CONFACL3[] = {
	{"0-255", "An IP protocol number", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"icmp","Internet Control Message Protocol", CMD_CONFACL_ICMP_4, NULL, 1, MSK_NORMAL},
	{"ip","Any Internet Protocol", CMD_CONFACL_ANY_4, NULL, 1, MSK_NORMAL},
	{"layer7","A layer 7 protocol", CMD_CONFACL_LAYER7_1, NULL, 1, MSK_NORMAL},
	{"mac","Source MAC address", CMD_CONFACL_MAC_4, NULL, 1, MSK_NORMAL},
	{"tcp","Transmission Control Protocol", CMD_CONFACL_TCP_4, NULL, 1, MSK_NORMAL},
	{"udp","User Datagram Protocol", CMD_CONFACL_UDP_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACL2B[] = {
	{"accept","Specify packets to accept", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"drop","Specify packets to drop", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"log","Specify packets to log", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"reject","Specify packets to reject", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"tcpmss","Specify packets to change mss", CMD_CONFACL3_TCPMSS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFACL2[] = {
	{"accept","Specify packets to accept", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"drop","Specify packets to drop", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"insert","Insert a matching rule on top", CMD_CONFACL2B, NULL, 1, MSK_NORMAL},
	{"log","Specify packets to log", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"no","Remove a matching rule", CMD_CONFACL2B, NULL, 1, MSK_NORMAL},
	{"reject","Specify packets to reject", CMD_CONFACL3, NULL, 1, MSK_NORMAL},
	{"tcpmss","Specify packets to change mss", CMD_CONFACL3_TCPMSS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFACL1[] = {
	{"<acl>","Access list name", CMD_CONFACL2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
/* END OF ACCESS-LIST CONFIGURATION */

/* BEGIN MARK-RULE CONFIGURATION */

cish_command CMD_CONFMANGLE_LENGTH_1[] = {
	{"<min:max>", "Length range", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#define CMD_CONFMANGLE_TCP_101_LOOP CMD_CONFMANGLE_TCP_101
cish_command CMD_CONFMANGLE_TCP_101[] = {
	{"established","Match packets associated with established connections", CMD_CONFMANGLE_TCP_101_LOOP, do_mangle, 1, MSK_NORMAL},
	{"new","Match packets starting new connections", CMD_CONFMANGLE_TCP_101_LOOP, do_mangle, 1, MSK_NORMAL},
	{"related","Match packets starting new connections associated with existing connections", CMD_CONFMANGLE_TCP_101_LOOP, do_mangle, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFMANGLE_UDP_100_DSCPCLASS[] = {
	{"AF11","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF12","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF13","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF21","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF22","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF23","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF31","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF32","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF33","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF41","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF42","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"AF43","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"BE","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"CS1","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"CS2","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"CS3","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"CS4","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"CS5","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"CS6","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"CS7","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"EF","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
cish_command CMD_CONFMANGLE_UDP_100_DSCP[] = {
	{"0-63","DSCP to compare", NULL, do_mangle, 1, MSK_NORMAL},
	{"class","DSCP class to compare", CMD_CONFMANGLE_UDP_100_DSCPCLASS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_TCP_100_DSCPCLASS[] = {
	{"AF11","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF12","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF13","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF21","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF22","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF23","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF31","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF32","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF33","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF41","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF42","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"AF43","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"BE","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"CS1","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"CS2","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"CS3","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"CS4","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"CS5","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"CS6","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"CS7","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"EF","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
cish_command CMD_CONFMANGLE_TCP_100_DSCP[] = {
	{"0-63","DSCP to compare", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"class","DSCP class to compare", CMD_CONFMANGLE_TCP_100_DSCPCLASS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_TCP_100_FLAGS[] = {
	{"<flags>", "Mask/Comp flags: FIN(0x01),SYN(0x02),RST(0x04),PSH(0x08),ACK(0x10),URG(0x20),ALL(0x3F)", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"syn","Match only tcp packets with SYN bit set (SYN,RST,ACK/SYN)", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_TCP_100_TOS[] = {
	{"16","Minimize-Delay", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"8", "Maximize-Throughput", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"4", "Maximize-Reliability", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"2", "Minimize-Cost", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{"0", "Normal-Service", CMD_CONFMANGLE_TCP_101, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_UDP_100_TOS[] = {
	{"16","Minimize-Delay", NULL, do_mangle, 1, MSK_NORMAL},
	{"8", "Maximize-Throughput", NULL, do_mangle, 1, MSK_NORMAL},
	{"4", "Maximize-Reliability", NULL, do_mangle, 1, MSK_NORMAL},
	{"2", "Minimize-Cost", NULL, do_mangle, 1, MSK_NORMAL},
	{"0", "Normal-Service", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

#define CMD_CONFMANGLE_TCP_99_LOOP CMD_CONFMANGLE_TCP_99
cish_command CMD_CONFMANGLE_TCP_99[] = {
	{"dscp","Match packets with given DSCP value", CMD_CONFMANGLE_TCP_100_DSCP, NULL, 1, MSK_NORMAL},
	{"established","Match packets associated with established connections", CMD_CONFMANGLE_TCP_99_LOOP, do_mangle, 1, MSK_NORMAL},
	{"flags","Match only tcp packets when TCP flags & mask == comp", CMD_CONFMANGLE_TCP_100_FLAGS, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_mangle, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFMANGLE_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"new","Match packets starting new connections", CMD_CONFMANGLE_TCP_99_LOOP, do_mangle, 1, MSK_NORMAL},
	{"related","Match packets starting new connections associated with existing connections", CMD_CONFMANGLE_TCP_99_LOOP, do_mangle, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFMANGLE_TCP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_UDP_99[] = {
	{"dscp","Match packets with given DSCP value", CMD_CONFMANGLE_UDP_100_DSCP, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_mangle, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFMANGLE_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFMANGLE_UDP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFMANGLE_TCP_41[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_TCP_99, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_UDP_41[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_UDP_99, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_TCP_41B[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_TCP_41, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_UDP_41B[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_UDP_41, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFMANGLE_ANY_40[] = {
	{"dscp","Match packets with given DSCP value", CMD_CONFMANGLE_UDP_100_DSCP, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_mangle, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFMANGLE_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFMANGLE_UDP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_TCP_40[] = {
	{"dscp","Match packets with given DSCP value", CMD_CONFMANGLE_TCP_100_DSCP, NULL, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFMANGLE_TCP_41, NULL, 1, MSK_NORMAL},
	{"established","Match packets associated with established connections", CMD_CONFMANGLE_TCP_99, do_mangle, 1, MSK_NORMAL},
	{"flags","Match only tcp packets when TCP flags & mask == comp", CMD_CONFMANGLE_TCP_100_FLAGS, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_mangle, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFMANGLE_TCP_41, NULL, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFMANGLE_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFMANGLE_TCP_41, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFMANGLE_TCP_41, NULL, 1, MSK_NORMAL},
	{"new","Match packets starting new connections", CMD_CONFMANGLE_TCP_99, do_mangle, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFMANGLE_TCP_41B, NULL, 1, MSK_NORMAL},
	{"related","Match packets starting new connections associated with existing connections", CMD_CONFMANGLE_TCP_99, do_mangle, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFMANGLE_TCP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_UDP_40[] = {
	{"dscp","Match packets with given DSCP value", CMD_CONFMANGLE_UDP_100_DSCP, NULL, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFMANGLE_UDP_41, NULL, 1, MSK_NORMAL},
	{"fragments", "Match packets with fragment bit set", NULL, do_mangle, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFMANGLE_UDP_41, NULL, 1, MSK_NORMAL},
	{"length", "Match packets within a length range", CMD_CONFMANGLE_LENGTH_1, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFMANGLE_UDP_41, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFMANGLE_UDP_41, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFMANGLE_UDP_41B, NULL, 1, MSK_NORMAL},
	{"tos","Match packets with given TOS value", CMD_CONFMANGLE_UDP_100_TOS, NULL, 1, MSK_NORMAL},
	{"<enter>","Enter rule", NULL, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_ANY_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFMANGLE_ANY_40, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_TCP_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFMANGLE_TCP_40, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_UDP_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFMANGLE_UDP_40, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_ANY_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_ANY_40, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_TCP_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_TCP_40, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_UDP_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_UDP_40, do_mangle, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_TCP_22[] = {
	{"any","Any destination host", CMD_CONFMANGLE_TCP_40, do_mangle, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFMANGLE_TCP_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_TCP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_UDP_22[] = {
	{"any","Any destination host", CMD_CONFMANGLE_UDP_40, do_mangle, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFMANGLE_UDP_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_UDP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFMANGLE_TCP_21[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_TCP_22, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_UDP_21[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_UDP_22, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFMANGLE_TCP_21B[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_TCP_21, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_UDP_21B[] = {
	{"<port>","Port number or service name", CMD_CONFMANGLE_UDP_21, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFMANGLE_ANY_20[] = {
	{"any","Any destination host", CMD_CONFMANGLE_ANY_40, do_mangle, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFMANGLE_ANY_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_ANY_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_TCP_20[] = {
	{"any","Any destination host", CMD_CONFMANGLE_TCP_40, do_mangle, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFMANGLE_TCP_21, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFMANGLE_TCP_21, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFMANGLE_TCP_26, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFMANGLE_TCP_21, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFMANGLE_TCP_21, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFMANGLE_TCP_21B, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_TCP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_UDP_20[] = {
	{"any","Any destination host", CMD_CONFMANGLE_UDP_40, do_mangle, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFMANGLE_UDP_21, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFMANGLE_UDP_21, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFMANGLE_UDP_26, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFMANGLE_UDP_21, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFMANGLE_UDP_21, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFMANGLE_UDP_21B, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFMANGLE_UDP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFMANGLE_ANY_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFMANGLE_ANY_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_TCP_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFMANGLE_TCP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_UDP_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFMANGLE_UDP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_ANY_6[] = {
	{"<ipaddress>","Source address", CMD_CONFMANGLE_ANY_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_TCP_6[] = {
	{"<ipaddress>","Source address", CMD_CONFMANGLE_TCP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_UDP_6[] = {
	{"<ipaddress>","Source address", CMD_CONFMANGLE_UDP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_ANY_4[] = {
	{"any","Any source host", CMD_CONFMANGLE_ANY_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFMANGLE_ANY_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFMANGLE_ANY_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFMANGLE_ICMP_TYPE_3_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-unreachable","network-unreachable ICMP type code (0)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-unreachable","host-unreachable ICMP type code (1)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"protocol-unreachable","protocol-unreachable ICMP type code (2)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"port-unreachable","port-unreachable ICMP type code (3)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"fragmentation-needed","fragmentation-needed ICMP type code (4)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"source-route-failed","source-route-failed ICMP type code (5)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-unknown","network-unknown ICMP type code (6)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-unknown","host-unknown ICMP type code (7)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-prohibited","network-prohibited ICMP type code (9)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-prohibited","host-prohibited ICMP type code (10)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-network-unreachable","TOS-network-unreachable ICMP type code (11)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-host-unreachable","TOS-host-unreachable ICMP type code (12)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"communication-prohibited","communication-prohibited ICMP type code (13)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-precedence-violation","host-precedence-violation ICMP type code (14)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"precedence-cutoff","precedence-cutoff ICMP type code (15)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},	
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_ICMP_TYPE_5_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"network-redirect","network-redirect ICMP type code (0)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"host-redirect","host-redirect ICMP type code (1)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-network-redirect","TOS-network-redirect ICMP type code (2)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"TOS-host-redirect","TOS-host-redirect ICMP type code (3)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},	
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_ICMP_TYPE_11_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"ttl-zero-during-transit","ttl-zero-during-transit ICMP type code (0)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"ttl-zero-during-reassembly","ttl-zero-during-reassembly ICMP type code (1)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_ICMP_TYPE_12_CODE[] = {
	{"any","Any ICMP type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"ip-header-bad","ip-header-bad ICMP type code (0)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"required-option-missing","required-option-missing ICMP type code (1)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type code", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_ICMP_TYPE[] = {
	{"any","Any ICMP type (255)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"echo-reply","echo-reply (pong) ICMP type (0)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"destination-unreachable","destination-unreachable ICMP type (3)", CMD_CONFMANGLE_ICMP_TYPE_3_CODE, NULL, 1, MSK_NORMAL},
	{"source-quench","source-quench ICMP type (4)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"redirect","redirect ICMP type (5)", CMD_CONFMANGLE_ICMP_TYPE_5_CODE, NULL, 1, MSK_NORMAL},
	{"echo-request","echo-request (ping) ICMP type (8)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"router-advertisement","router-advertisement ICMP type (9)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"router-solicitation","router-solicitation ICMP type (10)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"time-exceeded","time-exceeded (ttl-exceeded) ICMP type (11)", CMD_CONFMANGLE_ICMP_TYPE_11_CODE, NULL, 1, MSK_NORMAL},
	{"parameter-problem","parameter-problem ICMP type (12)", CMD_CONFMANGLE_ICMP_TYPE_12_CODE, NULL, 1, MSK_NORMAL},
	{"timestamp-request","timestamp-request ICMP type (13)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"timestamp-reply","timestamp-reply ICMP type (14)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"address-mask-request","address-mask-request ICMP type (17)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"address-mask-reply","address-mask-reply ICMP type (18)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"0-255","ICMP numeric type", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_ICMP_4[] = {
	{"any","Any source host", CMD_CONFMANGLE_ANY_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFMANGLE_ANY_6, NULL, 1, MSK_NORMAL},
	{"type","ICMP type", CMD_CONFMANGLE_ICMP_TYPE, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFMANGLE_ANY_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_TCP_4[] = {
	{"any","Any source host", CMD_CONFMANGLE_TCP_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFMANGLE_TCP_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFMANGLE_TCP_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFMANGLE_UDP_4[] = {
	{"any","Any source host", CMD_CONFMANGLE_UDP_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFMANGLE_UDP_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFMANGLE_UDP_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

/* Layer 7 support*/
cish_command CMD_CONFMANGLE_LAYER7_NEWENTRY[] = {
	{"<text>","A regular expression for matching patterns", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE_LAYER7_1[] = {
	{"bgp", "The Border Gateway Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"bittorrent", "The Bittorrent Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"cvs", "The Concurrent Versioning System", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"dhcp", "The Dynamic Host Configuration Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"dns", "The Domain Name Server Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"fasttrack", "The Fasttrack Protocol (P2P)", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"ftp", "The File Transfer Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"http", "The Hypertext Transfer Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"http-rtsp", "The Real Time Streaming Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"msnmessenger", "The MSN Messenger Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"netbios", "The netBIOS Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"ntp", "The Network Time Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"pop3", "The Post Office Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"rtp", "The Real-time Transfer Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"skypeout", "The Skypeout Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"skypetoskype", "The Skype Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"smb", "The Samba protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"smtp", "The Simple Mail Transfer Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"snmp", "The Simple Network Management Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"ssh", "The Secure Shell Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"ssl", "The Secure Sockets Layer Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"subversion", "The Subversion Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"telnet", "The Telecommunication Network Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"tftp", "The Trivial File Transfer Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"<text>", "Name of a new entry", CMD_CONFMANGLE_LAYER7_NEWENTRY, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
/* End of Layer 7 support */

cish_command CMD_CONFMANGLE3[] = {
	{"0-255", "An IP protocol number", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"icmp","Internet Control Message Protocol", CMD_CONFMANGLE_ICMP_4, NULL, 1, MSK_NORMAL},
	{"ip","Any Internet Protocol", CMD_CONFMANGLE_ANY_4, NULL, 1, MSK_NORMAL},
	{"layer7","A layer 7 protocol", CMD_CONFMANGLE_LAYER7_1, NULL, 1, MSK_NORMAL},
	{"tcp","Transmission Control Protocol", CMD_CONFMANGLE_TCP_4, NULL, 1, MSK_NORMAL},
	{"udp","User Datagram Protocol", CMD_CONFMANGLE_UDP_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE2_DSCP_CLASS[] = {
	{"AF11","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF12","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF13","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF21","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF22","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF23","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF31","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF32","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF33","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF41","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF42","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"AF43","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"BE","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"CS1","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"CS2","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"CS3","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"CS4","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"CS5","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"CS6","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"CS7","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{"EF","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFMANGLE2_DSCP[] = {
	{"0-63","DSCP to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
#if 1 /* !!! to resume browse output! */
	{"class","DSCP class to set", CMD_CONFMANGLE2_DSCP_CLASS, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFMANGLE2_MARK[] = {
	{"1-2000000000","Mark to set", CMD_CONFMANGLE3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFMANGLE1B[] = {
	{"dscp","Specify dscp to mark", CMD_CONFMANGLE2_DSCP, NULL, 1, MSK_NORMAL},
	{"mark","Specify mark code to mark", CMD_CONFMANGLE2_MARK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFMANGLE1[] = {
	{"dscp","Specify dscp to mark", CMD_CONFMANGLE2_DSCP, NULL, 1, MSK_NORMAL},
	{"mark","Specify mark code to mark", CMD_CONFMANGLE2_MARK, NULL, 1, MSK_NORMAL},
	{"insert","Insert a mark rule on top", CMD_CONFMANGLE1B, NULL, 1, MSK_NORMAL},
	{"no","Remove a mark rule", CMD_CONFMANGLE1B, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFMANGLE[] = {
	{"<acl>","MARK list name", CMD_CONFMANGLE1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
/* END OF MARK-RULE CONFIGURATION */

cish_command CMD_CONFNAT_TCP_307[] = {
	{"<port>","Last port number or service name", NULL, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_306[] = {
	{"<port>","First port number or service name", CMD_CONFNAT_TCP_307, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_305[] = {
	{"<port>","Port number or service name", NULL, do_nat_rule, 1, MSK_NORMAL},
	{"range","Use a range of ports", CMD_CONFNAT_TCP_306, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_304[] = {
	{"port","Change port", CMD_CONFNAT_TCP_305, NULL, 1, MSK_NORMAL},
	{"<enter>","", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_303[] = {
	{"<ipaddress>","Last destination address", CMD_CONFNAT_TCP_304, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_ANY_303[] = {
	{"<ipaddress>","Last destination address", NULL, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_302[] = {
	{"<ipaddress>","First destination address", CMD_CONFNAT_TCP_303, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_ANY_302[] = {
	{"<ipaddress>","First destination address", CMD_CONFNAT_ANY_303, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_TCP_301[] = {
	{"pool","Use a pool of destination addresses", CMD_CONFNAT_TCP_302, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFNAT_TCP_304, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_UDP_301[] = {
	{"pool","Use a pool of destination addresses", CMD_CONFNAT_TCP_302, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFNAT_TCP_304, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_ANY_301[] = {
	{"pool","Use a pool of destination addresses", CMD_CONFNAT_ANY_302, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", NULL, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_TCP_207[] = {
	{"<port>","Last port number or service name", NULL, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_206[] = {
	{"<port>","First port number or service name", CMD_CONFNAT_TCP_207, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_205[] = {
	{"range","Use a range of ports", CMD_CONFNAT_TCP_206, NULL, 1, MSK_NORMAL},
	{"<port>","Port number or service name", NULL, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_204[] = {
	{"port","Change port number or service name", CMD_CONFNAT_TCP_205, NULL, 1, MSK_NORMAL},
	{"<enter>","", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_203[] = {
	{"<ipaddress>","Last source address", CMD_CONFNAT_TCP_204, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_ANY_203[] = {
	{"<ipaddress>","Last source address", NULL, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_202[] = {
	{"<ipaddress>","First source address", CMD_CONFNAT_TCP_203, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_ANY_202[] = {
	{"<ipaddress>","First source address", CMD_CONFNAT_ANY_203, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_TCP_201[] = {
	{"interface-address","Change to interface's address", CMD_CONFNAT_TCP_204, do_nat_rule, 1, MSK_NORMAL},
	{"pool","Use a pool of source addresses", CMD_CONFNAT_TCP_202, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFNAT_TCP_204, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_UDP_201[] = {
	{"interface-address","Change to interface's address", CMD_CONFNAT_TCP_204, do_nat_rule, 1, MSK_NORMAL},
	{"pool","Use a pool of source addresses", CMD_CONFNAT_TCP_202, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFNAT_TCP_204, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_ANY_201[] = {
	{"interface-address","Change to interface's address", NULL, do_nat_rule, 1, MSK_NORMAL},
	{"pool","Use a pool of source addresses", CMD_CONFNAT_ANY_202, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", NULL, do_nat_rule, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_TCP_99[] = {
	{"change-destination-to","Change packet destination address", CMD_CONFNAT_TCP_301, NULL, 1, MSK_NORMAL},
	{"change-source-to","Change packet source address", CMD_CONFNAT_TCP_201, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_99[] = {
	{"change-destination-to","Change packet destination address", CMD_CONFNAT_UDP_301, NULL, 1, MSK_NORMAL},
	{"change-source-to","Change packet source address", CMD_CONFNAT_UDP_201, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_41[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_TCP_99, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_UDP_41[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_UDP_99, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_TCP_41B[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_TCP_41, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_41B[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_UDP_41, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_ANY_40[] = {
	{"change-destination-to","Change packet destination address", CMD_CONFNAT_ANY_301, NULL, 1, MSK_NORMAL},
	{"change-source-to","Change packet source address", CMD_CONFNAT_ANY_201, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_TCP_40[] = {
	{"change-destination-to","Change packet destination address", CMD_CONFNAT_TCP_301, NULL, 1, MSK_NORMAL},
	{"change-source-to","Change packet source address", CMD_CONFNAT_TCP_201, NULL, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFNAT_TCP_41, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFNAT_TCP_41, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFNAT_TCP_41, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFNAT_TCP_41, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFNAT_TCP_41B, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_40[] = {
	{"change-destination-to","Change packet destination address", CMD_CONFNAT_UDP_301, NULL, 1, MSK_NORMAL},
	{"change-source-to","Change packet source address", CMD_CONFNAT_UDP_201, NULL, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFNAT_UDP_41, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFNAT_UDP_41, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFNAT_UDP_41, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFNAT_UDP_41, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFNAT_UDP_41B, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_ANY_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFNAT_ANY_40, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_TCP_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFNAT_TCP_40, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_UDP_27[] = {
	{"<rnetmask>","Destination wildcard bits", CMD_CONFNAT_UDP_40, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_ANY_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFNAT_ANY_40, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_TCP_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFNAT_TCP_40, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_UDP_26[] = {
	{"<ipaddress>","Destination address", CMD_CONFNAT_UDP_40, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};


cish_command CMD_CONFNAT_TCP_22[] = {
	{"any","Any destination host", CMD_CONFNAT_TCP_40, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFNAT_TCP_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFNAT_TCP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_22[] = {
	{"any","Any destination host", CMD_CONFNAT_UDP_40, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFNAT_UDP_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFNAT_UDP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_21[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_TCP_22, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_21[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_UDP_22, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_TCP_21B[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_TCP_21, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_21B[] = {
	{"<port>","Port number or service name", CMD_CONFNAT_UDP_21, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_ANY_20[] = {
	{"any","Any destination host", CMD_CONFNAT_ANY_40, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFNAT_ANY_26, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFNAT_ANY_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_TCP_20[] = {
	{"any","Any destination host", CMD_CONFNAT_TCP_40, do_nat_rule, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port", CMD_CONFNAT_TCP_21, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFNAT_TCP_21, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFNAT_TCP_26, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFNAT_TCP_21, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFNAT_TCP_21, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFNAT_TCP_21B, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFNAT_TCP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_20[] = {
	{"any","Any destination host", CMD_CONFNAT_UDP_40, do_nat_rule, 1, MSK_NORMAL},
	{"eq","Match only packets on a given port number", CMD_CONFNAT_UDP_21, NULL, 1, MSK_NORMAL},
	{"gt","Match only packets with a greater or equal port", CMD_CONFNAT_UDP_21, NULL, 1, MSK_NORMAL},
	{"host","A single destination host", CMD_CONFNAT_UDP_26, NULL, 1, MSK_NORMAL},
	{"lt","Match only packets with a lower or equal port", CMD_CONFNAT_UDP_21, NULL, 1, MSK_NORMAL},
	{"neq","Match only packets not on a given port", CMD_CONFNAT_UDP_21, NULL, 1, MSK_NORMAL},
	{"range","Match only packets in the range of ports", CMD_CONFNAT_UDP_21B, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Destination address", CMD_CONFNAT_UDP_27, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT_ANY_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFNAT_ANY_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_TCP_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFNAT_TCP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_UDP_7[] = {
	{"<rnetmask>","Source wildcard bits", CMD_CONFNAT_UDP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_ANY_6[] = {
	{"<ipaddress>","Source address", CMD_CONFNAT_ANY_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_TCP_6[] = {
	{"<ipaddress>","Source address", CMD_CONFNAT_TCP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
cish_command CMD_CONFNAT_UDP_6[] = {
	{"<ipaddress>","Source address", CMD_CONFNAT_UDP_20, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT_ANY_4[] = {
	{"any","Any source host", CMD_CONFNAT_ANY_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFNAT_ANY_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFNAT_ANY_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_TCP_4[] = {
	{"any","Any source host", CMD_CONFNAT_TCP_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFNAT_TCP_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFNAT_TCP_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	
cish_command CMD_CONFNAT_UDP_4[] = {
	{"any","Any source host", CMD_CONFNAT_UDP_20, NULL, 1, MSK_NORMAL},
	{"host","A single source host", CMD_CONFNAT_UDP_6, NULL, 1, MSK_NORMAL},
	{"<ipaddress>","Source address", CMD_CONFNAT_UDP_7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};	

cish_command CMD_CONFNAT3[] = {
	{"0-255", "An IP protocol number", CMD_CONFNAT_ANY_4, NULL, 1, MSK_NORMAL},
	{"icmp","Internet Control Message Protocol", CMD_CONFNAT_ANY_4, NULL, 1, MSK_NORMAL},
	{"ip","Any Internet Protocol", CMD_CONFNAT_ANY_4, NULL, 1, MSK_NORMAL},
	{"tcp","Transmission Control Protocol", CMD_CONFNAT_TCP_4, NULL, 1, MSK_NORMAL},
	{"udp","User Datagram Protocol", CMD_CONFNAT_UDP_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFNAT2[] = {
	{"0-255", "An IP protocol number", CMD_CONFNAT_ANY_4, NULL, 1, MSK_NORMAL},
	{"icmp","Internet Control Message Protocol", CMD_CONFNAT_ANY_4, NULL, 1, MSK_NORMAL},
	{"insert","Insert a nat-rule on top", CMD_CONFNAT3, NULL, 1, MSK_NORMAL},
	{"ip","Any Internet Protocol", CMD_CONFNAT_ANY_4, NULL, 1, MSK_NORMAL},
	{"no","Remove a nat-rule", CMD_CONFNAT3, NULL, 1, MSK_NORMAL},
	{"tcp","Transmission Control Protocol", CMD_CONFNAT_TCP_4, NULL, 1, MSK_NORMAL},
	{"udp","User Datagram Protocol", CMD_CONFNAT_UDP_4, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFNAT1[] = {
	{"<acl>","NAT rule name", CMD_CONFNAT2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFACLPOL[] = {
	{"accept","Accept all packets", NULL, do_accesslist_policy, 1, MSK_NORMAL},
	{"drop","Drop all packets", NULL, do_accesslist_policy, 1, MSK_NORMAL},
#if 0
	{"reject","Reject all packets", NULL, do_accesslist_policy, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_CHATSCRIPT2[] = {
	{"<string>","Chat script in form EXPECT SEND EXPECT SEND ...", CMD_CONFIG_CHATSCRIPT2, ppp_chatscript, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_CHATSCRIPT[] = {
	{"<text>","Chatscript name", CMD_CONFIG_CHATSCRIPT2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_LOG_REMOTE[] = {
	{"<ipaddress>", "Remote log host", NULL, log_remote, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_LOG[] = {
	{"remote","Enable remote logging (do not forget syslogd -r option)", CMD_CONFIG_LOG_REMOTE, log_remote, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_NTPD
cish_command CMD_CONFIG_NTP_KEYS_VALUE[] = {
	{"<string>","Authentication key", NULL, ntp_set_key_value, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_KEYS_TYPE[] = {
	{"md5","MD5 authentication", CMD_CONFIG_NTP_KEYS_VALUE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_KEYS[] = {
	{"1-16","Key number", CMD_CONFIG_NTP_KEYS_TYPE, NULL, 1, MSK_NORMAL},
	{"generate","Generate new keys", NULL, ntp_generate_keys, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_RESTRICT_MASK[] = {
	{"<netmask>","Network mask to be restricted", NULL, ntp_restrict, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_RESTRICT_IP[] = {
	{"<ipaddress>","Address to be restricted", CMD_CONFIG_NTP_RESTRICT_MASK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_SERVER_IP_KEYNUM[] = {
	{"1-16","Key number", NULL, ntp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_SERVER_IP[] = {
	{"key","Configure key to use with server", CMD_CONFIG_NTP_SERVER_IP_KEYNUM, NULL, 1, MSK_NORMAL},
	{"<enter>", "Enter server", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_SERVER[] = {
	{"<ipaddress>","Address of the server", CMD_CONFIG_NTP_SERVER_IP, ntp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP_TRUSTEDKEY[] = {
	{"1-16","Key number", NULL, ntp_trust_on_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP[] = {
#ifdef OPTION_NTPD_authenticate
	{"authenticate","Authenticate time sources", NULL, ntp_authenticate, 1, MSK_NORMAL},
#endif
	{"authentication-key","Authentication key for trusted time sources", CMD_CONFIG_NTP_KEYS, NULL, 1, MSK_NORMAL},
	{"restrict","NTP restriction rules", CMD_CONFIG_NTP_RESTRICT_IP, NULL, 1, MSK_NORMAL},
	{"server","Add time synchronization server", CMD_CONFIG_NTP_SERVER, NULL, 1, MSK_NORMAL},
	{"trusted-key","Configure trusted keys", CMD_CONFIG_NTP_TRUSTEDKEY, NULL, 1, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"update-calendar","Sync RTC with system clock", NULL, ntp_update_calendar, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

#else

cish_command CMD_CONFIG_NTP_IP[] = {
	{"<ipaddress>","IP Address of NTP server host", NULL, ntp_sync, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_NTP[] = {
	{"300-86400", "Query interval (seconds)", CMD_CONFIG_NTP_IP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_BRIDGE_AGING[] = {
	{"10-1000000", "Seconds", NULL, bridge_setaging, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_FD[] = {
	{"4-200", "Seconds", NULL, bridge_setfd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_HELLO[] = {
	{"1-10", "Seconds", NULL, bridge_sethello, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_MAXAGE[] = {
	{"6-200", "Seconds", NULL, bridge_setmaxage, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_PRIO[] = {
	{"0-65535", "Priority (low priority more likely to be root)", NULL, bridge_setprio, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE_PROTO[] = {
	{"ieee", "IEEE 802.1 protocol", NULL, bridge_setproto, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE2[] = {
	{"aging-time", "Set forwarding entry aging time", CMD_CONFIG_BRIDGE_AGING, NULL, 1, MSK_NORMAL},
	{"forward-time", "Set forwarding delay time", CMD_CONFIG_BRIDGE_FD, NULL, 1, MSK_NORMAL},
	{"hello-time", "Set interval between HELLOs", CMD_CONFIG_BRIDGE_HELLO, NULL, 1, MSK_NORMAL},
	{"max-age", "Maximum allowed message age of received Hello BPDUs", CMD_CONFIG_BRIDGE_MAXAGE, NULL, 1, MSK_NORMAL},
	{"priority", "Set bridge priority", CMD_CONFIG_BRIDGE_PRIO, NULL, 1, MSK_NORMAL},
	{"protocol", "Specify spanning tree protocol", CMD_CONFIG_BRIDGE_PROTO, NULL, 1, MSK_NORMAL},
	{"spanning-disabled", "Disable spanning tree", NULL, bridge_nostp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_BRIDGE[] = {
	{"1-1", "Bridge Group number for Bridging", CMD_CONFIG_BRIDGE2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_HOSTNAME[] = {
	{"<text>", "This system's hostname", NULL, hostname, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_BGP
cish_command CMD_CONFIG_ROUTER_BGP_AS[] = {
	{"1-65535", "AS number", NULL, config_router, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif
cish_command CMD_CONFIG_ROUTER[] = {
#ifdef OPTION_BGP
	{"bgp", "Border Gateway Protocol (BGP)", CMD_CONFIG_ROUTER_BGP_AS, NULL, 1, MSK_NORMAL},
#endif
	{"ospf", "Open Shortest Path First (OSPF)", NULL, config_router, 1, MSK_NORMAL},
	{"rip", "Routing Information Protocol (RIP)", NULL, config_router, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_BERLIN_SATROUTER

cish_command CMD_ENABLE_AUTH_SECRET_VALUE[] = {
	{"<string>", "Password string", NULL, set_enable_secret, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ENABLE_AUTH_SECRET[] = {
	{"hash", "Encrypted secret for enable will follow", CMD_ENABLE_AUTH_SECRET_VALUE, NULL, 1, MSK_NORMAL},
	{"cleartext", "UNENCRYPTED secret for enable will follow", CMD_ENABLE_AUTH_SECRET_VALUE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ENABLE_AUTH[] = {
	{"secret", "Assign the privileged level secret", CMD_ENABLE_AUTH_SECRET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#endif

cish_command CMD_SECRET3[] = {
	{"<string>", "Encrypted password", NULL, setsecret, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SECRET2[] = {
	{"hash", "Encrypted password", CMD_SECRET3, NULL, 2, MSK_NORMAL}, /* needs especial privilege! (2) */
	{"<enter>", "Type password", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SECRET[] = {
	{"enable", "Set privileged password", CMD_SECRET2, setsecret, 1, MSK_NORMAL},
	{"login", "Set login password", CMD_SECRET2, setsecret, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TERMINAL_SIZE[] = {
	{"0", "No pausing", NULL, term_length, 0, MSK_NORMAL},
	{"22-99", "Number of lines on screen", NULL, term_length, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TERMINAL_TIMEOUT[] = {
	{"0", "No timeout", NULL, term_timeout, 0, MSK_NORMAL},
	{"10-600", "Timeout in seconds", NULL, term_timeout, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TERMINAL[] = {
	{"length", "Set number of lines on a screen", CMD_TERMINAL_SIZE, NULL, 0, MSK_NORMAL},
	{"timeout", "Set idle timeout", CMD_TERMINAL_TIMEOUT, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CLOCK5[] = {
	{"1970-2037", "Year", NULL, config_clock, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CLOCK4[] = {
	{"1-12", "Month of the year", CMD_CONFIG_CLOCK5, config_clock, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CLOCK3[] = {
	{"1-31", "Day of the month", CMD_CONFIG_CLOCK4, config_clock, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CLOCK2[] = {
	{"hh:mm:ss", "Current time", CMD_CONFIG_CLOCK3, config_clock, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CLOCK[] = {
	{"set", "Set the time and date", CMD_CONFIG_CLOCK2, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIGURE_CLOCK_TIMEZONE3[] = {
	{"0-59", "Minutes offset from UTC", NULL, config_clock_timezone, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIGURE_CLOCK_TIMEZONE2[] = {
	{"-23 - 23", "Hours offset from UTC", CMD_CONFIGURE_CLOCK_TIMEZONE3, config_clock_timezone, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIGURE_CLOCK_TIMEZONE[] = {
	{"<text>", "Name of time zone", CMD_CONFIGURE_CLOCK_TIMEZONE2, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIGURE_CLOCK[] = {
	{"timezone", "Set the timezone", CMD_CONFIGURE_CLOCK_TIMEZONE, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_LEVEL[] = {
	{"running-config", "Current configuration", NULL, show_level_running_config, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_IPSEC
cish_command CMD_CONFIG_CRYPTO_AUTORELOAD[] = {
	{"60-3600", "Set interval of auto-reload connections (dns)", NULL, ipsec_autoreload, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_AUTHBY_SECRET[] = {
	{"<text>", "pre-shared key", NULL, ipsec_set_secret_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_AUTHBY[] = {
	{"rsa", "Use RSA pair keys", NULL, ipsec_authby_rsa, 1, MSK_NORMAL},
	{"secret", "Use pre-shared key", CMD_IPSEC_CONNECTION_AUTHBY_SECRET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_AUTHPROTO[] = {
#if 0
	{"transport", "Transport mode", NULL, ipsec_authproto_ah, 1, MSK_NORMAL},
#endif
	{"tunnel", "Tunnel mode", NULL, ipsec_authproto_esp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ESP_HASH[] = {
	{"md5", "MD5 hash", NULL, set_esp_hash, 1, MSK_NORMAL},
	{"sha1", "SHA1 hash", NULL, set_esp_hash, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ESP[] = {
	{"3des", "3DES cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
	{"aes", "AES cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
#ifndef CONFIG_BERLIN_SATROUTER
	{"des", "DES cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
#endif
	{"null", "NULL cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
	{"<enter>", "cypher do not care", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_ADDR_IP[] = {
	{"<ipaddress>", "IP address", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_ADDR_FQDN[] = {
	{"<text>", "FQDN address", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_INTERFACE_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_INTERFACE_SERIAL[] = {
	{"0-0", "Serial interface number", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_INTERFACE[] = {
	{"ethernet", "Ethernet interface", CMD_IPSEC_CONNECTION_INTERFACE_ETHERNET, NULL, 1, MSK_NORMAL},
	{"serial", "Serial interface", CMD_IPSEC_CONNECTION_INTERFACE_SERIAL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L_ADDR[] = {
	{"default-route", "Use default route as address", NULL, set_ipsec_addr, 1, MSK_NORMAL},
#if 0
	{"fqdn", "Address in the name format", CMD_IPSEC_CONNECTION_LR_ADDR_FQDN, NULL, 1, MSK_NORMAL},
#endif
	{"ip", "Address in the dotted representation", CMD_IPSEC_CONNECTION_LR_ADDR_IP, NULL, 1, MSK_NORMAL},
	{"interface", "Interface to be used", CMD_IPSEC_CONNECTION_INTERFACE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_R_ADDR[] = {
	{"any", "Any address (roadwarrior)", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{"fqdn", "Address in the name format", CMD_IPSEC_CONNECTION_LR_ADDR_FQDN, NULL, 1, MSK_NORMAL},
	{"ip", "Address in the dotted representation", CMD_IPSEC_CONNECTION_LR_ADDR_IP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_ID[] = {
	{"<text>", "ID string (@)", NULL, set_ipsec_id, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_NEXTHOP[] = {
	{"<ipaddress>", "Address of the next hop", NULL, set_ipsec_nexthop, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_R_RSAKEY[] = {
	{"<text>", "The public key", NULL, set_ipsec_remote_rsakey, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_SUBNET_MASK[] = {
	{"<netmask>", "subnet mask", NULL, set_ipsec_subnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_SUBNET[] = {
	{"<ipaddress>", "Address of subnet", CMD_IPSEC_CONNECTION_LR_SUBNET_MASK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LOCAL[] = {
	{"address", "The local address type entered by the user", CMD_IPSEC_CONNECTION_L_ADDR, NULL, 1, MSK_NORMAL},
	{"id", "Local identification of the tunnel", CMD_IPSEC_CONNECTION_LR_ID, NULL, 1, MSK_NORMAL},
	{"nexthop", "Equipment that gives access to the network", CMD_IPSEC_CONNECTION_LR_NEXTHOP, NULL, 1, MSK_NORMAL},
	{"subnet", "The local subnet (network & mask)", CMD_IPSEC_CONNECTION_LR_SUBNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_REMOTE[] = {
	{"address", "The remote address type entered by the user", CMD_IPSEC_CONNECTION_R_ADDR, NULL, 1, MSK_NORMAL},
	{"id", "Remote identification of the tunnel", CMD_IPSEC_CONNECTION_LR_ID, NULL, 1, MSK_NORMAL},
	{"nexthop", "Equipment that gives access to the network", CMD_IPSEC_CONNECTION_LR_NEXTHOP, NULL, 1, MSK_NORMAL},
	{"rsakey", "The RSA public key of the remote", CMD_IPSEC_CONNECTION_R_RSAKEY, NULL, 1, MSK_NORMAL},
	{"subnet", "The remote subnet (network & mask)", CMD_IPSEC_CONNECTION_LR_SUBNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PEER1[] = {
	{"<netmask>", "Remote address mask", NULL, l2tp_peer, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PEER[] = {
	{"<ipaddress>", "Remote address", CMD_IPSEC_CONNECTION_L2TP_PEER1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_PASS[] = {
	{"<text>","Password", NULL, l2tp_ppp_auth_pass, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_USER[] = {
	{"<text>","Username", NULL, l2tp_ppp_auth_user, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH[] = {
	{"pass","Set authentication password", CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_PASS, NULL, 1, MSK_NORMAL},
	{"user","Set authentication username", CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_USER, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_ADDRESS[] = {
	{"<ipaddress>", "Local address (on internal interface)", NULL, l2tp_ppp_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_PEER[] = {
	{"pool", "Remote address from pool", NULL, l2tp_ppp_peeraddr, 1, MSK_NORMAL},
	{"<ipaddress>", "Remote address (on internal interface)", NULL, l2tp_ppp_peeraddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, l2tp_ppp_unnumbered, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_LOOPBACK[] = {
	{"0-4", "Loopback interface number", NULL, l2tp_ppp_unnumbered, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED[] = {
	{"ethernet", "Ethernet interface", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_LOOPBACK, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_ETHERNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP[] = {
	{"address", "Set local address", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_ADDRESS, NULL, 1, MSK_NORMAL},
	{"default-route", "Use default-route on this interface", NULL, l2tp_ppp_defaultroute, 1, MSK_NORMAL},
	{"peer-address", "Set peer address", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_PEER, NULL, 1, MSK_NORMAL},
	{"unnumbered", "Enable IP processing without an explicit address", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED, NULL, 1, MSK_NORMAL},
	{"vj", "Enable Van Jacobson style TCP/IP header compression", NULL, l2tp_ppp_vj, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_INTERVAL[] = {
	{"1-100", "seconds", NULL, l2tp_ppp_keepalive_interval, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_TIMEOUT[] = {
	{"1-100", "seconds", NULL, l2tp_ppp_keepalive_timeout, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE[] = {
	{"interval", "Set interval between two keepalive commands", CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_INTERVAL, NULL, 1, MSK_NORMAL},
	{"timeout", "Set keepalive failure timeout", CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_TIMEOUT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_MTU[] = {
	{"128-16384", "Max Transfer Unit", NULL, l2tp_ppp_mtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP[] = {
	{"authentication", "Authentication settings", CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_IPSEC_CONNECTION_L2TP_PPP_IP, NULL, 1, MSK_NORMAL},
	{"keepalive", "Set keepalive parameters", CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_IPSEC_CONNECTION_L2TP_PPP_MTU, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PROTOPORT[] = {
	{"SP1", "Windows XP SP1 protoport", NULL, set_ipsec_l2tp_protoport, 1, MSK_NORMAL},
	{"SP2", "Windows XP SP2 protoport", NULL, set_ipsec_l2tp_protoport, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP[] = {
	{"peer", "Set remote peer address/mask", CMD_IPSEC_CONNECTION_L2TP_PEER, NULL, 1, MSK_NORMAL},
	{"ppp", "Set PPP options", CMD_IPSEC_CONNECTION_L2TP_PPP, NULL, 1, MSK_NORMAL},
	{"protoport", "Set protoport", CMD_IPSEC_CONNECTION_L2TP_PROTOPORT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_LOCAL[] = {
	{"id", "Clear local identification of the tunnel", NULL, clear_ipsec_id, 1, MSK_NORMAL},
	{"nexthop", "Clear local nexthop", NULL, clear_ipsec_nexthop, 1, MSK_NORMAL},
	{"subnet", "Clear local subnet", NULL, clear_ipsec_subnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_REMOTE[] = {
	{"id", "Clear remote identification of the tunnel", NULL, clear_ipsec_id, 1, MSK_NORMAL},
	{"nexthop", "Clear remote nexthop", NULL, clear_ipsec_nexthop, 1, MSK_NORMAL},
	{"rsakey", "Clear the RSA public key of the remote", NULL, clear_ipsec_remote_rsakey, 1, MSK_NORMAL},
	{"subnet", "Clear remote subnet", NULL, clear_ipsec_subnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_L2TP_PPP_IP[] = {
	{"address", "Unset local address", NULL, l2tp_ppp_noipaddr, 1, MSK_NORMAL},
	{"default-route", "Don't use default-route on this interface", NULL, l2tp_ppp_no_defaultroute, 1, MSK_NORMAL},
	{"peer-address", "Unset peer address", NULL, l2tp_ppp_nopeeraddr, 1, MSK_NORMAL},
	{"unnumbered", "Disable IP processing without an explicit address", NULL, l2tp_ppp_no_unnumbered, 1, MSK_NORMAL},
	{"vj", "Disable Van Jacobson style TCP/IP header compression", NULL, l2tp_ppp_no_vj, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_L2TP_PPP[] = {
	{"authentication", "Turn off authentication", NULL, l2tp_ppp_noauth, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_IPSEC_CONNECTION_NO_L2TP_PPP_IP, NULL, 1, MSK_NORMAL},
	{"mtu", "Default interface mtu", NULL, l2tp_ppp_nomtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_L2TP[] = {
	{"peer", "Clear remote peer", NULL, l2tp_peer, 1, MSK_NORMAL},
	{"ppp", "Unset PPP options", CMD_IPSEC_CONNECTION_NO_L2TP_PPP, NULL, 1, MSK_NORMAL},
	{"protoport", "Clear protoport", NULL, set_ipsec_l2tp_protoport, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO[] = {
	{"local", "Local settings of the tunnel", CMD_IPSEC_CONNECTION_NO_LOCAL, NULL, 1, MSK_NORMAL},
	{"pfs", "Disable PFS", NULL, ipsec_pfs, 1, MSK_NORMAL},
	{"remote", "Remote settings of the tunnel", CMD_IPSEC_CONNECTION_NO_REMOTE, NULL, 1, MSK_NORMAL},
	{"l2tp", "L2TP settings of the tunnel", CMD_IPSEC_CONNECTION_NO_L2TP, NULL, 1, MSK_NORMAL},
	{"shutdown", "Bring the connection up", NULL, ipsec_link_up, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_CHILDREN[] = {
	{"authby", "Key type", CMD_IPSEC_CONNECTION_AUTHBY, NULL, 1, MSK_NORMAL},
	{"authproto", "Authentication protocol", CMD_IPSEC_CONNECTION_AUTHPROTO, NULL, 1, MSK_NORMAL},
	{"esp", "ESP crypto configuration", CMD_IPSEC_CONNECTION_ESP, set_esp_hash, 1, MSK_NORMAL},
	{"exit", "Exit from connection configuration mode", NULL, config_connection_done, 1, MSK_NORMAL},
	{"local", "Local settings of the tunnel", CMD_IPSEC_CONNECTION_LOCAL, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_IPSEC_CONNECTION_NO, NULL, 1, MSK_NORMAL},
	{"pfs", "Enable PFS", NULL, ipsec_pfs, 1, MSK_NORMAL},
	{"remote", "Remote settings of the tunnel", CMD_IPSEC_CONNECTION_REMOTE, NULL, 1, MSK_NORMAL},
	{"l2tp", "L2TP settings of the tunnel", CMD_IPSEC_CONNECTION_L2TP, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown connection", NULL, ipsec_link_down, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ADD_NAME[] = {
	{"<text>", "Connection name", NULL, add_ipsec_conn, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ADD[] = {
	{"add", "Add a new connection", CMD_IPSEC_CONNECTION_ADD_NAME, NULL, 1, MSK_NORMAL},
#if CMDS_BEF_LIST != 1	/* number of nodes before static list. BE CAREFUL */
  #error *** Review the code! Only one node before static list.
#endif
#if MAX_CONN == 5
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
#else
  #error *** This firmware supports exactly 5 tunnels. For another number review the code!
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_IPSEC_CONNECTION[] = {
	{"connection", "Manage connections", CMD_IPSEC_CONNECTION_ADD, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_KEY_RSA_LEN[] = {
	{"512-2048", "Length in bits (multiple of 16)", NULL, generate_rsa_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_KEY_RSA[] = {
	{"rsa", "RSA pair keys", CMD_CRYPTO_KEY_RSA_LEN, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_KEY_GENERATE[] = {
	{"generate", "Generate new keys", CMD_CRYPTO_KEY_RSA, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_IPSEC_NO_CONN[] = {
#if MAX_CONN == 5
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
#else
  #error *** This firmware supports exactly 5 tunnels. For another number review the code!
#endif	
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_IPSEC_NO[] = {
	{"connection", "Delete a connection", CMD_CRYPTO_IPSEC_NO_CONN, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

extern cish_command CMD_CRYPTO_L2TP_POOL3[]; /* Loop! */

cish_command CMD_CRYPTO_L2TP_POOL11[] = {
	{"<netmask>", "Network mask", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL10[] = {
	{"<text>", "Domain name for the client", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL9[] = {
	{"<ipaddress>", "IP address of a DNS server", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL83[] = {
	{"0-59", "seconds", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL82[] = {
	{"0-59", "minutes", CMD_CRYPTO_L2TP_POOL83, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL81[] = {
	{"0-23", "hours", CMD_CRYPTO_L2TP_POOL82, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL8[] = {
	{"0-20000", "days", CMD_CRYPTO_L2TP_POOL81, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL7[] = {
	{"<ipaddress>", "IP address of a NetBIOS name server WINS (NBNS)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL6[] = {
	{"<ipaddress>", "IP address of a NetBIOS datagram distribution server (NBDD)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL5[] = {
	{"B", "NetBIOS B-node (Broadcast - no WINS)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{"P", "NetBIOS P-node (Peer - WINS only)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{"M", "NetBIOS M-node (Mixed - broadcast, then WINS)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{"H", "NetBIOS H-node (Hybrid - WINS, then broadcast)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL4[] = {
	{"<ipaddress>", "IP address of the default router", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL3[] = {
	{"default-lease-time", "Specify default lease time", CMD_CRYPTO_L2TP_POOL8, NULL, 1, MSK_NORMAL},
	{"domain-name", "Specify the domain name for the client", CMD_CRYPTO_L2TP_POOL10, NULL, 1, MSK_NORMAL},
	{"dns-server", "Specify the IP address of a DNS server", CMD_CRYPTO_L2TP_POOL9, NULL, 1, MSK_NORMAL},
	{"mask", "Specify network mask", CMD_CRYPTO_L2TP_POOL11, NULL, 1, MSK_NORMAL},
	{"max-lease-time", "Specify maximum lease time", CMD_CRYPTO_L2TP_POOL8, NULL, 1, MSK_NORMAL},
	{"netbios-name-server", "Specify the IP address of the NetBIOS name server WINS (NBNS)", CMD_CRYPTO_L2TP_POOL7, NULL, 1, MSK_NORMAL},
	{"netbios-dd-server", "Specify the IP address of the NetBIOS datagram distribution server (NBDD)", CMD_CRYPTO_L2TP_POOL6, NULL, 1, MSK_NORMAL},
	{"netbios-node-type", "Specify the NetBIOS node type of the client", CMD_CRYPTO_L2TP_POOL5, NULL, 1, MSK_NORMAL},
	{"router", "Specify the IP address of the default router", CMD_CRYPTO_L2TP_POOL4, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL2[] = {
	{"<ipaddress>", "Pool end", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL1[] = {
	{"<ipaddress>", "Pool begin", CMD_CRYPTO_L2TP_POOL2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL_ETHERNET[] = {
	{"0-0", "DHCP address pool on ethernet", NULL, l2tp_dhcp_server, 1, MSK_NORMAL}, /* !!! MU ethernet1 */
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL[] = {
	{"ethernet", "DHCP address pool on ethernet", CMD_CRYPTO_L2TP_POOL_ETHERNET, NULL, 1, MSK_NORMAL},
	{"local", "Local DHCP address pool", CMD_CRYPTO_L2TP_POOL1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP[] = {
	{"pool", "L2TP IP pool server", CMD_CRYPTO_L2TP_POOL, NULL, 1, MSK_NORMAL},
	{"server", "Enable L2TP server", NULL, l2tp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_NO_L2TP[] = {
	{"server", "Disable L2TP server", NULL, l2tp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_NO[] = {
	{"auto-reload", "Disable auto-reload interval", NULL, ipsec_autoreload, 1, MSK_NORMAL},
	{"ipsec", "Manage IPSEC tunnels", CMD_CRYPTO_IPSEC_NO, NULL, 1, MSK_NORMAL},
	{"l2tp", "Manage L2TP server", CMD_CRYPTO_NO_L2TP, NULL, 1, MSK_NORMAL},
	{"nat-traversal", "Disable NAT-Traversal", NULL, ipsec_nat_traversal, 1, MSK_NORMAL},
	{"overridemtu", "Disable override interface crypto MTU setting", NULL, ipsec_overridemtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CRYPTO_OVERRIDEMTU[] = {
	{"64-1460", "Override interface crypto MTU setting", NULL, ipsec_overridemtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CRYPTO[] = {
	{"auto-reload", "Configure auto-reload interval (seconds)", CMD_CONFIG_CRYPTO_AUTORELOAD, NULL, 1, MSK_NORMAL},
	{"exit", "Exit from crypto configuration mode", NULL, config_crypto_done, 1, MSK_NORMAL},
	{"ipsec", "Manage IPSEC tunnels", CMD_CRYPTO_IPSEC_CONNECTION, NULL, 1, MSK_NORMAL},
	{"key", "Manage keys", CMD_CRYPTO_KEY_GENERATE, NULL, 1, MSK_NORMAL},
	{"l2tp", "Manage L2TP server", CMD_CRYPTO_L2TP, NULL, 1, MSK_NORMAL},
	{"nat-traversal", "Manage NAT-Traversal", NULL, ipsec_nat_traversal, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CRYPTO_NO, NULL, 1, MSK_NORMAL},
	{"overridemtu", "Override interface crypto MTU setting", CMD_CONFIG_CRYPTO_OVERRIDEMTU, NULL, 1, MSK_NORMAL},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP_LOCAL[] = {
	{"local", "Use local username authentication.", NULL, cmd_aaa_authen, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP[] = {
	{"radius", "Use list of all Radius hosts.", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP_LOCAL, cmd_aaa_authen, 1, MSK_NORMAL},
	{"tacacs+", "Use list of all Tacacs+ hosts.", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP_LOCAL, cmd_aaa_authen, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHENTICATION_LOGIN[] = {
	{"group", "Use Server-group", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN_GROUP, NULL, 1, MSK_NORMAL},
	{"local", "Use local username authentication.", NULL, cmd_aaa_authen, 1, MSK_NORMAL},
	{"none", "NO authentication.", NULL, cmd_aaa_authen, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHEN_DEFAULT[] = {
	{"default", "The default accounting list", CMD_CONFIG_AAA_AUTHENTICATION_LOGIN, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

// cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH[] = {
// 	{"<string>", "Encrypted password", NULL, add_user, 1, MSK_NORMAL},
// 	{NULL,NULL,NULL,NULL, 0}
// };

// cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA[] = {
// 	{"<text>", "The UNENCRYPTED (cleartext) user password", NULL, add_user, 1, MSK_NORMAL},
// 	{"hash", "Encrypted password", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH, NULL, 2, MSK_NORMAL}, /* needs especial privilege! (2) */
// 	{NULL,NULL,NULL,NULL, 0}
// };
// 
// cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD[] = {
// 	{"password", "Specify the password for the user", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA, NULL, 1, MSK_NORMAL},
// 	{NULL,NULL,NULL,NULL, 0}
// };



cish_command CMD_CONFIG_AAA_AUTHENTICATION[] = {
#ifdef CONFIG_BERLIN_SATROUTER
	{"enable", "Set authentication list for enable.", CMD_CONFIG_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_NORMAL},
#endif
	{"login", "Set authentication lists for logins.", CMD_CONFIG_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_SPPP_NETLINK
	{"ppp", "Set authentication lists for ppp", CMD_CONFIG_AAA_AUTHEN_DEFAULT, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH[] = {
	{"<string>", "Encrypted password", NULL, add_user, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA[] = {
	{"<text>", "The UNENCRYPTED (cleartext) user password", NULL, add_user, 1, MSK_NORMAL},
	{"hash", "Encrypted password", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATAHASH, 
					NULL, 2, MSK_NORMAL}, /* needs especial priviledge! (2) */
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME_PASSWORD[] = {
	{"password", "Specify the password for the user", CMD_CONFIG_AAA_USERNAME_PASSWORD_DATA, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_USERNAME[] = {
	{"<text>", "User name", CMD_CONFIG_AAA_USERNAME_PASSWORD, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_TACACS[] = {
	{"tacacs+", "Use list of all Tacacs+ hosts.", NULL, cmd_aaa_acct, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_GROUP[] = {
	{"group", "Use Server-group", CMD_CONFIG_AAA_ACCT_TACACS, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_STARTSTOP[] = {
	{"start-stop", "Record start and stop without waiting", CMD_CONFIG_AAA_ACCT_GROUP, NULL, 1, MSK_NORMAL},
	{"none", "no accounting", NULL, cmd_aaa_acct, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT_DEFAULT[] = {
	{"default", "The default accounting list", CMD_CONFIG_AAA_ACCT_STARTSTOP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT1[] = {
	{"0-15", "Enable Level", CMD_CONFIG_AAA_ACCT_DEFAULT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_ACCT[] = {
	{"commands", "For exec (shell) commands", CMD_CONFIG_AAA_ACCT1, NULL, 1, MSK_NORMAL},
	{"exec", "For starting an exec (shell)", CMD_CONFIG_AAA_ACCT_DEFAULT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
cish_command CMD_CONFIG_AAA_AUTHOR_TACACS_LOCAL[] = {
	{"local", "Use local database", NULL, cmd_aaa_author, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR_TACACS[] = {
	{"tacacs+", "Use list of all Tacacs+ hosts.", CMD_CONFIG_AAA_AUTHOR_TACACS_LOCAL, cmd_aaa_author, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR_GROUP[] = {
	{"group", "Use Server-group", CMD_CONFIG_AAA_AUTHOR_TACACS, NULL, 1, MSK_NORMAL},
	{"none", "No authorization (always succeeds)", NULL, cmd_aaa_author, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR_DEFAULT[] = {
	{"default", "The default accounting list", CMD_CONFIG_AAA_AUTHOR_GROUP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA_AUTHOR[] = {
	{"exec", "For starting an exec (shell)", CMD_CONFIG_AAA_AUTHOR_DEFAULT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_AAA[] = {
	{"accounting", "Accounting configurations parameters", CMD_CONFIG_AAA_ACCT, NULL, 1, MSK_NORMAL},
	{"authentication", "Authentication configurations parameters", CMD_CONFIG_AAA_AUTHENTICATION, NULL, 1, MSK_NORMAL},
	{"authorization", "Authorization configurations parameters", CMD_CONFIG_AAA_AUTHOR, NULL, 1, MSK_NORMAL},
	{"username", "Establish User Name Authentication", CMD_CONFIG_AAA_USERNAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_TIMEOUTVALUE[] = {
	{"1-1000", "Timeout value in seconds to wait for server to reply", NULL, add_radiusserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_TIMEOUT[] = {
	{"timeout", "Time to wait for this RADIUS server to reply", CMD_CONFIG_RADIUSSERVER_TIMEOUTVALUE, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_KEYDATA[] = {
	{"<text>", "The UNENCRYPTED (cleartext) server key", CMD_CONFIG_RADIUSSERVER_TIMEOUT, add_radiusserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_KEY[] = {
	{"key", "per-server encryption key", CMD_CONFIG_RADIUSSERVER_KEYDATA, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of RADIUS server", CMD_CONFIG_RADIUSSERVER_KEY, add_radiusserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_RADIUSSERVER_HOST[] = {
	{"host", "Specify a RADIUS server", CMD_CONFIG_RADIUSSERVER_HOSTIP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

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
	{"10-2592000", "Interval in seconds", RMON_ALARM_DATATYPE, NULL, 1, MSK_NORMAL},
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

cish_command CMD_CONFIG_RMON[] = {
	{"agent", "Start RMON agent", NULL, rmon_agent, 1, MSK_NORMAL},
	{"event", "Configure event", RMON_EVENT, NULL, 1, MSK_NORMAL},
	{"alarm", "Configure alarm", RMON_ALARM, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_TACACSSERVER_TIMEOUTVALUE[] = {
	{"1-1000", "Timeout value in seconds to wait for server to reply", NULL, add_tacacsserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_TIMEOUT[] = {
	{"timeout", "Time to wait for this TACACS server to reply", CMD_CONFIG_TACACSSERVER_TIMEOUTVALUE, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_KEYDATA[] = {
	{"<text>", "The UNENCRYPTED (cleartext) server key", CMD_CONFIG_TACACSSERVER_TIMEOUT, add_tacacsserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_KEY[] = {
	{"key", "per-server encryption key", CMD_CONFIG_TACACSSERVER_KEYDATA, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_HOSTIP[] = {
	{"<ipaddress>", "IP address of TACACS server", CMD_CONFIG_TACACSSERVER_KEY, add_tacacsserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_TACACSSERVER_HOST[] = {
	{"host", "Specify a TACACS server", CMD_CONFIG_TACACSSERVER_HOSTIP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ARP_MAC[] = {
	{"<mac>", "48-bit hardware address of ARP entry (xx:xx:xx:xx:xx:xx)", NULL, arp_entry, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ARP_IP[] = {
	{"<ipaddress>", "IP address of ARP entry", CMD_ARP_MAC, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_X25
cish_command CMD_X25_T2X[] = {
	{"1-300", "Seconds", NULL, x25_param, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_X25[] = {
	{"route","Add an entry to the X.25 routing table", CMD_X25_ROUTE1, NULL, 1, MSK_X25},
#ifdef OPTION_X25XOT
	{"routing","Enable X.25 switching", NULL, x25_param, 1, MSK_X25XOT},
#endif
	{"t2","Set DTE Frame Acknowledgement timeout", CMD_X25_T2X, NULL, 1, MSK_X25},
	{"t20","Set DTE Restart Request timeout", CMD_X25_T2X, NULL, 1, MSK_X25},
	{"t21","Set DTE Call Request timeout", CMD_X25_T2X, NULL, 1, MSK_X25},
	{"t22","Set DTE Reset Request timeout", CMD_X25_T2X, NULL, 1, MSK_X25},
	{"t23","Set DTE Clear Request timeout", CMD_X25_T2X, NULL, 1, MSK_X25},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_NEW_QOS_CONFIG
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
#endif /* OPTION_NEW_QOS_CONFIG */
cish_command CMD_CONFIGURE[] = {
	{"aaa","Authentication, Authorization and Accounting.", CMD_CONFIG_AAA, NULL, 1, MSK_NORMAL},
	{"access-list","Set an ACL", CMD_CONFACL1, NULL, 1, MSK_NORMAL},
	{"access-policy", "Set default access policy", CMD_CONFACLPOL, NULL, 1, MSK_NORMAL},
	{"arp", "Set a static ARP entry", CMD_ARP_IP, NULL, 1, MSK_NORMAL},
	{"bridge","Bridging Group", CMD_CONFIG_BRIDGE, NULL, 1, MSK_NORMAL},
	{"chatscript", "Set a chatscript line", CMD_CONFIG_CHATSCRIPT, NULL, 1, MSK_NORMAL},
	{"clock","Manage the system clock", CMD_CONFIGURE_CLOCK, NULL, 1, MSK_NORMAL},
#ifdef OPTION_IPSEC
	{"crypto","Manage cryptographic tunnels", NULL, cd_crypto_dir, 1, MSK_VPN},
#endif
	{"exit","Exit from configure mode", NULL, config_term_done, 0, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"hostname","Set system's hostname", CMD_CONFIG_HOSTNAME, NULL, 1, MSK_NORMAL},
	{"ip","IPv4 Configuration", CMD_IP, NULL, 1, MSK_NORMAL},
	{"ipx","IPX Configuration", CMD_IPX, NULL, 1, MSK_NORMAL},
	{"interface","Interface Configuration", CMD_CONFIG_INTERFACE, NULL, 1, MSK_NORMAL},
	{"key","Authentication key management (RIP)", CMD_CONFIG_KEY, NULL, 1, MSK_RIP},
	{"logging","Logging info", CMD_CONFIG_LOG, NULL, 1, MSK_NORMAL},
	{"mark-rule","Add MARK rule", CMD_CONFMANGLE, NULL, 1, MSK_QOS},
	{"nat-rule","Add NAT rule", CMD_CONFNAT1, NULL, 1, MSK_NORMAL},
	{"no","Reverse settings", CMD_CONFIG_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NTPD
	{"ntp","Set time synchronization", CMD_CONFIG_NTP, NULL, 1, MSK_NORMAL},
#else
	{"ntp-sync","Set time synchronization", CMD_CONFIG_NTP, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_NEW_QOS_CONFIG
	{"policy-map", "Configure QoS Policy Map", CMD_CONFIG_POLICYMAP, NULL, 1, MSK_QOS},
#endif
	{"radius-server", "Modify RADIUS query parameters", CMD_CONFIG_RADIUSSERVER_HOST, NULL, 1, MSK_NORMAL},
#ifdef OPTION_RMON
	{"rmon","Set RMON agent configuration", CMD_CONFIG_RMON, NULL, 1, MSK_NORMAL},
#endif
	{"router","Enable a routing process", CMD_CONFIG_ROUTER, NULL, 1, MSK_NORMAL},
	{"secret","Set authentication secrets", CMD_SECRET, NULL, 1, MSK_NORMAL},
	{"snmp-server","Set SNMP server configuration", CMD_CONFIG_SNMP, NULL, 1, MSK_NORMAL},
	{"tacacs-server","Modify TACACS query parameters", CMD_CONFIG_TACACSSERVER_HOST, NULL, 1, MSK_NORMAL},
	{"terminal","Set terminal line parameters", CMD_TERMINAL, NULL, 0, MSK_NORMAL},
#ifdef OPTION_X25
	{"x25","X.25 Level 3", CMD_X25, NULL, 1, MSK_X25},
#endif
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG[] = {
	{"memory","Configure from NV memory", NULL, config_memory, 1, MSK_NORMAL},
	{"terminal","Configure through terminal", NULL, config_term, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TRACEROUTE[] = {
	{"<ipaddress>", "Destination host", NULL, traceroute, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING7[] = {
	{"1-1000000", "count", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING6[] = {
	{"count", "Repeat count", CMD_PING7, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING5[] = {
	{"0-65468", "bytes", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING4[] = {
	{"size", "Datagram size", CMD_PING5, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING3B[] = {
	{"0-65468", "bytes", CMD_PING6, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING3A[] = {
	{"1-1000000", "count", CMD_PING4, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING2[] = {
	{"count", "Repeat count", CMD_PING3A, NULL, 0, MSK_NORMAL},
	{"size", "Datagram size", CMD_PING3B, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING[] = {
	{"<ipaddress>", "Destination host", CMD_PING2, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SSH3[] = {
	{"1-65535", "Port number", NULL, ssh, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SSH2[] = {
	{"<text>", "Username", CMD_SSH3, ssh, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SSH[] = {
	{"<ipaddress>", "IP address of a remote system", CMD_SSH2, ssh, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TELNET2[] = {
	{"1-65535", "Port number", NULL, telnet, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TELNET[] = {
	{"<ipaddress>", "IP address of a remote system", CMD_TELNET2, telnet, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TCPDUMP[] = {
	{"<text>", "tcpdump options", NULL, tcpdump, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_FEATURE
#ifdef NO_FEATURE
cish_command CMD_NO_FEATURE[] = {
#ifdef OPTION_IPSEC
	{"vpn", "Disable VPN support", NULL, no_feature, 1, MSK_FEATURE},
#endif
#ifdef OPTION_X25MAP
#if 1
	{"x25", "Disable X25 support", NULL, no_feature, 1, MSK_FEATURE},
#else
	{"x25map", "Disable X25 map support", NULL, no_feature, 1, MSK_FEATURE},
#endif
#endif
	{NULL, NULL, NULL, NULL}
};
#endif
#endif

cish_command CMD_COPY_TFTP3[] = {
	{"<text>", "Name of configuration file", NULL, cmd_copy, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_TFTP2[] = {
	{"<ipaddress>", "IP address of remote host", CMD_COPY_TFTP3, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_FROM_TFTP[] = {
	{"running-config", "Update (merge with) current system configuration", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{"startup-config", "Copy to startup configuration", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_FROM_START[] = {
	{"running-config", "Update (merge with) current system configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"tftp", "Copy to a TFTP server", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_FROM_RUN[] = {
#ifdef CONFIG_DEVELOPMENT
	{"slot0-config", "Copy to slot0 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot1-config", "Copy to slot1 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot2-config", "Copy to slot2 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot3-config", "Copy to slot3 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot4-config", "Copy to slot4 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
#endif
	{"startup-config", "Copy to startup configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"tftp", "Copy to a TFTP server", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY[] = {
	{"previous-config", "Copy from previous configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"running-config", "Copy from current system configuration", CMD_COPY_FROM_RUN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"slot0-config", "Copy from slot0 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot1-config", "Copy from slot1 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot2-config", "Copy from slot2 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot3-config", "Copy from slot3 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot4-config", "Copy from slot4 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
#endif
	{"startup-config", "Copy from startup configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"tftp", "Copy from a TFTP server", CMD_COPY_FROM_TFTP, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ERASE[] = {
	{"startup-config", "Erase contents of configuration memory", NULL, erase_cfg, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

#ifdef OPTION_FEATURE
cish_command CMD_FEATURE[] = {
#ifdef OPTION_IPSEC
	{"vpn", "Enable VPN support", NULL, feature, 1, MSK_FEATURE},
#endif
#ifdef OPTION_X25MAP
#ifndef OPTION_X25
	{"x25", "Enable X25 support", NULL, feature, 1, MSK_FEATURE},
#else
	{"x25map", "Enable X25 map support", NULL, feature, 1, MSK_FEATURE},
#endif
#endif
#if 0
	{"ospf", "Enable OSPF support", NULL, feature, 1, MSK_FEATURE},
	{"rip", "Enable RIP support", NULL, feature, 1, MSK_FEATURE},
#endif
	{NULL, NULL, NULL, NULL}
};
#endif

#if 0
cish_command CMD_FIRMWARE_DOWNLOAD_PASSWD[] = {
	{"<text>", "User password", NULL, firmware_download, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_FIRMWARE_DOWNLOAD_USER[] = {
	{"<text>", "Username", CMD_FIRMWARE_DOWNLOAD_PASSWD, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_FIRMWARE_DOWNLOAD[] = {
#ifdef CONFIG_DM
	{"<url>", "Remote site url (http://user:pass@www.enterprise.com.br/filename)", NULL, firmware_download, 1, MSK_NORMAL},
#else
	{"<url>", "Remote site url (http://user:pass@www.pd3.com.br/filename)", NULL, firmware_download, 1, MSK_NORMAL},
#endif
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_NO_FIRMWARE[] = {
	{"upload", "Disable upload firmware mode (FTP server)", NULL, no_firmware_upload, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_FIRMWARE[] = {
	{"download", "Download new firmware", CMD_FIRMWARE_DOWNLOAD, NULL, 1, MSK_NORMAL},
	{"save", "Save uploaded firmware to flash", NULL, firmware_save, 1, MSK_NORMAL},
	{"upload", "Enable upload firmware mode (FTP server)", NULL, firmware_upload, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_NO[] = {
	{"debug", "Disable Debugging parameters", CMD_DEBUG, NULL, 1, MSK_NORMAL},
#ifdef OPTION_FEATURE
#ifdef NO_FEATURE
	{"feature", "Disable feature", CMD_NO_FEATURE, NULL, 1, MSK_FEATURE},
#endif
#endif
	{"firmware", "Firmware update", CMD_NO_FIRMWARE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#if 0
cish_command CMD_FIRMWARE_RAM[] = {
	{"save", "Save uploaded firmware to flash", NULL, firmware_save, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_RAM[] = {
	{"exit","Exit session", NULL, exit_cish, 0, MSK_NORMAL},
	{"firmware","Firmware update", CMD_FIRMWARE_RAM, NULL, 0, MSK_NORMAL},
	{"reload", "Halt and perform a cold restart", NULL, reload, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_CLEAR_INTERFACE_AUX_[] = {
	{"0-1", "Aux interface number", NULL, clear_counters, 0, MSK_AUX},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_INTERFACE_ETHERNET_[] = {
	{"0-0", "Ethernet interface number", NULL, clear_counters, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_INTERFACE_LOOPBACK_[] = {
	{"0-4", "Loopback interface number", NULL, clear_counters, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_INTERFACE_SERIAL_[] = {
	{"0-0", "Serial interface number", NULL, clear_counters, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_INTERFACE_TUNNEL_[] = {
	{"0-9", "Tunnel interface number", NULL, clear_counters, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_IPSEC
cish_command CMD_CLEAR_CRYPTO_TUNNEL_[] = {
	{"<text>", "Connection name", NULL, clear_counters, 1, MSK_NORMAL},
	{"<enter>", "Clear counters of all tunnels", NULL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CLEAR_INTERFACE[] = {
	{"aux", "Aux interface", CMD_CLEAR_INTERFACE_AUX_, NULL, 1, MSK_AUX},
	{"ethernet", "Ethernet interface", CMD_CLEAR_INTERFACE_ETHERNET_, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_CLEAR_INTERFACE_LOOPBACK_, NULL, 1, MSK_NORMAL},
	{"serial", "Serial interface", CMD_CLEAR_INTERFACE_SERIAL_, NULL, 1, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_CLEAR_INTERFACE_TUNNEL_, NULL, 1, MSK_NORMAL},
#ifdef OPTION_IPSEC
	{"crypto", "IPSec tunnel", CMD_CLEAR_CRYPTO_TUNNEL_, clear_counters, 1, MSK_VPN},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_IPHC
cish_command CMD_CLEAR_IPHC_SERIAL[] = {
	{"0-0", "Serial interface number", NULL, clear_iphc, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_IPHC[] = {
	{"serial", "Serial interface", CMD_CLEAR_IPHC_SERIAL, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_IP[] = {
	{"header-compression", "Clear IP Header Compression statistics", CMD_CLEAR_IPHC, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_RMON
cish_command CMD_CLEAR_RMON[] = {
	{"events", "Clear RMON events", NULL, clear_rmon_events, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CLEAR_SSH[] = {
	{"hosts", "Clear known SSH hosts identification", NULL, clear_ssh_hosts, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR[] = {
	{"counters", "Clear counters on interface", CMD_CLEAR_INTERFACE, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_IPHC
	{"ip", "IP statistics", CMD_CLEAR_IP, NULL, 1, MSK_NORMAL},
#endif
	{"logging", "Clear the contents of logging buffers", NULL, clear_logging, 1, MSK_NORMAL},
#ifdef OPTION_RMON
	{"rmon", "Clear the RMON counters", CMD_CLEAR_RMON, NULL, 1, MSK_NORMAL},
#endif
	{"ssh", "Clear SSH informations", CMD_CLEAR_SSH, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_GIGA
cish_command CMD_GIGA[] = {
	{"script", "Auto configure", NULL, giga_script, 0, MSK_NORMAL},
	{"scriptplus", "Auto configure", NULL, giga_scriptplus, 0, MSK_NORMAL},
	{"terminal", "Terminal access", NULL, giga_terminal, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_RELOAD_TIMEOUT[] = {
	{"1-60", "Delay before reload in minutes", NULL, reload_in, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_RELOAD[] = {
	{"cancel", "Abort scheduled reload", NULL, reload_cancel, 1, MSK_NORMAL},
	{"in", "Schedule reload timeout", CMD_RELOAD_TIMEOUT, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD[] = {
	{"clear", "Reset functions", CMD_CLEAR, NULL, 1, MSK_NORMAL},
	{"clock", "Manage the system clock", CMD_CONFIG_CLOCK, NULL, 1, MSK_NORMAL},
	{"configure", "Configure parameters", CMD_CONFIG, NULL, 1, MSK_NORMAL},
	{"copy", "Copy configuration or image data", CMD_COPY, NULL, 1, MSK_NORMAL},
	{"debug", "Debugging parameters", CMD_DEBUG, NULL, 1, MSK_NORMAL},
	{"disable", "Leave administrator mode", NULL, disable, 1, MSK_NORMAL},
	{"enable", "Enter administrator mode", NULL, enable, 0, MSK_NORMAL}, /* enable(); disable(); */
	{"erase", "Erase configuration memory", CMD_ERASE, NULL, 1, MSK_NORMAL},
	{"exit", "Exit session", NULL, exit_cish, 0, MSK_NORMAL},
#ifdef OPTION_FEATURE
	{"feature", "Enable feature", CMD_FEATURE, NULL, 1, MSK_FEATURE},
#endif
	{"firmware", "Firmware update", CMD_FIRMWARE, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_GIGA
	{"giga", "Test commands", CMD_GIGA, NULL, 1, MSK_NORMAL},
#endif
	{"help", "Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"no", "Override parameters", CMD_NO, NULL, 1, MSK_NORMAL},
	{"ping", "Send echo messages", CMD_PING, NULL, 0, MSK_NORMAL},
	{"reload", "Halt and perform a cold restart", CMD_RELOAD, reload, 1, MSK_NORMAL},
	{"show", "Show running system information", CMD_SHOW, NULL, 0, MSK_NORMAL},
	{"ssh", "Open a SSH connection", CMD_SSH, NULL, 1, MSK_NORMAL},
	{"tcpdump", "Start packet sniffer", CMD_TCPDUMP, tcpdump, 1, MSK_NORMAL},
	{"telnet", "Open a telnet connection", CMD_TELNET, NULL, 1, MSK_NORMAL},
	{"terminal", "Set terminal line parameters", CMD_TERMINAL, NULL, 0, MSK_NORMAL},
	{"traceroute", "Traceroute to destination", CMD_TRACEROUTE, NULL, 0, MSK_NORMAL},
#ifdef OPTION_X25MAP
	{"wizard", "Run TEF Wizard", NULL, tefwiz_init, 1, MSK_X25MAP},
#endif
	{NULL, NULL, NULL, NULL}
};

/* rip key chain entries */
cish_command CMD_KEY_STRING[] = {
	{"<text>", "The key", NULL, config_key_string, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

#if 0
cish_command CMD_KEYCHAIN_KEY[];
#endif

cish_command CMD_KEY[] = {
#if 0
	{"accept-lifetime", "Set accept lifetime of the key", CMD_KEY_ACCEPTLIFE, NULL, 1, MSK_RIP},
#endif
	{"exit", "Exit current mode and down to previous mode", NULL, config_key_done, 0, MSK_RIP},
	{"help", "Description of the interactive help system", NULL, help, 0, MSK_RIP},
#if 0
	{"key", "Configure a key", CMD_KEYCHAIN_KEY, NULL, 1, MSK_RIP},
#endif
	{"key-string", "Set key string", CMD_KEY_STRING, NULL, 1, MSK_RIP},
#if 0
	{"send-lifetime", "Set send lifetime of the key", CMD_KEY_SENDLIFE, NULL, 1, MSK_RIP},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_KEYCHAIN_KEY[] = {
	{"0-2147483647", "Key identifier number", NULL, config_key, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_KEYCHAIN_NO[] = {
	{"key", "Delete a key", CMD_KEYCHAIN_KEY, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_KEYCHAIN[] = {
	{"exit", "Exit current mode and down to previous mode", NULL, config_keychain_done, 0, MSK_RIP},
	{"help", "Description of the interactive help system", NULL, help, 0, MSK_RIP},
	{"key", "Configure a key", CMD_KEYCHAIN_KEY, NULL, 1, MSK_RIP},
	{"no", "Negate a command or set its defaults", CMD_KEYCHAIN_NO, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_KEY_CHAIN[] = {
	{"<text>", "Key-chain name", NULL, config_keychain, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_KEY[] = {
	{"chain", "Key-chain management", CMD_CONFIG_KEY_CHAIN, NULL, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};


