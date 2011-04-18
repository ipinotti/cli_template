#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/autoconf.h>

#include "commands.h"
#include "commandtree.h"

char EXTCMD[1024];
char EXTSCRIPT[1024];
cish_command CEXT = {EXTCMD, EXTSCRIPT, NULL, NULL, 0};

#ifdef OPTION_EFM
cish_command CMD_CONFIG_INTERFACE_EFM_[] = {
	{"0-0", "EFM interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_ETHERNET_[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_LOOPBACK_[] = {
	{"0-0", "Loopback interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_TUNNEL_[] = {
	{"0-0", "Tunnel interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_MODEM3G
cish_command CMD_CONFIG_INTERFACE_M3G_[] = {
	{"0-2", "3G interface number -| 0 == Built-in | 1 == USB1 | 2 == USB2", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CONFIG_INTERFACE_PPTP_[] = {
	{"0-0", "PPTP interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_PPPOE_[] = {
	{"0-0", "PPPoE interface number", NULL, config_interface, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE[] = {
#ifdef OPTION_EFM
	{"efm", "Ethernet-First-Mile interface", CMD_CONFIG_INTERFACE_EFM_, NULL, 0, MSK_NORMAL},
#endif
	{"ethernet", "Ethernet interface", CMD_CONFIG_INTERFACE_ETHERNET_, NULL, 0, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_CONFIG_INTERFACE_LOOPBACK_, NULL, 0, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_CONFIG_INTERFACE_TUNNEL_, NULL, 0, MSK_NORMAL},
#ifdef OPTION_MODEM3G
	{"m3G", "3G interface", CMD_CONFIG_INTERFACE_M3G_, NULL, 0, MSK_NORMAL},
#endif
	{"pptp", "PPTP Interface", CMD_CONFIG_INTERFACE_PPTP_, NULL, 0, MSK_NORMAL},
	{"pppoe", "PPPoE Interface", CMD_CONFIG_INTERFACE_PPPOE_, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO_INTERFACE[] = {
	{"tunnel", "Tunnel interface", CMD_CONFIG_INTERFACE_TUNNEL_, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_FIREWALL
cish_command CMD_NO_ACL[] = {
	{"<acl>","Access lists name", NULL, no_accesslist, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif

#ifdef OPTION_QOS
cish_command CMD_NO_MANGLE[] = {
	{"<acl>","MARK rule name", NULL, no_mangle_rule, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif

#ifdef OPTION_NAT
cish_command CMD_NO_NAT[] = {
	{"<acl>","NAT rule name", NULL, no_nat_rule, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL, 0}
};
#endif

#ifdef OPTION_PPP
cish_command CMD_CONFIG_NO_CHATSCRIPT[] = {
	{"<text>","Chatscript name", NULL, ppp_nochatscript, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_NO_LOG[] = {
	{"remote","Disable remote logging", NULL, no_log_remote, 1, MSK_NORMAL},
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

#ifdef OPTION_ROUTER
cish_command CMD_CONFIG_NO_ROUTER[] = {
#ifdef OPTION_BGP
	{"bgp", "Border Gateway Protocol (BGP)", CMD_CONFIG_NO_ROUTER_BGP, NULL, 1, MSK_BGP},
#endif
	{"ospf", "Open Shortest Path First (OSPF)", NULL, config_no_router, 1, MSK_OSPF},
	{"rip", "Routing Information Protocol (RIP)", NULL, config_no_router, 1, MSK_RIP},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

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

cish_command CMD_CONFIG_POLICYMAP[] = {
	{"<text>","policy-map name", NULL, do_policymap, 1, MSK_QOS},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_NO[] = {
	{"aaa","Authentication, Authorization and Accounting.", CMD_CONFIG_NO_AAA, NULL, 1, MSK_NORMAL},
#ifdef OPTION_FIREWALL
	{"access-list","Remove access-list", CMD_NO_ACL, NULL, 1, MSK_NORMAL},
#endif
	{"arp", "Unset a static ARP entry", CMD_NO_ARP_IP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_BRIDGE
	{"bridge", "Bridging Group", CMD_CONFIG_NO_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PPP
	{"chatscript", "Reset a chatscript", CMD_CONFIG_NO_CHATSCRIPT, NULL, 1, MSK_NORMAL},
#endif
	{"interface","Interface Configuration", CMD_CONFIG_NO_INTERFACE, NULL, 1, MSK_NORMAL},
	{"ip","IPv4 Configuration", CMD_NO_IP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_ROUTER
	{"key","Authentication key management (RIP)", CMD_CONFIG_KEY, NULL, 1, MSK_RIP},
#endif
	{"logging", "Unset a logging target", CMD_CONFIG_NO_LOG, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark-rule","Remove MARK rule", CMD_NO_MANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat-rule","Remove NAT rule", CMD_NO_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_NTPD
	{"ntp", "NTP Configuration", CMD_NO_NTP, NULL, 1, MSK_NORMAL},
#else
	{"ntp-sync", "Disable NTP synchronization", NULL, no_ntp_sync, 1, MSK_NORMAL},
#endif
	{"policy-map", "Configure QoS Policy Map", CMD_CONFIG_POLICYMAP, NULL, 1, MSK_QOS},
	{"radius-server", "Modify RADIUS query parameters", CMD_CONFIG_NO_RADIUSSERVER_HOST, 
								del_radiusserver, 1, MSK_NORMAL},
#ifdef OPTION_RMON
	{"rmon", "Modify RMON settings", CMD_CONFIG_NO_RMON, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"router", "Disable a routing process", CMD_CONFIG_NO_ROUTER, NULL, 1, MSK_NORMAL},
#endif
	{"secret", "Disable authentication secrets", CMD_NO_SECRET, NULL, 1, MSK_NORMAL},
	{"snmp-server", "Remove SNMP settings", CMD_CONFIG_NO_SNMP, snmp_no_server, 1, MSK_NORMAL},
	{"tacacs-server", "Modify TACACS query parameters", CMD_CONFIG_NO_TACACSSERVER_HOST, 
								del_tacacsserver, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_FIREWALL
cish_command CMD_CONFACLPOL[] = {
	{"accept","Accept all packets", NULL, do_accesslist_policy, 1, MSK_NORMAL},
	{"drop","Drop all packets", NULL, do_accesslist_policy, 1, MSK_NORMAL},
#if 0
	{"reject","Reject all packets", NULL, do_accesslist_policy, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};
#endif /* OPTION_FIREWALL */

#ifdef OPTION_PPP
cish_command CMD_CONFIG_CHATSCRIPT2[] = {
	{"<string>","Chat script in form EXPECT SEND EXPECT SEND ...", CMD_CONFIG_CHATSCRIPT2, ppp_chatscript, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_CHATSCRIPT[] = {
	{"<text>","Chatscript name", CMD_CONFIG_CHATSCRIPT2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_CONFIG_LOG_REMOTE[] = {
	{"<ipaddress>", "Remote log host", NULL, log_remote, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_LOG[] = {
	{"remote","Enable remote logging (do not forget syslogd -r option)", CMD_CONFIG_LOG_REMOTE, log_remote, 1, MSK_NORMAL},
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

#ifdef OPTION_ROUTER
cish_command CMD_CONFIG_ROUTER[] = {
#ifdef OPTION_BGP
	{"bgp", "Border Gateway Protocol (BGP)", CMD_CONFIG_ROUTER_BGP_AS, NULL, 1, MSK_NORMAL},
#endif
	{"ospf", "Open Shortest Path First (OSPF)", NULL, config_router, 1, MSK_NORMAL},
	{"rip", "Routing Information Protocol (RIP)", NULL, config_router, 1, MSK_NORMAL},
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

#ifdef OPTION_SHOWLEVEL
cish_command CMD_SHOW_LEVEL[] = {
	{"running-config", "Current configuration", NULL, show_level_running_config, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_ARP_MAC[] = {
	{"<mac>", "48-bit hardware address of ARP entry (xx:xx:xx:xx:xx:xx)", NULL, arp_entry, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ARP_IP[] = {
	{"<ipaddress>", "IP address of ARP entry", CMD_ARP_MAC, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIGURE[] = {
	{"aaa","Authentication, Authorization and Accounting.", CMD_CONFIG_AAA, NULL, 1, MSK_NORMAL},
#ifdef OPTION_FIREWALL
	{"access-list","Set an ACL", CMD_CONFACL1, NULL, 1, MSK_NORMAL},
	{"access-policy", "Set default access policy", CMD_CONFACLPOL, NULL, 1, MSK_NORMAL},
#endif
	{"arp", "Set a static ARP entry", CMD_ARP_IP, NULL, 1, MSK_NORMAL},
#ifdef OPTION_BRIDGE
	{"bridge", "Bridging Group", CMD_CONFIG_BRIDGE, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PPP
	{"chatscript", "Set a chatscript line", CMD_CONFIG_CHATSCRIPT, NULL, 1, MSK_NORMAL},
#endif
	{"clock","Manage the system clock", CMD_CONFIGURE_CLOCK, NULL, 1, MSK_NORMAL},
#ifdef OPTION_IPSEC
	{"crypto","Manage cryptographic tunnels", NULL, cd_crypto_dir, 1, MSK_VPN},
#endif
	{"exit","Exit from configure mode", NULL, config_term_done, 0, MSK_NORMAL},
	{"help","Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"hostname","Set system's hostname", CMD_CONFIG_HOSTNAME, NULL, 1, MSK_NORMAL},
	{"ip","IPv4 Configuration", CMD_IP, NULL, 1, MSK_NORMAL},
	{"interface","Interface Configuration", CMD_CONFIG_INTERFACE, NULL, 1, MSK_NORMAL},
#ifdef OPTION_ROUTER
	{"key","Authentication key management (RIP)", CMD_CONFIG_KEY, NULL, 1, MSK_RIP},
#endif
	{"logging","Logging info", CMD_CONFIG_LOG, NULL, 1, MSK_NORMAL},
#ifdef OPTION_QOS
	{"mark-rule","Add MARK rule", CMD_CONFMANGLE, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_NAT
	{"nat-rule","Add NAT rule", CMD_CONFNAT1, NULL, 1, MSK_NORMAL},
#endif
	{"no","Reverse settings", CMD_CONFIG_NO, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NTPD
	{"ntp","Set time synchronization", CMD_CONFIG_NTP, NULL, 1, MSK_NORMAL},
#else
	{"ntp-sync","Set time synchronization", CMD_CONFIG_NTP, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_QOS
	{"policy-map", "Configure QoS Policy Map", CMD_CONFIG_POLICYMAP, NULL, 1, MSK_QOS},
#endif
#ifdef OPTION_ROUTER
	{"policy-route", "Configure Policy Route (PBR)", NULL, cd_policyroute_dir, 1, MSK_NORMAL},
#endif
	{"radius-server", "Modify RADIUS query parameters", CMD_CONFIG_RADIUSSERVER_HOST, NULL, 1, MSK_NORMAL},
#ifdef OPTION_RMON
	{"rmon","Set RMON agent configuration", CMD_CONFIG_RMON, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"router","Enable a routing process", CMD_CONFIG_ROUTER, NULL, 1, MSK_NORMAL},
#endif
	{"secret","Set authentication secrets", CMD_SECRET, NULL, 1, MSK_NORMAL},
	{"snmp-server","Set SNMP server configuration", CMD_CONFIG_SNMP, NULL, 1, MSK_NORMAL},
	{"tacacs-server","Modify TACACS query parameters", CMD_CONFIG_TACACSSERVER_HOST, NULL, 1, MSK_NORMAL},
	{"terminal","Set terminal line parameters", CMD_TERMINAL, NULL, 0, MSK_NORMAL},
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};
