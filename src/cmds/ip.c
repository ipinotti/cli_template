#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_ROUTER
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
#endif

#ifdef OPTION_HTTP
cish_command CMD_NO_IP_HTTP[] = {
	{"server", "Disable HTTP server", NULL, no_http_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_HTTPS
cish_command CMD_NO_IP_HTTPS[] = {
	{"server", "Disable HTTPS server", NULL, no_https_server, 1, MSK_NORMAL},
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
	{NULL,NULL,NULL,NULL, 0}
};


#ifdef OPTION_ROUTER
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

cish_command CMD_IP_ICMP_IGNORE[] = {
	{"all", "Ignore all icmp traffic", NULL, ip_param, 1, MSK_NORMAL},
	{"bogus", "Ignore bogus error responses", NULL, ip_param, 1, MSK_NORMAL},
	{"broadcasts", "Ignore broadcast traffic", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,0}
};

cish_command CMD_IP_ICMP[] = {
	{"ignore", "Set ignore parameters", CMD_IP_ICMP_IGNORE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif /* OPTION_ROUTER */

#ifdef OPTION_SMCROUTE
cish_command CMD_IP_MROUTE8_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Interface number", NULL, ip_mroute, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

#ifdef OPTION_SERIAL
cish_command CMD_IP_MROUTE8_SERIAL[] = {
	{"0-0", "Interface number", NULL, ip_mroute, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IP_MROUTE7[] = {
	{"ethernet", "Ethernet interface", CMD_IP_MROUTE8_ETHERNET, NULL, 1, MSK_NORMAL},
#ifdef OPTION_SERIAL
	{"serial", "Serial interface", CMD_IP_MROUTE8_SERIAL, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE6[] = {
	{"out", "Output interface", CMD_IP_MROUTE7, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE5_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Interface number", CMD_IP_MROUTE6, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE5_SERIAL[] = {
	{"0-0", "Interface number", CMD_IP_MROUTE6, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_MROUTE4[] = {
	{"ethernet", "Ethernet interface", CMD_IP_MROUTE5_ETHERNET, NULL, 1, MSK_NORMAL},
#ifdef OPTION_SERIAL
	{"serial", "Serial interface", CMD_IP_MROUTE5_SERIAL, NULL, 1, MSK_NORMAL},
#endif
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

#ifdef OPTION_EFM
cish_command CMD_IP_ROUTE4_EFM[] = {
	{CLI_STRING_EFM_IFACES, "EFM interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IP_ROUTE4_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_LOOPBACK[] = {
	{"0-0", "Loopback interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_TUNNEL[] = {
	{"0-9", "Tunnel interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#ifdef OPTION_MODEM3G
cish_command CMD_IP_ROUTE4_3G[] = {
	{"0-2", "3G interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_IP_ROUTE4_PPTP[] = {
	{"0-0", "PPTP interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE4_PPPOE[] = {
	{"0-0", "PPPoE interface number", CMD_IP_ROUTE5, zebra_execute_cmd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_IP_ROUTE3[] = {
#ifdef OPTION_EFM
	{"efm", "EFM interface", CMD_IP_ROUTE4_EFM, NULL, 1, MSK_NORMAL},
#endif
	{"ethernet", "Ethernet interface", CMD_IP_ROUTE4_ETHERNET, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_IP_ROUTE4_LOOPBACK, NULL, 1, MSK_NORMAL},
	{"tunnel", "Tunnel interface", CMD_IP_ROUTE4_TUNNEL, NULL, 1, MSK_NORMAL},
#ifdef OPTION_MODEM3G
	{"m3G", "3G Interface", CMD_IP_ROUTE4_3G, NULL, 1, MSK_NORMAL},
#endif
	{"pptp", "PPTP Interface", CMD_IP_ROUTE4_PPTP, NULL, 1, MSK_NORMAL},
	{"pppoe", "PPPoE Interface", CMD_IP_ROUTE4_PPPOE, NULL, 1, MSK_NORMAL},
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

#ifdef OPTION_ROUTER
cish_command CMD_IP_DEFAULT_TTL[] = {
	{"0-255", "Default TTL value", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_HTTP
cish_command CMD_IP_HTTP[] = {
	{"server", "Enable HTTP server", NULL, http_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_HTTPS
cish_command CMD_IP_HTTPS[] = {
	{"server", "Enable HTTPS server", NULL, https_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_IP_SSH_KEY_RSA[] = {
	{"768-2048", "Length in bits (multiple of 8)", NULL, ssh_generate_rsa_key, 1, MSK_NORMAL},
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


/* DHCP Server commands */
cish_command CMD_IP_DHCP_SERVER_DNS[] = {
	{"<ipaddress>", "IP address of a DNS server", NULL, dhcp_server_dns, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_DEFAULT_ROUTER[] = {
	{"<ipaddress>", "IP address of the default router", NULL, dhcp_server_default_router, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_NAME[] = {
	{"<text>", "Domain name for the client", NULL, dhcp_server_domainname, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_LEASETIME_3[] = {
	{"0-59", "seconds", NULL, dhcp_server_leasetime, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_LEASETIME_2[] = {
	{"0-59", "minutes", CMD_IP_DHCP_SERVER_LEASETIME_3, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_LEASETIME_1[] = {
	{"0-23", "hours", CMD_IP_DHCP_SERVER_LEASETIME_2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_LEASETIME[] = {
	{"0-20000", "days", CMD_IP_DHCP_SERVER_LEASETIME_1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_DHCP_NETBIOS
cish_command CMD_IP_DHCP_SERVER_NBNS[] = {
	{"<ipaddress>", "IP address of a NetBIOS name server WINS (NBNS)", NULL, dhcp_server_nbns, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_NBDD[] = {
	{"<ipaddress>", "IP address of a NetBIOS datagram distribution server (NBDD)", NULL, dhcp_server_nbdd, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_NBNT[] = {
	{"B", "NetBIOS B-node (Broadcast - no WINS)", NULL, dhcp_server_nbnt, 1, MSK_NORMAL},
	{"P", "NetBIOS P-node (Peer - WINS only)", NULL, dhcp_server_nbnt, 1, MSK_NORMAL},
	{"M", "NetBIOS M-node (Mixed - broadcast, then WINS)", NULL, dhcp_server_nbnt, 1, MSK_NORMAL},
	{"H", "NetBIOS H-node (Hybrid - WINS, then broadcast)", NULL, dhcp_server_nbnt, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_IP_DHCP_POOL_END[] = {
	{"<ipaddress>", "Pool end", NULL, dhcp_server_pool, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_POOL_BEGIN[] = {
	{"<ipaddress>", "Pool begin", CMD_IP_DHCP_POOL_END, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_NETWORK_MASK[] = {
	{"<netmask>", "Network mask of the DHCP pool", NULL, dhcp_server_network, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_NETWORK[] = {
	{"<ipaddress>", "Network number of the DHCP pool", CMD_IP_DHCP_NETWORK_MASK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER_NO[] = {
	{"default-lease-time", "Delete default lease time", NULL, dhcp_server_leasetime, 1, MSK_NORMAL},
	{"domain-name", "Delete current domain name for the client", NULL, dhcp_server_domainname, 1, MSK_NORMAL},
	{"dns-server", "Delete current IP address of a DNS server", NULL, dhcp_server_dns, 1, MSK_NORMAL},
	{"enable", "Disable DHCP Server", NULL, dhcp_server_disable, 1, MSK_NORMAL},
	{"max-lease-time", "Delete maximum lease time", NULL, dhcp_server_leasetime, 1, MSK_NORMAL},
#ifdef OPTION_DHCP_NETBIOS
	{"netbios-name-server", "Delete current IP address of the NetBIOS name server WINS (NBNS)",
			CMD_IP_DHCP_SERVER_NBNS, NULL, 1, MSK_NORMAL},
	{"netbios-dd-server", "Delete current the IP address of the NetBIOS datagram distribution server (NBDD)",
			CMD_IP_DHCP_SERVER_NBDD, NULL, 1, MSK_NORMAL},
	{"netbios-node-type", "Delete current NetBIOS node type of the client",
			CMD_IP_DHCP_SERVER_NBNT, NULL, 1, MSK_NORMAL},
#endif
	{"router", "Delete current IP address of the default router", NULL, dhcp_server_default_router, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_DHCP_SERVER[] = {
	{"default-lease-time", "Specify default lease time", CMD_IP_DHCP_SERVER_LEASETIME, NULL, 1, MSK_NORMAL},
	{"domain-name", "Specify the domain name for the client", CMD_IP_DHCP_SERVER_NAME, NULL, 1, MSK_NORMAL},
	{"dns-server", "Specify the IP address of a DNS server", CMD_IP_DHCP_SERVER_DNS, NULL, 1, MSK_NORMAL},
	{"enable", "Enable DHCP Server", NULL, dhcp_server_enable, 1, MSK_NORMAL},
	{"exit","Exit this menu", NULL, dhcp_server_exit, 0, MSK_NORMAL},
	{"max-lease-time", "Specify maximum lease time", CMD_IP_DHCP_SERVER_LEASETIME, NULL, 1, MSK_NORMAL},
#ifdef OPTION_DHCP_NETBIOS
	{"netbios-name-server", "Specify the IP address of the NetBIOS name server WINS (NBNS)",
			CMD_IP_DHCP_SERVER_NBNS, NULL, 1, MSK_NORMAL},
	{"netbios-dd-server", "Specify the IP address of the NetBIOS datagram distribution server (NBDD)",
			CMD_IP_DHCP_SERVER_NBDD, NULL, 1, MSK_NORMAL},
	{"netbios-node-type", "Specify the NetBIOS node type of the client",
			CMD_IP_DHCP_SERVER_NBNT, NULL, 1, MSK_NORMAL},
#endif
	{"network", "Specify the network for the DHCP pool", CMD_IP_DHCP_NETWORK, NULL, 1, MSK_NORMAL},
	{"no", "Reverse a Setting", CMD_IP_DHCP_SERVER_NO, NULL, 1, MSK_NORMAL},
	{"pool", "Specify a pool of supplied addresses", CMD_IP_DHCP_POOL_BEGIN, NULL, 1, MSK_NORMAL},
	{"router", "Specify the IP address of the default router", CMD_IP_DHCP_DEFAULT_ROUTER, NULL, 1, MSK_NORMAL},
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
	{"server", "Enter DHCP server menu", NULL, dhcp_server, 1, MSK_NORMAL},
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
	{"sparse-mode", "Disable PIM Sparse Mode", NULL, pim_sparse_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_ROUTER
cish_command CMD_NO_IP_TCP[] = {
	{"ecn", "Disable Explicit Congestion Notification", NULL, no_ip_param, 1, MSK_NORMAL},
	{"syncookies", "Disable syn cookies", NULL, no_ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif

cish_command CMD_NO_IP[] = {
	{"dhcp", "Disable DHCP server/relay", CMD_NO_IP_DHCP, NULL, 1, MSK_NORMAL},
	{"dns", "Configure DNS relay", CMD_IP_DNS, NULL, 1, MSK_NORMAL},
	{"domain", "Disable name lookup", CMD_IP_DOMAIN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_NET_FASTROUTE
	{"fastroute", "Enable interfaces fastroute (bypass firewall)", NULL, no_ip_param, 1, MSK_NORMAL},
#endif
#ifdef OPTION_HTTP
	{"http", "HTTP server configuration", CMD_NO_IP_HTTP, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_HTTPS
	{"https", "HTTPS server configuration", CMD_NO_IP_HTTPS, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"icmp", "Unset icmp parameters", CMD_NO_IP_ICMP, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PIMD
	{"multicast-routing", "Disable IP multicast forwarding", NULL, no_ip_param, 1, MSK_NORMAL},
#endif
#ifdef OPTION_SMCROUTE
	{"mroute", "Establish multicast static routes", CMD_IP_MROUTE1, NULL, 1, MSK_NORMAL},
#endif
	{"name-server", "Specify address of name server to remove", CMD_IP_NAMESERVER, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NAT
	{"nat", "NAT helper configuration", CMD_IP_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM global commands", CMD_NO_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"pmtu-discovery", "Disable Path MTU discovery", NULL, no_ip_param, 1, MSK_NORMAL},
	{"routing", "Disable IP routing", NULL, no_ip_param, 1, MSK_NORMAL},
	{"rp-filter", "Disable reverse path filter", NULL, no_ip_param, 1, MSK_NORMAL},
	{"tcp", "Unset tcp parameters", CMD_NO_IP_TCP, NULL, 1, MSK_NORMAL},
#endif
	{"route", "Establish static routes", CMD_IP_ROUTE1, NULL, 1, MSK_NORMAL},
	{"ssh", "SSH server configuration", CMD_NO_IP_SSH, NULL, 1, MSK_NORMAL},
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
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", CMD_IP_PIM_CAND_BSR_PRIORITY, pim_bsr_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_SERIAL
cish_command CMD_IP_PIM_CAND_BSR_INTF_SERIAL[] = {
	{"0-0", "Serial interface number", CMD_IP_PIM_CAND_BSR_PRIORITY, pim_bsr_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_IP_PIM_CAND_BSR_INTF[] = {
#ifdef OPTION_ETHERNET_WAN
	{"ethernet", "Ethernet interface", CMD_IP_PIM_CAND_BSR_INTF_ETHERNET, NULL, 0, MSK_NORMAL},
#endif
#ifdef OPTION_SERIAL
	{"serial", "Serial interface", CMD_IP_PIM_CAND_BSR_INTF_SERIAL, NULL, 0, MSK_NORMAL},
#endif
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
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", CMD_IP_PIM_CAND_RP_PRIORITY, pim_rp_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_INTF_SERIAL[] = {
	{"0-0", "Serial interface number", CMD_IP_PIM_CAND_RP_PRIORITY, pim_rp_candidate, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM_CAND_RP_INTF[] = {
#ifdef OPTION_ETHERNET_WAN
	{"ethernet", "Ethernet interface", CMD_IP_PIM_CAND_RP_INTF_ETHERNET, NULL, 0, MSK_NORMAL},
#endif
#ifdef OPTION_SERIAL
	{"serial", "Serial interface", CMD_IP_PIM_CAND_RP_INTF_SERIAL, NULL, 0, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IP_PIM[] = {
	{"bsr-candidate", "Candidate bootstrap router (candidate BSR)", CMD_IP_PIM_CAND_BSR_INTF, NULL, 1, MSK_NORMAL},
#if 0
	{"register-rate-limit", "Rate limit for PIM data registers", CMD_IP_PIM_RRL, NULL, 1, MSK_NORMAL},
#endif
	{"rp-address", "PIM RP-address (Rendezvous Point)", CMD_IP_PIM_RP_ADDRESS, NULL, 1, MSK_NORMAL},
	{"rp-candidate", "To be a PIMv2 RP candidate", CMD_IP_PIM_CAND_RP_INTF, NULL, 1, MSK_NORMAL},
	{"sparse-mode", "Enable PIM Sparse Mode", NULL, pim_sparse_mode, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef CONFIG_DEVELOPMENT
#ifdef OPTION_ROUTER
cish_command CMD_IP_MAXBACKLOG[] = {
	{"10-4096", "Max RX backlog size", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif
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

#ifdef OPTION_ROUTER
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
#ifdef OPTION_KEEPALIVE
	{"keepalive_intvl", "Keepalive probe interval time", CMD_IP_TCP_KEEPALIVE_INTVL, NULL, 1, MSK_NORMAL},
	{"keepalive_probes", "Keepalive probe retries", CMD_IP_TCP_KEEPALIVE_PROBES, NULL, 1, MSK_NORMAL},
	{"keepalive_time", "Keepalive idle timer", CMD_IP_TCP_KEEPALIVE_IDLE, NULL, 1, MSK_NORMAL},
#endif
	{"syncookies", "Enable syn cookies", NULL, ip_param, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL,0}
};
#endif /* OPTION_ROUTER */

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
	{"dhcp", "Enable DHCP server/relay", CMD_IP_DHCP, NULL, 1, MSK_NORMAL},
	{"dns", "Configure DNS relay", CMD_IP_DNS, NULL, 1, MSK_NORMAL},
	{"domain", "Enable name lookup", CMD_IP_DOMAIN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_NET_FASTROUTE
	{"fastroute", "Enable interfaces fastroute (bypass firewall)", NULL, ip_param, 1, MSK_NORMAL},
#endif
#ifdef OPTION_ROUTER
	{"fragment", "Set fragmenting parameters", CMD_IP_FRAG, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_HTTP
	{"http", "HTTP server configuration", CMD_IP_HTTP, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_HTTPS
	{"https", "HTTPS server configuration", CMD_IP_HTTPS, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PIMD
	{"multicast-routing", "Enable IP multicast forwarding", NULL, ip_param, 1, MSK_NORMAL},
#endif
#ifdef OPTION_SMCROUTE
	{"mroute", "Establish multicast static routes", CMD_IP_MROUTE1, NULL, 1, MSK_NORMAL},
#endif
	{"name-server", "Specify address of name server to add", CMD_IP_NAMESERVER, NULL, 1, MSK_NORMAL},
#ifdef OPTION_NAT
	{"nat", "NAT helper configuration", CMD_IP_NAT, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_PIMD
	{"pim", "PIM global commands", CMD_IP_PIM, NULL, 1, MSK_NORMAL},
#endif
	{"route", "Establish static routes", CMD_IP_ROUTE1, NULL, 1, MSK_NORMAL},
#ifdef OPTION_ROUTER
	{"default-ttl", "Default TTL value", CMD_IP_DEFAULT_TTL, NULL, 1, MSK_NORMAL},
	{"routing", "Enable IP routing", NULL, ip_param, 1, MSK_NORMAL},
	{"icmp", "Set icmp parameters", CMD_IP_ICMP, NULL, 1, MSK_NORMAL},
	{"pmtu-discovery", "Enable Path MTU discovery", NULL, ip_param, 1, MSK_NORMAL},
	{"rp-filter", "Enable reverse path filter", NULL, ip_param, 1, MSK_NORMAL},
	{"tcp", "Set tcp parameters", CMD_IP_TCP, NULL, 1, MSK_NORMAL},
#endif
	{"ssh", "SSH server configuration", CMD_IP_SSH, NULL, 1, MSK_NORMAL},
	{"telnet", "Telnet server configuration", CMD_IP_TELNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
