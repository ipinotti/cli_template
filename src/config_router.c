#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

/* deamon zebra */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/netdevice.h>

#include <libconfig/options.h>
#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"

#undef DEBUG_ZEBRA

#define ZEBRA_CONF "/etc/quagga/zebra.conf"
#define RIPD_CONF "/etc/quagga/ripd.conf"
#define OSPFD_CONF "/etc/quagga/ospfd.conf"
#define BGPD_CONF "/etc/quagga/bgpd.conf"

#define RIPD_RO_CONF "/etc.ro/quagga/ripd.conf"
#define OSPFD_RO_CONF "/etc.ro/quagga/ospfd.conf"
#define BGPD_RO_CONF "/etc.ro/quagga/bgpd.conf"

extern cish_command *command_root;
extern cish_command CMD_CONFIG_NO[];
extern cish_command CMD_CONFIGURE[];
extern cish_command CMD_CONFIG_ROUTER[];
extern cish_command CMD[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO_IP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_IP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO_IP[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_IP[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL_NO_IP[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC[];
extern cish_command CMD_SHOW[];
extern cish_command CMD_SHOW_IP[];
extern cish_command CMD_SHOW_INTERFACES[];
extern cish_command CMD_CONFIG_INTERFACE[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL_IP[];
#ifdef OPTION_BGP
extern cish_command CMD_IP[];
extern cish_command CMD_CONFIG_NO_ROUTER[];
#endif
extern cish_command CMD_IP_ROUTE3[];
extern cish_command CMD_CLEAR_INTERFACE[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_NO[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN_NO[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[];
extern cish_command CMD_SHOW_LEVEL[];

extern const char *_cish_source;

extern char buf[1024];

extern device_family  *interface_edited;
extern int interface_major;
extern int interface_minor;

/* deamon zebra */
static char buf_daemon[1024];

/*AS number for BGP*/
int asn = 0;

cish_command CMD_ROUTER_NO_RIP_DEFAULT_INFORMATION[] = {
	{"originate", "Distribute a default route", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_DEFAULT_INFORMATION[] = {
	{"originate", "Distribute a default route", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_NO_RIP_DEFAULT_METRIC[] = {
	{"1-16", "Default metric", NULL, rip_execute_router_cmd, 1},
        {"<enter>", "", NULL, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_DEFAULT_METRIC[] = {
	{"1-16", "Default metric", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

/*
cish_command CMD_ROUTER_RIP_ACL_METRIC_OFFSET[] = {
	{"<text>", "Interface to match", NULL, rip_execute_router_cmd, 1},
        {"<enter>", "", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_ACL_METRIC[] = {
	{"0-16", "Default metric", CMD_ROUTER_RIP_ACL_METRIC_OFFSET, NULL, 1},
        {NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_ACL[] = {
	{"in", "For incoming updates", CMD_ROUTER_RIP_ACL_METRIC, NULL, 1},
        {"out", "For outgoing updates", CMD_ROUTER_RIP_ACL_METRIC, NULL, 1},
        {NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_OFFSET_LIST[] = {
	{"<text>", "Access-list name", CMD_ROUTER_RIP_ACL, NULL, 1},
        {NULL,NULL,NULL,NULL,0}
};
*/

cish_command CMD_ROUTER_RIP_NETWORK_MASK[] = {
	{"<netmask>", "Network mask", NULL, rip_execute_router_cmd, 1},
        {NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_INTERFACE_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_RIP_INTERFACE_LOOPBACK[] = {
	{"0-4", "Loopback interface number", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_RIP_INTERFACE_TUNNEL[] = {
	{"0-9", "Tunnel interface number", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_RIP_NETWORK[] = {
	{"ethernet", "Ethernet interface", CMD_ROUTER_RIP_INTERFACE_ETHERNET, NULL, 1},
	{"loopback", "Loopback interface", CMD_ROUTER_RIP_INTERFACE_LOOPBACK, NULL, 1},
	{"tunnel", "Tunnel interface", CMD_ROUTER_RIP_INTERFACE_TUNNEL, NULL, 1},
	{"<ipaddress>", "Network address", CMD_ROUTER_RIP_NETWORK_MASK, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_NEIGHBOR[] = {
	{"<ipaddress>", "Neighbor address", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_PASSIVE_INTERFACE[] = {
	{"ethernet", "Ethernet interface", CMD_ROUTER_RIP_INTERFACE_ETHERNET, NULL, 1},
	{"loopback", "Loopback interface", CMD_ROUTER_RIP_INTERFACE_LOOPBACK, NULL, 1},
	{"tunnel", "Tunnel interface", CMD_ROUTER_RIP_INTERFACE_TUNNEL, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_REDISTRIBUTE2[] = {
	{"<text>", "Pointer to route-map entries", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_RIP_REDISTRIBUTE1[] = {
	{"metric", "Metric for redistributed routes", CMD_ROUTER_RIP_DEFAULT_METRIC, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_RIP_REDISTRIBUTE2, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_RIP_REDISTRIBUTE[] = {
#ifdef OPTION_BGP
	{"bgp", "Border Gateway Protocol (BGP)", CMD_ROUTER_RIP_REDISTRIBUTE1, rip_execute_router_cmd, 1},
#endif
	{"connected", "Connected", CMD_ROUTER_RIP_REDISTRIBUTE1, rip_execute_router_cmd, 1},
	{"kernel", "Kernel routes", CMD_ROUTER_RIP_REDISTRIBUTE1, rip_execute_router_cmd, 1},
	{"ospf", "Open Shortest Path First (OSPF)", CMD_ROUTER_RIP_REDISTRIBUTE1, rip_execute_router_cmd, 1},
	{"static", "Static routes", CMD_ROUTER_RIP_REDISTRIBUTE1, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_RIP_VERSION[] = {
	{"1-2", "RIP version", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_VERSION_NO[] = {
	{"1-2", "RIP version", NULL, rip_execute_router_cmd, 1},
	{"<enter>", "", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_TIMERS3[] = {
	{"0-4294967295", "Garbage collection timer. Default is 120.", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_TIMERS2[] = {
	{"0-4294967295", "Routing information timeout timer. Default is 180.", CMD_ROUTER_RIP_TIMERS3, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_TIMERS1[] = {
	{"0-4294967295", "Routing table update timer value in second. Default is 30.", CMD_ROUTER_RIP_TIMERS2, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_NO_RIP_TIMERS[] = {
	{"basic", "Basic routing protocol update timers", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_RIP_TIMERS[] = {
	{"basic", "Basic routing protocol update timers", CMD_ROUTER_RIP_TIMERS1, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_CONFIG_ROUTER_RIP_NO[] = {
	{"default-information", "Control distribution of default route", CMD_ROUTER_NO_RIP_DEFAULT_INFORMATION, NULL, 1},
	{"default-metric", "Set metric of redistribute routes", CMD_ROUTER_NO_RIP_DEFAULT_METRIC, rip_execute_router_cmd, 1},
//	{"distance", "Define an administrative distance", NULL, NULL, 1},
//	{"distribute-list", "Filter networks in routing updates", NULL, NULL, 1},
	{"neighbor", "Specify a neighbor router", CMD_ROUTER_RIP_NEIGHBOR, NULL, 1},
	{"network", "Enable routing on an IP network", CMD_ROUTER_RIP_NETWORK, NULL, 1},
//	{"offset-list", "Modify RIP metric", CMD_ROUTER_RIP_OFFSET_LIST, NULL, 1},
	{"passive-interface", "Suppress routing updates on an interface", CMD_ROUTER_RIP_PASSIVE_INTERFACE, NULL, 1},
	{"redistribute", "Redistribute information from another routing protocol", CMD_ROUTER_RIP_REDISTRIBUTE, NULL, 1},
	{"version", "Set routing protocol version", CMD_ROUTER_RIP_VERSION_NO, NULL, 1},
	{"timers", "Adjust routing timers", CMD_ROUTER_NO_RIP_TIMERS, NULL, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_ROUTER_RIP[] = {
	{"default-information", "Control distribution of default route", CMD_ROUTER_RIP_DEFAULT_INFORMATION, NULL, 1},
	{"default-metric", "Set a metric of redistribute routes", CMD_ROUTER_RIP_DEFAULT_METRIC, NULL, 1},
//	{"distance", "Administrative distance", NULL, NULL, 1},
//	{"distribute-list", "Filter networks in routing updates", NULL, NULL, 1},
        {"exit", "Exit current mode and down to previous mode", NULL, config_router_done, 1},
	{"neighbor", "Specify a neighbor router", CMD_ROUTER_RIP_NEIGHBOR, NULL, 1},
	{"network", "Enable routing on an IP network", CMD_ROUTER_RIP_NETWORK, NULL, 1},
	{"no", "Reverse settings", CMD_CONFIG_ROUTER_RIP_NO, NULL, 1},
//	{"offset-list", "Modify RIP metric", CMD_ROUTER_RIP_OFFSET_LIST, NULL, 1},
	{"passive-interface", "Suppress routing updates on an interface", CMD_ROUTER_RIP_PASSIVE_INTERFACE, NULL, 1},
	{"redistribute", "Redistribute information from another routing protocol", CMD_ROUTER_RIP_REDISTRIBUTE, NULL, 1},
	{"version", "Set routing protocol version", CMD_ROUTER_RIP_VERSION, NULL, 1},
	{"timers", "Adjust routing timers", CMD_ROUTER_RIP_TIMERS, rip_execute_router_cmd, 1},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0},
	{NULL,NULL,NULL,NULL, 0}
};


/*---------------------- Router OSPF Commands --------------------------------*/

#undef ROUTER_OSPF_EXPORT_INPORT_ACL
#undef ROUTER_OSPF_SHORTCUT
#undef ROUTER_OSPF_COMPATIBLE
#undef ROUTER_OSPF_DISTANCE
#undef ROUTER_OSPF_DISTRIBUTE
#undef ROUTER_OSPF_REFRESH
#undef ROUTER_OSPF_ROUTER_ID
#undef ROUTER_OSPF_VLINK2

extern cish_command CMD_ROUTER_OSPF_REDISTRIBUTE5[];
extern cish_command CMD_ROUTER_OSPF_REDISTRIBUTE6[];
extern cish_command CMD_ROUTER_OSPF_NEIGHBOR2[];
extern cish_command CMD_ROUTER_OSPF_DISTANCE1[];
extern cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION6[];
extern cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION7[];
extern cish_command CMD_ROUTER_OSPF_VLINK4[];
extern cish_command CMD_ROUTER_OSPF_VLINK5[];
extern cish_command CMD_ROUTER_OSPF_VLINK1B[];
extern cish_command CMD_ROUTER_OSPF_AREA_AUTHENTICATION[];

cish_command CMD_ROUTER_OSPF_TIMERS2[] = {
	{"0-4294967295", "Hold time between consecutive SPF calculations", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_TIMERS1[] = {
	{"0-4294967295", "Delay between receiving a change to SPF calculation", CMD_ROUTER_OSPF_TIMERS2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_TIMERS[] = {
	{"spf", "OSPF SPF timers", CMD_ROUTER_OSPF_TIMERS1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_ROUTER_ID
cish_command CMD_ROUTER_OSPF_ROUTER_ID[] = {
	{"<ipaddress>", "OSPF router-id in IP address format", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

#ifdef ROUTER_OSPF_REFRESH
cish_command CMD_ROUTER_OSPF_REFRESH1[] = {
	{"10-1800", "Timer value in seconds", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REFRESH[] = {
	{"timer", "Set refresh timer", CMD_ROUTER_OSPF_REFRESH1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE9[] = {
	{"0-16777214", "OSPF default metric", CMD_ROUTER_OSPF_REDISTRIBUTE5, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE8[] = {
	{"metric", "OSPF default metric", CMD_ROUTER_OSPF_REDISTRIBUTE9, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_REDISTRIBUTE6, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE7[] = {
	{"1", "Set OSPF External Type 1 metrics", CMD_ROUTER_OSPF_REDISTRIBUTE8, ospf_execute_router_cmd, 1},
	{"2", "Set OSPF External Type 2 metrics", CMD_ROUTER_OSPF_REDISTRIBUTE8, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE6[] = {
	{"<text>", "Pointer to route-map entries", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE5[] = {
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_REDISTRIBUTE6, NULL, 1},
	{"<enter>", "", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE4[] = {
	{"1", "Set OSPF External Type 1 metrics", CMD_ROUTER_OSPF_REDISTRIBUTE5, ospf_execute_router_cmd, 1},
	{"2", "Set OSPF External Type 2 metrics", CMD_ROUTER_OSPF_REDISTRIBUTE5, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE3[] = {
	{"metric-type", "OSPF exterior metric type for redistributed routes", CMD_ROUTER_OSPF_REDISTRIBUTE4, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_REDISTRIBUTE6, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE2[] = {
	{"0-16777214", "OSPF default metric", CMD_ROUTER_OSPF_REDISTRIBUTE3, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE1[] = {
	{"metric", "Metric for redistributed routes", CMD_ROUTER_OSPF_REDISTRIBUTE2, NULL, 1},
	{"metric-type", "OSPF exterior metric type for redistributed routes", CMD_ROUTER_OSPF_REDISTRIBUTE7, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_REDISTRIBUTE6, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_REDISTRIBUTE[] = {
#ifdef OPTION_BGP
	{"bgp", "Border Gateway Protocol (BGP)", CMD_ROUTER_OSPF_REDISTRIBUTE1, ospf_execute_router_cmd, 1},
#endif
	{"connected", "Connected", CMD_ROUTER_OSPF_REDISTRIBUTE1, ospf_execute_router_cmd, 1},
	{"kernel", "Kernel routes", CMD_ROUTER_OSPF_REDISTRIBUTE1, ospf_execute_router_cmd, 1},
	{"rip", "Routing Information Protocol (RIP)", CMD_ROUTER_OSPF_REDISTRIBUTE1, ospf_execute_router_cmd, 1},
	{"static", "Static routes", CMD_ROUTER_OSPF_REDISTRIBUTE1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_PASSIVE_INTERFACE1[] = {
	{"<ipaddress>", "Network address", NULL, ospf_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_PASSIVE_INTERFACE_ETHERNET[] = {
	{"0-0", "Ethernet interface number", CMD_ROUTER_OSPF_PASSIVE_INTERFACE1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_PASSIVE_INTERFACE_LOOPBACK[] = {
	{"0-4", "Loopback interface number", CMD_ROUTER_OSPF_PASSIVE_INTERFACE1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_PASSIVE_INTERFACE_TUNNEL[] = {
	{"0-9", "Tunnel interface number", CMD_ROUTER_OSPF_PASSIVE_INTERFACE1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_PASSIVE_INTERFACE[] = {
	{"ethernet", "Ethernet interface", CMD_ROUTER_OSPF_PASSIVE_INTERFACE_ETHERNET, NULL, 1},
	{"loopback", "Loopback interface", CMD_ROUTER_OSPF_PASSIVE_INTERFACE_LOOPBACK, NULL, 1},
	{"tunnel", "Tunnel interface", CMD_ROUTER_OSPF_PASSIVE_INTERFACE_TUNNEL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_SPECIFIC2[] = {
	{"<ipaddress>", "OSPF router-id in IP address format", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_SPECIFIC1[] = {
	{"cisco", "Alternative ABR, cisco implementation", NULL, ospf_execute_router_cmd, 1},
	{"ibm", "Alternative ABR, IBM implementation", NULL, ospf_execute_router_cmd, 1},
	{"shortcut", "Shortcut ABR", NULL, ospf_execute_router_cmd, 1},
	{"standard", "Standard behavior (RFC2328)", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_SPECIFIC[] = {
	{"abr-type", "Set OSPF ABR type", CMD_ROUTER_OSPF_SPECIFIC1, NULL, 1},
	{"rfc1583compatibility", "Enable the RFC1583Compatibility flag", NULL, ospf_execute_router_cmd, 1},
	{"router-id", "router-id for the OSPF process", CMD_ROUTER_OSPF_SPECIFIC2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NETWORK3[] = {
	{"0-4294967295", "OSPF area ID as a decimal value", NULL, ospf_execute_router_cmd, 1},
	{"<ipaddress>", "OSPF area ID in IP address format", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NETWORK2[] = {
	{"area", "Set the OSPF area ID", CMD_ROUTER_OSPF_NETWORK3, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NETWORK1[] = {
	{"<netmask>", "Network mask", CMD_ROUTER_OSPF_NETWORK2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NETWORK[] = {
	{"<ipaddress>", "OSPF network prefix", CMD_ROUTER_OSPF_NETWORK1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NEIGHBOR4[] = {
	{"poll-interval", "Dead Neighbor Polling interval", CMD_ROUTER_OSPF_NEIGHBOR2, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NEIGHBOR3[] = {
	{"0-255", "Priority", CMD_ROUTER_OSPF_NEIGHBOR4, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NEIGHBOR2[] = {
	{"1-65535", "Seconds", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NEIGHBOR1[] = {
	{"poll-interval", "Dead Neighbor Polling interval", CMD_ROUTER_OSPF_NEIGHBOR2, NULL, 1},
	{"priority", "Neighbor Priority", CMD_ROUTER_OSPF_NEIGHBOR3, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NEIGHBOR[] = {
	{"<ipaddress>", "Neighbor IP address", CMD_ROUTER_OSPF_NEIGHBOR1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_DISTRIBUTE
cish_command CMD_ROUTER_OSPF_DISTRIBUTE2[] = {
	{"connected", "Connected", NULL, ospf_execute_router_cmd, 1},
	{"kernel", "Kernel routes", NULL, ospf_execute_router_cmd, 1},
	{"rip", "Routing Information Protocol (RIP)", NULL, ospf_execute_router_cmd, 1},
	{"static", "Static routes", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTRIBUTE1[] = {
	{"out", "Filter outgoing routing updates", CMD_ROUTER_OSPF_DISTRIBUTE2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTRIBUTE[] = {
	{"<text>", "Access-list name", CMD_ROUTER_OSPF_DISTRIBUTE1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

#ifdef ROUTER_OSPF_DISTANCE
cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA7[] = {
	{"1-255", "Distance for external", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA6[] = {
	{"external", "External routes", CMD_ROUTER_OSPF_DISTANCE_INTRA7, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA5[] = {
	{"1-255", "Distance for inter-area", CMD_ROUTER_OSPF_DISTANCE_INTRA6, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA4[] = {
	{"1-255", "Distance for inter-area", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA3[] = {
	{"inter-area", "Inter-area routes", CMD_ROUTER_OSPF_DISTANCE_INTRA4, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA2[] = {
	{"1-255", "Distance for external", CMD_ROUTER_OSPF_DISTANCE_INTRA3, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA1[] = {
	{"external", "External routes", CMD_ROUTER_OSPF_DISTANCE_INTRA2, NULL, 1},
	{"inter-area", "Inter-area routes", CMD_ROUTER_OSPF_DISTANCE_INTRA5, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTRA[] = {
	{"1-255", "Distance for intra-area routes", CMD_ROUTER_OSPF_DISTANCE_INTRA1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER7[] = {
	{"1-255", "Distance for external routes", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER6[] = {
	{"external", "External routes", CMD_ROUTER_OSPF_DISTANCE_INTER7, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER5[] = {
	{"1-255", "Distance for intra-area routes", CMD_ROUTER_OSPF_DISTANCE_INTER6, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER4[] = {
	{"1-255", "Distance for intra-area routes", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER3[] = {
	{"intra-area", "Intra-area routes", CMD_ROUTER_OSPF_DISTANCE_INTER4, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER2[] = {
	{"1-255", "Distance for external", CMD_ROUTER_OSPF_DISTANCE_INTER3, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER1[] = {
	{"external", "External routes", CMD_ROUTER_OSPF_DISTANCE_INTER2, NULL, 1},
	{"intra-area", "Intra-area routes", CMD_ROUTER_OSPF_DISTANCE_INTER5, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_INTER[] = {
	{"1-255", "Distance for inter-area routes", CMD_ROUTER_OSPF_DISTANCE_INTER1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL7[] = {
	{"1-255", "Distance for inter-area routes", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL6[] = {
	{"inter-area", "Inter-area routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL7, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL5[] = {
	{"1-255", "Distance for intra-area routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL6, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL4[] = {
	{"1-255", "Distance for intra-area routes", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL3[] = {
	{"intra-area", "Intra-area routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL4, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL2[] = {
	{"1-255", "Distance for inter-area routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL3, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL1[] = {
	{"inter-area", "Inter-area routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL2, NULL, 1},
	{"intra-area", "Intra-area routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL5, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE_EXTERNAL[] = {
	{"1-255", "Distance for external routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE1[] = {
	{"external", "External routes", CMD_ROUTER_OSPF_DISTANCE_EXTERNAL, NULL, 1},
	{"inter-area", "Inter-area routes", CMD_ROUTER_OSPF_DISTANCE_INTER, NULL, 1},
	{"intra-area", "Intra-area routes", CMD_ROUTER_OSPF_DISTANCE_INTRA, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DISTANCE[] = {
	{"1-255", "OSPF Administrative distance", NULL, ospf_execute_router_cmd, 1},
	{"ospf", "OSPF Administrative distance", CMD_ROUTER_OSPF_DISTANCE1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_DEFAULT_METRIC[] = {
	{"0-16777214", "Default metric", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION10[] = {
	{"0-16777214", "OSPF metric", CMD_ROUTER_OSPF_DEFAULT_INFORMATION6, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION9[] = {
	{"metric", "OSPF default metric", CMD_ROUTER_OSPF_DEFAULT_INFORMATION10, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_DEFAULT_INFORMATION7, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION8[] = {
	{"1", "Set OSPF External Type 1 metrics", CMD_ROUTER_OSPF_DEFAULT_INFORMATION9, ospf_execute_router_cmd, 1},
	{"2", "Set OSPF External Type 2 metrics", CMD_ROUTER_OSPF_DEFAULT_INFORMATION9, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION7[] = {
	{"<text>", "Pointer to route-map entries", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION6[] = {
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_DEFAULT_INFORMATION7, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION5[] = {
	{"1", "Set OSPF External Type 1 metrics", CMD_ROUTER_OSPF_DEFAULT_INFORMATION6, ospf_execute_router_cmd, 1},
	{"2", "Set OSPF External Type 2 metrics", CMD_ROUTER_OSPF_DEFAULT_INFORMATION6, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION4[] = {
	{"metric-type", "OSPF metric type for default routes", CMD_ROUTER_OSPF_DEFAULT_INFORMATION5, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_DEFAULT_INFORMATION7, NULL, 1},
	{"<enter>", "", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION3[] = {
	{"0-16777214", "OSPF metric", CMD_ROUTER_OSPF_DEFAULT_INFORMATION4, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION2[] = {
	{"metric", "OSPF default metric", CMD_ROUTER_OSPF_DEFAULT_INFORMATION3, NULL, 1},
	{"metric-type", "OSPF metric type for default routes", CMD_ROUTER_OSPF_DEFAULT_INFORMATION8, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_DEFAULT_INFORMATION7, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION1[] = {
	{"always", "Always advertise default route", CMD_ROUTER_OSPF_DEFAULT_INFORMATION2, ospf_execute_router_cmd, 1},
	{"metric", "OSPF default metric", CMD_ROUTER_OSPF_DEFAULT_INFORMATION3, NULL, 1},
	{"metric-type", "OSPF metric type for default routes", CMD_ROUTER_OSPF_DEFAULT_INFORMATION8, NULL, 1},
	{"route-map", "Route map reference", CMD_ROUTER_OSPF_DEFAULT_INFORMATION7, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_DEFAULT_INFORMATION[] = {
	{"originate", "Distribute a default route", CMD_ROUTER_OSPF_DEFAULT_INFORMATION1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_COMPATIBLE
cish_command CMD_ROUTER_OSPF_COMPATIBLE[] = {
	{"rfc1583", "compatible with RFC 1583", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_AUTOCOST1[] = {
	{"1-65535", "The reference bandwidth in terms of Mbits per second", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_AUTOCOST[] = {
	{"reference-bandwidth", "Use reference bandwidth method to assign OSPF cost", CMD_ROUTER_OSPF_AUTOCOST1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

/*
  area <0-4294967295> shortcut (default|enable|disable)

  ?????????????????  Verificar primeiros comandos do virtual-link

  area <0-4294967295> virtual-link A.B.C.D (message-digest-key|) <1-255> md5 KEY

?????????????????  area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX

  area A.B.C.D virtual-link A.B.C.D (message-digest-key|) <1-255> md5 KEY
*/

#ifdef ROUTER_OSPF_VLINK2
cish_command CMD_ROUTER_OSPF_VLINK8[] = {
	{"authentication-key", "Authentication password (key)", CMD_ROUTER_OSPF_VLINK4, NULL, 1},
	{"message-digest-key", "Message digest authentication password (key)", CMD_ROUTER_OSPF_VLINK5, NULL, 1},
	{"<enter>", "", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_VLINK7[] = {
	{"<text>", "The OSPF password (key)", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_VLINK6[] = {
	{"md5", "Use MD5 algorithm", CMD_ROUTER_OSPF_VLINK7, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_VLINK5[] = {
	{"1-255", "Key ID", CMD_ROUTER_OSPF_VLINK6, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_VLINK4[] = {
	{"<text>", "Password (key)", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_VLINK2
cish_command CMD_ROUTER_OSPF_VLINK3[] = {
	{"authentication-key", "Authentication password (key)", CMD_ROUTER_OSPF_VLINK4, NULL, 1},
	{"message-digest-key", "Message digest authentication password (key)", CMD_ROUTER_OSPF_VLINK5, NULL, 1},
	{"<enter>", "", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_VLINK2[] = {
	{"authentication-key", "Authentication password (key)", CMD_ROUTER_OSPF_VLINK4, NULL, 1},
	{"message-digest-key", "Message digest authentication password (key)", CMD_ROUTER_OSPF_VLINK5, NULL, 1},
	{"message-digest", "Use message-digest authentication", CMD_ROUTER_OSPF_VLINK3, NULL, 1},
	{"null", "Use null authentication", CMD_ROUTER_OSPF_VLINK8, NULL, 1},
	{"<enter>", "", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_VLINK1B[] = {
	{"3-65535", "Seconds", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_VLINK1[] = {
	{"authentication-key", "Authentication password (key)", CMD_ROUTER_OSPF_VLINK4, NULL, 1},
	#ifdef ROUTER_OSPF_VLINK2
	{"authentication", "Enable authentication on this virtual link", CMD_ROUTER_OSPF_VLINK2, NULL, 1},
	#endif
	{"hello-interval", "Time between HELLO packets", CMD_ROUTER_OSPF_VLINK1B, NULL, 1},
	{"retransmit-interval", "Time between retransmitting lost link state advertisements", CMD_ROUTER_OSPF_VLINK1B, NULL, 1},
	{"transmit-delay", "Link state transmit delay", CMD_ROUTER_OSPF_VLINK1B, NULL, 1},
	{"dead-interval", "Interval after which a neighbor is declared dead", CMD_ROUTER_OSPF_VLINK1B, NULL, 1},
	{"message-digest-key", "Message digest authentication password (key)", CMD_ROUTER_OSPF_VLINK5, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_VLINK[] = {
	{"<ipaddress>", "Router ID of the remote ABR", CMD_ROUTER_OSPF_VLINK1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_STUB[] = {
	{"no-summary", "Do not inject inter-area routes into stub", NULL, ospf_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_SHORTCUT
cish_command CMD_ROUTER_OSPF_SHORTCUT[] = {
	{"default", "Set default shortcutting behavior", NULL, ospf_execute_router_cmd, 1},
	{"disable", "Disable shortcutting through the area", NULL, ospf_execute_router_cmd, 1},
	{"enable", "Enable shortcutting through the area", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_RANGE3[] = {
	{"<ipaddress>", "network prefix to be announced instead of range", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_RANGE2[] = {
	{"advertise", "advertise this range", NULL, ospf_execute_router_cmd, 1},
	{"not-advertise", "do not advertise this range", NULL, ospf_execute_router_cmd, 1},
	{"substitute", "announce area range as another prefix", CMD_ROUTER_OSPF_RANGE3, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_RANGE1[] = {
	{"<netmask>", "Network mask", CMD_ROUTER_OSPF_RANGE2, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_RANGE[] = {
	{"<ipaddress>", "area range prefix", CMD_ROUTER_OSPF_RANGE1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_EXPORT_INPORT_ACL
cish_command CMD_ROUTER_OSPF_IMPORT_ACL[] = {
	{"<text>", "Name of the access-list", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_EXPORT_ACL[] = {
	{"<text>", "Name of the access-list", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_COST[] = {
	{"0-16777215", "Stub's advertised default summary cost", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_AREA_AUTHENTICATION[] = {
	{"message-digest", "Use message-digest authentication", NULL, ospf_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_AREA1[] = {
	{"authentication", "Enable authentication", CMD_ROUTER_OSPF_AREA_AUTHENTICATION, ospf_execute_router_cmd, 1},
	{"default-cost", "Set the summary-default cost of a NSSA or stub area", CMD_ROUTER_OSPF_COST, NULL, 1},
	#ifdef ROUTER_OSPF_EXPORT_INPORT_ACL
	{"export-list", "Set the filter for networks announced to other areas", CMD_ROUTER_OSPF_EXPORT_ACL, NULL, 1},
	{"import-list", "Set the filter for networks from other areas announced to the specified one", CMD_ROUTER_OSPF_IMPORT_ACL, NULL, 1},
	#endif
	{"range", "Configure OSPF area range for route summarization", CMD_ROUTER_OSPF_RANGE, NULL, 1},
	#ifdef ROUTER_OSPF_SHORTCUT
	{"shortcut", "Configure the area's shortcutting mode", CMD_ROUTER_OSPF_SHORTCUT, NULL, 1},
	#endif
	{"stub", "Configure OSPF area as stub", CMD_ROUTER_OSPF_STUB, ospf_execute_router_cmd, 1},
	{"virtual-link", "Configure a virtual link", CMD_ROUTER_OSPF_VLINK, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_AREA[] = {
	{"0-4294967295", "OSPF area ID as a decimal value", CMD_ROUTER_OSPF_AREA1, NULL, 1},
	{"<ipaddress>", "OSPF area ID in IP address format", CMD_ROUTER_OSPF_AREA1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_NO_OSPF_TIMERS[] = {
	{"spf", "OSPF SPF timers", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_REFRESH
cish_command CMD_ROUTER_OSPF_NO_REFRESH1[] = {
	{"10-1800", "Timer value in seconds", NULL, ospf_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_REFRESH[] = {
	{"timer", "Set refresh timer", CMD_ROUTER_OSPF_NO_REFRESH1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_NO_REDISTRIBUTE[] = {
	{"connected", "Connected", NULL, ospf_execute_router_cmd, 1},
	{"kernel", "Kernel routes", NULL, ospf_execute_router_cmd, 1},
	{"rip", "Routing Information Protocol (RIP)", NULL, ospf_execute_router_cmd, 1},
	{"static", "Static routes", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_SPECIFIC1[] = {
	{"cisco", "Alternative ABR, cisco implementation", NULL, ospf_execute_router_cmd, 1},
	{"ibm", "Alternative ABR, IBM implementation", NULL, ospf_execute_router_cmd, 1},
	{"shortcut", "Shortcut ABR", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_SPECIFIC[] = {
	{"abr-type", "Set OSPF ABR type", CMD_ROUTER_OSPF_NO_SPECIFIC1, NULL, 1},
	{"rfc1583compatibility", "Disable the RFC1583Compatibility flag", NULL, ospf_execute_router_cmd, 1},
	{"router-id", "router-id for the OSPF process", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_DISTANCE
cish_command CMD_ROUTER_OSPF_NO_DISTANCE[] = {
	{"1-255", "OSPF Administrative distance", NULL, ospf_execute_router_cmd, 1},
	{"ospf", "OSPF Administrative distance", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_NO_DEFAULT_METRIC[] = {
	{"0-16777214", "Default metric", NULL, ospf_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_DEFAULT_INFORMATION[] = {
	{"originate", "Distribute a default route", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_AUTOCOST[] = {
	{"reference-bandwidth", "Use reference bandwidth method to assign OSPF cost", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_VLINK5[] = {
	{"1-255", "Key ID", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_VLINK2
cish_command CMD_ROUTER_OSPF_NO_VLINK2[] = {
	{"authentication-key", "Authentication password (key)", NULL, ospf_execute_router_cmd, 1},
	{"message-digest-key", "Message digest authentication password (key)", NULL, ospf_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_NO_VLINK1[] = {
	{"authentication-key", "Authentication password (key)", NULL, ospf_execute_router_cmd, 1},
	#ifdef ROUTER_OSPF_VLINK2
	{"authentication", "Enable authentication on this virtual link", CMD_ROUTER_OSPF_NO_VLINK2, ospf_execute_router_cmd, 1},
	#endif
	{"hello-interval", "Time between HELLO packets", NULL, ospf_execute_router_cmd, 1},
	{"retransmit-interval", "Time between retransmitting lost link state advertisements", NULL, ospf_execute_router_cmd, 1},
	{"transmit-delay", "Link state transmit delay", NULL, ospf_execute_router_cmd, 1},
	{"dead-interval", "Interval after which a neighbor is declared dead", NULL, ospf_execute_router_cmd, 1},
	{"message-digest-key", "Message digest authentication password (key)", CMD_ROUTER_OSPF_NO_VLINK5, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_VLINK[] = {
	{"<ipaddress>", "Router ID of the remote ABR", CMD_ROUTER_OSPF_NO_VLINK1, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef ROUTER_OSPF_SHORTCUT
cish_command CMD_ROUTER_OSPF_NO_SHORTCUT[] = {
	{"disable", "Disable shortcutting through the area", NULL, ospf_execute_router_cmd, 1},
	{"enable", "Enable shortcutting through the area", NULL, ospf_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

cish_command CMD_ROUTER_OSPF_NO_AREA1[] = {
	{"authentication", "Enable authentication", NULL, ospf_execute_router_cmd, 1},
	{"default-cost", "Set the summary-default cost of a NSSA or stub area", CMD_ROUTER_OSPF_COST, NULL, 1},
	#ifdef ROUTER_OSPF_EXPORT_INPORT_ACL
	{"export-list", "Set the filter for networks announced to other areas", CMD_ROUTER_OSPF_EXPORT_ACL, NULL, 1},
	{"import-list", "Set the filter for networks from other areas announced to the specified one", CMD_ROUTER_OSPF_IMPORT_ACL, NULL, 1},
	#endif
	{"range", "Configure OSPF area range for route summarization", CMD_ROUTER_OSPF_RANGE, NULL, 1},
	#ifdef ROUTER_OSPF_SHORTCUT
	{"shortcut", "Configure the area's shortcutting mode", CMD_ROUTER_OSPF_NO_SHORTCUT, NULL, 1},
	#endif
	{"stub", "Configure OSPF area as stub", CMD_ROUTER_OSPF_STUB, ospf_execute_router_cmd, 1},
	{"virtual-link", "Configure a virtual link", CMD_ROUTER_OSPF_NO_VLINK, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO_AREA[] = {
	{"0-4294967295", "OSPF area ID as a decimal value", CMD_ROUTER_OSPF_NO_AREA1, NULL, 1},
	{"<ipaddress>", "OSPF area ID in IP address format", CMD_ROUTER_OSPF_NO_AREA1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_OSPF_NO[] = {
	{"area", "OSPF area parameters", CMD_ROUTER_OSPF_NO_AREA, NULL, 1},
	{"auto-cost", "Calculate OSPF interface cost according to bandwidth", CMD_ROUTER_OSPF_NO_AUTOCOST, NULL, 1},
	#ifdef ROUTER_OSPF_COMPATIBLE
	{"compatible", "OSPF compatibility list", CMD_ROUTER_OSPF_COMPATIBLE, NULL, 1},
	#endif
	{"default-information", "Control distribution of default information", CMD_ROUTER_OSPF_NO_DEFAULT_INFORMATION, NULL, 1},
	{"default-metric", "Set metric of redistributed routes", CMD_ROUTER_OSPF_NO_DEFAULT_METRIC, ospf_execute_router_cmd, 1},
	#ifdef ROUTER_OSPF_DISTANCE
	{"distance", "Define an administrative distance", CMD_ROUTER_OSPF_NO_DISTANCE, NULL, 1},
	#endif
	#ifdef ROUTER_OSPF_DISTRIBUTE
	{"distribute-list", "Filter networks in routing updates", CMD_ROUTER_OSPF_DISTRIBUTE, NULL, 1},
	#endif
	{"neighbor", "Specify neighbor router", CMD_ROUTER_OSPF_NEIGHBOR, NULL, 1},
 	{"network", "Enable routing on an IP network", CMD_ROUTER_OSPF_NETWORK, NULL, 1},
	{"ospf", "OSPF specific commands", CMD_ROUTER_OSPF_NO_SPECIFIC, NULL, 1},
	{"passive-interface", "Suppress routing updates on an interface", CMD_ROUTER_OSPF_PASSIVE_INTERFACE, NULL, 1},
	{"redistribute", "Redistribute information from another routing protocol", CMD_ROUTER_OSPF_NO_REDISTRIBUTE, NULL, 1},
	#ifdef ROUTER_OSPF_REFRESH
	{"refresh", "Adjust refresh parameters", CMD_ROUTER_OSPF_NO_REFRESH, NULL, 1},
	#endif
	#ifdef ROUTER_OSPF_ROUTER_ID
	{"router-id", "router-id for the OSPF process", CMD_ROUTER_OSPF_ROUTER_ID, NULL, 1},
	#endif
	{"timers", "Adjust routing timers", CMD_ROUTER_NO_OSPF_TIMERS, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_CONFIG_ROUTER_OSPF[] = {
	{"area", "OSPF area parameters", CMD_ROUTER_OSPF_AREA, NULL, 1},
	{"auto-cost", "Calculate OSPF interface cost according to bandwidth", CMD_ROUTER_OSPF_AUTOCOST, NULL, 1},
	#ifdef ROUTER_OSPF_COMPATIBLE
	{"compatible", "OSPF compatibility list", CMD_ROUTER_OSPF_COMPATIBLE, NULL, 1},
	#endif
	{"default-information", "Control distribution of default information", CMD_ROUTER_OSPF_DEFAULT_INFORMATION, NULL, 1},
	{"default-metric", "Set metric of redistributed routes", CMD_ROUTER_OSPF_DEFAULT_METRIC, NULL, 1},
	#ifdef ROUTER_OSPF_DISTANCE
	{"distance", "Define an administrative distance", CMD_ROUTER_OSPF_DISTANCE, NULL, 1},
	#endif
	#ifdef ROUTER_OSPF_DISTRIBUTE
	{"distribute-list", "Filter networks in routing updates", CMD_ROUTER_OSPF_DISTRIBUTE, NULL, 1},
	#endif
        {"exit", "Exit current mode and down to previous mode", NULL, config_router_done, 1},
	{"neighbor", "Specify neighbor router", CMD_ROUTER_OSPF_NEIGHBOR, NULL, 1},
 	{"network", "Enable routing on an IP network", CMD_ROUTER_OSPF_NETWORK, NULL, 1},
	{"no", "Reverse settings", CMD_ROUTER_OSPF_NO, NULL, 1},
	{"ospf", "OSPF specific commands", CMD_ROUTER_OSPF_SPECIFIC, NULL, 1},
	{"passive-interface", "Suppress routing updates on an interface", CMD_ROUTER_OSPF_PASSIVE_INTERFACE, NULL, 1},
	{"redistribute", "Redistribute information from another routing protocol", CMD_ROUTER_OSPF_REDISTRIBUTE, NULL, 1},
	#ifdef ROUTER_OSPF_REFRESH
	{"refresh", "Adjust refresh parameters", CMD_ROUTER_OSPF_REFRESH, NULL, 1},
	#endif
	#ifdef ROUTER_OSPF_ROUTER_ID
	{"router-id", "router-id for the OSPF process", CMD_ROUTER_OSPF_ROUTER_ID, NULL, 1},
	#endif
	{"timers", "Adjust routing timers", CMD_ROUTER_OSPF_TIMERS, NULL, 1},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0},
	{NULL, NULL, NULL, NULL}
};


/*---------------------- OSPF SHOW IP Commands -------------------------------*/

cish_command CMD_SHOW_OSPF_NEIGHBOR3[] = {
	{"all", "include down status neighbor", NULL, show_ip_ospf, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_OSPF_NEIGHBOR2[] = {
	{"detail", "detail of all neighbors", NULL, show_ip_ospf, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_OSPF_NEIGHBOR[] = {
//	{"<ipaddress>", "Interface name", CMD_SHOW_OSPF_NEIGHBOR2, show_ip_ospf, 1},
	{"all", "include down status neighbor", NULL, show_ip_ospf, 1},
	{"detail", "detail of all neighbors", CMD_SHOW_OSPF_NEIGHBOR3, show_ip_ospf, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_OSPF_INTERFACE_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, show_ip_ospf, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_OSPF_INTERFACE_LOOPBACK[] = {
	{"0-4", "Loopback interface number", NULL, show_ip_ospf, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_OSPF_INTERFACE_TUNNEL[] = {
	{"0-9", "Tunnel interface number", NULL, show_ip_ospf, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SHOW_OSPF_INTERFACE[] = {
	{"ethernet", "Ethernet interface", CMD_SHOW_OSPF_INTERFACE_ETHERNET, NULL, 1},
	{"loopback", "Loopback interface", CMD_SHOW_OSPF_INTERFACE_LOOPBACK, NULL, 1},
	{"tunnel", "Tunnel interface", CMD_SHOW_OSPF_INTERFACE_TUNNEL, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

#if 0
cish_command CMD_SHOW_OSPF_DATABASE3[] = {
	{"<ipaddress>", "Advertising Router (as an IP address)", NULL, show_ip_ospf, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_OSPF_DATABASE2[] = {
	{"self-originate", "Self-originated link states", NULL, show_ip_ospf, 1},
	{"adv-router", "Advertising Router link states", CMD_SHOW_OSPF_DATABASE3, NULL, 1},
	{"<enter>", "", NULL, show_ip_ospf, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_OSPF_DATABASE1[] = {
	{"self-originate", "Self-originated link states", NULL, show_ip_ospf, 1},
	{"<ipaddress>", "Link State ID (as an IP address)", CMD_SHOW_OSPF_DATABASE2, NULL, 1},
	{"adv-router", "Advertising Router link states", CMD_SHOW_OSPF_DATABASE3, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
#else
#define CMD_SHOW_OSPF_DATABASE1 NULL
#endif

cish_command CMD_SHOW_OSPF_DATABASE[] = {
	{"asbr-summary", "ASBR summary link states", CMD_SHOW_OSPF_DATABASE1, show_ip_ospf, 1},
	{"external", "External link states", CMD_SHOW_OSPF_DATABASE1, show_ip_ospf, 1},
	{"max-age", "LSAs in MaxAge list", NULL, show_ip_ospf, 1},
	{"network", "Network link states", CMD_SHOW_OSPF_DATABASE1, show_ip_ospf, 1},
	{"router", "Router link states", CMD_SHOW_OSPF_DATABASE1, show_ip_ospf, 1},
	{"self-originate", "Self-originated link states", NULL, show_ip_ospf, 1},
	{"summary", "Network summary link states", CMD_SHOW_OSPF_DATABASE1, show_ip_ospf, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_OSPF[] = {
	{"database", "Database summary", CMD_SHOW_OSPF_DATABASE, show_ip_ospf, 1},
	{"interface", "Interface information", CMD_SHOW_OSPF_INTERFACE, show_ip_ospf, 1},
	{"neighbor", "Neighbor list", CMD_SHOW_OSPF_NEIGHBOR, show_ip_ospf, 1},
  	{"route", "OSPF routing table", NULL, show_ip_ospf, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

#ifdef OPTION_BGP /* BGP Commands - ThomÃ¡s Del Grande 25/09/07 */

/* Zebra and CISCO implements address-family. However, there was no example in how using it...
Left commented for further evaluations ....

cish_command CMD_ROUTER_BGP_ADDRFAM2[] = {  address family 
	{"unicast", "Address Family modifier", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_ADDRFAM1[] = {
	{"multicast", "Address Family modifier", NULL, bgp_execute_router_cmd, 1},
	{"unicast", "Address Family modifier", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_ADDRFAM[] = {
	{"ipv4", "Address family", CMD_ROUTER_BGP_ADDRFAM1, NULL, 1},
	{"vpnv4", "Address family", CMD_ROUTER_BGP_ADDRFAM2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};*/

cish_command CMD_ROUTER_BGP_AGGADDR4[] = { /* aggregate-address */
	{"summary-only", "Filter more specific routes from updates", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_AGGADDR3[] = {
	{"as-set", "Generate AS set path information", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_AGGADDR2[] = {
	{"as-set", "Generate AS set path information", CMD_ROUTER_BGP_AGGADDR4, bgp_execute_router_cmd, 1},
	{"summary-only", "Filter more specific routes from updates", CMD_ROUTER_BGP_AGGADDR3, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_AGGADDR1[] = {
	{"<netmask>", "Aggregate mask", CMD_ROUTER_BGP_AGGADDR2, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_AGGADDR[] = {
	{"<ipaddress>", "Aggregate address", CMD_ROUTER_BGP_AGGADDR1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

/* distance -- comentado pois utilizaÃ§Ã£o nÃ£o Ã© recomendada
cish_command CMD_ROUTER_BGP_DISTANCE_BGP2[] = {
	{"1-255", "Distance for local routes", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DISTANCE_BGP1[] = {
	{"1-255", "Distance for routes internal to the AS", CMD_ROUTER_BGP_DISTANCE_BGP2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DISTANCE_BGP[] = {
	{"1-255", "Distance for routes external to the AS", CMD_ROUTER_BGP_DISTANCE_BGP1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DISTANCE3[] = {
	{"<text>", "Standard access-list name", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},	
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DISTANCE2[] = {
	{"<rnetmask>", "Wildcard bits", CMD_ROUTER_BGP_DISTANCE3, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DISTANCE1[] = {
	{"<ipaddress>", "IP source address", CMD_ROUTER_BGP_DISTANCE2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DISTANCE[] = {
	{"1-255", "Administrative distance", CMD_ROUTER_BGP_DISTANCE1, NULL, 1},
	{"bgp", "BGP distance", CMD_ROUTER_BGP_DISTANCE_BGP, NULL, 1},
	{NULL, NULL, NULL, NULL}
}; */

//Route-map commented because they were not implemented yet. ThomÃ¡s Del Grande 16/10/07
/*cish_command CMD_ROUTER_BGP_NETWORK4[] = { 
	{"<text>", "Name of the route map", NULL, bgp_execute_router_cmd, 1},	
	{NULL, NULL, NULL, NULL}
};*/

cish_command CMD_ROUTER_BGP_NETWORK3[] = {
	{"backdoor", "Specify a BGP backdoor route", NULL, bgp_execute_router_cmd, 1},
	//{"route-map", "Route-map to modify the attributes", CMD_ROUTER_BGP_NETWORK4, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},	
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NETWORK2[] = {
	{"<netmask>", "Network mask", CMD_ROUTER_BGP_NETWORK3, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NETWORK1[] = {
	{"backdoor", "Specify a BGP backdoor route", NULL, bgp_execute_router_cmd, 1},
	{"mask", "Network mask", CMD_ROUTER_BGP_NETWORK2, NULL, 1},
	//{"route-map", "Route-map to modify the attributes", CMD_ROUTER_BGP_NETWORK4, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NETWORK[] = {
	{"<ipaddress>", "Network Number", CMD_ROUTER_BGP_NETWORK1, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
/* Commented because route-map is not implemented yet. ThomÃ¡s Del Grande 16/10/07
cish_command CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP[] = { 
	{"<text>", "Name of the route-map", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
*/
cish_command CMD_ROUTER_BGP_NEIGHBOR_ALLOWASIN[] = { /* allowas-in*/
	{"1-10", "Number of occurances of AS number", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_REMOTEAS[] = { /*neighbor remote-as*/
	{"1-65535", "AS number", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

/*
cish_command CMD_ROUTER_BGP_NEIGHBOR_VERSION[] = {
	{"4", "Border Gateway Protocol 4", NULL, bgp_execute_router_cmd, 1},
	{"4-", "Multiprotocol Extensions for BGP-4(Old Draft)", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
*/
/* attribute-unchanged - does not exist on CISCO, and not documented by zebra */
/* cish_command CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE6[] = { 
	{"next-hop", "Nexthop attribute", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},	
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE5[] = {
	{"med", "Med attribute", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},	
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE4[] = {
	{"as-path", "As-path attribute", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE3[] = {
	{"med", "Med attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE6, bgp_execute_router_cmd, 1},
	{"next-hop", "Nexthop attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE5, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},	
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE2[] = {
	{"as-path", "As-path attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE6, bgp_execute_router_cmd, 1},
	{"next-hop", "Nexthop attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE4, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE1[] = {
	{"as-path", "As-path attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE5, bgp_execute_router_cmd, 1},
	{"med", "Med attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE4, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE[] = {
	{"as-path", "As-path attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE3, bgp_execute_router_cmd, 1},
	{"med", "Med attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE2, bgp_execute_router_cmd, 1},
	{"next-hop", "Nexthop attribute", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE1, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
*/
/* default-originate
Route-maps commented because they were not implemented yet. 
cish_command CMD_ROUTER_BGP_NEIGHBOR_DEF_ORIG1[] = { 
	{"<text>", "Route-map name", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};*/

cish_command CMD_ROUTER_BGP_NEIGHBOR_DEF_ORIG[] = {
	//{"route-map", "Route-map to specify criteria to originate default", CMD_ROUTER_BGP_NEIGHBOR_DEF_ORIG1, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},	
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_BGP_INTERFACE_ETHERNET[] = {
	{"0-0", "Ethernet interface number", NULL, bgp_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BGP_INTERFACE_LOOPBACK[] = {
	{"0-4", "Loopback interface number", NULL, bgp_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_BGP_INTERFACE_TUNNEL[] = {
	{"0-9", "Tunnel interface number", NULL, bgp_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_UPDATE_SOURCE[] = {
	{"ethernet", "Ethernet interface", CMD_BGP_INTERFACE_ETHERNET, NULL, 1},
	{"loopback", "Loopback interface", CMD_BGP_INTERFACE_LOOPBACK, NULL, 1},
	{"tunnel", "Tunnel interface", CMD_BGP_INTERFACE_TUNNEL, NULL, 1},
	{NULL,NULL,NULL,NULL,0}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_WEIGHT[] = { /* weight */
	{"0-65535", "default weight", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_TIMERS[] = { /* timers */
	{"0-65535", "keepalive interval", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_SOFTRECONF[] = { /*soft-reconfiguration*/
	{"inbound", "Allow inbound soft reconfiguration for this neighbor", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_PEERGROUP[] = { /*peer-group*/
	{"<text>", "peer-group name", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR_DESC[] = { /*description*/
	{"<text>", "Up to 80 characters describing this neighbor", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_ADV_INTERVAL[] = { /*advertisement interval*/
	{"0-600", "time in seconds", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_LOCAL_AS[] = { /*local-as*/
	{"1-65535", "AS number used as local AS", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_HOPCOUNT[] = { /*ebgp-multihop*/
	{"1-255", "maximum hop count", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

/* Not used due to necessity of route-maps, which are not implemented yet. ThomÃ¡s Del Grande 16/10/07
cish_command CMD_ROUTER_BGP_DISTLIST1[] = { //distribute-list
	{"in", "Filter incoming updates", NULL, bgp_execute_router_cmd, 1},
	{"out", "Filter outgoing updates", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DISTLIST[] = {
	{"<text>", "IP Access-list name", CMD_ROUTER_BGP_DISTLIST1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
*/

cish_command CMD_ROUTER_BGP_FILTERLIST1[] = { /*filter-list*/
	{"in", "Filter incoming routes", NULL, bgp_execute_router_cmd, 1},
	{"out", "Filter outgoing routes", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_FILTERLIST[] = {
	{"<text>", "AS path access-list name", CMD_ROUTER_BGP_FILTERLIST1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_MAXPREFIX2[] = { //maximum-prefix
	{"warning-only", "Only give warning message when limit is exceeded", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},	
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_MAXPREFIX1[] = {
	{"1-100", "Threshold value (%) at which to generate a warning msg", CMD_ROUTER_BGP_MAXPREFIX2, bgp_execute_router_cmd, 1},
	{"warning-only", "Only give warning message when limit is exceeded", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_MAXPREFIX[] = {
	{"1-2147483647", "maximum no. of prefix limit", CMD_ROUTER_BGP_MAXPREFIX1, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

/* Not used due to necessity of route-maps, which are not implemented yet.ThomÃ¡s Del Grande 16/10/07
cish_command CMD_ROUTER_BGP_PREFIXLIST[] = { //prefix-list
	{"<text>", "Name of a prefix list", CMD_ROUTER_BGP_DISTLIST1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
*/

// Not used due to necessity of route-maps, which are not implemented yet.ThomÃ¡s Del Grande 16/10/07
/*cish_command CMD_ROUTER_BGP_SENDCOMMUNITY[] = { //send-community
	{"both", "Send Standard and Extended Community attributes", NULL, bgp_execute_router_cmd, 1},
	{"extended", "Send Extended Community attributes", NULL, bgp_execute_router_cmd, 1},
	{"standard", "Send Standard Community attributes", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};*/

cish_command CMD_ROUTER_BGP_CAPABILITY2[] = { //capability
	{"both", "Capability to SEND and RECEIVE the ORF to/from this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"receive", "Capability to SEND the ORF to this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"send", "Capability to RECEIVE the ORF from this neighbor", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CAPABILITY1[] = {
	{"prefix-list", "Advertise prefixlist ORF capability to this neighbor", CMD_ROUTER_BGP_CAPABILITY2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CAPABILITY[] = {
	{"dynamic", "Advertise dynamic capability to this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"orf", "Advertise ORF capability to the peer", CMD_ROUTER_BGP_CAPABILITY1, NULL, 1},
	{"route-refresh", "Advertise route-refresh capability to this neighbor", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR1[] = {
	/* Commented commands are not well documented or could not be implemented apropriately */
	//{"activate", "Enable the Address Family for this Neighbor", NULL, bgp_execute_router_cmd, 1}, 
	{"allowas-in", "Accept as-path with my AS present in it", CMD_ROUTER_BGP_NEIGHBOR_ALLOWASIN, bgp_execute_router_cmd, 1},
	//{"attribute-unchanged", "BGP attribute is propagated unchanged to this neighbor", CMD_ROUTER_BGP_NEIGHBOR_ATTRIBUTE, bgp_execute_router_cmd, 1},
	{"capability", "Advertise capability to the peer", CMD_ROUTER_BGP_CAPABILITY, NULL, 1},
	{"default-originate", "Originate default route to this neighbor", CMD_ROUTER_BGP_NEIGHBOR_DEF_ORIG, bgp_execute_router_cmd, 1},
	{"description", "Neighbor specific description", CMD_ROUTER_BGP_NEIGHBOR_DESC, NULL, 1}, 
	//{"distribute-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_DISTLIST, NULL, 1},
	{"dont-capability-negotiate", "Do not perform capability negotiation", NULL, bgp_execute_router_cmd, 1},
	{"ebgp-multihop", "Allow EBGP neighbors not on directly connected networks", CMD_ROUTER_BGP_HOPCOUNT, bgp_execute_router_cmd, 1},
	//{"enforce-multihop", "Enforce EBGP neighbors perform multihop", NULL, bgp_execute_router_cmd, 1}, 
	{"filter-list", "Establish BGP filters", CMD_ROUTER_BGP_FILTERLIST, NULL, 1},
	{"local-as", "Specify a local-as number", CMD_ROUTER_BGP_LOCAL_AS, NULL, 1},
	{"maximum-prefix", "Maximum number of prefix accept from this peer", CMD_ROUTER_BGP_MAXPREFIX, NULL, 1},
	{"next-hop-self", "Disable the next hop calculation for this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"override-capability", "Override capability negotiation result", NULL, bgp_execute_router_cmd, 1},
	{"passive", "Don't send open messages to this neighbor", NULL, bgp_execute_router_cmd, 1},
	//{"prefix-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_PREFIXLIST, NULL, 1},
	{"remote-as", "Specify a BGP neighbor", CMD_ROUTER_BGP_NEIGHBOR_REMOTEAS, NULL, 1},
	{"remove-private-AS", "Remove private AS number from outbound updates", NULL, bgp_execute_router_cmd, 1},
	//{"route-map", "Apply route map to neighbor", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"route-reflector-client", "Configure a neighbor as Route Reflector client", NULL, bgp_execute_router_cmd, 1},
	{"route-server-client", "Configure a neighbor as Route Server client", NULL, bgp_execute_router_cmd, 1},
	//{"send-community", "Send Community attribute to this neighbor", , NULL, 1},
	{"shutdown", "Administratively shut down this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"soft-reconfiguration", "Per neighbor soft reconfiguration", CMD_ROUTER_BGP_NEIGHBOR_SOFTRECONF, NULL, 1},
	{"timers", "BGP per neighbor timers", CMD_ROUTER_BGP_NEIGHBOR_TIMERS, NULL, 1},
	//{"unsuppress-map", "Route-map to selectively unsuppress suppressed routes", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"update-source", "Source of routing updates", CMD_ROUTER_BGP_NEIGHBOR_UPDATE_SOURCE, NULL, 1},
	{"weight", "Set default weight for routes from this neighbor", CMD_ROUTER_BGP_NEIGHBOR_WEIGHT, NULL, 1},
	{"advertisement-interval", "Minimum interval between sending BGP routing updates", CMD_ROUTER_BGP_ADV_INTERVAL, NULL, 1},
	//{"interface", "Interface", NULL, NULL, 1},
	{"peer-group", "Member of the peer-group", CMD_ROUTER_BGP_NEIGHBOR_PEERGROUP, NULL, 1}, 
	/* These ones are commented because they don't exist on CISCO's routers... just zebra has them*/
	//{"port", "Neighbor's BGP port", NULL, NULL, 1},
	//{"strict-capability-match", "Strict capability negotiation match", NULL, NULL, 1},
	//{"transparent-as", "Do not append my AS number even peer is EBGP peer", NULL, bgp_execute_router_cmd, 1},
	//{"transparent-nexthop", "Do not change nexthop even peer is EBGP peer", NULL, bgp_execute_router_cmd, 1},
	//{"version", "Neighbor's BGP version", CMD_ROUTER_BGP_NEIGHBOR_VERSION, NULL, 1}, 
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NEIGHBOR2[] = {
	/* Commented commands are not well documented or could not be implemented apropriately */
	//{"activate", "Enable the Address Family for this Neighbor", NULL, bgp_execute_router_cmd, 1},
	{"allowas-in", "Accept as-path with my AS present in it", CMD_ROUTER_BGP_NEIGHBOR_ALLOWASIN, bgp_execute_router_cmd, 1},
	//{"attribute-unchanged", "BGP attribute is propagated unchanged to this neighbor", NULL, NULL, 1},
	{"capability", "Advertise capability to the peer", CMD_ROUTER_BGP_CAPABILITY, NULL, 1},
	{"default-originate", "Originate default route to this neighbor", CMD_ROUTER_BGP_NEIGHBOR_DEF_ORIG, bgp_execute_router_cmd, 1},
	{"description", "Neighbor specific description", CMD_ROUTER_BGP_NEIGHBOR_DESC, NULL, 1},
	//{"distribute-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_DISTLIST, NULL, 1},
	{"dont-capability-negotiate", "Do not perform capability negotiation", NULL, bgp_execute_router_cmd, 1},
	{"ebgp-multihop", "Allow EBGP neighbors not on directly connected networks", CMD_ROUTER_BGP_HOPCOUNT, bgp_execute_router_cmd, 1},
	//{"enforce-multihop", "Enforce EBGP neighbors perform multihop", NULL, bgp_execute_router_cmd, 1},
	{"filter-list", "Establish BGP filters", CMD_ROUTER_BGP_FILTERLIST, NULL, 1},
	{"local-as", "Specify a local-as number", CMD_ROUTER_BGP_LOCAL_AS, NULL, 1},
	{"maximum-prefix", "Maximum number of prefix accept from this peer", CMD_ROUTER_BGP_MAXPREFIX, NULL, 1},
	{"next-hop-self", "Disable the next hop calculation for this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"override-capability", "Override capability negotiation result", NULL, bgp_execute_router_cmd, 1},
	{"passive", "Don't send open messages to this neighbor", NULL, bgp_execute_router_cmd, 1},
	//{"prefix-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_PREFIXLIST, NULL, 1},
	{"remote-as", "Specify a BGP neighbor", CMD_ROUTER_BGP_NEIGHBOR_REMOTEAS, NULL, 1}, 
	{"remove-private-AS", "Remove private AS number from outbound updates", NULL, bgp_execute_router_cmd, 1},
	//{"route-map", "Apply route map to neighbor", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"route-reflector-client", "Configure a neighbor as Route Reflector client", NULL, bgp_execute_router_cmd, 1},
	{"route-server-client", "Configure a neighbor as Route Server client", NULL, bgp_execute_router_cmd, 1},
	//{"send-community", "Send Community attribute to this neighbor", CMD_ROUTER_BGP_SENDCOMMUNITY, NULL, 1},
	{"shutdown", "Administratively shut down this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"soft-reconfiguration", "Per neighbor soft reconfiguration", CMD_ROUTER_BGP_NEIGHBOR_SOFTRECONF, NULL, 1},
	{"timers", "BGP per neighbor timers", CMD_ROUTER_BGP_NEIGHBOR_TIMERS, NULL, 1},
	//{"unsuppress-map", "Route-map to selectively unsuppress suppressed routes", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"update-source", "Source of routing updates", CMD_ROUTER_BGP_NEIGHBOR_UPDATE_SOURCE, NULL, 1},
	{"weight", "Set default weight for routes from this neighbor", CMD_ROUTER_BGP_NEIGHBOR_WEIGHT, NULL, 1},
	{"advertisement-interval", "Minimum interval between sending BGP routing updates", CMD_ROUTER_BGP_ADV_INTERVAL, NULL, 1},
	{"peer-group", "Member of the peer-group", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};


cish_command CMD_ROUTER_BGP_NEIGHBOR[] = {
	{"<ipaddress>", "Network Number", CMD_ROUTER_BGP_NEIGHBOR1, NULL, 1},
	{"<text>", "Neighbor tag", CMD_ROUTER_BGP_NEIGHBOR2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
//-----------------------------------------//
/*no neighbor*///////////////////////////////
//----------------------------------------///
cish_command CMD_ROUTER_BGP_NO_MAXPREFIX[] = {
	{"1-2147483647", "maximum no. of prefix limit", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NO_NEIGHBOR1[] = {
	/* Commented commands are not well documented or could not be implemented apropriately */
	//{"activate", "Enable the Address Family for this Neighbor", NULL, bgp_execute_router_cmd, 1},
	{"allowas-in", "Accept as-path with my AS present in it", CMD_ROUTER_BGP_NEIGHBOR_ALLOWASIN, bgp_execute_router_cmd, 1},
	//{"attribute-unchanged", "BGP attribute is propagated unchanged to this neighbor", NULL, NULL, 1},
	{"capability", "Advertise capability to the peer", CMD_ROUTER_BGP_CAPABILITY, NULL, 1},
	{"default-originate", "Originate default route to this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"description", "Neighbor specific description", NULL, bgp_execute_router_cmd, 1},
	//{"distribute-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_DISTLIST, NULL, 1},
	{"dont-capability-negotiate", "Do not perform capability negotiation", NULL, bgp_execute_router_cmd, 1},
	{"ebgp-multihop", "Allow EBGP neighbors not on directly connected networks", CMD_ROUTER_BGP_HOPCOUNT, bgp_execute_router_cmd, 1},
	//{"enforce-multihop", "Enforce EBGP neighbors perform multihop", NULL, bgp_execute_router_cmd, 1},
	{"filter-list", "Establish BGP filters", CMD_ROUTER_BGP_FILTERLIST, NULL, 1},
	{"local-as", "Specify a local-as number", CMD_ROUTER_BGP_LOCAL_AS, bgp_execute_router_cmd, 1},
	{"maximum-prefix", "Maximum number of prefix accept from this peer", CMD_ROUTER_BGP_NO_MAXPREFIX, NULL, 1},
	{"next-hop-self", "Disable the next hop calculation for this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"override-capability", "Override capability negotiation result", NULL, bgp_execute_router_cmd, 1},
	{"passive", "Don't send open messages to this neighbor", NULL, bgp_execute_router_cmd, 1},
	//{"prefix-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_PREFIXLIST, NULL, 1},
	{"remote-as", "Specify a BGP neighbor", CMD_ROUTER_BGP_NEIGHBOR_REMOTEAS, NULL, 1},
	{"remove-private-AS", "Remove private AS number from outbound updates", NULL, bgp_execute_router_cmd, 1},
	//{"route-map", "Apply route map to neighbor", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"route-reflector-client", "Configure a neighbor as Route Reflector client", NULL, bgp_execute_router_cmd, 1},
	{"route-server-client", "Configure a neighbor as Route Server client", NULL, bgp_execute_router_cmd, 1},
	//{"send-community", "Send Community attribute to this neighbor", CMD_ROUTER_BGP_SENDCOMMUNITY, NULL, 1},
	{"shutdown", "Administratively shut down this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"soft-reconfiguration", "Per neighbor soft reconfiguration", CMD_ROUTER_BGP_NEIGHBOR_SOFTRECONF, NULL, 1},
	{"timers", "BGP per neighbor timers", NULL, bgp_execute_router_cmd, 1},
	//{"unsuppress-map", "Route-map to selectively unsuppress suppressed routes", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"update-source", "Source of routing updates", CMD_ROUTER_BGP_NEIGHBOR_UPDATE_SOURCE, NULL, 1},
	{"weight", "Set default weight for routes from this neighbor", CMD_ROUTER_BGP_NEIGHBOR_WEIGHT, NULL, 1},
	{"advertisement-interval", "Minimum interval between sending BGP routing updates", CMD_ROUTER_BGP_ADV_INTERVAL, NULL, 1},
	//{"interface", "Interface", NULL, NULL, 1},
	{"peer-group", "Member of the peer-group", CMD_ROUTER_BGP_NEIGHBOR_PEERGROUP, NULL, 1},
	//{"port", "Neighbor's BGP port", NULL, NULL, 1},
	//{"strict-capability-match", "Strict capability negotiation match", NULL, NULL, 1},
	//{"transparent-as", "Do not append my AS number even peer is EBGP peer", NULL, bgp_execute_router_cmd, 1},
	//{"transparent-nexthop", "Do not change nexthop even peer is EBGP peer", NULL, bgp_execute_router_cmd, 1},
	//{"version", "Neighbor's BGP version", CMD_ROUTER_BGP_NEIGHBOR_VERSION, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NO_NEIGHBOR2[] = {
	/* Commented commands are not well documented or could not be implemented apropriately */
	//{"activate", "Enable the Address Family for this Neighbor", NULL, bgp_execute_router_cmd, 1},
	{"allowas-in", "Accept as-path with my AS present in it", CMD_ROUTER_BGP_NEIGHBOR_ALLOWASIN, bgp_execute_router_cmd, 1},
	//{"attribute-unchanged", "BGP attribute is propagated unchanged to this neighbor", NULL, NULL, 1},
	{"capability", "Advertise capability to the peer", CMD_ROUTER_BGP_CAPABILITY, NULL, 1},
	{"default-originate", "Originate default route to this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"description", "Neighbor specific description", NULL, bgp_execute_router_cmd, 1},
	//{"distribute-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_DISTLIST, NULL, 1},
	{"dont-capability-negotiate", "Do not perform capability negotiation", NULL, bgp_execute_router_cmd, 1},
	{"ebgp-multihop", "Allow EBGP neighbors not on directly connected networks", CMD_ROUTER_BGP_HOPCOUNT, bgp_execute_router_cmd, 1},
	//{"enforce-multihop", "Enforce EBGP neighbors perform multihop", NULL, bgp_execute_router_cmd, 1},
	{"filter-list", "Establish BGP filters", CMD_ROUTER_BGP_FILTERLIST, NULL, 1},
	{"local-as", "Specify a local-as number", CMD_ROUTER_BGP_LOCAL_AS, bgp_execute_router_cmd, 1},
	{"maximum-prefix", "Maximum number of prefix accept from this peer", CMD_ROUTER_BGP_NO_MAXPREFIX, NULL, 1},
	{"next-hop-self", "Disable the next hop calculation for this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"override-capability", "Override capability negotiation result", NULL, bgp_execute_router_cmd, 1},
	{"passive", "Don't send open messages to this neighbor", NULL, bgp_execute_router_cmd, 1},
	//{"prefix-list", "Filter updates to/from this neighbor", CMD_ROUTER_BGP_PREFIXLIST, NULL, 1},
	{"remote-as", "Specify a BGP neighbor", CMD_ROUTER_BGP_NEIGHBOR_REMOTEAS, NULL, 1},
	{"remove-private-AS", "Remove private AS number from outbound updates", NULL, bgp_execute_router_cmd, 1},
	//{"route-map", "Apply route map to neighbor", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"route-reflector-client", "Configure a neighbor as Route Reflector client", NULL, bgp_execute_router_cmd, 1},
	{"route-server-client", "Configure a neighbor as Route Server client", NULL, bgp_execute_router_cmd, 1},
	//{"send-community", "Send Community attribute to this neighbor", CMD_ROUTER_BGP_SENDCOMMUNITY, NULL, 1},
	{"shutdown", "Administratively shut down this neighbor", NULL, bgp_execute_router_cmd, 1},
	{"soft-reconfiguration", "Per neighbor soft reconfiguration", CMD_ROUTER_BGP_NEIGHBOR_SOFTRECONF, NULL, 1},
	{"timers", "BGP per neighbor timers", CMD_ROUTER_BGP_NEIGHBOR_TIMERS, NULL, 1},
	//{"unsuppress-map", "Route-map to selectively unsuppress suppressed routes", CMD_ROUTER_BGP_NEIGHBOR_ROUTEMAP, NULL, 1},
	{"update-source", "Source of routing updates", CMD_ROUTER_BGP_NEIGHBOR_UPDATE_SOURCE, NULL, 1},
	{"weight", "Set default weight for routes from this neighbor", CMD_ROUTER_BGP_NEIGHBOR_WEIGHT, NULL, 1},
	{"advertisement-interval", "Minimum interval between sending BGP routing updates", CMD_ROUTER_BGP_ADV_INTERVAL, NULL, 1},
	{"peer-group", "Member of the peer-group", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_NO_NEIGHBOR[] = {
	{"<ipaddress>", "Network Number", CMD_ROUTER_BGP_NO_NEIGHBOR1, bgp_execute_router_cmd, 1},
	{"<text>", "Neighbor tag", CMD_ROUTER_BGP_NO_NEIGHBOR2, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

/*reditribute
Route-maps commented because they were not implemented yet. ThomÃ¡s Del Grande 16/10/07
cish_command CMD_ROUTER_BGP_REDISTRIBUTE2[] = {
	{"<text>", "Pointer to route-map entries", NULL, rip_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}
};*/

cish_command CMD_ROUTER_BGP_REDISTRIBUTE1[] = {
	{"metric", "Metric for redistributed routes", CMD_ROUTER_RIP_DEFAULT_METRIC, NULL, 1},
	//{"route-map", "Route map reference", CMD_ROUTER_RIP_REDISTRIBUTE2, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_ROUTER_BGP_REDISTRIBUTE[] = {
	{"connected", "Connected", CMD_ROUTER_BGP_REDISTRIBUTE1, bgp_execute_router_cmd, 1},
	{"kernel", "Kernel routes", CMD_ROUTER_BGP_REDISTRIBUTE1, bgp_execute_router_cmd, 1},
	{"ospf", "Open Shortest Path First (OSPF)", CMD_ROUTER_BGP_REDISTRIBUTE1, bgp_execute_router_cmd, 1},
	{"rip", "Routing Information Protocol (RIP)", CMD_ROUTER_BGP_REDISTRIBUTE1, bgp_execute_router_cmd, 1},
	{"static", "Static routes", CMD_ROUTER_BGP_REDISTRIBUTE1, bgp_execute_router_cmd, 1},
	{NULL,NULL,NULL,NULL, 0}


};

cish_command CMD_ROUTER_BGP_TIMERS2[] = { /*timers*/
	{"1-65535", "Holdtime", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_TIMERS1[] = {
	{"1-65535", "Keepalive interval", CMD_ROUTER_BGP_TIMERS2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_TIMERS[] = {
	{"bgp", "BGP Timers", CMD_ROUTER_BGP_TIMERS1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_BESTPATH4[] = {
	{"missing-as-worst", "Treat missing MED as the least preferred one", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_BESTPATH3[] = {
	{"confed", "Compare MED among confederation paths", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_BESTPATH2[] = {
	{"confed", "Compare MED among confederation paths", CMD_ROUTER_BGP_BESTPATH4, bgp_execute_router_cmd, 1},
	{"missing-as-worst", "Treat missing MED as the least preferred one", CMD_ROUTER_BGP_BESTPATH3, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_BESTPATH1[] = {
	{"ignore", "Ignore as-path length in selecting a route", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};
cish_command CMD_ROUTER_BGP_BESTPATH[] = {
	{"as-path", "AS-path attribute", CMD_ROUTER_BGP_BESTPATH1, NULL, 1},
	{"compare-routerid", "Compare router-id for identical EBGP paths", NULL, bgp_execute_router_cmd, 1},
	{"med", "MED attribute", CMD_ROUTER_BGP_BESTPATH2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CLIENT_TO_CLIENT[] = {
	{"reflection", "reflection of routes allowed", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CLUSTERID[] = {
	{"1-4294967295", "MaximRoute-Reflector Cluster-id as 32 bit quantity", NULL, bgp_execute_router_cmd, 1},
	{"<ipaddress>", "Route-Reflector Cluster-id in IP address format", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CONFEDERATION3[] = {
	{"1-65535", "AS number", CMD_ROUTER_BGP_CONFEDERATION3, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CONFEDERATION2[] = {
	{"1-65535", "AS number", CMD_ROUTER_BGP_CONFEDERATION3, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CONFEDERATION1[] = {
	{"1-65535", "Set routing domain confederation AS", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_CONFEDERATION[] = {
	{"identifier", "AS number", CMD_ROUTER_BGP_CONFEDERATION1, NULL, 1},
	{"peers", "Peer ASs in BGP confederation", CMD_ROUTER_BGP_CONFEDERATION2, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DAMPENING3[] = {
	{"1-255", "Maximum duration to suppress a stable route", NULL, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DAMPENING2[] = {
	{"1-20000", "Value to start suppressing a route", CMD_ROUTER_BGP_DAMPENING3, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DAMPENING1[] = {
	{"1-20000", "Value to start reusing a route", CMD_ROUTER_BGP_DAMPENING2, NULL, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DAMPENING[] = {
	{"1-45", "Half-life time for the penalty", CMD_ROUTER_BGP_DAMPENING1, bgp_execute_router_cmd, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DEFAULT1[] = {
	{"0-4294967295", "Configure default local preference value", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_DEFAULT[] = {
	/* ipv4-unicast poorly documented */
	//{"ipv4-unicast", "Activate ipv4-unicast for a peer by default", NULL, bgp_execute_router_cmd, 1},
	{"local-preference", "local preference (higher=more preferred)", CMD_ROUTER_BGP_DEFAULT1, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_ROUTERID[] = {
	{"<ipaddress>", "Manually configured router identifier", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_SCANTIMER[] = {
	{"5-60", "Scanner interval (seconds)", NULL, bgp_execute_router_cmd, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ROUTER_BGP_BGP[] = {
	{"always-compare-med", "Allow comparing MED from different neighbors", NULL, bgp_execute_router_cmd, 1},
	{"bestpath", "Change the default bestpath selection", CMD_ROUTER_BGP_BESTPATH, NULL, 1},
	{"client-to-client", "Configure client to client route reflection", CMD_ROUTER_BGP_CLIENT_TO_CLIENT, NULL, 1},
	{"cluster-id", "Configure Route-Reflector Cluster-id", CMD_ROUTER_BGP_CLUSTERID, NULL, 1},
	{"confederation", "AS confederation parameters", CMD_ROUTER_BGP_CONFEDERATION, NULL, 1},
	{"dampening", "Enable route-flap dampening", CMD_ROUTER_BGP_DAMPENING, bgp_execute_router_cmd, 1},
	{"default", "Configure BGP defaults", CMD_ROUTER_BGP_DEFAULT, NULL, 1},
	{"deterministic-med", "Pick the best-MED path among paths advertised from the neighboring AS", NULL, bgp_execute_router_cmd, 1},
	{"enforce-first-as", "Enforce the first AS for EBGP routes", NULL, bgp_execute_router_cmd, 1},
	{"fast-external-failover", "Immediately reset session if a link to a directly connected external peer goes down", NULL, bgp_execute_router_cmd, 1},
	{"log-neighbor-changes", "Log neighbor up/down and reset reason", NULL, bgp_execute_router_cmd, 1},
	{"router-id", "Override configured router identifier", CMD_ROUTER_BGP_ROUTERID, NULL, 1},
	{"scan-time", "Configure background scanner interval", CMD_ROUTER_BGP_SCANTIMER, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_CONFIG_ROUTER_BGP_NO[] = {
	//{"address-family", "Enter Address Family command mode", , NULL, 1},
	{"aggregate-address", "Configure BGP aggregate entries", CMD_ROUTER_BGP_AGGADDR, NULL, 1},
	{"bgp", "BGP specific commands", CMD_ROUTER_BGP_BGP, NULL, 1},
//	{"distance", "Define an administrative distance", CMD_ROUTER_BGP_DISTANCE, NULL, 1},
	{"neighbor", "Specify neighbor router", CMD_ROUTER_BGP_NO_NEIGHBOR, NULL, 1},
	{"network", "Specify a network to announce via BGP", CMD_ROUTER_BGP_NETWORK, NULL, 1},
	{"redistribute", "Redistribute information from another routing protocol", CMD_ROUTER_BGP_REDISTRIBUTE, NULL, 1},
	{"timers", "Adjust routing timers", CMD_ROUTER_NO_OSPF_TIMERS, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_CONFIG_ROUTER_BGP[] = {
//	{"address-family", "Enter Address Family command mode", CMD_ROUTER_BGP_ADDRFAM, NULL, 1},
	{"aggregate-address", "Configure BGP aggregate entries", CMD_ROUTER_BGP_AGGADDR, NULL, 1},
	{"bgp", "BGP specific commands", CMD_ROUTER_BGP_BGP, NULL, 1},
//	{"distance", "Define an administrative distance", CMD_ROUTER_BGP_DISTANCE, NULL, 1},
	{"exit", "Exit current mode and down to previous mode", NULL, config_router_done, 1},
	{"neighbor", "Specify neighbor router", CMD_ROUTER_BGP_NEIGHBOR, NULL, 1},
	{"network", "Specify a network to announce via BGP", CMD_ROUTER_BGP_NETWORK, NULL, 1},
	{"no", "Reverse settings", CMD_CONFIG_ROUTER_BGP_NO, NULL, 1},
	{"redistribute", "Redistribute information from another routing protocol", CMD_ROUTER_BGP_REDISTRIBUTE, NULL, 1},
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0},
	{"timers", "Adjust routing timers", CMD_ROUTER_BGP_TIMERS, NULL, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_BGP_FILTER[] = {
	{"<text>", "Regular expression access list name", NULL, show_ip_bgp, 1},
	{NULL, NULL, NULL, NULL}
};


cish_command CMD_SHOW_BGP_REGEXP[] = {
	{"<text>", "A regular-expression to match the BGP AS paths", NULL, show_ip_bgp, 1},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_SHOW_BGP[] = {
	{"<ipaddress>", "Network in the BGP routing table to display", NULL, show_ip_bgp, 1},
	//{"A.B.C.D/M", "IP prefix <network>/<length>, e.g., 35.0.0.0/8", NULL, show_ip_bgp, 1},
	{"attribute-info", "List all bgp attribute information", NULL, show_ip_bgp, 1},
	//{"cidr-only", "Display only routes with non-natural netmasks", NULL, show_ip_bgp, 1},
	//{"community", "Display routes matching the communities", NULL, show_ip_bgp, 1},
	//{"community-info", "List all bgp community information", NULL, show_ip_bgp, 1},
	//{"community-list", "Display routes matching the community-list", NULL, show_ip_bgp, 1},
	{"dampened-paths", "Display paths suppressed due to dampening", NULL, show_ip_bgp, 1},
	{"filter-list", "Display routes conforming to the filter-list", CMD_SHOW_BGP_FILTER, NULL, 1},
	{"flap-statistics", "Display flap statistics of routes", NULL, show_ip_bgp, 1},
	//{"ipv4", "Address family", NULL, show_ip_bgp, 1},
	{"neighbors", "Detailed information on TCP and BGP neighbor connections", NULL, show_ip_bgp, 1},
	{"paths", "Path information", NULL, show_ip_bgp, 1},
	//{"prefix-list", "Display routes conforming to the prefix-list", NULL, show_ip_bgp, 1},
	{"regexp", "Display routes matching the AS path regular expression", CMD_SHOW_BGP_REGEXP, NULL, 1},
	//{"route-map", "Display routes matching the route-map", NULL, show_ip_bgp, 1},
	{"scan", "BGP scan status", NULL, show_ip_bgp, 1},
	{"summary", "Summary of BGP neighbor status", NULL, show_ip_bgp, 1},
	//{"view", "BGP view", NULL, show_ip_bgp, 1},
	//{"vpnv4", "Display VPNv4 NLRI specific information", NULL, show_ip_bgp, 1},
	{"<enter>", "", NULL, NULL, 1},
	{NULL, NULL, NULL, NULL}
};
#endif

// Recebe uma linha de comando com redes no estilo zebra (ex.: '10.0.0.0/8')
// e devolve a linha de comando com as redes traduzidas para estilo linux
// (ex.: '10.0.0.0 255.0.0.0').
char *zebra_to_linux_network_cmdline(char *cmdline)
{
	static char new_cmdline[2048];
	arglist *args;
	int i;
	char addr_net[64];

	new_cmdline[0]=0;
	if (is_empty(cmdline)) return new_cmdline;

	args=make_args(cmdline);

	for (i=0; i < args->argc; i++)
	{
		if (cidr_to_classic(args->argv[i], addr_net)==0)
			strcat(new_cmdline, addr_net);
		else
			strcat(new_cmdline, args->argv[i]);
		strcat(new_cmdline, " ");
	}

	destroy_args(args);
	return new_cmdline;
}

// Recebe uma linha de comando com redes no estilo linux
// (ex.: '10.0.0.0 255.0.0.0') e devolve a linha de comando 
// com as redes traduzidas para estilo zebra (ex.: '10.0.0.0/8')
char *linux_to_zebra_network_cmdline(char *cmdline)
{
	static char new_cmdline[2048];
	arglist *args;
	int i;
	char buf[64];

	new_cmdline[0] = 0;
	if (is_empty(cmdline)) return new_cmdline;

	args=make_args(cmdline);

	for (i=0; i<(args->argc-1); i++)
	{
		if ((validateip(args->argv[i])==0)&&
		    (classic_to_cidr(args->argv[i], args->argv[i+1], buf)==0))
		{
			strcat(new_cmdline, buf);
			i++;
		}
		else
		{
			strcat(new_cmdline, args->argv[i]);
		}
		strcat(new_cmdline, " ");
	}
	if (i<args->argc) strcat(new_cmdline, args->argv[i]);

	destroy_args(args);
	return new_cmdline;
}

void set_rip_interface_cmds(int enable)
{
	if (enable)
		_cish_mask |= MSK_RIP;
	else
		_cish_mask &= ~MSK_RIP;
}

void set_ospf_interface_cmds(int enable)
{
	if (enable)
		_cish_mask |= MSK_OSPF;
	else
		_cish_mask &= ~MSK_OSPF;
}

#ifdef OPTION_BGP
void set_bgp_interface_cmds(int enable)
{
	if (enable)
		_cish_mask |= MSK_BGP;
	else
		_cish_mask &= ~MSK_BGP;
}
#endif

void set_model_qos_cmds(int enable)
{
	if (enable)
		_cish_mask |= MSK_QOS;
	else
		_cish_mask &= ~MSK_QOS;
}

extern cish_command CMD_SHOW_INTERFACE_ETHERNET[];
#ifdef OPTION_SMCROUTE
extern cish_command CMD_IP_MROUTE8_ETHERNET[];
extern cish_command CMD_IP_MROUTE5_ETHERNET[];
#endif
extern cish_command CMD_IP_ROUTE4_ETHERNET[];
#ifdef OPTION_PIMD
extern cish_command CMD_IP_PIM_CAND_BSR_INTF_ETHERNET[];
extern cish_command CMD_IP_PIM_CAND_RP_INTF_ETHERNET[];
#endif
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_[];
#ifdef OPTION_IPSEC
extern cish_command CMD_IPSEC_CONNECTION_INTERFACE_ETHERNET[];
extern cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_ETHERNET[];
#endif
extern cish_command CMD_CLEAR_INTERFACE_ETHERNET_[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET[];

void set_model_ethernet_cmds(const char *name)
{
	/* commandtree.c */
	CMD_SHOW_INTERFACE_ETHERNET[0].name=name;
#ifdef OPTION_SMCROUTE
	CMD_IP_MROUTE8_ETHERNET[0].name=name;
	CMD_IP_MROUTE5_ETHERNET[0].name=name;
#endif
	CMD_IP_ROUTE4_ETHERNET[0].name=name;
#ifdef OPTION_PIMD
	CMD_IP_PIM_CAND_BSR_INTF_ETHERNET[0].name=name;
	CMD_IP_PIM_CAND_RP_INTF_ETHERNET[0].name=name;
#endif
	CMD_CONFIG_INTERFACE_ETHERNET_[0].name=name;
#ifdef OPTION_IPSEC
	CMD_IPSEC_CONNECTION_INTERFACE_ETHERNET[0].name=name;
	CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_ETHERNET[0].name=name;
#endif
	CMD_CLEAR_INTERFACE_ETHERNET_[0].name=name;
	/* configterm.c */
	CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET[0].name=name;
	/* config_router.c */
	CMD_ROUTER_RIP_INTERFACE_ETHERNET[0].name=name;
	CMD_ROUTER_OSPF_PASSIVE_INTERFACE_ETHERNET[0].name=name;
	CMD_SHOW_OSPF_INTERFACE_ETHERNET[0].name=name;
#ifdef OPTION_BGP
	CMD_BGP_INTERFACE_ETHERNET[0].name=name;
#endif
}

void config_router(const char *cmdline)
{
	arglist *args;
	char no_debug_ospf[]="no debug ospf event";
	char no_debug_rip[]="no debug rip events";
#ifdef OPTION_BGP
	char no_debug_bgp[]="no debug bgp events";
#endif

	syslog(LOG_INFO, "entered router configuration mode for session from %s", _cish_source);
	args=make_args(cmdline);
	if (strcasecmp(args->argv[1], "rip") == 0)
	{
		command_root = CMD_CONFIG_ROUTER_RIP;
		set_rip_interface_cmds(1);
		set_ripd(1);
		/* sync debug! */
		if (get_debug_state(args->argv[1])) {
			rip_execute_root_cmd(&no_debug_rip[3]);
		} else {
			rip_execute_root_cmd(no_debug_rip);
		}
	}
	else if (strcasecmp(args->argv[1], "ospf") == 0)
	{
		command_root = CMD_CONFIG_ROUTER_OSPF;
		set_ospf_interface_cmds(1);
		set_ospfd(1);
		/* sync debug! */
		if (get_debug_state(args->argv[1])) {
			ospf_execute_root_cmd(&no_debug_ospf[3]);
		} else {
			ospf_execute_root_cmd(no_debug_ospf);
		}
	}
#ifdef OPTION_BGP
	else if (strcasecmp(args->argv[1], "bgp") == 0)
	{
		int temp = atoi(args->argv[2]);
		set_bgp_interface_cmds(1);
		set_bgpd(1);
		bgp_start_router_cmd(temp);	/* Initiates BGP with ASN = temp */
		asn = get_bgp_asn();
		if ( asn == 0 || temp == asn)	/* Do not enter if another AS is already running */
		{
			asn=temp; 
			command_root = CMD_CONFIG_ROUTER_BGP;
			/* sync debug! */
			if (get_debug_state(args->argv[1])) {
				bgp_execute_root_cmd(&no_debug_bgp[3]);
			} else {
				bgp_execute_root_cmd(no_debug_bgp);
			}
		}
	}
#endif
	destroy_args(args);
}

void config_no_router(const char *cmdline)
{
	arglist *args;
	char tmp[64];

	args=make_args(cmdline);

	if (strcasecmp (args->argv[2], "rip") == 0)
	{
		set_rip_interface_cmds(0);
		set_ripd(0);
				sprintf(tmp, "cp %s %s", RIPD_RO_CONF, RIPD_CONF );	
#ifdef DEBUG_ZEBRA
		printf("%s\n", tmp);
#endif
		system(tmp);	/* clean configuration file */
	}
	else if (strcasecmp (args->argv[2], "ospf") == 0)
	{
		set_ospf_interface_cmds(0);
		set_ospfd(0);
		sprintf(tmp, "cp %s %s", OSPFD_RO_CONF, OSPFD_CONF );
#ifdef DEBUG_ZEBRA
		printf("%s\n", tmp);
#endif
		system(tmp);	/* clean configuration file */
	}
#ifdef OPTION_BGP
	else if (strcasecmp (args->argv[2], "bgp") == 0)
	{
		int asn_temp=atoi(args->argv[3]);
		asn = get_bgp_asn ();
		if (asn_temp == asn)	/* Make sure we're shutting down the correct AS...  otherwise, do nothing */
		{
			set_bgp_interface_cmds(0);
			set_bgpd(0);
			sprintf(tmp, "cp %s %s", BGPD_RO_CONF, BGPD_CONF );
#ifdef DEBUG_ZEBRA
			printf("%s\n", tmp);
#endif
			system(tmp);	/* clean configuration file */
		}
	}
#endif
	destroy_args(args);
}

#ifdef OPTION_BGP
/* Search the ASN in bgpd configuration file */
int get_bgp_asn(void)
{
	FILE *bgp_conf;
	const char router_bgp[] = "router bgp ";
	char *buf, *asn_add;
	int bgp_asn = 0;

	if (!get_bgpd()) return 0;

	bgp_conf = bgp_get_conf(1);
	if (bgp_conf)
	{
		buf=malloc(1024);
		asn_add=buf;
		while(!feof(bgp_conf))
		{
			fgets(buf, 1024, bgp_conf);
			if (!strncmp(buf,router_bgp,strlen(router_bgp)))
			{
				asn_add+=strlen(router_bgp); //move pointer to the AS number
				bgp_asn = atoi(asn_add);
				break;
			}
		}
		fclose(bgp_conf);
		free(buf);
	}
	return bgp_asn;
}
#endif

void config_router_done(const char *cmdline)
{
	syslog (LOG_INFO, "left router configuration mode for session from %s", _cish_source);
	command_root = CMD_CONFIGURE;
}

void zebra_execute_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(ZEBRA_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("zebra_execute_cmd = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

#if 0
void zebra_execute_interface_cmd(const char *cmdline)
{
	char *new_cmdline;
	char *dev;

	if (daemon_connect(ZEBRA_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(buf, "interface %s", dev);
	free(dev);
#ifdef DEBUG_ZEBRA
printf("zebra_execute_interface_cmd = %s\n", buf);
printf("zebra_execute_interface_cmd = %s\n", new_cmdline);
#endif
	daemon_client_execute(buf, stdout, buf_daemon, 0);
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);
	fd_daemon_close();
}
#endif

void ospf_execute_root_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(OSPF_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("ospf = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

void ospf_execute_router_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(OSPF_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	daemon_client_execute("router ospf", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("ospf = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

void ospf_execute_interface_cmd(const char *cmdline)
{
	char *new_cmdline;
	char *dev;

	if (daemon_connect(OSPF_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	sprintf(buf, "interface %s", dev);
	free(dev);
#ifdef DEBUG_ZEBRA
printf("ospf = %s\n", buf);
printf("ospf = %s\n", new_cmdline);
#endif
	daemon_client_execute(buf, stdout, buf_daemon, 0);
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

void rip_execute_root_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(RIP_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("rip = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

extern char keychain_name[64];
extern int key_number;

void rip_execute_keychain_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(RIP_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	sprintf(buf, "key chain %s", keychain_name);
	daemon_client_execute(buf, stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("rip = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

void rip_execute_key_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(RIP_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	sprintf(buf, "key chain %s", keychain_name);
	daemon_client_execute(buf, stdout, buf_daemon, 0);
	sprintf(buf, "key %d", key_number);
	daemon_client_execute(buf, stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("rip = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

void rip_execute_router_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(RIP_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	daemon_client_execute("router rip", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("rip = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

void rip_execute_interface_cmd(const char *cmdline)
{
	char *dev, *new_cmdline;

	if (daemon_connect(RIP_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(buf, "interface %s", dev);
	free(dev);
#ifdef DEBUG_ZEBRA
printf("rip = %s\n", buf);
printf("rip = %s\n", new_cmdline);
#endif
	daemon_client_execute(buf, stdout, buf_daemon, 0);
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

#ifdef OPTION_BGP /* COMEÃO  - Suporte ao BGP | ThomÃ¡s Del Grande 25/09/07*/
void bgp_execute_root_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (daemon_connect(BGP_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("bgp = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}

/* Initializes a BGP AS if one does not exist */
int bgp_start_router_cmd(int temp_asn)
{
	char tmp[32];

	if (daemon_connect(BGP_PATH) < 0) return -1;

	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	sprintf(tmp, "router bgp %d", temp_asn);
	daemon_client_execute(tmp, stdout, buf_daemon, 1); /* show errors! */

#ifdef DEBUG_ZEBRA
printf("bgp = %s\n", tmp);
#endif
	fd_daemon_close();
	
	return 0;
}

void bgp_execute_router_cmd(const char *cmdline)
{
	char *new_cmdline;
	char bgp_line[32];

	if (daemon_connect(BGP_PATH) < 0) return;

	new_cmdline=cish_to_linux_dev_cmdline((char*)cmdline);
	new_cmdline=linux_to_zebra_network_cmdline((char*)new_cmdline);
	daemon_client_execute("enable", stdout, buf_daemon, 0);
	daemon_client_execute("configure terminal", stdout, buf_daemon, 0);
	
	sprintf(bgp_line, "router bgp %d", asn);	
	daemon_client_execute(bgp_line, stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
printf("bgp = %s\n", new_cmdline);
#endif
	daemon_client_execute(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	daemon_client_execute("write file", stdout, buf_daemon, 0);

	fd_daemon_close();
}
#endif /* FIM - Suporte ao BGP | ThomÃ¡s Del Grande 25/09/07*/

/*  Abre o arquivo de 'filename' e posiciona o file descriptor na linha:
 *  - igual a 'key'
 *  Retorna o file descriptor, ou NULL se nao for possivel abrir o arquivo
 *  ou encontrar a posicao desejada.
 */
FILE *get_conf(char *filename, char *key)
{
	FILE *f;
	int len, found=0;
	char buf[1024];
	
	f = fopen(filename, "rt");
	if (!f) return f;
	while (!feof(f))
	{
		fgets(buf, 1024, f);
		len=strlen(buf);
		striplf(buf);
		if (strncmp(buf, key, strlen(key))==0)
		{
			found = 1;
			fseek(f, -len, SEEK_CUR);
			break;
		}
	}
	if (found) return f;
	fclose(f);
	return NULL;
}

/*  Abre o arquivo de configuracao do zebra e posiciona o file descriptor de
 *  acordo com o argumento:
 *  main_ninterf = 1 -> posiciona no inicio da configuracao geral (comandos
 			'ip route'); nesse caso o argumento intf eh ignorado
 *  main_ninterf = 0 -> posiciona no inicio da configuracao da interface 'intf',
 *			sendo que 'intf' deve estar no formato linux (ex.: 'eth0')
 */
FILE *zebra_get_conf(int main_ninterf, char *intf)
{
	char key[64];
	
	if (main_ninterf)
		strcpy(key, "ip route");
	else
		sprintf(key, "interface %s", intf);
	
	return get_conf(ZEBRA_CONF, key);
}

void zebra_dump_static_routes_conf(FILE *out)
{
	FILE *f;
	char buf[1024];
	
	f = zebra_get_conf(1, NULL);
	
	if (!f) return;
	
	while (!feof(f))
	{
		fgets(buf, 1024, f);
		if (buf[0] == '!') break;
		striplf(buf);
		fprintf(out, "%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
	}
	fprintf(out, "!\n");
	
	fclose(f);
}

void zebra_dump_routes(FILE *out)
{
	int n;
	FILE *f;
	arg_list argl = NULL;
	char *new_buf, buf[1024];
	unsigned int print, line = 0;

	if (!(f = zebra_show_cmd("show ip route")))
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			line++;
			striplf(buf);
			if (line == 1)
#ifdef OPTION_BGP
				fprintf(out, "Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF, B - BGP, > - selected route\n");
#else
				fprintf(out, "Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF, > - selected route\n");
#endif
			else if (line > 3) {
				if (strlen(buf) > 4) {
#if 0
					if (buf[0] == 'K')
						continue;
#endif

					new_buf = linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf + 4));
					buf[3] = 0;
					if (new_buf) {
						print = 1;
						if (strchr(buf, '>') == NULL) {
							if (((n = parse_args_din(new_buf, &argl)) > 0) && (strcmp(argl[n-1], "inactive") == 0))
								print = 0;
							free_args_din(&argl);
						}
						if (print)
							fprintf(out, "%s %s\n", buf, new_buf);
					}
				}
			}
		}
	}
	fclose(f);
}

void show_ip_ospf(const char *cmdline)
{
	FILE *f;
	char buf[1024];

	f=ospf_show_cmd(cmdline);
	if (!f) return;
	while (!feof(f))
	{
		if (fgets(buf, 1024, f))
		{
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
		}
	}
	fclose(f);
}

void show_ip_rip(const char *cmdline)
{
	FILE *f;
	char buf[1024];

	f=rip_show_cmd("show ip protocols");
	if (!f) return;
	while (!feof(f))
	{
		if (fgets(buf, 1024, f))
		{
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
		}
	}
	fclose(f);

	f=rip_show_cmd(cmdline); /* show ip rip */
	if (!f) return;
	while (!feof(f))
	{
		if (fgets(buf, 1024, f))
		{
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
		}
	}
	fclose(f);
}

#ifdef OPTION_BGP
void show_ip_bgp(const char *cmdline)
{


	FILE *f;
	char buf[1024];

	f=bgp_show_cmd(cmdline);
	if (!f) return;
	while (!feof(f))
	{
		if (fgets(buf, 1024, f))
		{
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));

		}
	}
	fclose(f);

}

/*  Abre o arquivo de configuracao do BGP e posiciona o file descriptor de
 *  acordo com o argumento:
 *  main_ninterf = 1 -> posiciona no inicio da configuracao geral ('router bgp "nÃºmero do as"');
 			nesse caso o argumento intf eh ignorado
 *  main_ninterf = 0 -> posiciona no inicio da configuracao da interface 'intf',
 *			sendo que 'intf' deve estar no formato linux (ex.: 'eth0')
 */
FILE *bgp_get_conf(int main_nip)
{
	char key[64];

	if (main_nip)
		strcpy(key, "router bgp");
	else
		sprintf(key, "ip as-path");

	return get_conf(BGPD_CONF, key);
}

void dump_router_bgp(FILE *out, int main_nip)
{
	FILE *f;
	char buf[1024];

	if (!get_bgpd()) return;


	/* dump router bgp info */

	f=bgp_get_conf(main_nip);
	if (f)
	{
		while(!feof(f))
		{
			fgets(buf, 1024, f);
			if (buf[0] == '!') break;
			striplf(buf);
			fprintf(out, "%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
		}
		fclose(f);
	}
	fprintf(out, "!\n");
}
#endif

/*  Abre o arquivo de configuracao do RIP e posiciona o file descriptor de
 *  acordo com o argumento:
 *  main_ninterf = 1 -> posiciona no inicio da configuracao geral ('router rip');
 			nesse caso o argumento intf eh ignorado
 *  main_ninterf = 0 -> posiciona no inicio da configuracao da interface 'intf',
 *			sendo que 'intf' deve estar no formato linux (ex.: 'eth0')
 */
FILE *rip_get_conf(int main_ninterf, char *intf)
{
	char key[64];

	if (main_ninterf)
		strcpy(key, "router rip");
	else
		sprintf(key, "interface %s", intf);

	return get_conf(RIPD_CONF, key);
}

void dump_router_rip(FILE *out)
{
	FILE *f;
	int end;
	char buf[1024];
	char keychain[]="key chain";

	if (!get_ripd()) return;

	/* dump router rip info */
	fprintf(out, "router rip\n"); /* if config not written */
	f=rip_get_conf(1, NULL);
	if (f)
	{
		fgets(buf, 1024, f); /* skip line */
		while(!feof(f))
		{
			fgets(buf, 1024, f);
			if (buf[0] == '!') break;
			striplf(buf);
			fprintf(out, "%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
		}
		fclose(f);
	}
	fprintf(out, "!\n");

	/* dump key info (after router rip!) */
	f=get_conf(RIPD_CONF, keychain);
	if (f)
	{
		end=0;
		while(!feof(f))
		{
			fgets(buf, 1024, f);
			if (end && (strncmp(buf, keychain, sizeof(keychain) != 0))) break;
				else end=0;
			if (buf[0] == '!') end=1;
			striplf(buf);
			fprintf(out, "%s\n", buf);
		}
		fclose(f);
	}
}

void dump_rip_interface(FILE *out, char *intf)
{
	FILE *f;
	char buf[1024];

	if (!get_ripd()) return;

	f=rip_get_conf(0, intf);
	if (!f) return;
	fgets(buf, 1024, f); /* skip line */
	while (!feof(f))
	{
		fgets(buf, 1024, f);
		if (buf[0] == '!') break;
		striplf(buf);
		fprintf(out, "%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
	}
	fclose(f);
}

/*  Abre o arquivo de configuracao do OSPF e posiciona o file descriptor de
 *  acordo com o argumento:
 *  main_ninterf = 1 -> posiciona no inicio da configuracao geral ('router ospf');
 			nesse caso o argumento intf eh ignorado
 *  main_ninterf = 0 -> posiciona no inicio da configuracao da interface 'intf',
 *			sendo que 'intf' deve estar no formato linux (ex.: 'eth0')
 */
FILE *ospf_get_conf(int main_ninterf, char *intf)
{
	char key[64];

	if (main_ninterf)
		strcpy(key, "router ospf");
	else
		sprintf(key, "interface %s", intf);

	return get_conf(OSPFD_CONF, key);
}

void dump_router_ospf(FILE *out)
{
	FILE *f;
	char buf[1024];

	if (!get_ospfd()) return;

	fprintf(out, "router ospf\n"); /* if config not written */
	f=ospf_get_conf(1, NULL);
	if (f)
	{
		fgets(buf, 1024, f); /* skip line */
		while (!feof(f))
		{
			fgets(buf, 1024, f);
			if (buf[0] == '!') break;
			striplf(buf);
			fprintf(out, "%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
		}
		fclose(f);
	}
	fprintf(out, "!\n");
}

void dump_ospf_interface(FILE *out, char *intf)
{
	FILE *f;
	char buf[1024];

	if (!get_ospfd()) return;

	f = ospf_get_conf(0, intf);
	if (!f) return;
	fgets(buf, 1024, f); /* skip line */
	while (!feof(f))
	{
		fgets(buf, 1024, f);
		if (buf[0] == '!') break;
		striplf(buf);
		fprintf(out, "%s\n", linux_to_cish_dev_cmdline(zebra_to_linux_network_cmdline(buf)));
	}
	fclose(f);
}

