#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"

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
