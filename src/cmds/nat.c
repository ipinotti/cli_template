#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"

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
