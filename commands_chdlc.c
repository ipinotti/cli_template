#include "commands.h"
#include "commandtree.h"
#include <libconfig/args.h>
#include <libconfig/device.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <linux/hdlc.h>
#include <stdlib.h>

#include <libconfig/typedefs.h>
#include <libconfig/chdlc.h>

extern int interface_major, interface_minor;

void chdlc_keepalive_interval(const char *cmd)
{
	arglist *args;
	cisco_proto cisco;
	
	args = make_args (cmd);
	
	chdlc_get_config(interface_major, &cisco);
	cisco.interval = atoi(args->argv[2]);
	chdlc_set_config(interface_major, &cisco);
	
	destroy_args (args);
}

void chdlc_keepalive_timeout(const char *cmd)
{
	arglist *args;
	cisco_proto cisco;
	
	args = make_args (cmd);
	
	chdlc_get_config(interface_major, &cisco);
	cisco.timeout = atoi(args->argv[2]);
	chdlc_set_config(interface_major, &cisco);
	
	destroy_args (args);
}

