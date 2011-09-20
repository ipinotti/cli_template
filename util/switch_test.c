/*
 * switch_test.c
 *
 *  Created on: Jul 28, 2011
 *      Author: tgrande
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/types.h>

#include <librouter/ksz8863.h>
#include <librouter/options.h>
#include <librouter/args.h>


int main(int argc, char **argv)
{
#if defined(OPTION_MANAGED_SWITCH) && defined(OPTION_DIGISTAR_EFM)
	int i = 1000;

	struct vlan_config_t vconf;

	while (--i) {
		vconf.membership = KSZ8863REG_VLAN_MEMBERSHIP_PORT1_MSK | KSZ8863REG_VLAN_MEMBERSHIP_PORT2_MSK;
		vconf.vid = 5;

		librouter_ksz8863_add_table(&vconf);
		usleep(10000);
		librouter_ksz8863_del_table(&vconf);
	}
#endif
	exit(0);
}
