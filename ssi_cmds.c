#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/hdlc.h>
#include <linux/ipx.h>

#include <stdio.h>
#include <stdlib.h>
#include "ssi_cmds.h"
#include <libconfig/args.h>
#include <libconfig/typedefs.h>
#include <libconfig/html-lib.h>
#include <libconfig/ip.h>
#include <libconfig/nv.h>

int ssi_cmd(char *ssi_cmd)
{
	char *html_cmds[] = {
	"hostname", "lan_ip_addr", "product_name"
	};
	
	enum { 
	H_HOSTNAME, H_LAN_IP_ADDR, H_PRODUCT_NAME,
	H_NUM_CMDS };

	int i;
			
	for (i=0; i<H_NUM_CMDS; i++)
	{
		if ( strcmp(html_cmds[i], ssi_cmd) == 0) break;
	}
	
	if (i==H_NUM_CMDS)
	{
		return (-1);
	}
	
	switch (i)
	{
		case H_LAN_IP_ADDR:
		{
			if (get_if_list() < 0) return -1;
			for (i=0; i < link_table_index; i++)
			{
				if (strcmp(link_table[i].ifname, "ethernet0") == 0) /* !!! MU ethernet1 */
				{
					printf(inet_ntoa(ip_addr_table[i].local));
					break;
				}
			}
		}
		break;
		
		case H_HOSTNAME:
		{
			char buf[512];
			gethostname(buf, 512);
			buf[511]=0;
			printf(buf);
		}
		break;
		
		case H_PRODUCT_NAME:
		{
#ifdef I2C_HC08_PRODUCT
			char *buf;
			buf=get_product_name();
			if (buf != NULL) printf(buf);
				else
#endif
					printf("AccessRouter");
		}
		break;
	}
	return 0;
}

