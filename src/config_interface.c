#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/config.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <linux/hdlc.h>
#include <linux/if_arp.h>
#include <linux/mii.h>

#include <librouter/options.h>
#include <librouter/usb.h>
#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"
#include <librouter/device.h>
#include "../../cish/util/backupd.h" /*FIXME*/
#ifdef OPTION_MODEM3G
#include <librouter/modem3G.h>
#endif

extern int _cish_booting;

dev_family *interface_edited;
int interface_major = -1;
int interface_minor = -1;

void config_interface_done(const char *cmdline)
{
	command_root=CMD_CONFIGURE;
	interface_major = -1;
	interface_minor = -1;
}

int validate_interface_minor(void)
{
	switch(interface_edited->type) {
		case eth:
			if(librouter_vlan_exists(interface_major, interface_minor))
				return 0; // ok
			break;
		default:
			break;
	}
	return -1; // subinterface invalida
}

void config_interface(const char *cmdline) /* [no] interface <device> <sub> */
{
	arglist *args;
	int no=0;
	char *major, *minor, *dev;
	char device[32], sub[16];

	args=librouter_make_args(cmdline);
	if (strcmp(args->argv[0], "no") == 0)
		no=1;
	strncpy(device, args->argv[no ? 2 : 1], 31);
	device[31]=0;
	strncpy(sub, args->argv[no ? 3 : 2], 15);
	sub[15]=0;
	librouter_destroy_args(args);

	if ((interface_edited=librouter_device_get_family_by_name(device, str_cish))) {

		major=sub;
		minor=strchr(major, '.');
		if (minor) *minor++ = 0;
		interface_major=atoi(major);
		if (minor)
		{
			interface_minor=atoi(minor);
			if (validate_interface_minor() < 0)
			{
				fprintf(stderr, "%% Invalid interface number.\n");
				return;
			}
		} else {
			interface_minor = -1;
		}

		switch(interface_edited->type) {
			case eth:
				if (interface_minor == -1) {
					command_root=CMD_CONFIG_INTERFACE_ETHERNET;
				} else {
					command_root=CMD_CONFIG_INTERFACE_ETHERNET_VLAN;
				}
				break;
			case lo:
				command_root=CMD_CONFIG_INTERFACE_LOOPBACK;
				break;
			case tun:
				dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
				if (no) {
					librouter_tunnel_del(dev);
				} else {
					librouter_tunnel_add(dev);
					command_root=CMD_CONFIG_INTERFACE_TUNNEL;
				}
				free(dev);
				break;
#ifdef OPTION_MODEM3G
			case ppp:
				if (interface_major == 0)
					command_root=CMD_CONFIG_INTERFACE_M3G_BTIN;
				else
					command_root=CMD_CONFIG_INTERFACE_M3G_USB;
				break;
#endif
			default:
				break;
		}
	}
	else {
		fprintf(stderr, "%% Unknown device type.\n");
	}
}



void interface_txqueue(const char *cmdline)
{
	arglist *args;
	int val;
	char *dev;

	args=librouter_make_args(cmdline);
	val = atoi(args->argv[1]);
#if 0 /* Use value from command definition! */
	if ((val<2) || (val>256))
	{
		librouter_destroy_args (args);
		fprintf (stderr, "%% Value way out of bounds\n");
		return;
	}
#endif
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_dev_set_qlen(dev, val);
	librouter_destroy_args(args);
	free(dev);
}

void interface_description(const char *cmd)
{
	char *description, *dev;

	dev=librouter_device_convert (interface_edited->cish_string, interface_major, interface_minor);
	description = (char *) cmd;
	while (*description == ' ') ++description;
	description = strchr (description, ' ');
	if (!description) return;
	while (*description == ' ') ++description;
	librouter_dev_add_description(dev, description);
	free(dev);
}

void interface_no_description(const char *cmd)
{
	char *dev;

	dev=librouter_device_convert (interface_edited->cish_string, interface_major, interface_minor);
	librouter_dev_del_description(dev);
	free(dev);
}

void interface_mtu(const char *cmdline)
{
	arglist *args;
	int val;
	char *dev;

	args = librouter_make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = librouter_device_convert (interface_edited->cish_string, interface_major, interface_minor);
	librouter_dev_set_mtu(dev, val);
	librouter_destroy_args(args);
	free(dev);
}

void interface_shutdown(const char *cmdline) /* shutdown */
{
	char *dev;

	dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);

	librouter_qos_tc_remove_all(dev);

	if (strstr(dev,"ppp") != NULL){
		/* [interface_major+1] devido a numeração do arquivo começar em 1 e nao em 0 */
		if (!librouter_usb_device_is_modem(interface_major+1)){
			printf("\n%% The interface is not connected or is not a modem");
			printf("\n%% Settings couldn't be applied at this moment\n\n");
		}

	}

	librouter_dev_set_link_down(dev);

	free(dev);
}

void interface_no_shutdown(const char *cmdline) /* no shutdown */
{
	char *dev;
	dev_family *fam;

	dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	fam = librouter_device_get_family_by_name(interface_edited->cish_string, str_cish);

	if (strstr(dev,"ppp") != NULL){
		/* [interface_major+1] devido a numeração do arquivo começar em 1 e nao em 0 */
		if (!librouter_usb_device_is_modem(interface_major+1)){
			printf("\n%% The interface is not connected or is not a modem");
			printf("\n%% Settings couldn't be applied at this moment\n\n");
		}

	}


	librouter_dev_set_link_up(dev); /* UP */

	if (fam) {
		switch(fam->type) {
			case eth:
				librouter_udhcpd_reload(interface_major); /* dhcp integration! force reload ethernet address */
				librouter_qos_tc_insert_all(dev);
				break;
			default:
				break;
		}
	}

	free(dev);
#ifdef OPTION_SMCROUTE
	librouter_smc_route_hup();
#endif
}

/*
 * Interface generic ([no] ip address)
 */
void interface_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	args=librouter_make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	librouter_ip_interface_set_addr(dev, addr, mask); /* preserve alias addresses */
	librouter_destroy_args(args);
	free(dev);
}

void interface_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	args=librouter_make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	librouter_ip_interface_set_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	args=librouter_make_args(cmdline);
	addr=args->argv[3];
	mask=args->argv[4];
	librouter_ip_interface_set_no_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_ip_interface_set_no_addr(dev);
	free(dev);
}

void interface_ethernet_ipaddr_dhcp (const char *cmdline) /* ip address dhcp */
{
	char *dev, daemon_dhcpc[32];

	dev = librouter_device_convert (interface_edited->cish_string, interface_major,
	                interface_minor);
	sprintf (daemon_dhcpc, DHCPC_DAEMON, dev);
	librouter_exec_daemon (daemon_dhcpc); /* inittab: #i:34:respawn:/bin/udhcpc -i ethernet0 >/dev/null 2>/dev/null */
	free (dev);
}

void interface_ethernet_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;
	ppp_config cfg;
	char daemon_dhcpc[32];

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (librouter_exec_check_daemon(daemon_dhcpc))
		librouter_kill_daemon(daemon_dhcpc); /* !!! dhcp x ppp unumbered */

	args=librouter_make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	librouter_ip_ethernet_set_addr(dev, addr, mask); /* preserve alias addresses */

	// Verifica se o ip unnumbered relaciona a ethernet com a serial
	librouter_ppp_get_config(0, &cfg); // Armazena em cfg a configuracao da serial
	if (cfg.ip_unnumbered == interface_major) {
		strncpy(cfg.ip_addr, addr, 16); // Atualiza cfg com os dados da ethernet
		cfg.ip_addr[15]=0;
		strncpy(cfg.ip_mask, mask, 16);
		cfg.ip_mask[15]=0;
		librouter_ppp_set_config(0, &cfg); // Atualiza as configuracoes da serial
	}

	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	args=librouter_make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	librouter_ip_ethernet_set_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	args=librouter_make_args(cmdline);
	addr=args->argv[3];
	mask=args->argv[4];
	librouter_ip_ethernet_set_no_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;
	char daemon_dhcpc[32];

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (librouter_exec_check_daemon(daemon_dhcpc))
		librouter_kill_daemon(daemon_dhcpc);
	librouter_ip_ethernet_set_no_addr(dev);
	free(dev);
}

void interface_fec_cfg(const char *cmdline) /* speed 10|100 half|full */
{
	char *dev;
	arglist *args;
	int speed100 = -1, duplex = -1;

	args = librouter_make_args(cmdline);
	if(args->argc == 3) {
		if ((dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor))) {
			if (strncmp(dev, "ethernet", 8) == 0) {
				/* Speed */
				if(strcmp(args->argv[1], "10") == 0)
					speed100 = 0;
				else if(strcmp(args->argv[1], "100") == 0)
					speed100 = 1;
				/* Duplex */
				if(strcmp(args->argv[2], "half") == 0)
					duplex = 0;
				else if(strcmp(args->argv[2], "full") == 0)
					duplex = 1;
				if(speed100 < 0 || duplex < 0)
					printf("%% Sintax error!\n");
				else {
					if(librouter_fec_config_link(dev, speed100, duplex) < 0)
						printf("%% Not possible to set PHY parameters\n");
				}
			}
			free(dev);
		}
	}
	librouter_destroy_args(args);
}

void interface_fec_autonegotiation(const char *cmdline) /* speed auto */
{
	char *dev;

#ifdef CONFIG_ROOT_NFS
	if (_cish_booting)
		return;
#endif
	if ((dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor))) {
		if (strncmp(dev, "ethernet", 8) == 0) {
			if(librouter_fec_autonegotiate_link(dev) < 0)
				printf("%% Not possible to set PHY parameters\n");
		}
		free(dev);
	}
}

#ifdef CONFIG_HDLC_SPPP
void interface_sppp_ipaddr(const char *cmdline) /* ip address [local] [remote] [mask] */
{
	arglist *args;
	char *local, *remote, *dev, *mask;

	args=librouter_make_args(cmdline);
	local=args->argv[2];
	remote=args->argv[3];
	if (args->argc > 4) mask=args->argv[4];
		else mask=NULL;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_ip_addr_flush(dev);
	ip_addr_add(dev, local, remote, mask ? mask : "255.255.255.255");
	librouter_destroy_args(args);
	free(dev);
}
#endif

/*
 * Used with PD3 implementation of TBF for Frame-Relay ()
 */
#ifdef CONFIG_HDLC_FR
void interface_traffic_rate_no(const char *cmdline) /* no frame-relay traffic-rate */
{
	char *dev;

	dev=librouter_device_convert (interface_edited->cish_string, interface_major, interface_minor);
	librouter_qos_del_frts_config(dev);
	librouter_qos_tc_insert_all(dev);
	free(dev);
}
#endif

/*
 * Tunnel related functions
 */
void tunnel_destination(const char *cmdline) /* [no] tunnel destination <ipaddress> */
{
	arglist *args;
	char *dev;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_tunnel_change(dev, TUNNEL_DESTINATION, NULL);
	} else {
		librouter_tunnel_change(dev, TUNNEL_DESTINATION, args->argv[2]);
	}
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_key(const char *cmdline) /* [no] tunnel key <key> */
{
	arglist *args;
	char *dev;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_tunnel_change(dev, TUNNEL_KEY, NULL);
	} else {
		librouter_tunnel_change(dev, TUNNEL_KEY, args->argv[2]);
	}
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_mode(const char *cmdline) /* tunnel mode gre|ipip */
{
	arglist *args;
	char *dev;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[2], "gre") == 0) {
		librouter_tunnel_mode(dev, IPPROTO_GRE);
	} else if (strcmp(args->argv[2], "ipip") == 0) {
		librouter_tunnel_mode(dev, IPPROTO_IPIP);
	}
	/* TODO: pptp l2tp ipsec ipsec-l2tp */
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_source_interface(const char *cmdline) /* tunnel source <intf> <sub> */
{
	arglist *args;
	char *dev, source[32];

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	strncpy(source, args->argv[2], 31);
	strncat(source, args->argv[3], 31);
	if (strcmp(dev, source) == 0) {
		fprintf(stderr, "%% Cannot use self\n");
	} else {
		librouter_tunnel_change(dev, TUNNEL_SOURCE_INTERFACE, source);
	}
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_source(const char *cmdline) /* [no] tunnel source <ipaddress> */
{
	arglist *args;
	char *dev;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_tunnel_change(dev, TUNNEL_SOURCE, NULL);
	} else {
		librouter_tunnel_change(dev, TUNNEL_SOURCE, args->argv[2]);
	}
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_checksum(const char *cmdline) /* [no] tunnel checksum */
{
	arglist *args;
	char *dev;
	int i;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_tunnel_change(dev, TUNNEL_CHECKSUM, NULL);
	} else {
		librouter_tunnel_change(dev, TUNNEL_CHECKSUM, &i);
	}
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_pmtu(const char *cmdline) /* [no] tunnel path-mtu-discovery */
{
	arglist *args;
	char *dev;
	int i;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_tunnel_change(dev, TUNNEL_PMTU, NULL);
	} else {
		librouter_tunnel_change(dev, TUNNEL_PMTU, &i);
	}
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_sequence(const char *cmdline) /* [no] tunnel sequence-datagrams */
{
	arglist *args;
	char *dev;
	int i;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_tunnel_change(dev, TUNNEL_SEQUENCE, NULL);
	} else {
		librouter_tunnel_change(dev, TUNNEL_SEQUENCE, &i);
	}
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_ttl(const char *cmdline) /* [no] tunnel ttl <0-255> */
{
	arglist *args;
	char *dev;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		librouter_tunnel_change(dev, TUNNEL_TTL, NULL);
	} else {
		librouter_tunnel_change(dev, TUNNEL_TTL, args->argv[2]);
	}
	free(dev);
	librouter_destroy_args(args);
}

#ifdef CONFIG_NET_IPGRE_KEEPALIVE
void tunnel_keepalive(const char *cmdline) /* [no] keepalive <0-255> <0-255> */
{
	arglist *args;
	char *dev;

	args=librouter_make_args(cmdline);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel_kp(dev, 0, 0);
	} else {
		change_tunnel_kp(dev, atoi(args->argv[1]), atoi(args->argv[2]));
	}
	free(dev);
	librouter_destroy_args(args);
}
#endif

/*
 * QoS related functions
 */

void do_bandwidth(const char *cmdline)
{
	char *dev;
	arglist *args;
	unsigned int bw=0;

	args = librouter_make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		librouter_destroy_args(args);
		return;
	}

	/* Check if it is bps, kbps or mbps */
	bw = atoi(args->argv[1]);
	if (strcasestr(args->argv[1],"kbps")) bw *= 1024;
	else if (strcasestr(args->argv[1],"mbps")) bw *= 1048576;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_qos_config_interface_bw(dev, bw);
	free(dev);
	librouter_destroy_args(args);
	return;
}

void do_max_reserved_bw(const char *cmdline)
{
	char *dev;
	arglist *args;
	unsigned char reserved_bw=0;

	args = librouter_make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		librouter_destroy_args(args);
		return;
	}

	reserved_bw = atoi(args->argv[1]);
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_qos_config_reserved_bw(dev, reserved_bw);
	free(dev);
	return;
}

void do_service_policy(const char *cmdline)
{
	char *dev;
	arglist *args;
	args = librouter_make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		librouter_destroy_args(args);
		return;
	}
	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_qos_apply_policy(dev,args->argv[1]);
	free(dev);
	return;
}

void no_service_policy(const char *cmdline)
{
	char *dev;
	intf_qos_cfg_t *intf_cfg;

	dev=librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_qos_get_interface_config (dev, &intf_cfg);
	if (intf_cfg)
		intf_cfg->pname[0] = 0; /* clean policy-map */
	librouter_qos_release_config(intf_cfg);
	librouter_qos_tc_insert_all(dev);
	free(dev);
	return;
}

/*
 * SNMP related functions
 */
void interface_snmptrap(const char *cmd)
{
	char *dev;

	if ((dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor)))
	{
		if (!strncmp(dev, "aux", 3) || !strncmp(dev, "ethernet", 8) || !strncmp(dev, "serial", 6))
			librouter_snmp_add_dev_trap(dev);
		free(dev);
	}
}

void interface_no_snmptrap(const char *cmd)
{
	char *dev;

	if ((dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor)))
	{
		if (!strncmp(dev, "aux", 3) || !strncmp(dev, "ethernet", 8) || !strncmp(dev, "serial", 6))
			librouter_snmp_del_dev_trap(dev);
		free(dev);
	}
}

#if 0 //#ifdef CONFIG_DEVELOPMENT
void interface_rxring(const char *cmdline) /* rxring <2-2048> */
{
	arglist *args;
	int val;
	char *dev;

	args = librouter_make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_dev_set_rxring(dev, val);
	librouter_destroy_args(args);
	free(dev);
}

void interface_txring(const char *cmdline) /* txring <2-2048> */
{
	arglist *args;
	int val;
	char *dev;

	args = librouter_make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	librouter_dev_set_txring(dev, val);
	librouter_destroy_args(args);
	free(dev);
}

void interface_weight(const char *cmdline) /* weight <2-1024> */
{
	arglist *args;
	int val;
	char *dev;

	args = librouter_make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = librouter_device_convert(interface_edited->cish_string, interface_major, interface_minor);

	if (wan_get_protocol(interface_major) == SCC_PROTO_MLPPP) {
		dev = (char *)malloc(2+1+1);
		sprintf(dev, "%s%d", SERIALDEV_PPP, interface_major); /* 'sx?' */
	} else
		librouter_dev_set_weight(dev, val);
	librouter_destroy_args(args);
	free(dev);
}
#endif

#ifdef OPTION_MODEM3G
void interface_modem3g_set_apn(const char *cmdline){

	arglist * args;
	int check = -1;
	char * apn = NULL;

	args = librouter_make_args(cmdline);
	apn = args->argv[2];

	check = librouter_modem3g_set_apn(apn, interface_major);

	if (check == -1)
		printf("%% Error on set APN\n");
#ifdef DEBUG_M3G
	else
		printf("\nAPN stored\n\n");
#endif

	librouter_destroy_args(args);

	apn=NULL;
}

void interface_modem3g_set_password(const char *cmdline){

	arglist * args;
	int check = -1;
	char * password = NULL;

	args = librouter_make_args(cmdline);

	password = args->argv[2];

	check = librouter_modem3g_set_password(password, interface_major);

	if (check == -1)
		printf("%% Error on set password\n");
#ifdef DEBUG_M3G
	else
		printf("\nPassword stored\n\n");
#endif

	librouter_destroy_args(args);

	password=NULL;
}

void interface_modem3g_set_username(const char *cmdline){

	arglist * args;
	int check = -1;
	char * username=NULL;

	args = librouter_make_args(cmdline);

	username = args->argv[2];

	check = librouter_modem3g_set_username(username, interface_major);

	if (check == -1)
		printf("%% Error on set username\n");
#ifdef DEBUG_M3G
	else
		printf("\nUsername stored\n\n");
#endif

	librouter_destroy_args(args);

	username=NULL;
}

void backup_interface_shutdown(const char *cmdline){

 	char * interface = malloc(24);
 	int check = -1;

 	snprintf(interface,24,"%s%d", interface_edited->linux_string,interface_major);

 	check = librouter_ppp_backupd_set_param_infile(interface,SHUTD_STR,"yes");
 	if (check < 0){
 		printf("%% Error on set backup interface shutdown\n");
 		goto end;
 	}

 	check = librouter_ppp_backupd_set_param_infile(interface,BCKUP_STR,"no");
 	if (check < 0){
 		printf("%% Error on set backup interface shutdown\n");
 		goto end;
 	}

 	check = librouter_ppp_backupd_set_param_infile(interface,MAIN_INTF_STR,"");
 	if (check < 0){
 		printf("%% Error on set backup interface shutdown\n");
 		goto end;
 	}

   	check = librouter_ppp_reload_backupd();
 	if (check < 0){
 		printf("%% Error on set backup interface shutdown - (reload configs)\n");
 		goto end;
 	}

end:
	free (interface);
}

void backup_interface(const char *cmdline){

 	arglist * args;
 	char * main_interface = malloc(24);
 	char * interface = malloc(24);
 	char * intf_return = malloc(24);
 	int check = -1;
 	args = librouter_make_args(cmdline);

 	main_interface = args->argv[1];
 	strcat(main_interface,args->argv[2]);
 	snprintf(interface,24,"%s%d", interface_edited->linux_string,interface_major);

 	if ( !librouter_ppp_backupd_verif_param_infile(MAIN_INTF_STR,main_interface, intf_return) ){
 		check = librouter_ppp_backupd_set_param_infile(interface,BCKUP_STR,"yes");
 		if (check < 0){
 			printf("%% Error on set backup interface\n");
 			goto end;
 		}
 		check = librouter_ppp_backupd_set_param_infile(interface,MAIN_INTF_STR,main_interface);
 		if (check < 0){
 			printf("%% Error on set backup interface\n");
 			goto end;
 		}
 		check = librouter_ppp_reload_backupd();
 		if (check < 0){
 			printf("%% Error on set backup interface - (reload configs.)\n");
 			goto end;
 		}
 	}
 	else{
 		printf("\n%% The interface is already with a backup connection by %s", intf_return);
 		printf("%% Settings could not be applied\n\n");
 	}


end:
 	main_interface = NULL;
 	interface = NULL;
 	intf_return = NULL;
 	librouter_destroy_args(args);
 	free (main_interface);
 	free (interface);
 	free (intf_return);
 }

void backup_method_set_ping (const char *cmdline){

	arglist * args;
	char * interface = malloc(24);
	char * ping=NULL;
	int check = -1;

	args = librouter_make_args(cmdline);
	ping = args->argv[2];

 	snprintf(interface,24,"%s%d", interface_edited->linux_string,interface_major);

	if ( !librouter_ppp_backupd_verif_param_byintf_infile(interface, BCKUP_STR, "yes") ){

		check = librouter_ppp_backupd_set_param_infile(interface,METHOD_STR,"ping");
		if (check < 0){
			printf("%% Error on set backup method - ping\n");
			goto end;
		}
		check = librouter_ppp_backupd_set_param_infile(interface,PING_ADDR_STR,ping);
		if (check < 0){
			printf("%% Error on set backup method - ping\n");
			goto end;
		}
		check = librouter_ppp_reload_backupd();
		if (check < 0){
			printf("%% Error on set backup method - ping - (reload configs.)\n");
			goto end;
		}
	}
	else{
		printf("\n%% The interface is already backing up");
		printf("\n%% It is necessary to shutdown backup first");
		printf("\n%% Settings could not be applied\n\n");
	}

end:
	librouter_destroy_args(args);
 	ping=NULL;
 	interface = NULL;
 	free(interface);
}

void backup_method_set_link (const char *cmdline){

	int check = -1;
	char * interface = malloc(24);

	snprintf(interface,24,"%s%d", interface_edited->linux_string,interface_major);

	if ( !librouter_ppp_backupd_verif_param_byintf_infile(interface,BCKUP_STR, "yes") ){

		check = librouter_ppp_backupd_set_param_infile(interface,METHOD_STR,"link");
		if (check < 0){
			printf("%% Error on set backup method - link\n");
			goto end;
		}
		check = librouter_ppp_backupd_set_param_infile(interface,PING_ADDR_STR,"");
		if (check < 0){
			printf("%% Error on set backup method - link\n");
			goto end;
		}
		check = librouter_ppp_reload_backupd();
		if (check < 0){
			printf("%% Error on set backup method - link - (reload configs.)\n");
			goto end;
		}
	}
	else{
		printf("\n%% The interface is already backing up");
		printf("\n%% It is necessary to shutdown backup first");
		printf("\n%% Settings could not be applied\n\n");
	}

end:
	interface=NULL;
	free(interface);


}


void interface_modem3g_sim_card_select(const char *cmdline){
	arglist * args;
	int main_intf = -1;
	int backup_intf = -1;
	struct sim_conf * sim = malloc(sizeof(struct sim_conf));

	args = librouter_make_args(cmdline);
	main_intf = atoi(args->argv[1]);
	backup_intf = atoi(args->argv[2]);

	if (main_intf == backup_intf){
		printf("\n%% Wrong input - same SIM card for <MAIN> interface and <BACKUP> interface");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	sim->sim_num = main_intf;

	if(librouter_modem3g_sim_set_order(sim->sim_num) < 0){
		printf("%% Error on set SIM card order\n");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if(librouter_modem3g_sim_get_info_fromfile(sim) < 0){
		printf("%% Error on set SIM card order - retrieving information\n");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if(!strcmp(sim->apn,"")){
		printf("\n%% Missing APN address");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if(librouter_modem3g_set_all_info(sim,interface_major) <0){
		printf("\n%% Error on set configuration");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if(librouter_modem3g_sim_set_card(sim->sim_num) < 0){
		printf("\n%% Error on set SIM card");
		printf("\n%% Settings could not be applied\n\n");
	}

end:
	librouter_destroy_args(args);
	if (sim)
		free(sim);
}

void interface_modem3g_btin_set_info(const char *cmdline){
	arglist * args;
	int check = -1;
	int sim;
	char * value = NULL;
	char * field = NULL;

	args = librouter_make_args(cmdline);

	sim = atoi(args->argv[1]);
	field = args->argv[2];
	value = args->argv[4];


	check = librouter_modem3g_sim_set_info_infile(sim, field, value);

	if (check == -1)
		printf("%% Error on set %s\n",field);
#ifdef DEBUG_M3G
	else
		printf("\n%s stored\n\n",field);
#endif

	librouter_destroy_args(args);
	value = NULL;
	field = NULL;
}


#endif
