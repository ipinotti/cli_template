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

#include "options.h"
#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"
#include "device.h"


extern int _cish_booting;

device_family *interface_edited;
int interface_major, interface_minor;

void config_interface_done(const char *cmdline)
{
	command_root=CMD_CONFIGURE;
}

int validate_interface_minor(void)
{
	switch(interface_edited->type) {
		case eth:
			if(vlan_exists(interface_major, interface_minor))
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

	args=make_args(cmdline);
	if (strcmp(args->argv[0], "no") == 0)
		no=1;
	strncpy(device, args->argv[no ? 2 : 1], 31);
	device[31]=0;
	strncpy(sub, args->argv[no ? 3 : 2], 15);
	sub[15]=0;
	destroy_args(args);

	if ((interface_edited=getfamily(device))) {

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
				dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
				if (no) {
					del_tunnel(dev);
				} else {
					add_tunnel(dev);
					command_root=CMD_CONFIG_INTERFACE_TUNNEL;
				}
				free(dev);
				break;
#ifdef OPTION_MODEM3G
			case ppp:
				command_root=CMD_CONFIG_INTERFACE_M3G;
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

	args=make_args(cmdline);
	val = atoi(args->argv[1]);
#if 0 /* Use value from command definition! */
	if ((val<2) || (val>256))
	{
		destroy_args (args);
		fprintf (stderr, "%% Value way out of bounds\n");
		return;
	}
#endif
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	dev_set_qlen(dev, val);
	destroy_args(args);
	free(dev);
}

void interface_description(const char *cmd)
{
	char *description, *dev;

	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	description = (char *) cmd;
	while (*description == ' ') ++description;
	description = strchr (description, ' ');
	if (!description) return;
	while (*description == ' ') ++description;
	dev_add_description(dev, description);
	free(dev);
}

void interface_no_description(const char *cmd)
{
	char *dev;

	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	dev_del_description(dev);
	free(dev);
}

void interface_mtu(const char *cmdline)
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);
	dev_set_mtu(dev, val);
	destroy_args(args);
	free(dev);
}

void interface_shutdown(const char *cmdline) /* shutdown */
{
	char *dev;

	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);

	tc_remove_all(dev);

	dev_set_link_down(dev);

	free(dev);
}

void interface_no_shutdown(const char *cmdline) /* no shutdown */
{
	char *dev;
	device_family *fam;

	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	fam = getfamily(interface_edited->cish_string);

	dev_set_link_up(dev); /* UP */

	if (fam) {
		switch(fam->type) {
			case eth:
				reload_udhcpd(interface_major); /* dhcp integration! force reload ethernet address */
				tc_insert_all(dev);
				break;
			default:
				break;
		}
	}

	free(dev);
#ifdef OPTION_SMCROUTE
	lconfig_smcroute_hup();
#endif
}

/*
 * Interface generic ([no] ip address)
 */
void interface_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_interface_ip_addr(dev, addr, mask); /* preserve alias addresses */
	destroy_args(args);
	free(dev);
}

void interface_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_interface_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[3];
	mask=args->argv[4];
	set_interface_no_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	set_interface_no_ip_addr(dev);
	free(dev);
}

void interface_ethernet_ipaddr_dhcp (const char *cmdline) /* ip address dhcp */
{
	char *dev, daemon_dhcpc[32];

	dev = convert_device (interface_edited->cish_string, interface_major,
	                interface_minor);
	sprintf (daemon_dhcpc, DHCPC_DAEMON, dev);
	exec_daemon (daemon_dhcpc); /* inittab: #i:34:respawn:/bin/udhcpc -i ethernet0 >/dev/null 2>/dev/null */
	free (dev);
}

void interface_ethernet_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;
	ppp_config cfg;
	char daemon_dhcpc[32];

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (is_daemon_running(daemon_dhcpc))
		kill_daemon(daemon_dhcpc); /* !!! dhcp x ppp unumbered */

	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_ethernet_ip_addr(dev, addr, mask); /* preserve alias addresses */

	// Verifica se o ip unnumbered relaciona a ethernet com a serial
	ppp_get_config(0, &cfg); // Armazena em cfg a configuracao da serial
	if (cfg.ip_unnumbered == interface_major) {
		strncpy(cfg.ip_addr, addr, 16); // Atualiza cfg com os dados da ethernet
		cfg.ip_addr[15]=0;
		strncpy(cfg.ip_mask, mask, 16);
		cfg.ip_mask[15]=0;
		ppp_set_config(0, &cfg); // Atualiza as configuracoes da serial
	}

	destroy_args(args);
	free(dev);
}

void interface_ethernet_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[2];
	mask=args->argv[3];
	set_ethernet_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	addr=args->argv[3];
	mask=args->argv[4];
	set_ethernet_no_ip_addr_secondary(dev, addr, mask);
	destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;
	char daemon_dhcpc[32];

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (is_daemon_running(daemon_dhcpc))
		kill_daemon(daemon_dhcpc);
	set_ethernet_no_ip_addr(dev);
	free(dev);
}

void interface_fec_cfg(const char *cmdline) /* speed 10|100 half|full */
{
	char *dev;
	arglist *args;
	int speed100 = -1, duplex = -1;

	args = make_args(cmdline);
	if(args->argc == 3) {
		if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor))) {
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
					if(fec_config_link(dev, speed100, duplex) < 0)
						printf("%% Not possible to set PHY parameters\n");
				}
			}
			free(dev);
		}
	}
	destroy_args(args);
}

void interface_fec_autonegotiation(const char *cmdline) /* speed auto */
{
	char *dev;

#ifdef CONFIG_ROOT_NFS
	if (_cish_booting)
		return;
#endif
	if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor))) {
		if (strncmp(dev, "ethernet", 8) == 0) {
			if(fec_autonegotiate_link(dev) < 0)
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

	args=make_args(cmdline);
	local=args->argv[2];
	remote=args->argv[3];
	if (args->argc > 4) mask=args->argv[4];
		else mask=NULL;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	ip_addr_flush(dev);
	ip_addr_add(dev, local, remote, mask ? mask : "255.255.255.255");
	destroy_args(args);
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

	dev=convert_device (interface_edited->cish_string, interface_major, interface_minor);
	del_frts_cfg(dev);
	tc_insert_all(dev);
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

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, destination, NULL);
	} else {
		change_tunnel(dev, destination, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_key(const char *cmdline) /* [no] tunnel key <key> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, key, NULL);
	} else {
		change_tunnel(dev, key, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_mode(const char *cmdline) /* tunnel mode gre|ipip */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[2], "gre") == 0) {
		mode_tunnel(dev, IPPROTO_GRE);
	} else if (strcmp(args->argv[2], "ipip") == 0) {
		mode_tunnel(dev, IPPROTO_IPIP);
	}
	/* TODO: pptp l2tp ipsec ipsec-l2tp */
	free(dev);
	destroy_args(args);
}

void tunnel_source_interface(const char *cmdline) /* tunnel source <intf> <sub> */
{
	arglist *args;
	char *dev, source[32];

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	strncpy(source, args->argv[2], 31);
	strncat(source, args->argv[3], 31);
	if (strcmp(dev, source) == 0) {
		fprintf(stderr, "%% Cannot use self\n");
	} else {
		change_tunnel(dev, source_interface, source);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_source(const char *cmdline) /* [no] tunnel source <ipaddress> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, source, NULL);
	} else {
		change_tunnel(dev, source, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_checksum(const char *cmdline) /* [no] tunnel checksum */
{
	arglist *args;
	char *dev;
	int i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, checksum, NULL);
	} else {
		change_tunnel(dev, checksum, &i);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_pmtu(const char *cmdline) /* [no] tunnel path-mtu-discovery */
{
	arglist *args;
	char *dev;
	int i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, pmtu, NULL);
	} else {
		change_tunnel(dev, pmtu, &i);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_sequence(const char *cmdline) /* [no] tunnel sequence-datagrams */
{
	arglist *args;
	char *dev;
	int i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, sequence, NULL);
	} else {
		change_tunnel(dev, sequence, &i);
	}
	free(dev);
	destroy_args(args);
}

void tunnel_ttl(const char *cmdline) /* [no] tunnel ttl <0-255> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel(dev, ttl, NULL);
	} else {
		change_tunnel(dev, ttl, args->argv[2]);
	}
	free(dev);
	destroy_args(args);
}

#ifdef CONFIG_NET_IPGRE_KEEPALIVE
void tunnel_keepalive(const char *cmdline) /* [no] keepalive <0-255> <0-255> */
{
	arglist *args;
	char *dev;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel_kp(dev, 0, 0);
	} else {
		change_tunnel_kp(dev, atoi(args->argv[1]), atoi(args->argv[2]));
	}
	free(dev);
	destroy_args(args);
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

	args = make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		destroy_args(args);
		return;
	}

	/* Check if it is bps, kbps or mbps */
	bw = atoi(args->argv[1]);
	if (strcasestr(args->argv[1],"kbps")) bw *= 1024;
	else if (strcasestr(args->argv[1],"mbps")) bw *= 1048576;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	cfg_interface_bw(dev, bw);
	free(dev);
	destroy_args(args);
	return;
}

void do_max_reserved_bw(const char *cmdline)
{
	char *dev;
	arglist *args;
	unsigned char reserved_bw=0;

	args = make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		destroy_args(args);
		return;
	}

	reserved_bw = atoi(args->argv[1]);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	cfg_interface_reserved_bw(dev, reserved_bw);
	free(dev);
	return;
}

void do_service_policy(const char *cmdline)
{
	char *dev;
	arglist *args;
	args = make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		destroy_args(args);
		return;
	}
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	apply_policy(dev,args->argv[1]);
	free(dev);
	return;
}

void no_service_policy(const char *cmdline)
{
	char *dev;
	intf_qos_cfg_t *intf_cfg;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	get_interface_qos_config (dev, &intf_cfg);
	if (intf_cfg)
		intf_cfg->pname[0] = 0; /* clean policy-map */
	release_qos_config(intf_cfg);
	tc_insert_all(dev);
	free(dev);
	return;
}

/*
 * SNMP related functions
 */
void interface_snmptrap(const char *cmd)
{
	char *dev;

	if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor)))
	{
		if (!strncmp(dev, "aux", 3) || !strncmp(dev, "ethernet", 8) || !strncmp(dev, "serial", 6))
			dev_add_snmptrap(dev);
		free(dev);
	}
}

void interface_no_snmptrap(const char *cmd)
{
	char *dev;

	if ((dev = convert_device(interface_edited->cish_string, interface_major, interface_minor)))
	{
		if (!strncmp(dev, "aux", 3) || !strncmp(dev, "ethernet", 8) || !strncmp(dev, "serial", 6))
			dev_del_snmptrap(dev);
		free(dev);
	}
}

#if 0 //#ifdef CONFIG_DEVELOPMENT
void interface_rxring(const char *cmdline) /* rxring <2-2048> */
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	dev_set_rxring(dev, val);
	destroy_args(args);
	free(dev);
}

void interface_txring(const char *cmdline) /* txring <2-2048> */
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	dev_set_txring(dev, val);
	destroy_args(args);
	free(dev);
}

void interface_weight(const char *cmdline) /* weight <2-1024> */
{
	arglist *args;
	int val;
	char *dev;

	args = make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);

	if (wan_get_protocol(interface_major) == SCC_PROTO_MLPPP) {
		dev = (char *)malloc(2+1+1);
		sprintf(dev, "%s%d", SERIALDEV_PPP, interface_major); /* 'sx?' */
	} else
		dev_set_weight(dev, val);
	destroy_args(args);
	free(dev);
}
#endif

#ifdef OPTION_MODEM3G
void interface_modem3g_set_apn(const char *cmdline)
{
	arglist * args;
	int check=0;
	char * apn=NULL;
	char buffer[256]="\"";
	char plus[]="\"'";

	args = make_args(cmdline);
	apn=args->argv[2];

	strcat(buffer,apn);
	strcat(buffer,plus);

	check = modem3g_set_apn(buffer, interface_major);
	if (check == -1){
		printf("Error on set APN\n");
		destroy_args(args);
		apn=NULL;
		return;
	}

#ifdef DEBUG
	printf("\nAPN stored\n\n");
#endif

	destroy_args(args);

	apn=NULL;
}

void interface_modem3g_set_password(const char *cmdline)
{
	arglist * args;
	char * password=NULL;
	int check=0;

	args = make_args(cmdline);

	password = args->argv[2];

	check = modem3g_set_password(password, interface_major);

	if (check == -1){
		printf("Error on set password\n");
		destroy_args(args);
		password=NULL;
		return;
	}

#ifdef DEBUG
	printf("\nPassword stored\n\n");
#endif

	destroy_args(args);

	password=NULL;
}

void interface_modem3g_set_username(const char *cmdline)
{
	arglist * args;
	char * username=NULL;
	int check=0;

	args = make_args(cmdline);

	username = args->argv[2];

	check = modem3g_set_username(username, interface_major);

	if (check == -1){
		printf("Error on set username\n");
		destroy_args(args);
		username=NULL;
		return;
	}

#ifdef DEBUG
	printf("\nUsername stored\n\n");
#endif

	destroy_args(args);

	username=NULL;
}
#endif
