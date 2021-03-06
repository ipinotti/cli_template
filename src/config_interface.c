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

#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <linux/hdlc.h>
#include <linux/if_arp.h>
#include <linux/mii.h>

#include <librouter/options.h>
#include <librouter/usb.h>
#include <librouter/ppp.h>
#include <librouter/device.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"

#ifdef OPTION_MODEM3G
#include <librouter/modem3G.h>
#endif

extern int _cish_booting;

dev_family *interface_edited;
int interface_major = -1;
int interface_minor = -1;

#ifdef OPTION_MANAGED_SWITCH
int switch_port = -1;
int switch_port_real = -1;

void config_interface_switch_port_done(const char *cmdline)
{
	switch_port = -1;
	switch_port_real = -1;
	command_root = CMD_CONFIG_INTERFACE_ETHERNET_LAN;
}

void config_interface_switch_port(const char *cmdline)
{
	arglist *args;
	int port;

	args = librouter_make_args(cmdline);

	port = atoi(args->argv[1]);


	if (port < 1 || port > OPTION_SWITCH_PORT_NUM)
	{
		printf("%% Invalid port\n");
		librouter_destroy_args(args);
		return;
	}

	switch_port = port;
#if defined(OPTION_SWITCH_MICREL_KSZ8863)
	switch_port_real = librouter_ksz8863_get_realport_by_aliasport(port);
#elif defined(OPTION_SWITCH_MICREL_KSZ8895)
	switch_port_real = librouter_ksz8895_get_realport_by_aliasport(port);
#elif defined(OPTION_SWITCH_BROADCOM)
	switch_port_real = librouter_bcm53115s_get_realport_by_aliasport(port);
#endif

	command_root = CMD_CONFIG_INTERFACE_ETHERNET_SW_PORT;
}
#endif /* OPTION_MANAGED_SWITCH */

void config_interface_done(const char *cmdline)
{
	command_root = CMD_CONFIGURE;
	interface_major = -1;
	interface_minor = -1;
}

int validate_interface_minor(void)
{
	switch (interface_edited->type) {
	case eth:
#ifdef OPTION_EFM
	case efm:
#endif
		if (librouter_vlan_exists(interface_major, interface_minor))
			return 0;
		break;
	default:
		break;
	}
	return -1; /* Invalid Sub-Interface */
}

void config_interface(const char *cmdline) /* [no] interface <device> <sub> */
{
	arglist *args;
	int no = 0;
	char *major, *minor;
	char device[32], sub[16];
#ifdef OPTION_TUNNEL
	char *dev;
#endif

	args = librouter_make_args(cmdline);
	if (strcmp(args->argv[0], "no") == 0)
		no = 1;
	strncpy(device, args->argv[no ? 2 : 1], 31);
	device[31] = 0;
	strncpy(sub, args->argv[no ? 3 : 2], 15);
	sub[15] = 0;
	librouter_destroy_args(args);

	if ((interface_edited = librouter_device_get_family_by_name(device, str_cish))) {

		major = sub;
		minor = strchr(major, '.');
		if (minor)
			*minor++ = 0;
		interface_major = atoi(major);

		if (minor)
			interface_minor = atoi(minor);
		else
			interface_minor = -1;

		switch (interface_edited->type) {
		case eth:
			switch (interface_major) {
				case 0:
						if (interface_minor == -1)
							command_root = CMD_CONFIG_INTERFACE_ETHERNET_LAN;
						else {
							if (validate_interface_minor() < 0)
								goto subiface_error;
							command_root = CMD_CONFIG_INTERFACE_ETHERNET_VLAN;
						}
						break;

				case 1:
						if (interface_minor == -1)
							command_root = CMD_CONFIG_INTERFACE_ETHERNET_WAN;
						else {
							if (validate_interface_minor() < 0)
								goto subiface_error;
							command_root = CMD_CONFIG_INTERFACE_ETHERNET_VLAN;
						}
						break;
				default:
						goto subiface_error;
						break;
			}
			break;
		case lo:
			if (interface_minor == -1)
				command_root = CMD_CONFIG_INTERFACE_LOOPBACK;
			else
				goto subiface_error;
			break;
#ifdef OPTION_WIFI
		case wlan:
			command_root = CMD_CONFIG_INTERFACE_WLAN;
			break;
#endif
#ifdef OPTION_TUNNEL
		case tun:
			dev = librouter_device_cli_to_linux(interface_edited->cish_string,
			                interface_major, interface_minor);
			if (no) {
				librouter_tunnel_del(dev);
			} else {
				librouter_tunnel_add(dev);
				command_root = CMD_CONFIG_INTERFACE_TUNNEL;
			}
			free(dev);
			break;
#endif
#ifdef OPTION_PPTP
			case pptp:
			command_root = CMD_CONFIG_INTERFACE_PPTP;
			break;
#endif
#ifdef OPTION_PPPOE
			case pppoe:
			command_root = CMD_CONFIG_INTERFACE_PPPOE;
			break;
#endif
#ifdef OPTION_MODEM3G
		case ppp:
#ifdef CONFIG_DIGISTAR_3G
			if (interface_major == 0)
				command_root = CMD_CONFIG_INTERFACE_M3G_BTIN;
			else
#endif
				command_root = CMD_CONFIG_INTERFACE_M3G_USB;
			break;
#endif
#ifdef OPTION_EFM
		case efm:
			interface_major += EFM_INDEX_OFFSET;
			if (interface_minor == -1)
				command_root = CMD_CONFIG_INTERFACE_EFM;
			else {
				if (validate_interface_minor() < 0)
					goto subiface_error;
				command_root = CMD_CONFIG_INTERFACE_EFM_VLAN;
			}
			break;
#endif
		default:
			break;
		}
	} else {
		fprintf(stderr, "%% Unknown device type.\n");
	}

	return;

	subiface_error: fprintf(stderr, "%% Invalid interface number.\n");
	interface_major = -1;
	interface_minor = -1;
	return;
}

#ifdef CONFIG_DEVELOPMENT
void interface_txqueue(const char *cmdline)
{
	arglist *args;
	int val;
	char *dev;

	args = librouter_make_args(cmdline);
	val = atoi(args->argv[1]);

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	librouter_dev_set_qlen(dev, val);
	librouter_destroy_args(args);
	free(dev);
}
#endif

void interface_description(const char *cmd)
{
	char *description, *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	description = (char *) cmd;
	while (*description == ' ')
		++description;
	description = strchr(description, ' ');
	if (!description)
		return;
	while (*description == ' ')
		++description;
	librouter_dev_add_description(dev, description);
	free(dev);
}

void interface_no_description(const char *cmd)
{
	char *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	librouter_dev_set_mtu(dev, val);
	librouter_destroy_args(args);
	free(dev);
}

void interface_shutdown(const char *cmdline) /* shutdown */
{
	char *dev;
	dev_family *fam;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	fam = librouter_device_get_family_by_name(interface_edited->cish_string, str_cish);

	librouter_dev_shutdown(dev, fam);
	free(dev);
}

void interface_no_shutdown(const char *cmdline) /* no shutdown */
{
	char *dev;
	dev_family *fam;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	fam = librouter_device_get_family_by_name(interface_edited->cish_string, str_cish);

	/* Do it ! */
	librouter_dev_noshutdown(dev, fam); /* UP */
	free(dev);
}

/*
 * Interface generic ([no] ip address)
 */
void interface_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	addr = args->argv[2];
	mask = args->argv[3];
	librouter_ip_interface_set_addr(dev, addr, mask); /* preserve alias addresses */
	librouter_destroy_args(args);
	free(dev);
}

/*
 * Interface generic ([no] ipv6 address)
 */
void interface_ipaddr_v6(const char *cmdline) /* ipv6 address <ipv6address> <mask_v6> */
{
	arglist *args;
	char *addr, *mask, *dev, *feat;
	int ret = 0;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	addr = args->argv[2];

	if (args->argc == 4){
		/*Addr IPv6 with feature*/
		if (!strcmp(args->argv[3], "link-local")){
			feat = args->argv[3];
			ret = librouter_ipv6_ethernet_set_addr(dev, addr, NULL, feat);
		}
		else{ /*IPv6 addr with mask*/
			mask = args->argv[3];
			ret = librouter_ipv6_ethernet_set_addr(dev,addr,mask, NULL);
		}
	}

	/*IPv6 addr with mask + feature*/
	if (args->argc == 5){
		mask = args->argv[3];
		feat = args->argv[4];
		ret = librouter_ipv6_ethernet_set_addr(dev,addr,mask,feat);
	}

	librouter_destroy_args(args);
	free(dev);

	if (ret < 0)
		printf("%% Not possible to set IPv6 parameters\n");
}

void interface_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	addr = args->argv[2];
	mask = args->argv[3];
	librouter_ip_interface_set_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	addr = args->argv[3];
	mask = args->argv[4];
	librouter_ip_interface_set_no_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	librouter_ip_interface_set_no_addr(dev);
	free(dev);
}

void interface_no_ipaddr_v6(const char *cmdline) /* no ipv6 address <ipv6addr> <mask_v6>*/
{
	arglist *args;
	char *addr, *mask, *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);
	args = librouter_make_args(cmdline);
	addr = args->argv[3];

	/* No mask added*/
	if (args->argc == 4){
		librouter_ipv6_interface_set_no_addr(dev, addr, NULL);
	}

	if (args->argc == 5){
		mask = args->argv[4];
		librouter_ipv6_interface_set_no_addr(dev, addr, mask);
	}

	librouter_destroy_args(args);
	free(dev);
}

void interface_flush_ipaddr_v6(const char *cmdline) /* no ipv6 address */
{
	char *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	librouter_ipv6_interface_set_no_addr_flush(dev);
	free(dev);
}


void interface_ethernet_ipaddr_dhcp(const char *cmdline) /* ip address dhcp */
{
	char *dev, daemon_dhcpc[32];

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	librouter_exec_daemon (daemon_dhcpc); /* inittab: #i:34:respawn:/bin/udhcpc -i ethernet0 >/dev/null 2>/dev/null */
	free(dev);
}

void interface_ethernet_ipaddr(const char *cmdline) /* ip address <address> <mask> */
{
	arglist *args;
	char *addr, *mask, *dev;
	ppp_config cfg;
	char daemon_dhcpc[32];

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	if (!strstr(dev, "wlan")){
		sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
		if (librouter_exec_check_daemon(daemon_dhcpc))
			librouter_kill_daemon(daemon_dhcpc); /* !!! dhcp x ppp unumbered */
	}

	args = librouter_make_args(cmdline);
	addr = args->argv[2];
	mask = args->argv[3];
	librouter_ip_ethernet_set_addr(dev, addr, mask); /* preserve alias addresses */

	// Verifica se o ip unnumbered relaciona a ethernet com a serial
	librouter_ppp_get_config(0, &cfg); // Armazena em cfg a configuracao da serial
	if (cfg.ip_unnumbered == interface_major) {
		strncpy(cfg.ip_addr, addr, 16); // Atualiza cfg com os dados da ethernet
		cfg.ip_addr[15] = 0;
		strncpy(cfg.ip_mask, mask, 16);
		cfg.ip_mask[15] = 0;
		librouter_ppp_set_config(0, &cfg); // Atualiza as configuracoes da serial
	}

	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_ipaddr_v6(const char *cmdline) /* ipv6 address <ipv6address> <mask_v6> [feature]*/
{
	arglist *args;
	char *addr, *mask, *dev, *feat;
	int ret = 0;
#ifdef NOT_YET_IMPLEMENTED
//	ppp_config cfg;
//	char daemon_dhcpcv6[32];
#endif

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
#ifdef NOT_YET_IMPLEMENTED
//	sprintf(daemon_dhcpcv6, DHCPCV6_DAEMON, dev);
//	if (librouter_exec_check_daemon(daemon_dhcpcv6))
//		librouter_kill_daemon(daemon_dhcpcv6); /* !!! dhcp x ppp unumbered */
#endif

	args = librouter_make_args(cmdline);
	addr = args->argv[2];

	if (args->argc == 4){
		/*Addr IPv6 with feature*/
		if (!strcmp(args->argv[3], "link-local")){
			feat = args->argv[3];
			ret = librouter_ipv6_ethernet_set_addr(dev, addr, NULL, feat);
		}
		else{ /*IPv6 addr with mask*/
			mask = args->argv[3];
			ret = librouter_ipv6_ethernet_set_addr(dev,addr,mask, NULL);
		}
	}

	/*IPv6 addr with mask + feature*/
	if (args->argc == 5){
		mask = args->argv[3];
		feat = args->argv[4];
		ret = librouter_ipv6_ethernet_set_addr(dev,addr,mask,feat);
	}

#ifdef NOT_YET_IMPLEMENTED
	// Verifica se o ip unnumbered relaciona a ethernet com a serial
	librouter_ppp_get_config(0, &cfg); // Armazena em cfg a configuracao da serial
	if (cfg.ip_unnumbered == interface_major) {
		strncpy(cfg.ip_addr, addr, 16); // Atualiza cfg com os dados da ethernet
		cfg.ip_addr[15] = 0;
		strncpy(cfg.ip_mask, mask, 16);
		cfg.ip_mask[15] = 0;
		librouter_ppp_set_config(0, &cfg); // Atualiza as configuracoes da serial
	}
#endif

	librouter_destroy_args(args);
	free(dev);

	if (ret < 0)
		printf("%% Not possible to set IPv6 parameters\n");

}

void interface_ethernet_ipaddr_secondary(const char *cmdline) /* ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	addr = args->argv[2];
	mask = args->argv[3];
	librouter_ip_ethernet_set_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr_secondary(const char *cmdline) /* no ip address <address> <mask> secondary */
{
	arglist *args;
	char *addr, *mask, *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	addr = args->argv[3];
	mask = args->argv[4];
	librouter_ip_ethernet_set_no_addr_secondary(dev, addr, mask);
	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_no_ipaddr(const char *cmdline) /* no ip address */
{
	char *dev;
	char daemon_dhcpc[32];
	char * dhcpd_intf = NULL;
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	if (!strstr(dev, "wlan")){
		sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
		if (librouter_exec_check_daemon(daemon_dhcpc))
			librouter_kill_daemon(daemon_dhcpc);
	}

	/*Verify DHCP Server on intf and shut it down*/
	librouter_dhcp_server_get_iface(&dhcpd_intf);
	if (dhcpd_intf){
		if (!strcmp(dev, dhcpd_intf))
			librouter_dhcp_server_set_status(0);
		free (dhcpd_intf);
	}

	librouter_ip_ethernet_set_no_addr(dev);
	free(dev);
}

void interface_ethernet_no_ipaddr_v6(const char *cmdline) /* no ip address <ipv6addr> <mask>*/
{
	arglist *args;
	char *addr, *mask, *dev;

#ifdef NOT_YET_IMPLEMENTED
	ppp_config cfg;
	char daemon_dhcpcv6[32];
#endif

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);

#ifdef NOT_YET_IMPLEMENTED
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (librouter_exec_check_daemon(daemon_dhcpc))
		librouter_kill_daemon(daemon_dhcpc);
#endif
	args = librouter_make_args(cmdline);
	addr = args->argv[3];

	/* No mask added*/
	if (args->argc == 4){
		librouter_ipv6_ethernet_set_no_addr(dev, addr, NULL);
	}

	if (args->argc == 5){
		mask = args->argv[4];
		librouter_ipv6_ethernet_set_no_addr(dev, addr, mask);
	}

	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_flush_ipaddr_v6(const char *cmdline) /* no ipv6 address */
{
	char *dev;
#ifdef NOT_YET_IMPLEMENTED
	char daemon_dhcpc[32];
#endif
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
#ifdef NOT_YET_IMPLEMENTED
	sprintf(daemon_dhcpc, DHCPC_DAEMON, dev);
	if (librouter_exec_check_daemon(daemon_dhcpc))
		librouter_kill_daemon(daemon_dhcpc);
#endif
	librouter_ipv6_ethernet_set_no_addr_flush(dev);
	free(dev);
}


void interface_ethernet_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32];
	char *dev;

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	/* Do we have a bridge interface already? */
	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[1]);

	if (!librouter_br_exists(brname)) {
		printf("%% bridge group %s does not exist\n", args->argv[1]);
		return;
	}

	/* Is this interface part of this bridge already? */
	if (librouter_br_checkif(brname, dev)) {
		printf("%% interface already assigned to bridge group %s\n", args->argv[1]);
		goto bridgegroup_done;
	}

	/* Add interface to bridge */
	librouter_br_addif(brname, dev);

bridgegroup_done:
	librouter_destroy_args(args);
	free(dev);
}

void interface_ethernet_no_bridgegroup(const char *cmdline)
{
	arglist *args;
	char brname[32];
	char *dev;

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	/* Do we have a bridge interface? */
	strcpy(brname, BRIDGE_NAME);
	strcat(brname, args->argv[2]);
	if (!librouter_br_exists(brname))
		goto no_bridgegroup_done;

	/* Is this interface part of this bridge? */
	if (!librouter_br_checkif(brname, dev))
		goto no_bridgegroup_done;

	/* Remove interface from bridge */
	librouter_br_delif(brname, dev);


no_bridgegroup_done:
	librouter_destroy_args(args);
	free(dev);
}

void interface_fec_cfg(const char *cmdline) /* speed 10|100|1000 half|full */
{
	char *dev;
	arglist *args;
	int speed = -1, duplex = -1;

	args = librouter_make_args(cmdline);
	if (args->argc == 3) {
		if ((dev = librouter_device_cli_to_linux(interface_edited->cish_string,
		                interface_major, interface_minor))) {

			/* Speed */
			speed = atoi(args->argv[1]);

			/* Duplex */
			if (strcmp(args->argv[2], "half") == 0)
				duplex = 0;
			else if (strcmp(args->argv[2], "full") == 0)
				duplex = 1;
			if (speed < 0 || duplex < 0)
				printf("%% Sintax error!\n");
			else {
				if (librouter_fec_config_link(dev, speed, duplex) < 0)
					printf("%% Not possible to set PHY parameters\n");
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
	if ((dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor))) {
		if (librouter_fec_autonegotiate_link(dev) < 0)
			printf("%% Not possible to set PHY parameters\n");
		free(dev);
	}
}

#ifdef OPTION_TUNNEL
/*
 * Tunnel related functions
 */

void tunnel_ipv6_6to4_addr_set(const char *cmdline)
{
	arglist *args;
	char *dev, *addr_6to4, *addr_ipv4, *mask_ipv6;

	args = librouter_make_args(cmdline);

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);
	addr_ipv4 = args->argv[3];
	mask_ipv6 = args->argv[4];

	addr_6to4 = malloc (64);
	strncpy(addr_6to4, addr_ipv4, 64);

	if (librouter_ipv6_conv_ipv4_addr_in_6to4_ipv6_addr(addr_6to4) < 0){
		printf("%% Not possible to set Tunnel 6to4 Address parameters\n");
		goto end;
	}

	if (librouter_ipv6_interface_set_addr(dev, addr_6to4, mask_ipv6, NULL) < 0)
		printf("%% Not possible to set Tunnel 6to4 Address parameters\n");

end:
	free(addr_6to4);
	addr_6to4 = NULL;
	librouter_destroy_args(args);
}

void tunnel_destination(const char *cmdline) /* [no] tunnel destination <ipaddress> */
{
	arglist *args;
	char *dev;

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	if (args->argc == 3){
		if (strcmp(args->argv[2], "gre") == 0){
			_cish_mask |= MSK_TUNNEL_DEST;
			librouter_tunnel_mode(dev, IPPROTO_GRE);
			goto end;
		}

		if (strcmp(args->argv[2], "ipip") == 0) {
			_cish_mask |= MSK_TUNNEL_DEST;
			librouter_tunnel_mode(dev, IPPROTO_IPIP);
			goto end;
		}
	}

	if ((args->argc == 4))
		if (strcmp(args->argv[3], "6to4") == 0){
			_cish_mask &= ~MSK_TUNNEL_DEST;
			librouter_tunnel_mode(dev, IPPROTO_IPV6);
		}

end:
	free(dev);
	librouter_destroy_args(args);
}

void tunnel_source_interface(const char *cmdline) /* tunnel source <intf> <sub> */
{
	arglist *args;
	char *dev, *source;

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	source = librouter_device_cli_to_linux(args->argv[2],atoi(args->argv[3]),-1);

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

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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

	args = librouter_make_args(cmdline);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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
	dev=librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);
	if (strcmp(args->argv[0], "no") == 0) {
		change_tunnel_kp(dev, 0, 0);
	} else {
		change_tunnel_kp(dev, atoi(args->argv[1]), atoi(args->argv[2]));
	}
	free(dev);
	librouter_destroy_args(args);
}
#endif
#endif /* OPTION_TUNNEL */

/*
 * QoS related functions
 */
#ifdef OPTION_QOS
void do_bandwidth(const char *cmdline)
{
	char *dev;
	arglist *args;
	unsigned int bw = 0;

	args = librouter_make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		librouter_destroy_args(args);
		return;
	}

	/* Check if it is bps, kbps or mbps */
	bw = atoi(args->argv[1]);
	if (strcasestr(args->argv[1], "kbps"))
		bw *= 1024;
	else if (strcasestr(args->argv[1], "mbps"))
		bw *= 1048576;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);

	librouter_qos_config_interface_bw(dev, bw);
	free(dev);
	librouter_destroy_args(args);
	return;
}

void do_max_reserved_bw(const char *cmdline)
{
	char *dev;
	arglist *args;
	unsigned char reserved_bw = 0;

	args = librouter_make_args(cmdline);

	if (args->argc != 2) {
		printf("%% Invalid arguments!\n");
		librouter_destroy_args(args);
		return;
	}

	reserved_bw = atoi(args->argv[1]);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
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
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	librouter_qos_apply_policy(dev, args->argv[1]);
	free(dev);
	return;
}

void no_service_policy(const char *cmdline)
{
	char *dev;
	intf_qos_cfg_t *intf_cfg;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	librouter_qos_get_interface_config(dev, &intf_cfg);
	if (intf_cfg)
		intf_cfg->pname[0] = 0; /* clean policy-map */
	librouter_qos_release_config(intf_cfg);
	librouter_qos_tc_insert_all(dev);
	free(dev);
	return;
}
#endif /* OPTION_QOS */

#ifdef OPTION_LINKSTATUS_TRAP
/*
 * SNMP related functions
 */
void interface_snmptrap(const char *cmd)
{
	char *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
                interface_minor);
	if (dev) {
		librouter_snmp_add_dev_trap(dev);
		free(dev);
	}
}

void interface_no_snmptrap(const char *cmd)
{
	char *dev;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
                interface_minor);
	if (dev) {
		librouter_snmp_del_dev_trap(dev);
		free(dev);
	}
}
#endif

#if 0 //#ifdef CONFIG_DEVELOPMENT
void interface_rxring(const char *cmdline) /* rxring <2-2048> */
{
	arglist *args;
	int val;
	char *dev;

	args = librouter_make_args(cmdline);
	val = atoi(args->argv[1]);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);
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
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);
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
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);

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
void interface_modem3g_set_apn(const char *cmdline)
{
	arglist * args;
	int check = -1;
	char * apn;

	args = librouter_make_args(cmdline);
	apn = args->argv[2];

	check = librouter_modem3g_set_apn(apn, interface_major);

	if (check < 0) {
		printf("\n%% Error on set APN");
		printf("\n%% Settings could not be applied\n\n");
	}
#ifdef DEBUG_M3G
	else
	printf("\nAPN stored\n\n");
#endif
	apn = NULL;
	librouter_destroy_args(args);
}

void interface_modem3g_set_password(const char *cmdline)
{
	arglist * args;
	int check = -1;
	char * password;

	args = librouter_make_args(cmdline);

	password = args->argv[2];

	check = librouter_modem3g_set_password(password, interface_major);

	if (check < 0) {
		printf("\n%% Error on set password");
		printf("\n%% Settings could not be applied\n\n");
	}
#ifdef DEBUG_M3G
	else
	printf("\nPassword stored\n\n");
#endif
	password = NULL;
	librouter_destroy_args(args);
}

void interface_modem3g_set_username(const char *cmdline)
{
	arglist * args;
	int check = -1;
	char * username;

	args = librouter_make_args(cmdline);

	username = args->argv[2];

	check = librouter_modem3g_set_username(username, interface_major);

	if (check < 0) {
		printf("\n%% Error on set username");
		printf("\n%% Settings could not be applied\n\n");
	}
#ifdef DEBUG_M3G
	else
	printf("\nUsername stored\n\n");
#endif
	username = NULL;
	librouter_destroy_args(args);
}

void backup_interface_shutdown(const char *cmdline)
{
	char * interface = malloc(16);
	int check = -1;

	snprintf(interface, 16, "%s%d", interface_edited->linux_string, interface_major);

	check = librouter_ppp_backupd_set_param_infile(interface, SHUTD_STR, "yes");
	if (check < 0) {
		printf("\n%% Error on set backup interface shutdown");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	check = librouter_ppp_backupd_set_param_infile(interface, BCKUP_STR, "no");
	if (check < 0) {
		printf("\n%% Error on set backup interface shutdown");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	check = librouter_ppp_backupd_set_param_infile(interface, MAIN_INTF_STR, "");
	if (check < 0) {
		printf("\n%% Error on set backup interface shutdown");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	check = librouter_ppp_reload_backupd();
	if (check < 0) {
		printf("\n%% Error on set backup interface shutdown - (reload configs)\n");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	end: free(interface);
}

void backup_interface(const char *cmdline)
{
	arglist *args;
	char *main_interface = malloc(16);
	char *interface = malloc(16);
#ifdef AVOID_SAME_BCKP_INTF
	char *intf_return = malloc(16);
#endif
	int check = -1;

	args = librouter_make_args(cmdline);

	snprintf(main_interface, 16, "%s %s", args->argv[1], args->argv[2]);
	snprintf(interface, 16, "%s%d", interface_edited->linux_string, interface_major);

	if (librouter_dev_exists(interface)) {
		printf("\n%% Error on set backup interface");
		printf("\n%% It is necessary to shutdown %s%d interface first",
		                interface_edited->cish_string, interface_major);
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if (!strcmp(interface, librouter_ppp_backupd_intf_to_kernel_intf(main_interface))) {
		printf("\n%% Error on set backup interface");
		printf("\n%% Settings could not be applied");
		printf("\n%% The current interface can not backup itself\n\n");
		goto end;
	}

	if (librouter_ppp_backupd_verify_m3G_loop_backup(interface, main_interface)) {
		printf("\n%% Error on set backup interface");
		printf("\n%% Settings could not be applied");
		printf("\n%% Making a backup loop with 3G interfaces\n\n");
		goto end;
	}

#ifdef AVOID_SAME_BCKP_INTF
	//WARNING: Bloco de código retirado para possibilitar duas interfaces backups distintas de monitorar uma mesma interface

	if (librouter_ppp_backupd_verif_param_infile(MAIN_INTF_STR, main_interface, intf_return)) {
		//Already applied in another 3G interface ?
		if (strcmp(intf_return, interface)) {
			printf("\n%% The interface is already with a backup connection by %s",
					librouter_device_from_linux_cmdline(intf_return));
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
	}
#endif

	check = librouter_ppp_backupd_set_param_infile(interface, BCKUP_STR, "yes");
	if (check < 0) {
		printf("\n%% Error on set backup interface");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}
	check = librouter_ppp_backupd_set_param_infile(interface, MAIN_INTF_STR, main_interface);
	if (check < 0) {
		printf("\n%% Error on set backup interface");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}
	check = librouter_ppp_reload_backupd();
	if (check < 0) {
		printf("\n%% Error on set backup interface - (reload configs.)");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	end:
#ifdef AVOID_SAME_BCKP_INTF
	free(intf_return);
#endif
	free(main_interface);
	free(interface);
	librouter_destroy_args(args);
}

void backup_method_set_ping(const char *cmdline)
{
	arglist * args;
	char * interface = malloc(16);
	char * ping;
	int check = -1;
	args = librouter_make_args(cmdline);
	ping = args->argv[2];

	snprintf(interface, 16, "%s%d", interface_edited->linux_string, interface_major);

	if (!librouter_ppp_backupd_verif_param_byintf_infile(interface, BCKUP_STR, "yes")) {

		check = librouter_ppp_backupd_set_param_infile(interface, METHOD_STR, "ping");
		if (check < 0) {
			printf("\n%% Error on set backup method - ping");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
		check = librouter_ppp_backupd_set_param_infile(interface, PING_ADDR_STR, ping);
		if (check < 0) {
			printf("\n%% Error on set backup method - ping");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
		check = librouter_ppp_reload_backupd();
		if (check < 0) {
			printf("\n%% Error on set backup method - ping - (reload configs.)");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
	} else {
		printf("\n%% The interface is already backing up");
		printf("\n%% It is necessary to shutdown backup first");
		printf("\n%% Settings could not be applied\n\n");
	}

	end: ping = NULL;
	free(interface);
	interface = NULL;
	librouter_destroy_args(args);
}

void backup_method_set_link(const char *cmdline)
{
	int check = -1;
	char * interface = malloc(16);

	snprintf(interface, 16, "%s%d", interface_edited->linux_string, interface_major);

	if (!librouter_ppp_backupd_verif_param_byintf_infile(interface, BCKUP_STR, "yes")) {

		check = librouter_ppp_backupd_set_param_infile(interface, METHOD_STR, "link");
		if (check < 0) {
			printf("\n%% Error on set backup method - link");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
		check = librouter_ppp_backupd_set_param_infile(interface, PING_ADDR_STR, "");
		if (check < 0) {
			printf("\n%% Error on set backup method - link");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
		check = librouter_ppp_reload_backupd();
		if (check < 0) {
			printf("\n%% Error on set backup method - link - (reload configs.)");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
	} else {
		printf("\n%% The interface is already backing up");
		printf("\n%% It is necessary to shutdown backup first");
		printf("\n%% Settings could not be applied\n\n");
	}

	end: free(interface);
	interface = NULL;
}

void interface_modem3g_sim_card_select(const char *cmdline)
{
	arglist * args;
	int main_sim = -1;
	struct sim_conf * sim = malloc(sizeof(struct sim_conf));
	char * interface = malloc(16);
	args = librouter_make_args(cmdline);
	main_sim = atoi(args->argv[1]);

	snprintf(interface, 16, "%s%d", interface_edited->linux_string, interface_major);

	if (librouter_dev_exists(interface)) {
		printf("\n%% Error on set SIM card order");
		printf("\n%% It is necessary to shutdown %s%d interface first",
		                interface_edited->cish_string, interface_major);
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if (args->argc >= 3) {
		if (main_sim == atoi(args->argv[2])) {
			printf("\n%% Wrong input - same SIM card for <MAIN> interface and <BACKUP> interface");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}

		if (librouter_modem3g_sim_order_set_enable(1) < 0) {
			printf("\n%% Error on set SIM card order - enable backup sim");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
	} else {
		if (librouter_modem3g_sim_order_set_enable(0) < 0) {
			printf("\n%% Error on set SIM card order - disable backup sim");
			printf("\n%% Settings could not be applied\n\n");
			goto end;
		}
	}

	if ((sim->sim_num = librouter_modem3g_sim_get_realport_by_aliasport(main_sim)) < 0){
		printf("\n%% Error on set SIM card order");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if (librouter_modem3g_sim_order_set_mainsim(sim->sim_num) < 0) {
		printf("\n%% Error on set SIM card order");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if (librouter_modem3g_sim_get_info_fromfile(sim) < 0) {
		printf("\n%% Error on set SIM card order - retrieving information");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if (!strcmp(sim->apn, "")) {
		printf("\n%% Missing APN address");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	if (librouter_modem3g_set_all_info_inchat(sim, interface_major) < 0) {
		printf("\n%% Error on set configuration");
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	/* Removido " librouter_modem3g_sim_card_set(sim->sim_num) " devido a aplicação da mesma diretiva
	 * no backupd quando o modulo vai ser conectado
	 */

	end: free(interface);
	interface = NULL;
	free(sim);
	sim = NULL;
	librouter_destroy_args(args);
}

void interface_modem3g_btin_set_info(const char *cmdline)
{
	arglist * args;
	int check = -1;
	int sim;
	char * value;
	char * field;

	args = librouter_make_args(cmdline);

	field = args->argv[2];
	value = args->argv[4];

	if ((sim = librouter_modem3g_sim_get_realport_by_aliasport(atoi(args->argv[1]))) < 0)
		goto end;

	check = librouter_modem3g_sim_set_info_infile(sim, field, value);

end:
	if (check < 0) {
		printf("\n%% Error on set %s", field);
		printf("\n%% Settings could not be applied\n\n");
	}
#ifdef DEBUG_M3G
	else
	printf("\n%s stored\n\n",field);
#endif

	value = NULL;
	field = NULL;
	librouter_destroy_args(args);
}

void interface_modem3g_default_gateway(const char *cmdline)
{
	arglist *args = librouter_make_args(cmdline);
	char iface[32];

	sprintf(iface, "ppp%d", interface_major);

	if (!strcmp(args->argv[0], "no"))
		librouter_ppp_backupd_set_default_route(iface, 0);
	else {
		librouter_ppp_backupd_set_default_route(iface, 1);
		librouter_ppp_backupd_set_default_metric(iface, atoi(args->argv[1]));
	}

	librouter_destroy_args(args);
}
#endif /* OPTION_MODEM3G */

#ifdef OPTION_PPTP
void pptp_set_info(const char *cmd)
{
	arglist * args;
	int check = 0;
	args = librouter_make_args(cmd);

	if (strcmp(args->argv[0], "server")) {
		check = librouter_pptp_analyze_input(args->argv[1]);
		if (check < 0) {
			printf("\n %% Error on set configuration!\n");
			printf(" %% Wrong input! \n");
			printf(
					" %% The system do not accept special characters like: .@<>#\\/&* \n");
			goto end;
		}
	}

	check = librouter_pptp_set_config_cli(args->argv[0], args->argv[1]);
	if (check < 0) {
		printf("\n%% Error on set %s", args->argv[0]);
		printf("\n%% Settings could not be applied\n\n");
	}

	end: librouter_destroy_args(args);

}

void pptp_set_no_info(const char *cmd)
{
	arglist * args;
	args = librouter_make_args(cmd);
	int check = 0;

	if (strcmp(args->argv[0], "no")) {
		printf("\n%% Error on set no %s", args->argv[1]);
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	check = librouter_pptp_set_config_cli(args->argv[1], "");
	if (check < 0) {
		printf("\n%% Error on set no %s", args->argv[1]);
		printf("\n%% Settings could not be applied\n\n");
	}

	end: librouter_destroy_args(args);
}

void pptp_set_mppe(const char *cmd)
{
	arglist * args;
	int check = 0;
	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0], "no"))
	check = librouter_pptp_set_mppe(0);
	else
	check = librouter_pptp_set_mppe(1);

	if (check < 0) {
		printf("\n%% Error on set PPTP MPPE\n");
		printf("\n%% Settings could not be applied\n\n");
	}

	librouter_destroy_args(args);

}

void pptp_set_clientmode(const char *cmd)
{
	arglist * args;
	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0], "no"))
	librouter_pptp_set_clientmode(0);
	else
	librouter_pptp_set_clientmode(1);

	librouter_destroy_args(args);
}

#endif /* OPTION_PPTP */

#ifdef OPTION_PPPOE
void pppoe_set_info(const char *cmd)
{
	arglist * args;
	int check = 0;
	args = librouter_make_args(cmd);

	check = librouter_pppoe_analyze_input(args->argv[1]);
	if (check < 0) {
		printf("\n %% Error on set configuration!\n");
		printf(" %% Wrong input! \n");
		printf(" %% The system do not accept special characters like: <>#\\/&* \n");
		goto end;
	}

	check = librouter_pppoe_set_config_cli(args->argv[0], args->argv[1]);
	if (check < 0) {
		printf("\n%% Error on set %s", args->argv[0]);
		printf("\n%% Settings could not be applied\n\n");
	}

	end: librouter_destroy_args(args);

}

void pppoe_set_no_info(const char *cmd)
{
	arglist * args;
	args = librouter_make_args(cmd);
	int check = 0;

	if (strcmp(args->argv[0], "no")) {
		printf("\n%% Error on set no %s", args->argv[1]);
		printf("\n%% Settings could not be applied\n\n");
		goto end;
	}

	check = librouter_pppoe_set_config_cli(args->argv[1], "");
	if (check < 0) {
		printf("\n%% Error on set no %s", args->argv[1]);
		printf("\n%% Settings could not be applied\n\n");
	}

	end: librouter_destroy_args(args);
}

void pppoe_set_clientmode(const char *cmd)
{
	arglist * args;
	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0], "no"))
	librouter_pppoe_set_clientmode(0);
	else
	librouter_pppoe_set_clientmode(1);

	librouter_destroy_args(args);
}
#endif /* OPTION_PPPOE */

#ifdef OPTION_EFM
void interface_efm_set_mode(const char *cmdline)
{
	arglist *args;
	struct orionplus_conf conf;

	args = librouter_make_args(cmdline);

	if (args->argc < 2 || args->argc > 6) {
		printf("%% Wrong number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	if (!strcmp(args->argv[1], "cpe")) {
		conf.mode = GTI_CPE;
	} else {
		conf.mode = GTI_CO;
	}

	if (conf.mode == GTI_CO) {
		if (args->argc != 4) {
			printf("%% Wrong number of arguments\n");
			librouter_destroy_args(args);
			return;
		}

		if (strstr(args->argv[2], "32"))
			conf.modulation = GTI_32_TCPAM_MODE;
		else
			conf.modulation = GTI_16_TCPAM_MODE;
		conf.linerate = atoi(args->argv[3]);
	}

	if (librouter_efm_set_mode(&conf)) {
		printf("%% Could not set DSP mode\n");
	}

	librouter_destroy_args(args);
}

#endif /* OPTION_EFM */

#ifdef OPTION_WIFI
void config_interface_wlan_ap_manager_done(const char *cmdline)
{
	switch_port = -1;
	switch_port_real = -1;
	command_root = CMD_CONFIG_INTERFACE_WLAN;
}

void config_interface_wlan_ap_manager(const char *cmdline)
{
	command_root = CMD_CONFIG_INTERFACE_WLAN_APMANAGER;
}

#endif /* OPTION_WIFI */
