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

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"

#undef DEBUG_ZEBRA

/* deamon zebra */
static char buf_daemon[1024];

/*AS number for BGP*/
int asn = 0;

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

void set_model_vpn_cmds(int enable)
{
	if (enable)
		_cish_mask |= MSK_VPN;
	else
		_cish_mask &= ~MSK_VPN;
}

void set_model_vlan_cmds(int enable)
{
	if (enable)
		_cish_mask |= MSK_VLAN;
	else
		_cish_mask &= ~MSK_VLAN;
}

void set_model_cmd_mask(int mask)
{
	_cish_mask |= mask;
}

void del_model_cmd_mask(int mask)
{
	_cish_mask &= ~mask;
}

#ifdef OPTION_MANAGED_SWITCH
void set_model_switch_cmds(void)
{
	int enable = librouter_ksz8863_probe();

	if (enable == 1)
		_cish_mask |= MSK_MANAGED_SWITCH;
	else
		_cish_mask &= ~MSK_MANAGED_SWITCH;
}
#endif

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
#ifdef OPTION_MODEM3G
extern cish_command CMD_BACKUP_INTERFACE_ETHERNET[];
#endif
extern cish_command CMD_POLICYROUTE_ROUTE_DEV_ETHERNET[];

void set_model_ethernet_cmds(int num_ifaces)
{
	static char name[8];

	sprintf(name, "0-%d", num_ifaces - 1);

	cish_dbg("Setting ethernet interface number : %s\n", name);

	/* commandtree.c */
	CMD_SHOW_INTERFACE_ETHERNET[0].name = name;
#ifdef OPTION_SMCROUTE
	CMD_IP_MROUTE8_ETHERNET[0].name = name;
	CMD_IP_MROUTE5_ETHERNET[0].name = name;
#endif
	CMD_IP_ROUTE4_ETHERNET[0].name = name;
#ifdef OPTION_PIMD
	CMD_IP_PIM_CAND_BSR_INTF_ETHERNET[0].name = name;
	CMD_IP_PIM_CAND_RP_INTF_ETHERNET[0].name = name;
#endif
	CMD_CONFIG_INTERFACE_ETHERNET_[0].name = name;
#ifdef OPTION_IPSEC
	CMD_IPSEC_CONNECTION_INTERFACE_ETHERNET[0].name = name;
	CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_ETHERNET[0].name = name;
#endif
	CMD_CLEAR_INTERFACE_ETHERNET_[0].name = name;
	/* configterm.c */
	CMD_CONFIG_INTERFACE_TUNNEL_TUNNEL_SRC_ETHERNET[0].name = name;
	/* config_router.c */
	CMD_ROUTER_RIP_INTERFACE_ETHERNET[0].name = name;
	CMD_ROUTER_OSPF_PASSIVE_INTERFACE_ETHERNET[0].name = name;
	CMD_SHOW_OSPF_INTERFACE_ETHERNET[0].name = name;
#ifdef OPTION_BGP
	CMD_BGP_INTERFACE_ETHERNET[0].name = name;
#endif
#ifdef OPTION_MODEM3G
	CMD_BACKUP_INTERFACE_ETHERNET[0].name = name;
#endif
	CMD_POLICYROUTE_ROUTE_DEV_ETHERNET[0].name = name;
}

void config_router(const char *cmdline)
{
	arglist *args;
	char no_debug_ospf[] = "no debug ospf event";
	char no_debug_rip[] = "no debug rip events";
#ifdef OPTION_BGP
	char no_debug_bgp[] = "no debug bgp events";
#endif

	syslog(LOG_INFO, "entered router configuration mode for session from %s", _cish_source);
	args = librouter_make_args(cmdline);
	if (strcasecmp(args->argv[1], "rip") == 0) {
		command_root = CMD_CONFIG_ROUTER_RIP;
		set_rip_interface_cmds(1);
		librouter_quagga_ripd_exec(1);
		/* sync debug! */
		if (librouter_debug_get_state(args->argv[1])) {
			rip_execute_root_cmd(&no_debug_rip[3]);
		} else {
			rip_execute_root_cmd(no_debug_rip);
		}
	} else if (strcasecmp(args->argv[1], "ospf") == 0) {
		command_root = CMD_CONFIG_ROUTER_OSPF;
		set_ospf_interface_cmds(1);
		librouter_quagga_ospfd_exec(1);
		/* sync debug! */
		if (librouter_debug_get_state(args->argv[1])) {
			ospf_execute_root_cmd(&no_debug_ospf[3]);
		} else {
			ospf_execute_root_cmd(no_debug_ospf);
		}
	}
#ifdef OPTION_BGP
	else if (strcasecmp(args->argv[1], "bgp") == 0) {
		int temp = atoi(args->argv[2]);
		set_bgp_interface_cmds(1);
		librouter_quagga_bgpd_exec(1);
		bgp_start_router_cmd(temp); /* Initiates BGP with ASN = temp */
		asn = librouter_quagga_bgp_get_asn();
		if (asn == 0 || temp == asn) /* Do not enter if another AS is already running */
		{
			asn = temp;
			command_root = CMD_CONFIG_ROUTER_BGP;
			/* sync debug! */
			if (librouter_debug_get_state(args->argv[1])) {
				bgp_execute_root_cmd(&no_debug_bgp[3]);
			} else {
				bgp_execute_root_cmd(no_debug_bgp);
			}
		}
	}
#endif
	librouter_destroy_args(args);
}

void config_no_router(const char *cmdline)
{
	arglist *args;
	char tmp[64];

	args = librouter_make_args(cmdline);

	if (strcasecmp(args->argv[2], "rip") == 0) {
		set_rip_interface_cmds(0);
		librouter_quagga_ripd_exec(0);
		sprintf(tmp, "cp %s %s", RIPD_RO_CONF, RIPD_CONF );
#ifdef DEBUG_ZEBRA
		printf("%s\n", tmp);
#endif
		system(tmp); /* clean configuration file */
	} else if (strcasecmp(args->argv[2], "ospf") == 0) {
		set_ospf_interface_cmds(0);
		librouter_quagga_ospfd_exec(0);
		sprintf(tmp, "cp %s %s", OSPFD_RO_CONF, OSPFD_CONF );
#ifdef DEBUG_ZEBRA
		printf("%s\n", tmp);
#endif
		system(tmp); /* clean configuration file */
	}
#ifdef OPTION_BGP
	else if (strcasecmp(args->argv[2], "bgp") == 0) {
		int asn_temp = atoi(args->argv[3]);
		asn = librouter_quagga_bgp_get_asn();
		if (asn_temp == asn) /* Make sure we're shutting down the correct AS...  otherwise, do nothing */
		{
			set_bgp_interface_cmds(0);
			librouter_quagga_bgpd_exec(0);
			sprintf(tmp, "cp %s %s", BGPD_RO_CONF, BGPD_CONF );
#ifdef DEBUG_ZEBRA
			printf("%s\n", tmp);
#endif
			system(tmp); /* clean configuration file */
		}
	}
#endif
	librouter_destroy_args(args);
}

void config_router_done(const char *cmdline)
{
	syslog(LOG_INFO, "left router configuration mode for session from %s", _cish_source);
	command_root = CMD_CONFIGURE;
}

void zebra_execute_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(ZEBRA_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);

	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("zebra_execute_cmd = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

#if 0
void zebra_execute_interface_cmd(const char *cmdline)
{
	char *new_cmdline;
	char *dev;

	if (librouter_quagga_connect_daemon(ZEBRA_PATH) < 0) return;

	new_cmdline=librouter_device_to_linux_cmdline((char*)cmdline);
	new_cmdline=librouter_zebra_from_linux_cmdline((char*)new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	dev=librouter_device_cli_to_linux(interface_edited->cish_string, interface_major, interface_minor);
	sprintf(buf, "interface %s", dev);
	free(dev);
#ifdef DEBUG_ZEBRA
	printf("zebra_execute_interface_cmd = %s\n", buf);
	printf("zebra_execute_interface_cmd = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(buf, stdout, buf_daemon, 0);
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);
	librouter_quagga_close_daemon();
}
#endif

void ospf_execute_root_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(OSPF_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("ospf = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

void ospf_execute_router_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(OSPF_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("router ospf", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("ospf = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

void ospf_execute_interface_cmd(const char *cmdline)
{
	char *new_cmdline;
	char *dev;

	if (librouter_quagga_connect_daemon(OSPF_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	sprintf(buf, "interface %s", dev);
	free(dev);
#ifdef DEBUG_ZEBRA
	printf("ospf = %s\n", buf);
	printf("ospf = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(buf, stdout, buf_daemon, 0);
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

void rip_execute_root_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(RIP_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("rip = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

extern char keychain_name[64];
extern int key_number;

void rip_execute_keychain_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(RIP_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	sprintf(buf, "key chain %s", keychain_name);
	librouter_quagga_execute_client(buf, stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("rip = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

void rip_execute_key_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(RIP_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	sprintf(buf, "key chain %s", keychain_name);
	librouter_quagga_execute_client(buf, stdout, buf_daemon, 0);
	sprintf(buf, "key %d", key_number);
	librouter_quagga_execute_client(buf, stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("rip = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

void rip_execute_router_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(RIP_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("router rip", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("rip = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

void rip_execute_interface_cmd(const char *cmdline)
{
	char *dev, *new_cmdline;

	if (librouter_quagga_connect_daemon(RIP_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	sprintf(buf, "interface %s", dev);
	free(dev);
#ifdef DEBUG_ZEBRA
	printf("rip = %s\n", buf);
	printf("rip = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(buf, stdout, buf_daemon, 0);
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

#ifdef OPTION_BGP
void bgp_execute_root_cmd(const char *cmdline)
{
	char *new_cmdline;

	if (librouter_quagga_connect_daemon(BGP_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("bgp = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}

/* Initializes a BGP AS if one does not exist */
int bgp_start_router_cmd(int temp_asn)
{
	char tmp[32];

	if (librouter_quagga_connect_daemon(BGP_PATH) < 0)
		return -1;

	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);
	sprintf(tmp, "router bgp %d", temp_asn);
	librouter_quagga_execute_client(tmp, stdout, buf_daemon, 1); /* show errors! */

#ifdef DEBUG_ZEBRA
	printf("bgp = %s\n", tmp);
#endif
	librouter_quagga_close_daemon();

	return 0;
}

void bgp_execute_router_cmd(const char *cmdline)
{
	char *new_cmdline;
	char bgp_line[32];

	if (librouter_quagga_connect_daemon(BGP_PATH) < 0)
		return;

	new_cmdline = librouter_device_to_linux_cmdline((char*) cmdline);
	new_cmdline = librouter_zebra_from_linux_cmdline((char*) new_cmdline);
	librouter_quagga_execute_client("enable", stdout, buf_daemon, 0);
	librouter_quagga_execute_client("configure terminal", stdout, buf_daemon, 0);

	sprintf(bgp_line, "router bgp %d", asn);
	librouter_quagga_execute_client(bgp_line, stdout, buf_daemon, 0);
#ifdef DEBUG_ZEBRA
	printf("bgp = %s\n", new_cmdline);
#endif
	librouter_quagga_execute_client(new_cmdline, stdout, buf_daemon, 1); /* show errors! */
	librouter_quagga_execute_client("write file", stdout, buf_daemon, 0);

	librouter_quagga_close_daemon();
}
#endif

void zebra_dump_routes(FILE *out)
{
	int n;
	FILE *f;
	arg_list argl = NULL;
	char *new_buf, buf[1024];
	unsigned int print, line = 0;

	if (!(f = librouter_quagga_zebra_show_cmd("show ip route")))
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			line++;
			librouter_str_striplf(buf);
			if (line == 1)
#ifdef OPTION_BGP
				fprintf(
				                out,
				                "Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF, B - BGP, > - selected route\n");
#else
			fprintf(out, "Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF, > - selected route\n");
#endif
			else if (line > 3) {
				if (strlen(buf) > 4) {
#if 0
					if (buf[0] == 'K')
					continue;
#endif

					new_buf = librouter_device_from_linux_cmdline(
					                librouter_zebra_to_linux_cmdline(buf + 4));
					buf[3] = 0;
					if (new_buf) {
						print = 1;
						if (strchr(buf, '>') == NULL) {
							if (((n = librouter_parse_args_din(new_buf,
							                &argl)) > 0) && (strcmp(
							                argl[n - 1], "inactive")
							                == 0))
								print = 0;
							librouter_destroy_args_din(&argl);
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

	f = librouter_quagga_ospf_show_cmd(cmdline);
	if (!f)
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			librouter_str_striplf(buf);
			pprintf("%s\n", librouter_device_from_linux_cmdline(
			                librouter_zebra_to_linux_cmdline(buf)));
		}
	}
	fclose(f);
}

void show_ip_rip(const char *cmdline)
{
	FILE *f;
	char buf[1024];

#ifdef OPTION_UNKNOWN
	f = librouter_quagga_rip_show_cmd("show ip protocols");
	if (!f)
	return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			librouter_str_striplf(buf);
			pprintf("%s\n", librouter_device_from_linux_cmdline(
							librouter_zebra_to_linux_cmdline(buf)));
		}
	}
	fclose(f);
#endif

	f = librouter_quagga_rip_show_cmd(cmdline); /* show ip rip */
	if (!f)
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			librouter_str_striplf(buf);
			pprintf("%s\n", librouter_device_from_linux_cmdline(
			                librouter_zebra_to_linux_cmdline(buf)));
		}
	}
	fclose(f);
}

#ifdef OPTION_BGP
void show_ip_bgp(const char *cmdline)
{

	FILE *f;
	char buf[1024];

	f = librouter_quagga_bgp_show_cmd(cmdline);
	if (!f)
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			librouter_str_striplf(buf);
			pprintf("%s\n", librouter_device_from_linux_cmdline(
			                librouter_zebra_to_linux_cmdline(buf)));

		}
	}
	fclose(f);

}
#endif

