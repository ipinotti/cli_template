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
		asn = lconfig_bgp_get_asn();
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
		asn = lconfig_bgp_get_asn ();
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

#ifdef OPTION_BGP
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
#endif

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

	f = ospf_show_cmd(cmdline);
	if (!f)
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(
			                zebra_to_linux_network_cmdline(buf)));
		}
	}
	fclose(f);
}

void show_ip_rip(const char *cmdline)
{
	FILE *f;
	char buf[1024];

	f = rip_show_cmd("show ip protocols");
	if (!f)
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(
			                zebra_to_linux_network_cmdline(buf)));
		}
	}
	fclose(f);

	f = rip_show_cmd(cmdline); /* show ip rip */
	if (!f)
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(
			                zebra_to_linux_network_cmdline(buf)));
		}
	}
	fclose(f);
}

#ifdef OPTION_BGP
void show_ip_bgp(const char *cmdline)
{

	FILE *f;
	char buf[1024];

	f = bgp_show_cmd(cmdline);
	if (!f)
		return;
	while (!feof(f)) {
		if (fgets(buf, 1024, f)) {
			striplf(buf);
			pprintf("%s\n", linux_to_cish_dev_cmdline(
			                zebra_to_linux_network_cmdline(buf)));

		}
	}
	fclose(f);

}
#endif
