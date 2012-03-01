/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <linux/if_arp.h>
#include <syslog.h>

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"
#include "cish_main.h"


int get_procip_val(const char *);

#ifdef OPTION_ROUTER
/* FIXME Move this functions to librouter */
void ip_param(const char *cmd)
{
	const char *dst_file;
	int dst_val;
	FILE *F;

	dst_file = (const char *) NULL;
	dst_val = -1;


	if (strncmp(cmd, "ip forwarding", 13) == 0 || strncmp(cmd, "ip routing", 10) == 0) {
		dst_file = "/proc/sys/net/ipv4/ip_forward"; /* "/proc/sys/net/ipv4/conf/all/forwarding" */
		dst_val = 1;
	} else

#ifdef OPTION_PIMD
	if (strncmp(cmd, "ip multicast-routing", 20) == 0) {
		dst_file = "/proc/sys/net/ipv4/conf/all/mc_forwarding";
		dst_val = 1;
	} else
#endif
	if (strncmp(cmd, "ip pmtu-discovery", 17) == 0) {
		dst_file = "/proc/sys/net/ipv4/ip_no_pmtu_disc";
		dst_val = 0;
	} else if (strncmp(cmd, "ip default-ttl ", 15) == 0) {
		if ((dst_val = atoi(cmd + 15)) <= 0) {
			printf("%% Parameter error\n");
			return;
		}
		dst_file = "/proc/sys/net/ipv4/ip_default_ttl";
	} else if (strncmp(cmd, "ip icmp ignore all", 18) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
		dst_val = 1;
	} else if (strncmp(cmd, "ip icmp ignore broadcast", 24) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts";
		dst_val = 1;
	} else if (strncmp(cmd, "ip icmp ignore bogus", 20) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses";
		dst_val = 1;
	} else if (strncmp(cmd, "ip icmp rate dest-unreachable ", 30) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_destunreach_rate";
		dst_val = atoi(cmd + 30);

		if ((!dst_val) && (cmd[30] != '0'))
			return;
	} else if (strncmp(cmd, "ip icmp rate echo-reply ", 24) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_echoreply_rate";
		dst_val = atoi(cmd + 24);

		if ((!dst_val) && (cmd[24] != '0'))
			return;
	} else if (strncmp(cmd, "ip icmp rate param-prob ", 24) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_paramprob_rate";
		dst_val = atoi(cmd + 24);

		if ((!dst_val) && (cmd[24] != '0'))
			return;
	} else if (strncmp(cmd, "ip icmp rate time-exceed ", 25) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_timeexceed_rate";
		dst_val = atoi(cmd + 25);

		if ((!dst_val) && (cmd[25] != '0'))
			return;
	} else if (strncmp(cmd, "ip fragment high ", 17) == 0) {
		dst_file = "/proc/sys/net/ipv4/ipfrag_high_thresh";
		dst_val = atoi(cmd + 17);

		if ((!dst_val) && (cmd[17] != '0'))
			return;
	} else if (strncmp(cmd, "ip fragment low ", 16) == 0) {
		dst_file = "/proc/sys/net/ipv4/ipfrag_low_thresh";
		dst_val = atoi(cmd + 16);

		if ((!dst_val) && (cmd[16] != '0'))
			return;
	} else if (strncmp(cmd, "ip fragment time ", 17) == 0) {
		dst_file = "/proc/sys/net/ipv4/ipfrag_time";
		dst_val = atoi(cmd + 17);

		if ((!dst_val) && (cmd[17] != '0'))
			return;
	} else if (strncmp(cmd, "ip tcp ecn", 10) == 0) {
		dst_file = "/proc/sys/net/ipv4/tcp_ecn";
		dst_val = 1;
	} else if (strncmp(cmd, "ip tcp syncookies", 17) == 0) {
		dst_file = "/proc/sys/net/ipv4/tcp_syncookies";
		dst_val = 1;
	} else if (strncmp(cmd, "ip rp-filter", 12) == 0) {
		dst_file = "/proc/sys/net/ipv4/conf/all/rp_filter";
		dst_val = 1;
	}

	if (!dst_file) {
		printf("%% Error! No such file\n");
		return;
	}

	F = fopen(dst_file, "w");
	if (!F) {
		printf("%% Not possible to set this parameter now\n");
		return;
	}

	fprintf(F, "%d", dst_val);
	fclose(F);
}

void no_ip_param(const char *_cmd)
{
	const char *cmd;
	const char *dst_file;
	int dst_val;
	FILE *F;

	cmd = _cmd + 3;

	dst_file = (const char *) NULL;
	dst_val = -1;

	if (strncmp(cmd, "ip forwarding", 13) == 0 || strncmp(cmd, "ip routing", 10) == 0) {
		dst_file = "/proc/sys/net/ipv4/ip_forward"; /* "/proc/sys/net/ipv4/conf/all/forwarding" */
		dst_val = 0;
	}
#ifdef OPTION_PIMD
	else if (strncmp(cmd, "ip multicast-routing", 20) == 0) {
		dst_file = "/proc/sys/net/ipv4/conf/all/mc_forwarding";
		dst_val = 0;
	}
#endif
	else if (strncmp(cmd, "ip pmtu-discovery", 17) == 0) {
		dst_file = "/proc/sys/net/ipv4/ip_no_pmtu_disc";
		dst_val = 1;
	} else if (strncmp(cmd, "ip icmp ignore all", 18) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
		dst_val = 0;
	} else if (strncmp(cmd, "ip icmp ignore broadcast", 24) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts";
		dst_val = 0;
	} else if (strncmp(cmd, "ip icmp ignore bogus", 20) == 0) {
		dst_file = "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses";
		dst_val = 0;
	} else if (strncmp(cmd, "ip tcp ecn", 10) == 0) {
		dst_file = "/proc/sys/net/ipv4/tcp_ecn";
		dst_val = 0;
	} else if (strncmp(cmd, "ip tcp syncookies", 17) == 0) {
		dst_file = "/proc/sys/net/ipv4/tcp_syncookies";
		dst_val = 0;
	} else if (strncmp(cmd, "ip rp-filter", 12) == 0) {
		dst_file = "/proc/sys/net/ipv4/conf/all/rp_filter";
		dst_val = 0;
	}

	if (!dst_file) {
		printf("%% Error\n");
		return;
	}

	F = fopen(dst_file, "w");
	if (!F) {
		printf("%% Error opening %s\n", dst_file);
		return;
	}
	fprintf(F, "%d", dst_val);
	fclose(F);
}
#endif /* OPTION_ROUTER */

#ifdef OPTION_HTTP
void http_server(const char *cmd)
{
	librouter_exec_daemon(HTTP_DAEMON);
}

void no_http_server(const char *cmd)
{
	librouter_kill_daemon(HTTP_DAEMON);
}
#endif

#ifdef OPTION_HTTPS
void https_server(const char *cmd)
{
	librouter_exec_daemon(HTTPS_DAEMON);
}

void no_https_server(const char *cmd)
{
	librouter_kill_daemon(HTTPS_DAEMON);
}
#endif

void telnet_server(const char *cmd)
{
	librouter_exec_set_inetd_program(1, TELNET_DAEMON);
}

void no_telnet_server(const char *cmd)
{
	librouter_exec_set_inetd_program(0, TELNET_DAEMON);
}

/* DHCP Server */
void dhcp_server_enable(const char *cmd)
{
	if (!librouter_dhcp_server_verify_ip_intf()){
		printf("%% Could not start DHCP Server\n");
		printf("%% Missing IP Address / Netmask on the DHCP Server interface\n");
		return;
	}

	if (librouter_dhcp_server_set(1) < 0)
		printf("%% Could not start DHCP Server\n");
}

void dhcp_server_disable(const char *cmd)
{
	if (librouter_dhcp_server_set(0) < 0)
		printf("%% Could not stop DHCP Server\n");
}

void dhcp_server_dns(const char *cmd)
{
	arglist *args;
	char *dns;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0], "no"))
		dns = NULL;
	else
		dns = args->argv[1];

	if (librouter_dhcp_server_set_dnsserver(dns) < 0)
		printf("%% Could not set DNS server\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);
	free(args);
}

void dhcp_server_leasetime(const char *cmd)
{
	arglist *args;
	int lease_time;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0], "no")) {
		if (!strcmp(args->argv[1], "default-lease-time")) {
			if (librouter_dhcp_server_set_leasetime(0) < 0)
				printf("%% Could not deleted default lease time\n");
		} else {
			if (librouter_dhcp_server_set_maxleasetime(0) < 0)
				printf("%% Could not deleted max lease time\n");
		}
		return;
	}

	lease_time = atoi(args->argv[1]) * 86400;
	lease_time += atoi(args->argv[2]) * 3600;
	lease_time += atoi(args->argv[3]) * 60;
	lease_time += atoi(args->argv[4]);

	if (!strcmp(args->argv[0], "default-lease-time")) {
		if (librouter_dhcp_server_set_leasetime(lease_time) < 0)
			printf("%% Could not set default lease time\n");
	} else {
		if (librouter_dhcp_server_set_maxleasetime(lease_time) < 0)
			printf("%% Could not set max lease time\n");
	}

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

void dhcp_server_domainname(const char *cmd)
{
	arglist *args;
	char *dn;

	args = librouter_make_args(cmd);
	if (!strcmp(args->argv[0],"no"))
		dn = NULL;
	else
		dn = args->argv[1];

	if (librouter_dhcp_server_set_domain(dn) < 0)
		printf("%% Could not set Domain Name\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

void dhcp_server_iface(const char *cmd)
{
	arglist *args;
	char *dev;

	args = librouter_make_args(librouter_device_to_linux_cmdline((char *)cmd));
	if (!strcmp(args->argv[0],"no"))
		dev = NULL;
	else
		dev = args->argv[1];

	/* Special case: if bridge, check if it exists on system */
	if (strstr(dev, "bridge")) {
		if (!librouter_br_exists(dev)) {
			printf("%% %s must be created first\n", dev);
			free(args);
			return;
		}
	}

	/* All OK, add to file */
	if (librouter_dhcp_server_set_iface(dev) < 0)
		printf("%% Could not set Domain Name\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

#ifdef OPTION_DHCP_NETBIOS
void dhcp_server_nbns(const char *cmd)
{
	arglist *args;
	char *ns;

	args = librouter_make_args(cmd);
	if (!strcmp(args->argv[0],"no"))
		ns = NULL;
	else
		ns = args->argv[1];

	if (librouter_dhcp_server_set_nbns(ns) < 0)
		printf("%% Could not set NetBIOS Name Server\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

void dhcp_server_nbdd(const char *cmd)
{
	arglist *args;
	char *dd;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0],"no"))
		dd = NULL;
	else
		dd = args->argv[1];

	if (librouter_dhcp_server_set_nbdd(dd) < 0)
		printf("%% Could not set NetBIOS Datagram Distribution server\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

void dhcp_server_nbnt(const char *cmd)
{
	arglist *args;
	int netbios_node_type;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0],"no"))
		netbios_node_type = 0;
	else {
		switch (args->argv[1][0]) {
		case 'B':
			netbios_node_type = 1;
			break;
		case 'P':
			netbios_node_type = 2;
			break;
		case 'M':
			netbios_node_type = 4;
			break;
		case 'H':
			netbios_node_type = 8;
			break;
		default:
			netbios_node_type = 0;
			break;
		}
	}

	if (librouter_dhcp_server_set_nbnt(netbios_node_type) < 0)
		printf("%% Could not set NetBIOS node type\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}
#endif /* OPTION_DHCP_NETBIOS */

void dhcp_server_default_router(const char *cmd)
{
	arglist *args;
	char *router;

	args = librouter_make_args(cmd);

	if (!strcmp(args->argv[0],"no"))
		router = NULL;
	else
		router = args->argv[1];

	if (librouter_dhcp_server_set_router(router) < 0)
		printf("%% Could not set default router\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

void dhcp_server_pool(const char *cmd)
{
	arglist *args;
	char *start, *end;

	args = librouter_make_args(cmd);

	start = args->argv[1];
	end = args->argv[2];

	if (librouter_dhcp_server_set_pool(start, end) < 0)
		printf("%% Could not set pool\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

void dhcp_server_network(const char *cmd)
{
	arglist *args;
	char *network, *mask;

	args = librouter_make_args(cmd);

	network = args->argv[1];
	mask = args->argv[2];

	if (librouter_dhcp_server_set_network(network, mask) < 0)
		printf("%% Could not set network\n");

	if (librouter_dhcp_get_status() == DHCP_SERVER)
		librouter_dhcp_server_set_status(1);

	free(args);
}

void dhcp_server(const char *cmd)
{
	command_root = CMD_IP_DHCP_SERVER;
}

void dhcp_server_exit(const char *cmd)
{
	command_root = CMD_CONFIGURE;
}

void dhcp_relay(const char *cmd)
{
	char *p;

	p = strstr(cmd, "relay");
	if (!p)
		return;
	p += 5;
	while (*p == ' ')
		p++;
	librouter_dhcp_set_relay(p);
}

void no_dhcp_relay(const char *cmd)
{
	librouter_dhcp_set_no_relay();
}

void ip_dnsrelay(const char *cmd) /* [no] ip dns relay */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 4)
		librouter_kill_daemon(DNS_DAEMON);
	else
		librouter_exec_daemon(DNS_DAEMON);
	librouter_destroy_args(args);
}

void ip_domainlookup(const char *cmd) /* [no] ip domain lookup */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 4)
		librouter_dns_lookup(0);
	else
		librouter_dns_lookup(1);
	librouter_destroy_args(args);
}

void ip_nameserver(const char *cmd) /* [no] ip name-server <ipaddress> */
{
	arglist *args;

	args = librouter_make_args(cmd);
	switch (args->argc) {
	case 3:
		librouter_dns_nameserver(1, args->argv[2]);
		break;
	case 4:
		librouter_dns_nameserver(0, args->argv[3]);
		break;
	}
	librouter_destroy_args(args);
}

int delete_module(const char *name);

void ip_nat_ftp(const char *cmd) /* [no] ip nat helper ftp [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args = librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0)
		no = 1;
	else
		no = 0;
	/* always remove modules first... */
	sprintf(buf, "ip_nat_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	sprintf(buf, "ip_conntrack_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	router_cfg->nat_helper_ftp_ports[0] = 0;
	if (!no && args->argc == 6) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s ports=%s >/dev/null 2>/dev/null",
		                args->argv[3], args->argv[5]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s ports=%s >/dev/null 2>/dev/null",
		                args->argv[3], args->argv[5]);
		system(buf);
		strncpy(router_cfg->nat_helper_ftp_ports, args->argv[5], 48);
	} else if (!no && args->argc == 4) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		strcpy(router_cfg->nat_helper_ftp_ports, "21"); /* netfilter_ipv4/ip_conntrack_ftp.h:#define FTP_PORT      21 */
	}
	librouter_destroy_args(args);
}

void ip_nat_irc(const char *cmd) /* [no] ip nat helper irc [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args = librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0)
		no = 1;
	else
		no = 0;
	/* always remove modules first... */
	sprintf(buf, "ip_nat_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	sprintf(buf, "ip_conntrack_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	router_cfg->nat_helper_irc_ports[0] = 0;
	if (!no && args->argc == 6) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s ports=%s >/dev/null 2>/dev/null",
		                args->argv[3], args->argv[5]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s ports=%s >/dev/null 2>/dev/null",
		                args->argv[3], args->argv[5]);
		system(buf);
		strncpy(router_cfg->nat_helper_irc_ports, args->argv[5], 48);
	} else if (!no && args->argc == 4) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		strcpy(router_cfg->nat_helper_irc_ports, "6667"); /* netfilter_ipv4/ip_conntrack_irc.h:#define IRC_PORT      6667 */
	}
	librouter_destroy_args(args);
}

void ip_nat_tftp(const char *cmd) /* [no] ip nat helper tftp [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args = librouter_make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0)
		no = 1;
	else
		no = 0;
	/* always remove modules first... */
	sprintf(buf, "ip_nat_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	sprintf(buf, "ip_conntrack_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	router_cfg->nat_helper_tftp_ports[0] = 0;
	if (!no && args->argc == 6) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s ports=%s >/dev/null 2>/dev/null",
		                args->argv[3], args->argv[5]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s ports=%s >/dev/null 2>/dev/null",
		                args->argv[3], args->argv[5]);
		system(buf);
		strncpy(router_cfg->nat_helper_tftp_ports, args->argv[5], 48);
	} else if (!no && args->argc == 4) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		strcpy(router_cfg->nat_helper_tftp_ports, "69"); /* netfilter_ipv4/ip_conntrack_tftp.h:#define TFTP_PORT 69 */
	}
	librouter_destroy_args(args);
}

void ssh_server(const char *cmd)
{
	if (librouter_nv_load_ssh_secret(SSH_KEY_FILE) < 0)
		fprintf(stderr, "%% ERROR: You must create RSA keys first (ip ssh key rsa 1024).\n");
	else
#ifdef OPTION_OPENSSH
		librouter_exec_daemon(SSH_DAEMON);
#else
	librouter_exec_set_inetd_program(1, SSH_DAEMON);
#endif
}

void no_ssh_server(const char *cmd)
{
#ifdef OPTION_OPENSSH
	librouter_kill_daemon(SSH_DAEMON);
#else
	librouter_exec_set_inetd_program(0, SSH_DAEMON);
#endif
}

void ssh_generate_rsa_key(const char *cmd) /* ip ssh key rsa 768-2048 */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (args->argc == 5) {
		printf("%% Please wait... computation may take long time!\n");
		if (librouter_ssh_create_rsakey(atoi(args->argv[4])) < 0) {
			printf("%% Not possible to generate RSA key!\n");
		}
	}
	librouter_destroy_args(args);
}

#ifdef OPTION_PIMD
#if 0
void pim_dense_server(const char *cmd) /* ip pim dense-mode */
{
	if (librouter_exec_check_daemon(PIMS_DAEMON)) librouter_kill_daemon(PIMS_DAEMON);
	librouter_exec_daemon(PIMD_DAEMON);
}

void no_pim_dense_server(const char *cmd)
{
	librouter_kill_daemon(PIMD_DAEMON);
}

void pim_sparse_server(const char *cmd) /* ip pim sparse-mode */
{
	if (librouter_exec_check_daemon(PIMD_DAEMON)) librouter_kill_daemon(PIMD_DAEMON);
	librouter_exec_daemon(PIMS_DAEMON);
}

void no_pim_sparse_server(const char *cmd)
{
	librouter_kill_daemon(PIMS_DAEMON);
}
#endif

void pim_dense_mode(const char *cmd) /* [no] ip pim dense-mode */
{
	int dense, sparse;
	char *dev;
	arglist *args;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmd);

	if (args->argc == 4 && !strcmp(args->argv[0], "no"))
		dense = librouter_pim_dense_phyint(0, dev);
	else {
#ifdef OPTION_SMCROUTE
		if (librouter_exec_check_daemon(SMC_DAEMON)) {
			printf("%% Disable static multicast routing first\n");
			goto clean;
		}
#endif
		sparse = librouter_pim_sparse_phyint(0, dev, 0 , 0);
		/* Kill pimsd if it is running */
		if (sparse < 2 && librouter_exec_check_daemon(PIMS_DAEMON))
			librouter_kill_daemon(PIMS_DAEMON);

		dense = librouter_pim_dense_phyint(1, dev);
	}

	if (dense < 2) {
		if (librouter_exec_check_daemon(PIMD_DAEMON))
			librouter_kill_daemon(PIMD_DAEMON);
	} else {
		if (!librouter_exec_check_daemon(PIMD_DAEMON))
			librouter_exec_daemon(PIMD_DAEMON);
	}
	clean: librouter_destroy_args(args);
	free(dev);
}

void pim_sparse_mode(const char *cmd) /* [no] ip pim sparse-mode */
{
	arglist *args;
	int enabled_intf = 0, i;
	args = librouter_make_args(cmd);
	dev_family *fam;
	char *dev=malloc(16);

	fam = librouter_device_get_family_by_type(eth);

	if (args->argc == 4 && !strcmp(args->argv[0], "no")){
		if (librouter_exec_check_daemon(PIMS_DAEMON)){
			librouter_kill_daemon(PIMS_DAEMON);
			librouter_pim_sparse_enable(0);
		}
	}
	else {
		for (i=0; i < OPTION_NUM_ETHERNET_IFACES; i++){
			snprintf(dev,16,"%s%d",fam->linux_string,i);
			enabled_intf = enabled_intf || librouter_pim_sparse_verify_intf_enable(dev);
		}

		if (enabled_intf){
			if (!librouter_exec_check_daemon(PIMS_DAEMON)){
				librouter_exec_daemon(PIMS_DAEMON);
				librouter_pim_sparse_enable(1);
			}
		}
		else {
			printf("\n%% Interface ethernet PIM configuration must be applied first");
			printf("\n%% Settings could not be applied\n\n");
		}
	}

	librouter_destroy_args(args);
	free(dev);
	dev=NULL;
}

void pim_sparse_mode_intf(const char *cmd) /* [no] ip pim sparse-mode */
{
#ifdef OPTION_PIMD_DENSE
	int dense = 0;
#endif
	int sparse = 0;
	char *dev;
	arglist *args;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmd);

	if (args->argc == 4 && !strcmp(args->argv[0], "no"))
		sparse = librouter_pim_sparse_phyint(0, dev, 0, 0); /*(remove, dev, NULL, NULL)*/
	else {
#ifdef OPTION_SMCROUTE
		if (librouter_exec_check_daemon(SMC_DAEMON)) {
			printf("%% Disable static multicast routing first\n");
			goto clean;
		}
#endif
#ifdef OPTION_PIMD_DENSE
		dense = librouter_pim_dense_phyint(0, dev);
		if (dense < 2 && librouter_exec_check_daemon(PIMD_DAEMON))
			librouter_kill_daemon(PIMD_DAEMON);
#endif

		if (args->argc == 3)
			sparse = librouter_pim_sparse_phyint(1, dev, 0, 0); /*(add, dev, NULL, NULL) - default config*/
		else
			if (args->argc == 7)
				sparse = librouter_pim_sparse_phyint(1, dev, atoi(args->argv[4]), atoi(args->argv[6])); /*(add, dev, preference, metric) - custom config*/

	}

	if (sparse < 0)
		syslog(LOG_ERR,"Problem with PIM conf file");

	clean: librouter_destroy_args(args);
	free(dev);
}

void pim_bsr_candidate(const char *cmd) /* [no] ip pim bsr-candidate <ethernet|serial> <0-x> [priority <0-255>] */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (!strcmp(args->argv[0], "no"))
		librouter_pim_sparse_bsr_candidate(0, NULL, NULL, NULL);
	else if (args->argc == 5)
		librouter_pim_sparse_bsr_candidate(1, librouter_device_to_linux_cmdline(args->argv[3]), args->argv[4], NULL);
	else if (args->argc == 7)
		librouter_pim_sparse_bsr_candidate(1, librouter_device_to_linux_cmdline(args->argv[3]), args->argv[4], args->argv[6]);
	librouter_destroy_args(args);
}

void pim_rp_address(const char *cmd) /* [no] ip pim rp-address <ipaddress> */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (!strcmp(args->argv[0], "no"))
		librouter_pim_sparse_rp_address(0, NULL);
	else if (args->argc == 4)
		librouter_pim_sparse_rp_address(1, args->argv[3]);
	librouter_destroy_args(args);
}

void pim_rp_candidate(const char *cmd) /* [no] ip pim rp-candidate <ethernet|serial> <0-0> [priority <0-255>] [interval <5-16383>] */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (!strcmp(args->argv[0], "no"))
		librouter_pim_sparse_rp_candidate(0, NULL, NULL, NULL, NULL);
	else if (args->argc == 5)
		librouter_pim_sparse_rp_candidate(1, librouter_device_to_linux_cmdline(args->argv[3]), args->argv[4], NULL, NULL);
	else if (args->argc == 7)
		librouter_pim_sparse_rp_candidate(1, librouter_device_to_linux_cmdline(args->argv[3]), args->argv[4], args->argv[6],
		                NULL);
	else if (args->argc == 9)
		librouter_pim_sparse_rp_candidate(1, librouter_device_to_linux_cmdline(args->argv[3]), args->argv[4], args->argv[6],
		                args->argv[8]);
	librouter_destroy_args(args);
}
#endif

void arp_entry(const char *cmd) /* [no] arp <ipaddress> [<mac>] */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (!strcmp(args->argv[0], "no"))
		librouter_arp_del(args->argv[2]);
	else if (args->argc == 3)
		librouter_arp_add(args->argv[1], args->argv[2]);
	librouter_destroy_args(args);
}

void clear_ssh_hosts(const char *cmd)
{
	remove(FILE_SSH_KNOWN_HOSTS);
}

void clear_counters(const char *cmd)
{
	arglist *args;
	dev_family *fam;
	char dev[32];
	char *p;
	int idx, subidx = 0;

	args = librouter_make_args(cmd);

	if (args->argc != 4) {
		librouter_destroy_args(args);
		return;
	}

	fam = librouter_device_get_family_by_name(args->argv[2], str_cish);
	idx = atoi(args->argv[3]);
	if ((p = strstr(args->argv[3], ".")) != NULL)
		subidx = atoi(p + 1);

#ifdef OPTION_EFM
	/* FIXME Do this in a specific function */
	if (fam->type == efm) {
		librouter_efm_clear_counters();
		idx += EFM_INDEX_OFFSET;
	}
#endif

	if (subidx)
		sprintf(dev,"%s%d.%d", fam->linux_string, idx, subidx);
	else
		sprintf(dev,"%s%d", fam->linux_string, idx);

	if (librouter_dev_clear_interface_counters(dev))
		printf("%% Could not clear counters : Interface exists? \n");

	librouter_destroy_args(args);
}
