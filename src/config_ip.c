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
#include <linux/config.h>
#include <linux/if_arp.h>

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"
#include "cish_main.h"
#include "cish_config.h"

int get_procip_val (const char *);

void ip_param (const char *cmd)
{
	const char	*dst_file;
	int  		 dst_val;
	FILE		*F;
	
	dst_file	= (const char *) NULL;
	dst_val     = -1;
	
	if (strncmp(cmd, "ip forwarding", 13) == 0 || strncmp(cmd, "ip routing", 10) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/ip_forward"; /* "/proc/sys/net/ipv4/conf/all/forwarding" */
		dst_val  = 1;
	}
#ifdef OPTION_PIMD
	else if (strncmp (cmd, "ip multicast-routing", 20) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/conf/all/mc_forwarding";
		dst_val = 1;
	}
#endif
	else if (strncmp (cmd, "ip pmtu-discovery", 17) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/ip_no_pmtu_disc";
		dst_val = 0;
	}
	else if (strncmp (cmd, "ip default-ttl ", 15) == 0)
	{
		if ((dst_val = atoi (cmd+15))<=0)
		{
			printf ("%% Parameter error\n");
			return;
		}
		dst_file = "/proc/sys/net/ipv4/ip_default_ttl";
	}
	else if (strncmp (cmd, "ip icmp ignore all", 18) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
		dst_val  = 1;
	}
	else if (strncmp (cmd, "ip icmp ignore broadcast", 24) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts";
		dst_val  = 1;
	}
	else if (strncmp (cmd, "ip icmp ignore bogus", 20) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses";
		dst_val  = 1;
	}
	else if (strncmp (cmd, "ip icmp rate dest-unreachable ", 30) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_destunreach_rate";
		dst_val  = atoi (cmd+30);
		
		if ((!dst_val)&&(cmd[30]!='0')) return;
	} 
	else if (strncmp (cmd, "ip icmp rate echo-reply ", 24) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_echoreply_rate";
		dst_val  = atoi (cmd+24);
		
		if ((!dst_val)&&(cmd[24]!='0')) return;
	}
	else if (strncmp (cmd, "ip icmp rate param-prob ", 24) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_paramprob_rate";
		dst_val  = atoi (cmd+24);
		
		if ((!dst_val)&&(cmd[24]!='0')) return;
	}
	else if (strncmp (cmd, "ip icmp rate time-exceed ", 25) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_timeexceed_rate";
		dst_val  = atoi (cmd+25);
		
		if ((!dst_val)&&(cmd[25]!='0')) return;
	}
	else if (strncmp (cmd, "ip fragment high ", 17) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/ipfrag_high_thresh";
		dst_val  = atoi (cmd+17);

		if ((!dst_val)&&(cmd[17]!='0')) return;
	}
	else if (strncmp (cmd, "ip fragment low ", 16) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/ipfrag_low_thresh";
		dst_val  = atoi (cmd+16);

		if ((!dst_val)&&(cmd[16]!='0')) return;
	}
	else if (strncmp (cmd, "ip fragment time ", 17) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/ipfrag_time";
		dst_val  = atoi (cmd+17);

		if ((!dst_val)&&(cmd[17]!='0')) return;
	}
	else if (strncmp (cmd, "ip tcp ecn", 10) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/tcp_ecn";
		dst_val = 1;
	}
	else if (strncmp (cmd, "ip tcp syncookies", 17) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/tcp_syncookies";
		dst_val = 1;
	}
	else if (strncmp (cmd, "ip rp-filter", 12) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/conf/all/rp_filter";
		dst_val = 1;
	}

	if (!dst_file)
	{
		printf ("%% Error\n");
		return;
	}
	
	F = fopen (dst_file, "w");
	if (!F)
	{
		printf ("%% Error opening %s\n", dst_file);
		return;
	}
	fprintf (F, "%d", dst_val);
	fclose (F);
}

void no_ip_param (const char *_cmd)
{
	const char	*cmd;
	const char	*dst_file;
	int  		 dst_val;
	FILE		*F;
	
	cmd = _cmd + 3;
	
	dst_file	= (const char *) NULL;
	dst_val     = -1;
	
	if (strncmp(cmd, "ip forwarding", 13) == 0 || strncmp(cmd, "ip routing", 10) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/ip_forward"; /* "/proc/sys/net/ipv4/conf/all/forwarding" */
		dst_val  = 0;
	}
#ifdef OPTION_PIMD
	else if (strncmp (cmd, "ip multicast-routing", 20) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/conf/all/mc_forwarding";
		dst_val = 0;
	}
#endif
	else if (strncmp (cmd, "ip pmtu-discovery", 17) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/ip_no_pmtu_disc";
		dst_val = 1;
	}
	else if (strncmp (cmd, "ip icmp ignore all", 18) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
		dst_val  = 0;
	}
	else if (strncmp (cmd, "ip icmp ignore broadcast", 24) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts";
		dst_val  = 0;
	}
	else if (strncmp (cmd, "ip icmp ignore bogus", 20) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses";
		dst_val  = 0;
	}
	else if (strncmp (cmd, "ip tcp ecn", 10) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/tcp_ecn";
		dst_val = 0;
	}
	else if (strncmp (cmd, "ip tcp syncookies", 17) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/tcp_syncookies";
		dst_val = 0;
	}
	else if (strncmp (cmd, "ip rp-filter", 12) == 0)
	{
		dst_file = "/proc/sys/net/ipv4/conf/all/rp_filter";
		dst_val = 0;
	}

	if (!dst_file)
	{
		printf ("%% Error\n");
		return;
	}
	
	F = fopen (dst_file, "w");
	if (!F)
	{
		printf ("%% Error opening %s\n", dst_file);
		return;
	}
	fprintf (F, "%d", dst_val);
	fclose (F);
}

int get_procip_val (const char *parm)
{
	int   fid;
	
	sprintf (buf, "/proc/sys/net/ipv4/%s", parm);
	fid = open (buf, O_RDONLY);
	if (fid < 0)
	{
		printf ("%% Error opening %s\n%% %s\n", buf, strerror (errno));
		return -1;
	}
	read (fid, buf, 16);
	close (fid);
	return atoi (buf);
}

void dump_ip (FILE *out, int conf_format)
{
	int val;

	val = get_procip_val ("ip_forward");
#if 1
	fprintf (out, val ? "ip routing\n" : "no ip routing\n");
#else
	fprintf (out, val ? "ip forwarding\n" : "no ip forwarding\n");
#endif
#ifdef OPTION_PIMD
	val = get_procip_val ("conf/all/mc_forwarding");
	fprintf (out, val ? "ip multicast-routing\n" : "no ip multicast-routing\n");
#endif
	val = get_procip_val ("ip_no_pmtu_disc");
	fprintf (out, val ? "no ip pmtu-discovery\n" : "ip pmtu-discovery\n");

	val = get_procip_val ("ip_default_ttl");
	fprintf (out, "ip default-ttl %i\n", val);

	val = get_procip_val ("conf/all/rp_filter");
	fprintf (out, val ? "ip rp-filter\n" : "no ip rp-filter\n");

	val = get_procip_val ("icmp_echo_ignore_all");
	fprintf (out, val ? "ip icmp ignore all\n" : "no ip icmp ignore all\n");

	val = get_procip_val ("icmp_echo_ignore_broadcasts");
	fprintf (out, val ? "ip icmp ignore broadcasts\n" : "no ip icmp ignore broadcasts\n");

	val = get_procip_val ("icmp_ignore_bogus_error_responses");
	fprintf (out, val ? "ip icmp ignore bogus\n" : "no ip icmp ignore bogus\n");

#if 0 /* This are not present in earlier kernel versions ... is this PD3 invention ? */
	val = get_procip_val ("icmp_destunreach_rate");
	fprintf (out, "ip icmp rate dest-unreachable %i\n", val);

	val = get_procip_val ("icmp_echoreply_rate");
	fprintf (out, "ip icmp rate echo-reply %i\n", val);

	val = get_procip_val ("icmp_paramprob_rate");
	fprintf (out, "ip icmp rate param-prob %i\n", val);

	val = get_procip_val ("icmp_timeexceed_rate");
	fprintf (out, "ip icmp rate time-exceed %i\n", val);
#endif

	val = get_procip_val ("ipfrag_high_thresh");
	fprintf (out, "ip fragment high %i\n", val);

	val = get_procip_val ("ipfrag_low_thresh");
	fprintf (out, "ip fragment low %i\n", val);

	val = get_procip_val ("ipfrag_time");
	fprintf (out, "ip fragment time %i\n", val);

	val = get_procip_val ("tcp_ecn");
	fprintf (out, val ? "ip tcp ecn\n" : "no ip tcp ecn\n");

	val = get_procip_val ("tcp_syncookies");
	fprintf (out, val ? "ip tcp syncookies\n" : "no ip tcp syncookies\n");

	fprintf (out, "!\n");
}

void dump_ip_nameservers(FILE *out, int conf_format)
{
	char addr[16];
	unsigned int i;

	/* Lista servidores DNS estaticos */
	for (i=0; i < DNS_MAX_SERVERS; i++) {
		if (get_nameserver_by_type_index(DNS_STATIC_NAMESERVER, i, addr) < 0)
			break;
		fprintf(out, "ip name-server %s\n", addr);
	}
}

void dump_ip_servers(FILE *out, int conf_format)
{
	char buf[2048];
	int dhcp;

	dhcp=get_dhcp();
	if (dhcp == DHCP_SERVER)
	{
		if (get_dhcp_server(buf) == 0)
		{
			fprintf(out, "%s\n", buf);
			fprintf(out, "no ip dhcp relay\n");
		}
	}
	else if (dhcp == DHCP_RELAY)
	{
		if (get_dhcp_relay(buf) == 0)
		{
			fprintf(out, "no ip dhcp server\n");
			fprintf(out, "ip dhcp relay %s\n", buf);
		}
	}
	else
	{
		fprintf(out, "no ip dhcp server\n");
		fprintf(out, "no ip dhcp relay\n");
	}

	fprintf (out, "%sip dns relay\n", is_daemon_running(DNS_DAEMON) ? "" : "no ");
	fprintf (out, "%sip domain lookup\n", is_domain_lookup_enabled() ? "" : "no ");
	dump_ip_nameservers(out, conf_format);

#ifdef OPTION_HTTP
	fprintf (out, "%sip http server\n", is_daemon_running(HTTP_DAEMON) ? "" : "no ");
#endif
#ifdef OPTION_PIMD
#if 0
	if (is_daemon_running(PIMD_DAEMON)) fprintf(out, "ip pim dense-mode\n");
	if (is_daemon_running(PIMS_DAEMON)) fprintf(out, "ip pim sparse-mode\n");
#endif
	dump_pim(out, conf_format);
#endif
#ifdef OPTION_OPENSSH
	fprintf (out, "%sip ssh server\n", is_daemon_running(SSH_DAEMON) ? "" : "no ");
#else
	fprintf (out, "%sip ssh server\n", get_inetd_program(SSH_DAEMON) ? "" : "no ");
#endif
	fprintf (out, "%sip telnet server\n", get_inetd_program(TELNET_DAEMON) ? "" : "no ");
	fprintf (out, "!\n");
}

#ifdef OPTION_HTTP
void http_server (const char *cmd)
{
	exec_daemon(HTTP_DAEMON);
}

void no_http_server (const char *cmd)
{
	kill_daemon(HTTP_DAEMON);
}
#endif

void telnet_server(const char *cmd)
{
	set_inetd_program(1, TELNET_DAEMON);
}

void no_telnet_server(const char *cmd)
{
	set_inetd_program(0, TELNET_DAEMON);
}

void dhcp_server(const char *cmd)
{
	set_dhcp_server(1, (char*)cmd);
}

void no_dhcp_server(const char *cmd)
{
	set_no_dhcp_server();
}

void dhcp_relay(const char *cmd)
{
	char *p;
	
	p=strstr(cmd, "relay");
	if (!p) return;
	p += 5;
	while (*p == ' ') p++;
	set_dhcp_relay(p);
}

void no_dhcp_relay(const char *cmd)
{
	set_no_dhcp_relay();
}

void ip_dnsrelay(const char *cmd) /* [no] ip dns relay */
{
	arglist *args;

	args=make_args(cmd);
	if (args->argc == 4) kill_daemon(DNS_DAEMON);
		else exec_daemon(DNS_DAEMON);
	destroy_args(args);
}

void ip_domainlookup(const char *cmd) /* [no] ip domain lookup */
{
	arglist *args;

	args=make_args(cmd);
	if (args->argc == 4) dns_lookup(0);
		else dns_lookup(1);
	destroy_args(args);
}

void ip_nameserver(const char *cmd) /* [no] ip name-server <ipaddress> */
{
	arglist *args;

	args = make_args(cmd);
	switch (args->argc) {
		case 3:
			dns_nameserver(1, args->argv[2]);
			break;
		case 4:
			dns_nameserver(0, args->argv[3]);
			break;
	}
	destroy_args(args);
}

int delete_module(const char *name);

void ip_nat_ftp(const char *cmd) /* [no] ip nat helper ftp [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args=make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) no=1;
		else no=0;
	/* always remove modules first... */
	sprintf(buf, "ip_nat_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	sprintf(buf, "ip_conntrack_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	cish_cfg->nat_helper_ftp_ports[0]=0;
	if (!no && args->argc == 6) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s ports=%s >/dev/null 2>/dev/null", args->argv[3], args->argv[5]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s ports=%s >/dev/null 2>/dev/null", args->argv[3], args->argv[5]);
		system(buf);
		strncpy(cish_cfg->nat_helper_ftp_ports, args->argv[5], 48);
	} else if (!no && args->argc == 4) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		strcpy(cish_cfg->nat_helper_ftp_ports, "21"); /* netfilter_ipv4/ip_conntrack_ftp.h:#define FTP_PORT      21 */
	}
	destroy_args(args);
}

void ip_nat_irc(const char *cmd) /* [no] ip nat helper irc [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args=make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) no=1;
		else no=0;
	/* always remove modules first... */
	sprintf(buf, "ip_nat_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	sprintf(buf, "ip_conntrack_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	cish_cfg->nat_helper_irc_ports[0]=0;
	if (!no && args->argc == 6) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s ports=%s >/dev/null 2>/dev/null", args->argv[3], args->argv[5]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s ports=%s >/dev/null 2>/dev/null", args->argv[3], args->argv[5]);
		system(buf);
		strncpy(cish_cfg->nat_helper_irc_ports, args->argv[5], 48);
	} else if (!no && args->argc == 4) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		strcpy(cish_cfg->nat_helper_irc_ports, "6667"); /* netfilter_ipv4/ip_conntrack_irc.h:#define IRC_PORT      6667 */
	}
	destroy_args(args);
}

void ip_nat_tftp(const char *cmd) /* [no] ip nat helper tftp [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args=make_args(cmd);
	if (strcmp(args->argv[0], "no") == 0) no=1;
		else no=0;
	/* always remove modules first... */
	sprintf(buf, "ip_nat_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	sprintf(buf, "ip_conntrack_%s", args->argv[no ? 4 : 3]);
	delete_module(buf);
	cish_cfg->nat_helper_tftp_ports[0]=0;
	if (!no && args->argc == 6) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s ports=%s >/dev/null 2>/dev/null", args->argv[3], args->argv[5]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s ports=%s >/dev/null 2>/dev/null", args->argv[3], args->argv[5]);
		system(buf);
		strncpy(cish_cfg->nat_helper_tftp_ports, args->argv[5], 48);
	} else if (!no && args->argc == 4) {
		snprintf(buf, 127, "modprobe ip_conntrack_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		snprintf(buf, 127, "modprobe ip_nat_%s >/dev/null 2>/dev/null", args->argv[3]);
		system(buf);
		strcpy(cish_cfg->nat_helper_tftp_ports, "69"); /* netfilter_ipv4/ip_conntrack_tftp.h:#define TFTP_PORT 69 */
	}
	destroy_args(args);
}

void dump_nat_helper(FILE *F)
{
	if (cish_cfg->nat_helper_ftp_ports[0]) {
		fprintf(F, "ip nat helper ftp ports %s\n", cish_cfg->nat_helper_ftp_ports);
	} else {
		fprintf(F, "no ip nat helper ftp\n");
	}
	if (cish_cfg->nat_helper_irc_ports[0]) {
		fprintf(F, "ip nat helper irc ports %s\n", cish_cfg->nat_helper_irc_ports);
	} else {
		fprintf(F, "no ip nat helper irc\n");
	}
	if (cish_cfg->nat_helper_tftp_ports[0]) {
		fprintf(F, "ip nat helper tftp ports %s\n", cish_cfg->nat_helper_tftp_ports);
	} else {
		fprintf(F, "no ip nat helper tftp\n");
	}
	fprintf(F, "!\n");
}

void ssh_server(const char *cmd)
{
	if (load_ssh_secret(SSH_KEY_FILE) < 0) fprintf(stderr, "%% ERROR: You must create RSA keys first (ip ssh key rsa 1024).\n");
		else
#ifdef OPTION_OPENSSH
				exec_daemon(SSH_DAEMON);
#else
				set_inetd_program(1, SSH_DAEMON);
#endif
}

void no_ssh_server(const char *cmd)
{
#ifdef OPTION_OPENSSH
	kill_daemon(SSH_DAEMON);
#else
	set_inetd_program(0, SSH_DAEMON);
#endif
}

void ssh_generate_rsa_key(const char *cmd) /* ip ssh key rsa 512-2048 */
{
	arglist *args;

	args=make_args(cmd);
	if (args->argc == 5)
	{
		printf("%% Please wait... computation may take long time!\n");
		if (ssh_create_rsakey(atoi(args->argv[4])) < 0)
		{
			printf("%% Not possible to generate RSA key!\n");
		}
	}
	destroy_args(args);
}

#ifdef OPTION_PIMD
#if 0
void pim_dense_server(const char *cmd) /* ip pim dense-mode */
{
	if (is_daemon_running(PIMS_DAEMON)) kill_daemon(PIMS_DAEMON);
	exec_daemon(PIMD_DAEMON);
}

void no_pim_dense_server(const char *cmd)
{
	kill_daemon(PIMD_DAEMON);
}

void pim_sparse_server(const char *cmd) /* ip pim sparse-mode */
{
	if (is_daemon_running(PIMD_DAEMON)) kill_daemon(PIMD_DAEMON);
	exec_daemon(PIMS_DAEMON);
}

void no_pim_sparse_server(const char *cmd)
{
	kill_daemon(PIMS_DAEMON);
}
#endif

extern device_family *interface_edited;
extern int interface_major, interface_minor;

void pim_dense_mode(const char *cmd) /* [no] ip pim dense-mode */
{
	int dense, sparse;
	char *dev;
	arglist *args;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmd);

	if (args->argc == 4 && !strcmp(args->argv[0], "no")) 
		dense = pimdd_phyint(0, dev);
	else {
#ifdef OPTION_SMCROUTE
		if (is_daemon_running(SMC_DAEMON))
		{
			printf("%% Disable static multicast routing first\n");
			goto clean;
		}
#endif
		sparse = pimsd_phyint(0, dev);
		/* Kill pimsd if it is running */			
		if (sparse < 2 && is_daemon_running(PIMS_DAEMON)) 
			kill_daemon(PIMS_DAEMON);

		dense = pimdd_phyint(1, dev);
	}

	if (dense < 2)	{
		if (is_daemon_running(PIMD_DAEMON)) 
			kill_daemon(PIMD_DAEMON);
	} else {
		if (!is_daemon_running(PIMD_DAEMON)) 
			exec_daemon(PIMD_DAEMON);
	}
clean:
	destroy_args(args);
	free(dev);
}

void pim_sparse_mode(const char *cmd) /* [no] ip pim sparse-mode */
{
	int dense, sparse;
	char *dev;
	arglist *args;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmd);

	if (args->argc == 4 && !strcmp(args->argv[0], "no")) 
		sparse=pimsd_phyint(0, dev);
	else {
#ifdef OPTION_SMCROUTE
		if (is_daemon_running(SMC_DAEMON))
		{
			printf("%% Disable static multicast routing first\n");
			goto clean;
		}
#endif
		dense = pimdd_phyint(0, dev);
		if (dense < 2 && is_daemon_running(PIMD_DAEMON)) 
			kill_daemon(PIMD_DAEMON);
		sparse = pimsd_phyint(1, dev);
	}

	if (sparse < 2)	{
		if (is_daemon_running(PIMS_DAEMON)) 
			kill_daemon(PIMS_DAEMON);
	} else {
		if (!is_daemon_running(PIMS_DAEMON)) 
			exec_daemon(PIMS_DAEMON);
	}
clean:
	destroy_args(args);
	free(dev);
}

void pim_bsr_candidate(const char *cmd) /* [no] ip pim bsr-candidate <ethernet|serial> <0-x> [priority <0-255>] */
{
	arglist *args;

	args=make_args(cmd);
	if (!strcmp(args->argv[0], "no")) pimsd_bsr_candidate(0, NULL, NULL, NULL);
		else if (args->argc == 5) pimsd_bsr_candidate(1, args->argv[3], args->argv[4], NULL);
			else if (args->argc == 7) pimsd_bsr_candidate(1, args->argv[3], args->argv[4], args->argv[6]);
	destroy_args(args);
}

void pim_rp_address(const char *cmd) /* [no] ip pim rp-address <ipaddress> */
{
	arglist *args;

	args=make_args(cmd);
	if (!strcmp(args->argv[0], "no")) pimsd_rp_address(0, NULL);
		else if (args->argc == 4) pimsd_rp_address(1, args->argv[3]);
	destroy_args(args);
}

void pim_rp_candidate(const char *cmd) /* [no] ip pim rp-candidate <ethernet|serial> <0-0> [priority <0-255>] [interval <5-16383>] */
{
	arglist *args;

	args=make_args(cmd);
	if (!strcmp(args->argv[0], "no")) pimsd_rp_candidate(0, NULL, NULL, NULL, NULL);
		else if (args->argc == 5) pimsd_rp_candidate(1, args->argv[3], args->argv[4], NULL, NULL);
			else if (args->argc == 7) pimsd_rp_candidate(1, args->argv[3], args->argv[4], args->argv[6], NULL);
				else if (args->argc == 9) pimsd_rp_candidate(1, args->argv[3], args->argv[4], args->argv[6], args->argv[8]);
	destroy_args(args);
}
#endif

void arp_entry(const char *cmd) /* [no] arp <ipaddress> [<mac>] */
{
	arglist *args;

	args=make_args(cmd);
	if (!strcmp(args->argv[0], "no")) arp_del(args->argv[2]);
		else if (args->argc == 3) arp_add(args->argv[1], args->argv[2]);
	destroy_args(args);
}

void dump_arp(FILE *out)
{
	FILE	*F;
	char	*ipaddr;
	char	*hwaddr;
	char	*type;
	char	*osdev;
	long	flags;
	arglist *args;
	int print_something=0;
	char tbuf[128];

	F = fopen("/proc/net/arp", "r");
	if (!F)
	{
		printf("%% Unable to read ARP table\n");
		return;
	}
	fgets (tbuf, 127, F);
	while (!feof (F))
	{
		tbuf[0] = 0;
		fgets (tbuf, 127, F);
		tbuf[127] = 0;
		striplf (tbuf);
		args=make_args(tbuf);
		if (args->argc >= 6)
		{
			ipaddr = args->argv[0];
			hwaddr = args->argv[3];
			type   = args->argv[1];
			osdev  = args->argv[5];
			flags = strtoul(args->argv[2], 0, 16);
			if (flags&ATF_PERM) // permanent entry
			{
				fprintf(out, "arp %s %s\n", ipaddr, hwaddr);
				print_something=1;
			}
		}
		destroy_args(args);
	}
	if (print_something) fprintf(out, "!\n");
}

void clear_ssh_hosts(const char *cmd)
{
	remove(FILE_SSH_KNOWN_HOSTS);
}
