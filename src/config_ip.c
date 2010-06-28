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

#ifdef OPTION_HTTP
void http_server (const char *cmd)
{
	libconfig_exec_daemon(HTTP_DAEMON);
}

void no_http_server (const char *cmd)
{
	libconfig_kill_daemon(HTTP_DAEMON);
}
#endif

#ifdef OPTION_HTTPS
void https_server (const char *cmd)
{
	libconfig_exec_daemon(HTTPS_DAEMON);
}

void no_https_server (const char *cmd)
{
	libconfig_kill_daemon(HTTPS_DAEMON);
}
#endif

void telnet_server(const char *cmd)
{
	libconfig_exec_set_inetd_program(1, TELNET_DAEMON);
}

void no_telnet_server(const char *cmd)
{
	libconfig_exec_set_inetd_program(0, TELNET_DAEMON);
}

void dhcp_server(const char *cmd)
{
	libconfig_dhcp_set_server(1, (char*)cmd);
}

void no_dhcp_server(const char *cmd)
{
	libconfig_dhcp_set_no_server();
}

void dhcp_relay(const char *cmd)
{
	char *p;
	
	p=strstr(cmd, "relay");
	if (!p) return;
	p += 5;
	while (*p == ' ') p++;
	libconfig_dhcp_set_relay(p);
}

void no_dhcp_relay(const char *cmd)
{
	libconfig_dhcp_set_no_relay();
}

void ip_dnsrelay(const char *cmd) /* [no] ip dns relay */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (args->argc == 4)
		libconfig_kill_daemon(DNS_DAEMON);
	else
		libconfig_exec_daemon(DNS_DAEMON);
	libconfig_destroy_args(args);
}

void ip_domainlookup(const char *cmd) /* [no] ip domain lookup */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (args->argc == 4) libconfig_dns_lookup(0);
		else libconfig_dns_lookup(1);
	libconfig_destroy_args(args);
}

void ip_nameserver(const char *cmd) /* [no] ip name-server <ipaddress> */
{
	arglist *args;

	args = libconfig_make_args(cmd);
	switch (args->argc) {
		case 3:
			libconfig_dns_nameserver(1, args->argv[2]);
			break;
		case 4:
			libconfig_dns_nameserver(0, args->argv[3]);
			break;
	}
	libconfig_destroy_args(args);
}

int delete_module(const char *name);

void ip_nat_ftp(const char *cmd) /* [no] ip nat helper ftp [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args=libconfig_make_args(cmd);
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
	libconfig_destroy_args(args);
}

void ip_nat_irc(const char *cmd) /* [no] ip nat helper irc [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args=libconfig_make_args(cmd);
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
	libconfig_destroy_args(args);
}

void ip_nat_tftp(const char *cmd) /* [no] ip nat helper tftp [ports <ports>] */
{
	arglist *args;
	char buf[128];
	int no;

	args=libconfig_make_args(cmd);
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
	libconfig_destroy_args(args);
}

void ssh_server(const char *cmd)
{
	if (libconfig_nv_load_ssh_secret(SSH_KEY_FILE) < 0) fprintf(stderr, "%% ERROR: You must create RSA keys first (ip ssh key rsa 1024).\n");
		else
#ifdef OPTION_OPENSSH
				libconfig_exec_daemon(SSH_DAEMON);
#else
				libconfig_exec_set_inetd_program(1, SSH_DAEMON);
#endif
}

void no_ssh_server(const char *cmd)
{
#ifdef OPTION_OPENSSH
	libconfig_kill_daemon(SSH_DAEMON);
#else
	libconfig_exec_set_inetd_program(0, SSH_DAEMON);
#endif
}

void ssh_generate_rsa_key(const char *cmd) /* ip ssh key rsa 512-2048 */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (args->argc == 5)
	{
		printf("%% Please wait... computation may take long time!\n");
		if (libconfig_ssh_create_rsakey(atoi(args->argv[4])) < 0)
		{
			printf("%% Not possible to generate RSA key!\n");
		}
	}
	libconfig_destroy_args(args);
}

#ifdef OPTION_PIMD
#if 0
void pim_dense_server(const char *cmd) /* ip pim dense-mode */
{
	if (libconfig_exec_check_daemon(PIMS_DAEMON)) libconfig_kill_daemon(PIMS_DAEMON);
	libconfig_exec_daemon(PIMD_DAEMON);
}

void no_pim_dense_server(const char *cmd)
{
	libconfig_kill_daemon(PIMD_DAEMON);
}

void pim_sparse_server(const char *cmd) /* ip pim sparse-mode */
{
	if (libconfig_exec_check_daemon(PIMD_DAEMON)) libconfig_kill_daemon(PIMD_DAEMON);
	libconfig_exec_daemon(PIMS_DAEMON);
}

void no_pim_sparse_server(const char *cmd)
{
	libconfig_kill_daemon(PIMS_DAEMON);
}
#endif

void pim_dense_mode(const char *cmd) /* [no] ip pim dense-mode */
{
	int dense, sparse;
	char *dev;
	arglist *args;

	dev=libconfig_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	args=libconfig_make_args(cmd);

	if (args->argc == 4 && !strcmp(args->argv[0], "no")) 
		dense = libconfig_pim_dense_phyint(0, dev);
	else {
#ifdef OPTION_SMCROUTE
		if (libconfig_exec_check_daemon(SMC_DAEMON))
		{
			printf("%% Disable static multicast routing first\n");
			goto clean;
		}
#endif
		sparse = libconfig_pim_sparse_phyint(0, dev);
		/* Kill pimsd if it is running */			
		if (sparse < 2 && libconfig_exec_check_daemon(PIMS_DAEMON)) 
			libconfig_kill_daemon(PIMS_DAEMON);

		dense = libconfig_pim_dense_phyint(1, dev);
	}

	if (dense < 2)	{
		if (libconfig_exec_check_daemon(PIMD_DAEMON)) 
			libconfig_kill_daemon(PIMD_DAEMON);
	} else {
		if (!libconfig_exec_check_daemon(PIMD_DAEMON)) 
			libconfig_exec_daemon(PIMD_DAEMON);
	}
clean:
	libconfig_destroy_args(args);
	free(dev);
}

void pim_sparse_mode(const char *cmd) /* [no] ip pim sparse-mode */
{
	int dense, sparse;
	char *dev;
	arglist *args;

	dev=libconfig_device_convert(interface_edited->cish_string, interface_major, interface_minor);
	args=libconfig_make_args(cmd);

	if (args->argc == 4 && !strcmp(args->argv[0], "no")) 
		sparse=libconfig_pim_sparse_phyint(0, dev);
	else {
#ifdef OPTION_SMCROUTE
		if (libconfig_exec_check_daemon(SMC_DAEMON))
		{
			printf("%% Disable static multicast routing first\n");
			goto clean;
		}
#endif
		dense = libconfig_pim_dense_phyint(0, dev);
		if (dense < 2 && libconfig_exec_check_daemon(PIMD_DAEMON)) 
			libconfig_kill_daemon(PIMD_DAEMON);
		sparse = libconfig_pim_sparse_phyint(1, dev);
	}

	if (sparse < 2)	{
		if (libconfig_exec_check_daemon(PIMS_DAEMON)) 
			libconfig_kill_daemon(PIMS_DAEMON);
	} else {
		if (!libconfig_exec_check_daemon(PIMS_DAEMON)) 
			libconfig_exec_daemon(PIMS_DAEMON);
	}
clean:
	libconfig_destroy_args(args);
	free(dev);
}

void pim_bsr_candidate(const char *cmd) /* [no] ip pim bsr-candidate <ethernet|serial> <0-x> [priority <0-255>] */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (!strcmp(args->argv[0], "no")) libconfig_pim_sparse_bsr_candidate(0, NULL, NULL, NULL);
		else if (args->argc == 5) libconfig_pim_sparse_bsr_candidate(1, args->argv[3], args->argv[4], NULL);
			else if (args->argc == 7) libconfig_pim_sparse_bsr_candidate(1, args->argv[3], args->argv[4], args->argv[6]);
	libconfig_destroy_args(args);
}

void pim_rp_address(const char *cmd) /* [no] ip pim rp-address <ipaddress> */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (!strcmp(args->argv[0], "no")) libconfig_pim_sparse_rp_address(0, NULL);
		else if (args->argc == 4) libconfig_pim_sparse_rp_address(1, args->argv[3]);
	libconfig_destroy_args(args);
}

void pim_rp_candidate(const char *cmd) /* [no] ip pim rp-candidate <ethernet|serial> <0-0> [priority <0-255>] [interval <5-16383>] */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (!strcmp(args->argv[0], "no")) libconfig_pim_sparse_rp_candidate(0, NULL, NULL, NULL, NULL);
		else if (args->argc == 5) libconfig_pim_sparse_rp_candidate(1, args->argv[3], args->argv[4], NULL, NULL);
			else if (args->argc == 7) libconfig_pim_sparse_rp_candidate(1, args->argv[3], args->argv[4], args->argv[6], NULL);
				else if (args->argc == 9) libconfig_pim_sparse_rp_candidate(1, args->argv[3], args->argv[4], args->argv[6], args->argv[8]);
	libconfig_destroy_args(args);
}
#endif

void arp_entry(const char *cmd) /* [no] arp <ipaddress> [<mac>] */
{
	arglist *args;

	args=libconfig_make_args(cmd);
	if (!strcmp(args->argv[0], "no")) libconfig_arp_del(args->argv[2]);
		else if (args->argc == 3) libconfig_arp_add(args->argv[1], args->argv[2]);
	libconfig_destroy_args(args);
}

void clear_ssh_hosts(const char *cmd)
{
	remove(FILE_SSH_KNOWN_HOSTS);
}
