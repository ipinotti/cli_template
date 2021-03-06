#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <dirent.h>

#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/mii.h>
#include <syslog.h>

#define __USE_XOPEN
#include <time.h>
#include <linux/if_vlan.h>	/* 802.1p mappings */

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"
#include "terminal_echo.h"

#include <librouter/options.h>
#include <librouter/usb.h>
#include <librouter/pptp.h>
#include <librouter/acl.h>
#include <librouter/pbr.h>
#include <librouter/pam.h>
#include <librouter/wifi.h>

#define PPPDEV "ppp"

extern int _cish_aux;
extern char *tzname[2];

static char tbuf[256];

void show_output(FILE *tf)
{
	if (tf == NULL)
		return;

	while (!feof(tf)) {
		tbuf[0] = 0;
		fgets(tbuf, 255, tf);
		tbuf[255] = 0;
		if (strlen(tbuf))
			pprintf("%s", tbuf);
	}
}

void show_cpu(const char *cmdline)
{
	float cpu;
	long long idle, user, nice, system, iowait, irq, softirq;
	static long long idle_old = 0, nice_old = 0, user_old = 0, system_old = 0;
	static long long iowait_old = 0, irq_old = 0, softirq_old = 0;
	FILE *tf;

	float scale;
	/* enough for a /proc/stat CPU line (not the intr line) */
	char buf[256];

	tf = fopen("/proc/stat", "r");
	if (tf) {
		fgets(buf, sizeof(buf), tf);
		if (sscanf(buf, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu", &user, &nice, &system, &idle, &iowait,
		                &irq, &softirq) == 7) {
			scale = 100.0 / (float) ((user - user_old) + (nice - nice_old)
			                + (system - system_old) + (idle - idle_old) + (iowait - iowait_old)
			                + (irq - irq_old) + (softirq - softirq_old));

			cpu = (float) ((user - user_old) + (nice - nice_old) + (system - system_old)
			                + (iowait - iowait_old) + (irq - irq_old) + (softirq - softirq_old))
			                * scale;
#if 0
			pprintf ("processor usage : %#5.1f%% user, %#5.1f%% system, %#5.1f%% nice, %#5.1f%% idle\n"
					"\t%#5.1f%% iowait, %#5.1f%% irq, %#5.1f%% softirq\n",
					(float)(user-user_old)*scale, (float)(system-system_old)*scale,
					(float)(nice-nice_old)*scale, (float)(idle-idle_old)*scale,
					(float)(iowait-iowait_old)*scale, (float)(irq-irq_old)*scale,
					(float)(softirq-softirq_old)*scale);

#else
			pprintf("processor usage : %0.1f%% system, %0.1f%% idle\n", cpu,
			                (float) (idle - idle_old) * scale);
#endif

			user_old = user;
			nice_old = nice;
			system_old = system;
			idle_old = idle;
			iowait_old = iowait;
			irq_old = irq;
			softirq_old = softirq;
		}
		fclose(tf);
	}
	tf = fopen("/proc/cpuinfo", "r");
	if (tf == NULL) {
		printf("Could not ready cpu information\n");
		return;
	}

	while (!feof(tf)) {
		tbuf[0] = 0;
		fgets(tbuf, 255, tf);

		tbuf[255] = 0;
		if (strlen(tbuf))
			pprintf("%s", tbuf);
	}

	fclose(tf);
}

/* <7> Jan  9 23:41:40 kernel: X.25(1): TX on serial0 size=131 frametype=0x54 */
static int show_logging_file(time_t tm_start, FILE *tf)
{
	int status;
	pid_t pid;
	time_t tm = 0;
	struct tm tm_time;

	save_termios();
	switch (pid = fork()) {
	case -1:
		fprintf(stderr, "%% No processes left\n");
		return -1;

	case 0:
		pager_init();
		signal(SIGINT, SIG_DFL);
		while (!feof(tf)) {
			char *date, *info, *p;
			char name[16];
			int last_one_was_printed = 0;

			if (pager_skipping())
				raise(SIGINT);

			tbuf[0] = 0;
			fgets(tbuf, 255, tf);
			tbuf[255] = 0;

			if (!strlen(tbuf))
				continue;

			/* Get data -> Jan  9 23:41:40 */
			tbuf[16] = 0;
			date = tbuf;

			/* Get the rest -> DigistarEFM user.info kernel: X.25(1): TX on serial0 size=131 frametype=0x54 */
			info = tbuf + 17;

			if (tm_start) {
				time(&tm);
				localtime_r(&tm, &tm_time);
				strptime(date, "%b %d %T", &tm_time);
				tm = mktime(&tm_time);
				if (tm < tm_start)
					continue; /* skip! */
			}

			p = librouter_debug_find_token(info, name, 1);
			if (p != NULL) {
				last_one_was_printed = 1;
				pprintf("%s %s%s", date, name, p);
			} else {
				if ((strncmp(info, "last message repeated", 21) == 0) && last_one_was_printed) {
					pprintf("%s %s", date, info);
				}
#if 0 //#ifdef CONFIG_DEVELOPMENT /* Show all lines... */
				else
				pprintf("%s %s", date, info);
#endif
			}
			last_one_was_printed = 0;

		}
		exit(0);

	default:
		waitpid(pid, &status, 0);
		signal(SIGINT, SIG_IGN);
		reload_termios();
		break;
	}
	fclose(tf);
	if (WIFSIGNALED(status))
		if (WTERMSIG(status) == SIGINT)
			return -1;
	return 0;
}

void show_logging(const char *cmdline) /* show logging [tail] */
{
	int i;
	arglist *args;
	char logname[32];

	int tail = 0;
	int hour, min, sec;
	time_t tm = 0;
	struct tm tm_time;

	FILE *tf;

	args = librouter_make_args(cmdline);
	if (args->argc > 2) {
		if (strcmp(args->argv[2], "tail") == 0) {
			tail = 1;
		} else {
			if (parse_time(args->argv[2], &hour, &min, &sec) < 0) {
				librouter_destroy_args(args);
				return;
			}
			time(&tm);
			localtime_r(&tm, &tm_time);
			tm_time.tm_hour = hour;
			tm_time.tm_min = min;
			tm_time.tm_sec = sec;
			if (args->argc > 3)
				tm_time.tm_mday = atoi(args->argv[3]);
			if (args->argc > 4)
				tm_time.tm_mon = atoi(args->argv[4]) - 1;
			if (args->argc > 5)
				tm_time.tm_year = atoi(args->argv[5]) - 1900;
			tm = mktime(&tm_time);
		}
	}
	if (!tail) {
#ifdef OPTION_IPSEC
		for (i = 199; i >= 0; i--) /* have to match syslogd configuration */
#else
		for (i=49; i >= 0; i--) /* have to match syslogd configuration */
#endif
		{
			sprintf(logname, "/var/log/messages.%d", i);
			if ((tf = fopen(logname, "r")) != NULL) {
				if (show_logging_file(tm, tf)) {
					pprintf("%s", "\n");
					goto skip;
				}
			}
		}
	}
	strcpy(logname, "/var/log/messages");
	if ((tf = fopen(logname, "r")) != NULL) {
		if (show_logging_file(tm, tf))
			pprintf("%s", "\n");
	}
	skip: librouter_destroy_args(args);
}

void clear_logging(const char *cmdline) /* clear logging */
{
	int i;
	char logname[32];

#ifdef OPTION_IPSEC
	for (i = 200; i >= 0; i--) /* have to match syslogd configuration */
#else
	for (i=50; i >= 0; i--)
#endif
	{
		sprintf(logname, "/var/log/messages.%d", i);
		unlink(logname);
	}
	strcpy(logname, "/var/log/messages");
	unlink(logname);
}

void show_processes(const char *cmdline)
{
	struct process_t *ps, *next;

	next = ps = librouter_ps_get_info();
	if (ps == NULL)
		return;

	printf("\tPID\tPROCESS\n");
	while (next != NULL) {
		if (next->name[0])
			printf("\t%d\t%s\n", next->pid, next->name);
		next = next->next;
	}
	printf("\n");

	librouter_ps_free_info(ps);
	return;

}

void show_uptime(const char *cmdline)
{
	FILE *tf;

	tf = popen("/bin/uptime", "r");
	show_output(tf);
	if (tf)
		pclose(tf);
}

const char *_WKDAY[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

const char *_MONTH[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void show_clock(const char *cmdline)
{
	system("/bin/date");
}

char *get_linux_version(void)
{
	static struct utsname u;

	if (uname(&u) == 0)
		return u.release;
	else
		return "<unknown>";
}

void show_version(const char *cmdline)
{
#ifdef CONFIG_DEVELOPMENT
	printf("Engineering prototype\n");
#endif
	printf("Bootloader version: %s\n", librouter_get_boot_version());
	printf("System version: %s\n", librouter_get_system_version());
#if 0
	printf("Owner: %s\n", get_product_owner());
	printf("Licensed: %s\n", get_product_licensed());
	printf("Serial number: %s\n", get_serial_number());
	printf("System ID: %s\n", get_system_ID(1));
#endif
}

const char SPAC32[] = "                                ";

void show_arp(const char *cmdline)
{
	FILE *F;
	char *ipaddr;
	char *hwaddr;
	char *type;
	char *osdev;
	char *cdev;
	long flags;
	arglist *args;

	F = fopen("/proc/net/arp", "r");
	if (!F) {
		printf("%% Unable to read ARP table\n");
		return;
	}

	printf("Protocol  Address          Age (min)    Hardware Addr  Type   Interface\n");

	fgets(tbuf, 127, F);

	while (!feof(F)) {
		tbuf[0] = 0;
		fgets(tbuf, 127, F);
		tbuf[127] = 0;
		librouter_str_striplf(tbuf);

		args = librouter_make_args(tbuf);
		if (args->argc >= 6) {
			ipaddr = args->argv[0];
			hwaddr = args->argv[3];
			type = args->argv[1];
			osdev = args->argv[5];
			flags = strtoul(args->argv[2], 0, 16);

			if (flags & ATF_COM) /* Entrada valida (completed) */
			{
				pprintf("Internet  %s%s", ipaddr, SPAC32 + 16 + strlen(ipaddr));
				pprintf("        0     %c%c%c%c.%c%c%c%c.%c%c%c%c ", tolower(hwaddr[0]),
				                tolower(hwaddr[1]), tolower(hwaddr[3]), tolower(hwaddr[4]),
				                tolower(hwaddr[6]), tolower(hwaddr[7]), tolower(hwaddr[9]),
				                tolower(hwaddr[10]), tolower(hwaddr[12]),
				                tolower(hwaddr[13]), tolower(hwaddr[15]), tolower(hwaddr[16]));

				if (strcmp(type, "0x1") == 0)
					printf("ARPA   ");
				else
					pprintf("other  ");
				cdev = librouter_device_linux_to_cli(osdev, 1);
				if (cdev)
					pprintf("%s", cdev);
				pprintf("\n");
			}
		}
		librouter_destroy_args(args);
	}
}

void show_ip_dns(const char *cmdline)
{
	/*
	 DNS is currently enabled.
	 The default DNS domain name is: corp.com
	 DNS name server                          status
	 ---------------------------------------- -------
	 dns_serv2
	 dns_serv1                                primary
	 dns_serv3
	 Console> (enable)
	 */
	char addr[16];
	unsigned int i;

	printf("IP domain lookup is currently %sabled\n",
	                librouter_dns_domain_lookup_enabled() ? "en" : "dis");
	printf("DNS relay is currently %sabled\n", librouter_exec_check_daemon(DNS_DAEMON) ? "en" : "dis");

	/* Lista servidores DNS estaticos */
	for (i = 0; i < DNS_MAX_SERVERS; i++) {
		if (librouter_dns_get_nameserver_by_type_actv_index(DNS_STATIC_NAMESERVER, 1, i, addr) < 0)
			break;
		printf("Static ip name-server %s\n", addr);
	}
	for (i = 0; i < DNS_MAX_SERVERS; i++) {
		if (librouter_dns_get_nameserver_by_type_actv_index(DNS_STATIC_NAMESERVER, 0, i, addr) < 0)
			break;
		printf("Static ip name-server %s (inactive)\n", addr);
	}

	/* Lista servidores DNS dinamicos */
	for (i = 0;; i++) {
		if (librouter_dns_get_nameserver_by_type_actv_index(DNS_DYNAMIC_NAMESERVER, 1, i, addr) < 0)
			break;
		printf("Dynamic ip name-server %s\n", addr);
	}
	for (i = 0;; i++) {
		if (librouter_dns_get_nameserver_by_type_actv_index(DNS_DYNAMIC_NAMESERVER, 0, i, addr) < 0)
			break;
		printf("Dynamic ip name-server %s (inactive)\n", addr);
	}
}

void show_memory(const char *cmdline)
{
	int i;
	FILE *tf;

	if ((tf = fopen("/proc/meminfo", "r"))) {
		for (i = 0; (i < 2) && !feof(tf); i++) {
			if (fgets(tbuf, 255, tf)) {
				tbuf[255] = 0;
				pprintf("%s", tbuf);
			}
		}
		fclose(tf);
	}
}

#ifdef CONFIG_KMALLOC_ACCOUNTING
void show_kmalloc(const char *cmdline)
{
	int i;

	if ((tf=fopen("/proc/kmalloc", "r"))) {
		for (i=0; !feof(tf); i++) {
			tbuf[0]=0;
			fgets(tbuf, 255, tf);
			tbuf[255]=0;
			if (strlen(tbuf))
			pprintf("%s", tbuf);
		}
		fclose(tf);
	}
}
#endif

#ifdef CONFIG_DEVELOPMENT
void show_softnet(const char *cmdline)
{
	FILE *tf;
	if ((tf = fopen("/proc/net/softnet_stat", "r"))) {
		for (; !feof(tf);) {
			tbuf[0] = 0;
			fgets(tbuf, 255, tf);
			tbuf[255] = 0;
			if (strlen(tbuf))
			pprintf("%s", tbuf);
		}
		fclose(tf);
	}
}
#endif

void dump_routing(FILE *out, int conf_format)
{
	if (conf_format) {
		librouter_quagga_zebra_dump_static_routes(out, 4); /*Ip_version = 4 -> ipv4*/
	} else {
		zebra_dump_routes(out);
	}
}

void dump_routing_ipv6(FILE *out, int conf_format)
{
	if (conf_format) {
		librouter_quagga_zebra_dump_static_routes(out, 6); /*Ip_version = 6 -> ipv6*/
	} else {
		zebra_dump_routes_ipv6(out);
	}
}

static void __dump_intf_secondary_ipaddr_status(FILE *out, struct interface_conf *conf)
{
	int i;
	struct ip_t *ip = &conf->sec_ip[0];

	cish_dbg("%s : %s\n", __FUNCTION__, conf->name);

	/* Go through IP configuration */
	for (i = 0; i < MAX_NUM_IPS; i++, ip++) {

		if (ip->ipaddr[0] == 0)
			break;

		fprintf(out, "  Secondary internet address is %s %s\n", ip->ipaddr, ip->ipmask);
	}

	cish_dbg("%s : Exiting ...\n", __FUNCTION__);
}

#ifdef NOT_YET_IMPLEMENTED
static void __dump_intf_secondary_ipaddr_v6_status(FILE *out, struct interfacev6_conf *conf)
{
	int i;
	struct ipv6_t *ipv6 = &conf->sec_ip[0];

	cish_dbg("%s : %s\n", __FUNCTION__, conf->name);

	/* Go through IP configuration */
	for (i = 0; i < MAX_NUM_IPS; i++, ipv6++) {

		if (ipv6->ipv6addr[0] == 0)
		break;

		fprintf(out, "  Secondary internet 6 address is %s/%s | Scope: %s\n", ipv6->ipv6addr, ipv6->ipv6mask, librouter_ipv6_is_addr_link_local(ipv6->ipv6addr)? "Link":"Global");
	}

	cish_dbg("%s : Exiting ...\n", __FUNCTION__);
}
#endif

static void __dump_intf_ipaddr_v6_status(FILE *out, struct interfacev6_conf *conf)
{
#ifdef OPTION_IPV6
	int i;
	struct ipv6_t *ipv6 = &conf->main_ip[0];

	cish_dbg("%s : %s\n", __FUNCTION__, conf->name);

	for (i = 0; i < MAX_NUM_IPS; i++, ipv6++) {
		if (ipv6->ipv6addr[0] == 0)
			break;

		fprintf(out, "  Internet 6 address is %s/%s | Scope: %s\n",
		                ipv6->ipv6addr, ipv6->ipv6mask,
		                librouter_ipv6_is_addr_link_local(ipv6->ipv6addr) ? "Link" : "Global");
	}

#if 0 /*Realiza analise sobre o endereço para BRIDGE*/
	else {
		struct ipv6_t ipv6_addr;
		librouter_br_get_ipaddr(dev, &ipv6_addr);

		if (ipv6_addr.addr[0])
		fprintf(out, "  Internet address is %s %s\n", ipv6_addr.ipv6addr, ipv6_addr.ipv6mask);
	}
#endif
#endif /* OPTION_IPV6 */
	cish_dbg("%s : Exiting ...\n", __FUNCTION__);
}

static void __dump_intf_ipaddr_status(FILE *out, struct interface_conf *conf)
{
	struct ip_t *ip = &conf->main_ip;

	cish_dbg("%s : %s\n", __FUNCTION__, conf->name);

	if (ip->ipaddr[0])
		fprintf(out, "  Internet address is %s %s\n", ip->ipaddr, ip->ipmask);

	if (ip->ippeer[0]
	                && !(conf->linktype == ARPHRD_TUNNEL || conf->linktype == ARPHRD_IPGRE
	                || conf->linktype == ARPHRD_PPP))
		fprintf(out, "  Peer address is %s\n", ip->ippeer);

	cish_dbg("%s : Exiting ...\n", __FUNCTION__);
}

static void __dump_ethernet_status(FILE *out, struct interface_conf *conf)
{
	struct lan_status st;
	int phy_status;

	if (conf->mac[0])
		fprintf(out, "  Hardware address is %s\n", conf->mac);

	phy_status = librouter_lan_get_status(conf->name, &st);

	if (phy_status < 0) {
		fprintf(out, "Could not fetch %s status\n", conf->name);
		return;
	}

	if (conf->running) {

		if (st.autoneg)
			fprintf(out, "  Auto-sense");
		else
			fprintf(out, "  Forced");

		fprintf(out, " %dMbps, ", st.speed);

		if (st.duplex)
			fprintf(out, " Full-Duplex");
		else
			fprintf(out, " Half-Duplex");

		fprintf(out, "\n");
	}

#if 0 /* TODO Show more PHY information */
	if (phy_status & PHY_STAT_FAULT) {
		fprintf(out, ", Remote Fault Detect!\n");
	} else {
		fprintf(out, "\n");
	}

	/* FIXME HACK para evitar que eth1 faça requisição do PHY, devido a MOD no kernel */
	if (!strcmp(conf->name,"eth1")) {
		pgsr = 1;
		pssr = 1;
	}
	else {
		pgsr = librouter_lan_get_phy_reg(conf->name, MII_ADM7001_PGSR);
		pssr = librouter_lan_get_phy_reg(conf->name, MII_ADM7001_PSSR);
	}

	if (pgsr & MII_ADM7001_PGSR_XOVER) {
		fprintf(out, "  Cable MDIX");
	} else {
		fprintf(out, "  Cable MDI");
	}
	if (pssr & MII_ADM7001_PSSR_SPD) {
		if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0xab)
		fprintf(out, ", length over 140m");
		else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0xa2)
		fprintf(out, ", length over 120m");
		else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x9a)
		fprintf(out, ", length over 100m");
		else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x94)
		fprintf(out, ", length over 80m");
		else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x22)
		fprintf(out, ", length over 60m");
		else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x1a)
		fprintf(out, ", length over 40m");
		else
		fprintf(out, ", length below 40m");
#ifdef CONFIG_DEVELOPMENT
		fprintf(out, " (cblen=%d)\n", pgsr & MII_ADM7001_PGSR_CBLEN);
#else
		fprintf (out, "\n");
#endif

	} else {
		fprintf(out, "\n");
	}
}
#endif
}

#ifdef OPTION_EFM
static void __dump_efm_status(FILE *out, struct interface_conf *conf)
{
	struct orionplus_stat st[4];
	struct orionplus_counters cnt;
	struct orionplus_conf dspconf;
	int n; /* Number of channels */
	int i;

	/*  normal ethernet dump */
	__dump_ethernet_status(out, conf);

	/* extra DSP information */
	n = librouter_efm_get_num_channels();

	if (librouter_efm_get_status(st) < 0) {
		printf("%% Could not get EFM status\n");
		return;
	}

	if (librouter_efm_get_counters(&cnt) < 0) {
		printf("%% Could not get EFM counters\n");
		return;
	}

	librouter_efm_get_mode(&dspconf);
	printf("  %d channel DSP, %s mode\n", n, dspconf.mode ? "CPE" : "CO");
	for (i = 0; i < n; i++) {
		char buf[32];
		int d, h, m, s, t;

		t = cnt.xcvr_cnt[i].uptime;
		d = t / 86400;
		t %= 86400;
		h = t / 3600;
		t %= 3600;
		m = t / 60;
		t %= 60;
		s = t;

		librouter_efm_get_channel_state_string(st[i].channel_st, buf, sizeof(buf));

		printf("  Channel %d is %s\n", i, buf);
		if (st[i].channel_st == CHANNEL_STATE_CONNECTED) {
			printf("  Connection time : %d days %d hours %d min %d sec\n", d, h, m, s);
			printf("    SNR %.02fdB\n", librouter_efm_get_snr(i));
			printf("    SNR Margin %.02fdB\n", librouter_efm_get_data_mode_margin(i));
		}

		switch (st[i].op_state[0]) {
		case GTI_DATA_OP:
		case GTI_TRAINING_OP:
		case GTI_FRAMER_SYNC_OP:
		case GTI_FRAMER_GEAR_SHIFT_OP:
		case GTI_WAIT_ACTION_GEAR_SHIFT_OP:
			printf("    Transmit Power %.02fdBm\n", librouter_efm_get_xmit_power(i));
			printf("    Receiver Gain %.02fdB\n", librouter_efm_get_receiver_gain(i));
			printf("    Loop Attenuation %.02fdB\n", librouter_efm_get_loop_attn(i));
			printf("    Line rate %d kbps\n    CRC: %d SEGA: %d LOSW: %d\n", st[i].bitrate[0],
			                cnt.xcvr_cnt[i].crc, cnt.xcvr_cnt[i].sega, cnt.xcvr_cnt[i].losw);
			break;
		default:
			break;
		}
	}

	printf("  General Interface Statistics\n");
}
#endif

#ifdef OPTION_WIFI
static int wifi_hw_mode_get(char * hw_mode_string, int size_mode)
{
	char mode;

	switch (librouter_wifi_hw_mode_get()) {
		case a_hw:
			mode = 'a';
			break;
		case b_hw:
			mode = 'b';
			break;
		case g_hw:
			mode = 'g';
			break;
		case n_hw:
			mode = 'n';
			break;
		default:
			return -1;
			break;
	}

	snprintf(hw_mode_string, size_mode, "802.11%c", mode);

	return 0;
}

static void __dump_wlan_status(FILE *out, struct interface_conf *conf)
{
	int wifi_channel = 0;
	char ssid[64], hw_mode_string[10];
	memset(ssid, 0, sizeof(ssid));
	memset(hw_mode_string, 0, sizeof(hw_mode_string));

	if (librouter_wifi_ssid_get(ssid, sizeof(ssid)) < 0)
		printf(" Error - reading SSID\n");

	if ((wifi_channel = librouter_wifi_channel_get()) < 0)
		printf(" Error - reading Wifi Channel\n");

	if (wifi_hw_mode_get(hw_mode_string, sizeof(hw_mode_string)) < 0)
		printf(" Error - reading Wifi Mode\n");

	if (conf->mac[0])
		fprintf(out, "  Hardware address is %s\n", conf->mac);

	fprintf(out, "  Wireless Network Name (SSID) is %s\n", ssid);
	fprintf(out, "  Wireless Operation Mode is %s, at Channel %d\n", hw_mode_string, wifi_channel);
}
#endif /* OPTION WIFI */

static void __dump_loopback_status(FILE *out, struct interface_conf *conf)
{
}

#ifdef OPTION_PPP
#ifdef OPTION_PPPOE
static void __dump_ppp_pppoe_status(FILE *out, struct interface_conf *conf)
{
	ppp_config ppp_cfg;
	pppoe_config pppoe_cfg;
	struct ip_t ip;
	char *osdev = conf->name;
	int serial_no=0;
	int running = conf->running;

	/* Get interface index --> ex: ppp0 -> 0*/
	serial_no = atoi(osdev + strlen(PPPDEV));

	librouter_ppp_get_config(serial_no, &ppp_cfg);

	librouter_pppoe_get_config(&pppoe_cfg);

	if (ppp_cfg.ip_addr[0]) {strncpy(ip.ipaddr, ppp_cfg.ip_addr, 16); printf("TESTE CFG IP\n\n"); ip.ipaddr[15]=0;}
	if (ppp_cfg.ip_mask[0]) {strncpy(ip.ipmask, ppp_cfg.ip_mask, 16); printf("TESTE CFG MASK\n\n"); ip.ipmask[15]=0;}
	if (ppp_cfg.ip_peer_addr[0]) {strncpy(ip.ippeer, ppp_cfg.ip_peer_addr, 16); ip.ippeer[15]=0;}
	if (ppp_cfg.dial_on_demand && !running) { /* filtra enderecos aleatorios atribuidos pelo pppd */
		ip.ipaddr[0]=0;
		ip.ippeer[0]=0;
	}

	if (ppp_cfg.ip_unnumbered != -1) /* Verifica a flag ip_unnumbered do cfg e exibe a mensagem correta */
	fprintf(out, "  Interface is unnumbered. Using address of ethernet %d (%s)\n", ppp_cfg.ip_unnumbered, ip.ipaddr);
	else
	if (ip.ipaddr[0])
	fprintf(out, "  Internet address is %s %s\n", ip.ipaddr, ip.ipmask);

	fprintf(out, "  Encapsulation PPP");
	if (strlen(pppoe_cfg.network) > 0)
	fprintf(out, ", Network is \"%s\"", pppoe_cfg.network);
	fprintf(out, "\n  Username is \"%s\"", pppoe_cfg.username);
	if (strlen(pppoe_cfg.service_name) > 0)
	fprintf(out, "  Service name is \"%s\"", pppoe_cfg.service_name);
	if (strlen(pppoe_cfg.ac_name) > 0)
	fprintf(out, ", AC name is \"%s\"", pppoe_cfg.ac_name);

	fprintf(out, "\n");

}
#endif /* OPTION_PPPOE */
#ifdef OPTION_PPTP
static void __dump_ppp_pptp_status(FILE *out, struct interface_conf *conf)
{
	ppp_config ppp_cfg;
	pptp_config pptp_cfg;
	struct ip_t ip;
	char *osdev = conf->name;
	int serial_no=0;
	int running = conf->running;

	/* Get interface index --> ex: ppp0 -> 0*/
	serial_no = atoi(osdev + strlen(PPPDEV));

	librouter_ppp_get_config(serial_no, &ppp_cfg);

	librouter_pptp_get_config(&pptp_cfg);

	if (ppp_cfg.ip_addr[0]) {strncpy(ip.ipaddr, ppp_cfg.ip_addr, 16); printf("TESTE CFG IP\n\n"); ip.ipaddr[15]=0;}
	if (ppp_cfg.ip_mask[0]) {strncpy(ip.ipmask, ppp_cfg.ip_mask, 16); printf("TESTE CFG MASK\n\n"); ip.ipmask[15]=0;}
	if (ppp_cfg.ip_peer_addr[0]) {strncpy(ip.ippeer, ppp_cfg.ip_peer_addr, 16); ip.ippeer[15]=0;}
	if (ppp_cfg.dial_on_demand && !running) { /* filtra enderecos aleatorios atribuidos pelo pppd */
		ip.ipaddr[0]=0;
		ip.ippeer[0]=0;
	}

	if (ppp_cfg.ip_unnumbered != -1) /* Verifica a flag ip_unnumbered do cfg e exibe a mensagem correta */
	fprintf(out, "  Interface is unnumbered. Using address of ethernet %d (%s)\n", ppp_cfg.ip_unnumbered, ip.ipaddr);
	else
	if (ip.ipaddr[0])
	fprintf(out, "  Internet address is %s %s\n", ip.ipaddr, ip.ipmask);

	fprintf(out, "  Encapsulation PPP");
	fprintf(out, ", Server is %s\n", pptp_cfg.server);
	fprintf(out, "  Username is \"%s\"", pptp_cfg.username);
	if (strlen(pptp_cfg.domain) > 0)
	fprintf(out, ", Domain is \"%s\"", pptp_cfg.domain);

	fprintf(out, "\n");

}
#endif /* OPTION_PPTP */

#ifdef OPTION_MODEM3G
static void __dump_ppp_status(FILE *out, struct interface_conf *conf)
{
	ppp_config cfg;
	char *osdev = conf->name;
	int serial_no = 0, lusb_descriptor = -1, lusb_tty_verify = -1;
	char * apn = malloc(100);
	librouter_usb_dev * usbdev = malloc(sizeof(librouter_usb_dev));

	/* Get interface index --> ex: ppp0 -> 0*/
	serial_no = atoi(osdev + strlen(PPPDEV));
	/* Get usb port from interface index */
	usbdev->port = librouter_usb_get_realport_by_aliasport(serial_no);

	/* Get config PPP ;
	 * Get USB description ;
	 * Verify existence of TTY, means USB device is a modem 3g ; */
	librouter_ppp_get_config(serial_no, &cfg);
	lusb_descriptor = librouter_usb_get_descriptor(usbdev);
	lusb_tty_verify = librouter_usb_device_is_modem(usbdev->port);

	fprintf(out, "  Encapsulation PPP");

	if (!librouter_modem3g_get_apn(apn, serial_no))
		fprintf(out, ", APN is \"%s\"\n", apn);
	else
		printf(" Error - reading APN\n");

	free(apn);

	if ((!lusb_descriptor) && (lusb_tty_verify != -1))
		fprintf(out, "  USB 3G Device: %s - %s, on USB-Port %d", usbdev->product_str,
		                usbdev->manufacture_str, usbdev->port);
	else if ((!lusb_descriptor) && (lusb_tty_verify < 0))
		fprintf(out, "  USB device connected, but not a modem.");
	else
		fprintf(out, "  No USB device connected.");

	free(usbdev);

	fprintf(out, "\n");

}
#endif /* OPTION_MODEM3G */

#endif /* OPTION_PPP */

int intf_cmp(const void *a, const void *b)
{
	char *t1 = *(char * const *) a;
	char *t2 = *(char * const *) b;

	return strcmp(t1, t2);
}

void dump_interfaces(FILE *out, int conf_format, char *intf)
{
	int i;
	char *cish_dev;
	char *description;
	struct net_device_stats *st;
	struct interface_conf conf;
	struct interfacev6_conf conf_v6;
	struct intf_info info;
	char *intf_list[MAX_NUM_LINKS];
	int num_of_ifaces = 0;

	/* Get interface names */
	librouter_ip_get_if_list(&info);
	for (i = 0; i < MAX_NUM_LINKS; i++) {
		intf_list[i] = info.link[i].ifname;

	}

	/* Get number of interfaces and sort them by name */
	for (i = 0; intf_list[i][0] != '\0'; i++)
		num_of_ifaces++;
	qsort(&intf_list[0], num_of_ifaces, sizeof(char *), intf_cmp);

	for (i = 0; i < num_of_ifaces; i++) {
		cish_dbg("%s\n", intf_list[i]);

		/* Ignore IPSec devices */
		if (!strncmp(intf_list[i], "ipsec", 5))
			continue;

		if (librouter_ip_iface_get_config(intf_list[i], &conf, &info) < 0) {
			cish_dbg("%s not found\n", intf_list[i]);
			continue;
		}

		/* Ignore the following interfaces: bridge*/
		if (strstr(conf.name, "bridge"))
			continue;

		st = conf.stats;

		cish_dev = librouter_device_linux_to_cli(conf.name, conf_format ? 0 : 1);
		if (cish_dev == NULL)
			continue; /* ignora dev nao usado pelo cish */
		cish_dbg("cish_dev : %s\n", cish_dev);

		/* Check if only one interface is needed */
		if (intf && strcasecmp(cish_dev, intf)) {
			continue;
		}

		cish_dbg("Device found : %s\n", cish_dev);

		if (strncmp(conf.name, "ipsec", 5) == 0)
			conf.linktype = ARPHRD_TUNNEL6; /* !!! FIXME */

		conf.running = (conf.flags & IFF_RUNNING) ? 1 : 0;

		/* Ignore loopback that are down */
		if ((conf.linktype == ARPHRD_LOOPBACK && !conf.running)) {
			continue;
		}

		fprintf(out, "%s is %s, line protocol is %s\n", cish_dev,
		                conf.up ? (1 ? "up" : "down") : "administratively down", /* FIXME */
		                conf.running ? "up" : "down");

		description = librouter_dev_get_description(conf.name);
		if (description)
			fprintf(out, "  Description: %s\n", description);

		/* Dump IP address */
		__dump_intf_ipaddr_status(out, &conf);
		__dump_intf_secondary_ipaddr_status(out, &conf);

		/* Dump IPv6 address -- Ignoring PPP interfaces */
		if (!strstr(conf.name, "ppp")) {
			memset(&conf_v6, 0, sizeof(struct interfacev6_conf));
			if (librouter_ipv6_iface_get_config(intf_list[i], &conf_v6, NULL) < 0) {
				cish_dbg("%s not found in ipv6\n", intf_list[i]);
			} else {
				__dump_intf_ipaddr_v6_status(out, &conf_v6);
#ifdef NOT_YET_IMPLEMENTED
				__dump_intf_secondary_ipaddr_v6_status(out, &conf_v6);
#endif
			}
		}

		if (conf.linktype == ARPHRD_PPP && conf.running)
			fprintf(out, "  MTU is %i bytes\n", conf.mtu);

		if (conf.linktype != ARPHRD_PPP)
			fprintf(out, "  MTU is %i bytes\n", conf.mtu);

		if (conf.txqueue)
			fprintf(out, "  Output queue size: %i\n", conf.txqueue);

		switch (conf.linktype) {
#ifdef OPTION_PPP
		case ARPHRD_PPP:
#ifdef OPTION_PPTP
			if (strstr(cish_dev, "Pptp"))
				__dump_ppp_pptp_status(out, &conf);
#endif
#ifdef OPTION_PPPOE
			if (strstr(cish_dev, "Pppoe"))
				__dump_ppp_pppoe_status(out, &conf);
#endif
#ifdef OPTION_MODEM3G
			if (strstr(cish_dev, "M3G"))
				__dump_ppp_status(out, &conf);
			break;
#endif
#endif
		case ARPHRD_ETHER:
#ifdef OPTION_EFM
			if (strstr(cish_dev, "Efm"))
				__dump_efm_status(out, &conf);
			else
#endif
#ifdef OPTION_WIFI
			if (strstr(cish_dev, "Wlan"))
				__dump_wlan_status(out, &conf);
			else
#endif
				__dump_ethernet_status(out, &conf);
			break;

		case ARPHRD_LOOPBACK:
			__dump_loopback_status(out, &conf);
			break;
#ifdef OPTION_TUNNEL
		case ARPHRD_SIT:
		case ARPHRD_TUNNEL:
		case ARPHRD_IPGRE:
			librouter_tunnel_dump_interface(out, conf_format, conf.name);
			break;
#endif

		case ARPHRD_TUNNEL6: /* ipsec decoy! */
			break;

		default:
			fprintf(stderr, "%% unknown link type: %d\n", conf.linktype);
			break;
		}

		/* Se dispositivo 3G USB não estiver presente no sistema, ou sem ppp ativo,
		 * Description não será apresentado
		 */
		if (conf.linktype == ARPHRD_PPP && !conf.running && !conf.up) {
			fprintf(out, "\n");
			continue;
		}

		fprintf(out, "     %lu packets input, %lu bytes\n", st->rx_packets, st->rx_bytes);
		fprintf(
		                out,
		                "     %lu input errors, %lu dropped, %lu overruns, %lu frame, %lu crc, %lu fifo\n",
		                st->rx_errors, st->rx_dropped, st->rx_over_errors, st->rx_frame_errors,
		                st->rx_crc_errors, st->rx_fifo_errors);

		fprintf(out, "     %lu packets output, %lu bytes\n", st->tx_packets, st->tx_bytes);
		fprintf(out, "     %lu output errors, %lu collisions, %lu dropped, %lu carrier, %lu fifo\n",
		                st->tx_errors, st->collisions, st->tx_dropped, st->tx_carrier_errors,
		                st->tx_fifo_errors);

		fprintf(out, "\n");

	}
}

void show_routingtables(const char *cmdline)
{
	dump_routing(stdout, 0);
}

void show_routingtables_ipv6(const char *cmdline)
{
	dump_routing_ipv6(stdout, 0);
}

void show_running_config(const char *cmdline)
{
	FILE *tf;

	show_banner(cmdline);

	printf("Building configuration...\n");

	/* Write config to f descriptor */
	if (librouter_config_write(TMP_CFG_FILE, router_cfg) < 0) {
		fprintf(stderr, "%% Can't build configuration\n");
		return;
	}

	tf = fopen(TMP_CFG_FILE, "r");

	/* Show the configuration */
	show_output(tf);

	if (tf)
		fclose(tf);

	unlink(TMP_CFG_FILE);
}

#if 0
void show_level_running_config(const char *cmdline)
{
	FILE *f;
	FILE *tf;

	if ((f = fopen(TMP_CFG_FILE, "wt")) == NULL) {
		fprintf(stderr, "%% Not possible to show configuration\n");
		return;
	}
	if (command_root == CMD_CONFIGURE) {
		dump_secret(f);
		dump_aaa(f);
		dump_hostname(f);
		dump_log(f, 1);
		dump_ip(f, 1);
		dump_snmp(f, 1);
#ifdef OPTION_RMON
		dump_rmon(f);
#endif
		dump_chatscripts(f);
		acl_dump_policy(f);
		librouter_acl_dump(0, f, 1);
		librouter_nat_dump(0, f, 1);
		librouter_mangle_dump(0, f, 1);
		dump_nat_helper(f);
		dump_routing(f, 1);
#ifdef OPTION_SMCROUTE
		dump_mroute(f);
#endif
		dump_clock(f);
		dump_ntp(f);
		dump_ip_servers(f, 1);
		dump_arp(f);

	} else if (command_root == CMD_CONFIG_CRYPTO) {
#ifdef OPTION_IPSEC
		dump_crypto(f);
#endif
	} else if ((command_root == CMD_CONFIG_INTERFACE_ETHERNET_WAN)
			|| (command_root == CMD_CONFIG_INTERFACE_ETHERNET_LAN)
			|| (command_root == CMD_CONFIG_INTERFACE_ETHERNET_VLAN)
			|| (command_root == CMD_CONFIG_INTERFACE_LOOPBACK)
			|| (command_root == CMD_CONFIG_INTERFACE_TUNNEL)
			|| (command_root == CMD_CONFIG_INTERFACE_M3G_USB)) {

		char *intf = librouter_device_cli_to_linux(interface_edited->cish_string,
				interface_major, interface_minor);

		dump_interfaces(f, 1, intf);
		free(intf);
	} else if (command_root == CMD_CONFIG_ROUTER_RIP)
	dump_router_rip(f);
	else if (command_root == CMD_CONFIG_ROUTER_OSPF)
	dump_router_ospf(f);
#ifdef OPTION_BGP
	else if (command_root == CMD_CONFIG_ROUTER_BGP)
	dump_router_bgp(f, 1);
#endif
	else
	write_config(f);
	fclose(f);

	//exclude_last_line_from_file_if_excl(TMP_CFG_FILE);
	tf = fopen(TMP_CFG_FILE, "r");
	show_output(tf);
	if (tf)
	fclose(tf);
	unlink(TMP_CFG_FILE);
}
#endif

void show_startup_config(const char *cmdline)
{
	FILE *tf;

	if (librouter_nv_load_configuration(STARTUP_CFG_FILE) > 0) {
		tf = fopen(STARTUP_CFG_FILE, "r");
		show_output(tf);
		if (tf)
			fclose(tf);
	}
}

void show_previous_config(const char *cmdline)
{
	FILE *tf;

	if (librouter_nv_load_previous_configuration(TMP_CFG_FILE) > 0) {
		tf = fopen(TMP_CFG_FILE, "r");
		show_output(tf);
		if (tf)
			fclose(tf);
	}
}

void show_techsupport(const char *cmdline)
{
	printf("\n------------------ show version ------------------\n\n");
	show_version("");
	printf("\n-------------- show running-config ---------------\n\n");
	show_running_config("");
	printf("\n---------------- show interfaces -----------------\n\n");
	show_interfaces("show interfaces");
	printf("----------------- show processes -----------------\n\n");
	show_processes("");
	printf("\n");
}

void cmd_copy(const char *cmdline)
{
	char *in = NULL;
	arglist *args;
	char from, to;
	char *host = NULL, *filename = NULL;

	args = librouter_make_args(cmdline);
	from = args->argv[1][0];
	to = args->argv[2][0];
	if ((from == 't') || (to == 't')) {
		host = args->argv[3];
		filename = args->argv[4];
	}
	switch (from) {
	case 'p': {
		if (librouter_nv_load_previous_configuration(TMP_CFG_FILE) == 0) {
			fprintf(stderr, "%% No previous configuration\n");
			librouter_destroy_args(args);
			return;
		}
		in = TMP_CFG_FILE;
	}
		break;

	case 'r':
		printf("Building configuration...\n");

		if (librouter_config_write(TMP_CFG_FILE, router_cfg) < 0) {
			fprintf(stderr, "%% Can't build configuration\n");
			librouter_destroy_args(args);
			return;
		}

		in = TMP_CFG_FILE;
		break;

	case 's':
		if (librouter_nv_load_configuration(STARTUP_CFG_FILE) == 0) {
			fprintf(stderr, "%% Configuration not saved\n");
			librouter_destroy_args(args);
			return;
		}
		in = STARTUP_CFG_FILE;
		break;

	case 't': {
		char buf[128];
		FILE *f;
		char *s;

		sprintf(buf, "/bin/tftp -g -l %s -r %s %s 2> "
		TMP_TFTP_OUTPUT_FILE, TFTP_CFG_FILE, filename, host);

		system(buf);
		f = fopen(TMP_TFTP_OUTPUT_FILE, "rt");
		if (!f) {
			fprintf(stderr, "%% Can't read output\n");
			librouter_destroy_args(args);
			return;
		}
		fgets(buf, 127, f);
		fclose(f);
		s = strstr(buf, "tftp: ");
		if (s) {
			fprintf(stderr, "%% TFTP:%s", s + 5);
			librouter_destroy_args(args);
			return;
		}
		in = TFTP_CFG_FILE;
	}
		break;
	}

	switch (to) {
	case 'r': {
		extern int _cish_booting;
		_cish_booting = 1;
		_cish_enable = 2; /* Enable special commands! */
		config_file(in);
		_cish_enable = 1; /* Restore enable level! */
		_cish_booting = 0;
	}
		break;

	case 's': {
		if (librouter_nv_save_configuration(in) < 0) {
			fprintf(stderr, "%% Error writing configuration\n");
			librouter_destroy_args(args);
			return;
		}
	}
		break;

	case 't': {
		char buf[128];
		FILE *f;
		char *s;

		sprintf(buf, "/bin/tftp -p -l %s -r %s %s 2> "TMP_TFTP_OUTPUT_FILE, in, filename, host);
		system(buf);
		f = fopen(TMP_TFTP_OUTPUT_FILE, "rt");
		if (!f) {
			fprintf(stderr, "%% Can't read output\n");
			librouter_destroy_args(args);
			return;
		}
		fgets(buf, 127, f);
		fclose(f);
		s = strstr(buf, "tftp: ");
		if (s) {
			fprintf(stderr, "%% TFTP:%s", s + 5);
			librouter_destroy_args(args);
			return;
		}
	}
		break;
	}
	printf("[OK]\n");
	unlink(TMP_CFG_FILE);
	unlink(TFTP_CFG_FILE);
	librouter_destroy_args(args);
}

void config_memory(const char *cmdline)
{
	cmd_copy("copy startup-config running-config");
}

void config_write(const char *cmdline)
{
	cmd_copy("copy running-config startup-config");
}

void erase_cfg(const char *cmdline)
{
	FILE *f;

	f = fopen(STARTUP_CFG_FILE, "wt");
	fclose(f); /* zero size! */
	librouter_nv_save_configuration(STARTUP_CFG_FILE);
}

void show_privilege(const char *cmdline)
{
	int priv = 0;

	if (!_cish_enable) {
		printf("Current privilege level is 1\n");
		return;
	}

	if ((priv = librouter_pam_get_privilege()) < 0) {
		fprintf(stderr, "%% Error retriving privilege\n");
		return;
	}

	/*Usuário root no inicio dos tempos nao pertence a nenhum grupo PRIV
	 * necessitando um tweak para setar seu privilegio para 15*/
	if (priv == 0)
		priv = 15;

	printf("Current privilege level is %i\n", priv);

}

void show_interfaces(const char *cmdline) /* show interfaces [aux|ethernet|loopback|serial|tunnel] [0-?] */
{
	arglist *args;
	char intf[32];

	args = librouter_make_args(cmdline);
	if (args->argc > 2) {
		strncpy(intf, args->argv[2], sizeof(intf));
		if (args->argc > 3)
			strncat(intf, args->argv[3], sizeof(intf));
		dump_interfaces(stdout, 0, intf);
	} else
		dump_interfaces(stdout, 0, NULL);
	librouter_destroy_args(args);
}

#ifdef OPTION_FIREWALL
void show_accesslists(const char *cmdline)
{
	arglist *args;

	args = librouter_make_args(cmdline);
	librouter_acl_dump((args->argc == 3) ? args->argv[2] : NULL, stdout, 0);
	librouter_destroy_args(args);
}
#endif

#ifdef OPTION_QOS
void show_manglerules(const char *cmdline)
{
	arglist *args;

	args = librouter_make_args(cmdline);
	librouter_mangle_dump((args->argc == 3) ? args->argv[2] : NULL, stdout, 0);
	librouter_destroy_args(args);
}
#endif

#ifdef OPTION_NAT
void show_natrules(const char *cmdline)
{
	arglist *args;

	args = librouter_make_args(cmdline);
	librouter_nat_dump((args->argc == 3) ? args->argv[2] : NULL, stdout, 0);
	librouter_destroy_args(args);
}
#endif

void show_performance(const char *cmdline)
{
	pid_t pid;
	arglist *args;

	args = librouter_make_args(cmdline);
	switch ((pid = fork())) {
	case -1:
		fprintf(stderr, "%% No processes left\n");
		break;
	case 0:
		execv("/bin/bwmon", args->argv);
		fprintf(stderr, "%% bwmon exec error!\n");
		exit(-1);
	default:
		waitpid(pid, NULL, 0);
		break;
	}
	librouter_destroy_args(args);
}

#ifdef OPTION_QOS
void show_qos(const char *cmdline)
{
	librouter_qos_dump_interfaces();
}
#endif

#ifdef OPTION_IPSEC

#if 0
static void print_ipsec_show_line(char *name,
                                  char *local,
                                  char *remote,
                                  char *authby,
                                  char *authproto,
                                  char *esp_c,
                                  char *pfs,
                                  int len,
                                  int shift,
                                  int second_shift,
                                  int third_shift,
                                  int state,
                                  int *net_flag)
{
	if (!(*net_flag)) {
		printf("\033[3C%s\033[%dC%s\033[%dC%s\033[%dC%s", name, total_name_len - strlen(name), local,
		                len - strlen(local) + (shift - len) / 2, separator, second_shift, remote);
		printf("\033[%dC", third_shift - strlen(remote));
		if (strlen(authby))
			printf("%s+", authby);
		if (strlen(authproto))
			printf("%s+", authproto);
		if (strlen(esp_c))
			printf("%s+", esp_c);
		if (strlen(pfs))
			printf("%s+", pfs);
		printf("\033[1D ");
		printf("\033[5C");
		if (state == CONN_UP)
			printf("tunnel established");
		else if (state == CONN_DOWN)
			printf("tunnel not established");
		else if (state == CONN_INCOMPLETE)
			printf("incomplete configuration");
		else if (state == CONN_SHUTDOWN)
			printf("shutdown");
		else if (state == CONN_WAIT)
			printf("waiting...");
		*net_flag = 1;
	} else
		printf("\033[%dC%s\033[%dC%s", total_name_len + 3, local, shift - strlen(local), remote);
	printf("\n");
}

static int show_conn_specific(char *name, int state)
{
	int ret, len, len2, net_flag = 0, shift = 0, second_shift = 0, third_shift = 0;
	char *p;
	char tmp[256];
	struct {
		char mask[20];
		char authby[10];
		char authproto[10];
		char esp_c[20];
		char pfs[5];
		char addr_l[MAX_ADDR_SIZE];
		char cidr_l[20];
		char id_l[MAX_ADDR_SIZE];
		char nexthop_l[20];
		char addr_r[MAX_ADDR_SIZE];
		char cidr_r[20];
		char id_r[MAX_ADDR_SIZE];
		char nexthop_r[20];
	} b;

	memset(&b, 0, sizeof(b));

	/* Get local id */
	if (librouter_ipsec_get_id(LOCAL, name, tmp) >= 0) {
		if (strlen(tmp) > 0 && strlen(tmp) < MAX_ADDR_SIZE)
			strcpy(b.id_l, tmp);
	}

	/* Get local subnet */
	if (librouter_ipsec_get_subnet(LOCAL, name, tmp) >= 0) {
		if (strlen(tmp) > 0) {
			if ((p = strchr(tmp, ' '))) {
				strncpy(b.addr_l, tmp, p - tmp);
				*(b.addr_l + (p - tmp)) = '\0';
				p++;
				for (; *p == ' '; p++)
					;
				if (strlen(p) > 0) {
					strcpy(b.mask, p);
					if (librouter_quagga_classic_to_cidr(b.addr_l, b.mask, b.cidr_l) != 0)
						b.cidr_l[0] = '\0';
				}
			}
		}
	}

	/* Get local address */
	ret = librouter_ipsec_get_local_addr(name, tmp);
	if (ret >= 0) {
		if (ret > 0 && strlen(tmp) < MAX_ADDR_SIZE) {
			if (ret == ADDR_DEFAULT) {
				strcpy(b.addr_l, "default-route");
			} else if (ret == ADDR_INTERFACE) {
				strcpy(b.addr_l, librouter_device_linux_to_cli(tmp + 1, 0));
			} else if (ret == ADDR_IP) {
				strcpy(b.addr_l, tmp);
			}
		}
	}

	/* Get local nexthop */
	ret = librouter_ipsec_get_nexthop(LOCAL, name, tmp);
	if (ret >= 0) {
		if (strlen(tmp) > 0 && strlen(tmp) < 20)
			strcpy(b.nexthop_l, tmp);
	}

	/* Get remote id */
	if (librouter_ipsec_get_id(REMOTE, name, tmp) >= 0) {
		if (strlen(tmp) > 0 && strlen(tmp) < MAX_ADDR_SIZE)
			strcpy(b.id_r, tmp);
	}

	/* Get remote subnet */
	ret = librouter_ipsec_get_subnet(REMOTE, name, tmp);
	if (ret >= 0) {
		if (strlen(tmp) > 0) {
			if ((p = strchr(tmp, ' '))) {
				strncpy(b.addr_r, tmp, p - tmp);
				*(b.addr_r + (p - tmp)) = '\0';
				p++;
				for (; *p == ' '; p++)
					;
				if (strlen(p) > 0) {
					strcpy(b.mask, p);
					if (librouter_quagga_classic_to_cidr(b.addr_r, b.mask, b.cidr_r) != 0)
						b.cidr_r[0] = '\0';
				}
			}
		}
	}

	/* Get remote address */
	ret = librouter_ipsec_get_remote_addr(name, tmp);
	if (ret >= 0) {
		if (ret > 0 && strlen(tmp) < MAX_ADDR_SIZE) {
			if (ret == ADDR_ANY)
				strcpy(b.addr_r, "any");
			else
				strcpy(b.addr_r, tmp);
		} else
			b.addr_r[0] = '\0';
	} else
		b.addr_r[0] = '\0';

	/* Get remote nexthop */
	ret = librouter_ipsec_get_nexthop(REMOTE, name, tmp);
	if (ret >= 0) {
		if (strlen(tmp) > 0 && strlen(tmp) < 20)
			strcpy(b.nexthop_r, tmp);
	}

	/* Get authentication type */
	switch (librouter_ipsec_get_auth(name)) {
	case SECRET:
		strcpy(b.authby, "SECRET");
		break;
	case RSA:
		strcpy(b.authby, "RSA");
		break;
	}

	/* Get cyphers */
	switch (librouter_ipsec_get_ike_auth_type(name)) {
	case AUTH_ESP:
		strcat(b.authproto, "ESP");
		switch (librouter_ipsec_get_esp(name, tmp)) {
		case 1:
			if (strlen(tmp) > 0 && strlen(tmp) < 10) {
				if (!strncmp(tmp, "des", 3))
					strcpy(b.esp_c, "DES");
				else if (!strncmp(tmp, "3des", 4))
					strcpy(b.esp_c, "3DES");
				else if (!strncmp(tmp, "aes", 3))
					strcpy(b.esp_c, "AES");
				else if (!strncmp(tmp, "null", 4))
					strcpy(b.esp_c, "NULL");
				if (strstr(tmp, "md5"))
					strcat(b.esp_c, "+MD5");
				else if (strstr(tmp, "sha1"))
					strcat(b.esp_c, "+SHA1");
			}
			break;
		default:
			//strcat(b.authproto, "+NOCRYPT");
			break;
		}
		break;
	case AUTH_AH:
		break;
	}

	/* Get PFS */
	ret = librouter_ipsec_get_pfs(name);
	if (ret >= 0) {
		if (ret > 0)
			strcpy(b.pfs, "PFS");
	}

	/* Get biggest length to be shown */
	if ((len = strlen(b.addr_l)) > shift)
		shift = len;
	if ((len = strlen(b.cidr_l)) > shift)
		shift = len;
	if ((len = strlen(b.id_l)) > shift)
		shift = len;
	if ((len = strlen(b.nexthop_l)) > shift)
		shift = len;
	len = shift;

	if ((len2 = strlen(b.addr_r)) > third_shift)
		third_shift = len2;
	if ((len2 = strlen(b.cidr_r)) > third_shift)
		third_shift = len2;
	if ((len2 = strlen(b.id_r)) > third_shift)
		third_shift = len2;
	if ((len2 = strlen(b.nexthop_r)) > third_shift)
		third_shift = len2;

	shift += 23;
	if (((shift - len) % 2) > 0)
		shift++;
	second_shift = ((shift - len) / 2) - strlen(separator);
	third_shift += 8;

	/* Start printing data */
	if (strlen(b.id_l) || strlen(b.id_r)) {
		print_ipsec_show_line(name, b.id_l, b.id_r, b.authby, b.authproto, b.esp_c, b.pfs, len,
		                shift, second_shift, third_shift, state, &net_flag);
	}
	if (strlen(b.addr_l) || strlen(b.addr_r)) {
		print_ipsec_show_line(name, b.addr_l, b.addr_r, b.authby, b.authproto, b.esp_c, b.pfs, len,
		                shift, second_shift, third_shift, state, &net_flag);
	}
	if (strlen(b.cidr_l) || strlen(b.cidr_r)) {
		print_ipsec_show_line(name, b.cidr_l, b.cidr_r, b.authby, b.authproto, b.esp_c, b.pfs, len,
		                shift, second_shift, third_shift, state, &net_flag);
	}
	if (strlen(b.nexthop_l) || strlen(b.nexthop_r)) {
		print_ipsec_show_line(name, b.nexthop_l, b.nexthop_r, b.authby, b.authproto, b.esp_c, b.pfs,
		                len, shift, second_shift, third_shift, state, &net_flag);
	}
	if (!net_flag) {
		printf("\033[3C%s\033[%dC", name, total_name_len - strlen(name));
		if (strlen(b.authby))
			printf("%s+", b.authby);
		if (strlen(b.authproto))
			printf("%s+", b.authproto);
		if (strlen(b.esp_c))
			printf("%s+", b.esp_c);
		if (strlen(b.pfs))
			printf("%s+", b.pfs);
		printf("\033[1D ");
		printf("\033[5C");
		printf("incomplete configuration\n");
	}
	return 1;
}
#endif /* if 0 */

/* FIXME Most stuff here should be in librouter */
void show_crypto(const char *cmdline)
{
#if 1
	arglist *args;

	args = librouter_make_args(cmdline);

	if (args->argc == 3) /* show crypto <conn-name> */
		librouter_ipsec_show_conn(args->argv[2]);
	else
		librouter_ipsec_show_all();

	librouter_destroy_args(args);
#else
	int i, ret;
	arglist *args;
	char *p, *rsa, **list = NULL, **list_ini = NULL, line[1024];
	FILE *output;

	args = librouter_make_args(cmdline);
	if (args->argc == 3) {
		if (librouter_ipsec_is_running()) /* Wait pluto start! */
		{
			char search_str[MAX_CMD_LINE];

			output = popen("/lib/ipsec/whack --status", "r");
			if (!output)
				return;
			sprintf(search_str, "\"%s\"", args->argv[2]);
			while (fgets(line, 1024, output)) {
				if (strstr(line, search_str))
					fputs(line, stdout);
			}
			pclose(output);
		}
		librouter_destroy_args(args);
		return;
	}
	librouter_destroy_args(args);

	total_name_len = 0;

	if ((ret = librouter_ipsec_get_autoreload()) > 0)
		printf("auto-reload in %d seconds\n", ret);
	if ((ret = librouter_ipsec_get_nat_traversal()) >= 0) {
		if (ret)
			printf("NAT-Traversal on\n");
		else
			printf("NAT-Traversal off\n");
	}
	if ((ret = librouter_ipsec_get_overridemtu()) > 0)
		printf("overridemtu %d\n", ret);

#ifdef IPSEC_SUPPORT_RSA_RAW
	/* RSA Keys */
	rsa = malloc(8192);
	if (librouter_nv_load_ipsec_secret(rsa)) {
		if ((p = strstr(rsa, "#pubkey="))) {
			p += 8;
			for (; *p == ' '; p++)
				;
			if (strchr(p, '\n')) {
				*(strchr(p, '\n')) = '\0';
				printf("public local rsa key %s\n", p);
			}
		}
	} else
		printf("You have to generate rsa keys!\n");
	free(rsa);
#endif

	/* Search for connections */
	if (librouter_ipsec_list_all_names(&list_ini) < 1) {
		printf("%% Not possible to show ipsec connections\n");
		return;
	}
	if (*list_ini != NULL) {
		printf("Connections:\n");
		for (i = 0, list = list_ini; i < IPSEC_MAX_CONN; i++, list++) {
			if (*list) {
				if (strlen(*list) > total_name_len)
					total_name_len = strlen(*list);
			}
		}
		total_name_len += 9;

		if (librouter_ipsec_is_running()) /* Wait pluto start! */
		{
			if (!(output = popen("/lib/ipsec/whack --status", "r"))) {
				printf("%% Not possible to show ipsec connections\n");
				goto go_error;
			}
			/* 000 caca 192.168.2.0/24===10.0.0.1[@server]...10.0.0.2[@roadwarrior]===192.168.1.0/24 RSASIG+ENCRYPT+TUNNEL+PFS "erouted" */
			/* 000 caca 192.168.2.0/24===10.0.0.1[@server]---10.0.0.2...%any[@roadwarrior]===192.168.1.0/24 RSASIG+ENCRYPT+TUNNEL+PFS "unrouted"  */
			while (fgets(line, 1024, output)) {
				int flag = CONN_INCOMPLETE;

				if (!strstr(line, "..."))
					continue;
				if (strlen(line) == 0)
					break;
				args = librouter_make_args(line);

				if (!strstr(args->argv[2], "...%any")) /* skip roadwarrior master! */
				{
					for (i = 0, list = list_ini; i < IPSEC_MAX_CONN;
					                i++, list++) {
						if (*list) {
							char name[64];
							sprintf(name, "\"%s\"", *list);
							if (strstr(args->argv[1], name)) {
								if (strstr(line, "erouted"))
									flag = CONN_UP;
								else if (strstr(line, "unrouted"))
									flag = CONN_DOWN;

								if (show_conn_specific(*list, flag)
								                < 1)
									goto go_error;

								printf("\n");
								free(*list);
								*list = NULL;
								break;
							}
						}
					}
				}


				librouter_destroy_args(args);
			}
			pclose(output);
		}
		for (i = 0, list = list_ini; i < IPSEC_MAX_CONN; i++, list++) {
			if (*list) {
				switch (librouter_ipsec_get_link(*list)) {
				case AUTO_IGNORE:
					if (show_conn_specific(*list, CONN_SHUTDOWN) < 1)
						goto go_error;
					break;
				case AUTO_START:
					if (show_conn_specific(*list, CONN_DOWN) < 1)
						goto go_error;
					break;
				case AUTO_ADD:
					if (show_conn_specific(*list, CONN_WAIT) < 1)
						goto go_error;
					break;
				}
				printf("\n");
				free(*list);
				*list = NULL;
			}
		}
		go_error: for (i = 0, list = list_ini; i < IPSEC_MAX_CONN; i++, list++) {
			if (*list)
				free(*list);
		}
		free(list_ini);
	} else
		printf("No connections configured!\n"); /*\033[30C*/
#if 0
	ret=librouter_ip_get_if_list();
	if (ret < 0) return;
	for (i=0; i < link_table_index; i++)
	{
		struct net_device_stats *st;

		if (strcmp(link_table[i].ifname, "ipsec0")) continue;
		st=&link_table[i].stats;
		printf(" %lu packets input, %lu bytes\n", st->rx_packets, st->rx_bytes);
		printf(" %lu input errors, %lu dropped, %lu overruns, %lu mcast\n", st->rx_errors, st->rx_dropped, st->rx_over_errors, st->multicast);
		printf(" %lu packets output, %lu bytes\n", st->tx_packets, st->tx_bytes);
		printf(" %lu output errors, %lu collisions, %lu dropped, %lu carrier\n", st->tx_errors, st->collisions, st->tx_dropped, st->tx_carrier_errors);
		printf("\n");
	}
#endif
	return;
#endif /* #if 0 */
}

#ifdef OPTION_PKI
void show_pki(const char *cmdline)
{
	char buf[32*1024];
	arglist *args;

	memset(buf, 0, sizeof(buf));

	args = librouter_make_args(cmdline);

	if (!librouter_ipsec_is_running())
		librouter_ipsec_exec(START);
	else
		librouter_ipsec_exec(RELOAD);

	if (args->argc == 2) {
		librouter_pki_dump_general_info();
	} else if (args->argc == 4) {
		if (strstr(args->argv[2], "csr")) {
			if (librouter_pki_get_csr_contents(buf, sizeof(buf)) == 0)
				printf(buf);
		} else if (strstr(args->argv[2], "host")) {
			if (librouter_pki_get_cert_contents(buf, sizeof(buf)) == 0)
				printf(buf);
		}
	} else {
		if (strstr(args->argv[2], "csr")) {
			if (librouter_pki_get_csr(buf, sizeof(buf)) == 0)
				printf(buf);
		} else if (strstr(args->argv[2], "host")) {
			if (librouter_pki_get_cert(buf, sizeof(buf)) == 0)
				printf(buf);
		} else if (!strcmp(args->argv[2], "ca")) {
			int i, n;
			char name[32];

			n = librouter_pki_get_ca_num();
			printf("Number of CA certificates: %d\n", n);
			for (i = 0; i < n; i++) {
				librouter_pki_get_ca_name_by_index(i, name);
				librouter_pki_get_cacert(name, buf, sizeof(buf));
				printf("CA Name: %s\n", name);
				if (strstr(buf,"-----BEGIN CERTIFICATE-----"))
					printf(buf);
				else
					printf("Binary DER ASN.1 Format\n");
				printf("-------------------------\n");
			}
		}
	}

	librouter_destroy_args(args);
}

void show_pki_csr_contents(const char *cmdline)
{
	char buf[2048];

	if (librouter_pki_get_csr_contents(buf, sizeof(buf)) == 0)
		printf(buf);
}
#endif

void show_l2tp(const char *cmdline)
{
	struct sockaddr_un addr;
	int fd;
	int n;
	char buf[4096];
	char dump[] = "dump-sessions";
	struct iovec v[2];

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, "/var/run/l2tpctrl", sizeof(addr.sun_path) - 1);

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		return;
	}
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd);
		return;
	}
	v[0].iov_base = (char *) dump;
	v[0].iov_len = strlen(dump);
	v[1].iov_base = "\n";
	v[1].iov_len = 1;
	writev(fd, v, 2);
	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			close(fd);
			return;
		}
		if (n == 0) {
			close(fd);
			return;
		}
		write(1, buf, n);
	}
}
#endif /* OPTION_IPSEC */

#ifdef UDHCPD
void show_dumpleases(const char *cmdline)
{
	int i;
	char filename[64];
	FILE *tf;

	for (i = 0; i < MAX_DHCP_SERVER_INSTANCES; i++) {
		if (librouter_dhcp_reload_leases_file() == 0) {
			tf = fopen(FILE_DHCPDLEASES, "r");
			if (!tf)
				continue;
			fclose(tf);
			sprintf(filename, "/bin/dumpleases -f "FILE_DHCPDLEASES);
			tf = popen(filename, "r");
			if (tf) {
				char *dev = NULL;
				librouter_dhcp_server_get_iface(&dev);
				if (dev) {
					pprintf("interface %s\n", dev);
					free(dev);
				}
				show_output(tf);
				pclose(tf);
			}
		}
	}
}
#endif

#ifdef OPTION_NTPD
void show_ntpkeys(const char *cmdline)
{
	FILE *f;
	arglist *args;
	char *p, line[200];

	if ((f = fopen(FILE_NTPD_KEYS, "r"))) {
		while (fgets(line, 200, f)) {
			if ((p = strchr(line, '\n')))
				*p = '\0';
			if (strlen(line)) {
				args = librouter_make_args(line);
				if (args->argc >= 3 && args->argv[0][0] != '#') /* 1 MD5 4+?PD7j5a$0jdy7@ # MD5 key */
				{
					if (!strcmp(args->argv[1], "MD5"))
						printf("%2s   %s\n", args->argv[0], args->argv[2]);
				}
			}
		}
		fclose(f);
	}
}

void show_ntpassociations(const char *cmdline)
{
	FILE *f;
	struct in_addr inp;
	arg_list argl = NULL;
	int i, used, n_local_addr = 0;
	char buf[256], local_addr[16][16];

	if (!librouter_exec_check_daemon(NTP_DAEMON))
		return;

	/* Inicialmente temos que descobrir quais enderecos das interfaces locais estao operando com NTP */
	if (!(f = popen("ntpq -c opeers 0.0.0.0", "r")))
		return;
	for (;;) {
		fgets(buf, 255, f);
		buf[255] = 0;
		if (feof(f))
			break;
		if (librouter_parse_args_din(buf, &argl) == 10) {
			if (inet_aton(argl[1], &inp) == 1) {
				for (i = 0, used = 0; (i < n_local_addr) && (i < 16); i++) {
					if (strcmp(argl[1], local_addr[i]) == 0) {
						used = 1;
						break;
					}
				}
				if (used == 0)
					strcpy(local_addr[n_local_addr++], argl[1]);
			}
		}
		librouter_destroy_args_din(&argl);
	}
	pclose(f);

	if (n_local_addr == 0)
		return;

	/* Exibimos todos os peers */
	printf("PEERS:\n");
	for (i = 0; i < n_local_addr; i++) {
		sprintf(buf, "ntpq -c opeers %s", local_addr[i]);
		system(buf);
	}
	printf("\nASSOCIATIONS:\n");
	for (i = 0; i < n_local_addr; i++) {
		sprintf(buf, "ntpq -c associations %s", local_addr[i]);
		system(buf);
	}
	printf("\n");
}
#endif /* OPTION_NTPD */

#ifdef OPTION_SMCROUTE
void show_mroute(const char *cmdline) /* !!! */
{
	FILE *tf;
#if 0
	if ((tf=fopen("/proc/net/dev_mcast","r")))
	{
		show_output(tf);
		fclose(tf);
	}
#endif
	pprintf("Multicast Interfaces:\n");
	if ((tf = fopen("/proc/net/ip_mr_vif", "r"))) {
		show_output(tf);
		fclose(tf);
	}
	pprintf("\nMulticast Group Cache:\n");
	if ((tf = fopen("/proc/net/ip_mr_cache", "r"))) {
		show_output(tf);
		fclose(tf);
	}
}
#endif

#ifdef OPTION_VRRP
void show_vrrp(const char *cmdline)
{
	FILE *tf;
	librouter_vrrp_dump_status();

	if (!(tf = fopen(VRRP_SHOW_FILE, "r"))) /* Open vrrp show file */
		return;

	show_output(tf); /* Print file */
	fclose(tf);
}
#endif

#ifdef OPTION_MODEM3G
void show_modem3g_apn(const char *cmdline)
{
	int check = 0;
	char * apn = malloc(256);
	check = librouter_modem3g_get_apn(apn, interface_major);
	if (check == -1) {
		printf("Error on show APN\n");
		free(apn);
		return;
	}

#ifdef DEBUG
	printf("\nAPN: %s  \n\n", apn);
#endif

	free(apn);
	apn = NULL;

}

void show_modem3g_username(const char *cmdline)
{
	int check = 0;
	char * username = malloc(256);

	check = librouter_modem3g_get_username(username, interface_major);
	if (check == -1) {
		printf("Error on show username\n");
		free(username);
		return;
	}

#ifdef DEBUG
	printf("\nUsername: %s \n\n", username);
#endif

	free(username);
	username = NULL;

}

void show_modem3g_password(const char *cmdline)
{
	int check = 0;
	char * password = malloc(256);

	check = librouter_modem3g_get_password(password, interface_major);
	if (check == -1) {
		printf("Error on show password\n");
		free(password);
		return;
	}

#ifdef DEBUG
	printf("\nPassword: %s \n\n", password);
#endif

	free(password);
	password = NULL;

}
#endif

#if defined (OPTION_PBR)
void show_policyroute_rules(const char *cmdline)
{
	char * show_rules_buffer = NULL;
	int size_show = 0;

	if ((size_show = librouter_pbr_get_show_rules_cli_size()) < 0) {
		printf("Error on show Policy-Route Rules\n");
		return;
	}

	show_rules_buffer = malloc(size_show);
	memset(show_rules_buffer,0,sizeof(show_rules_buffer));

	if (librouter_pbr_get_show_rules_cli(show_rules_buffer) < 0)
	printf("Error on show Policy-Route Rules\n");
	else
	printf("%s\n",show_rules_buffer);

	free (show_rules_buffer);
}

void show_policyroute_routes(const char *cmdline)
{
	arglist *args;
	args = librouter_make_args(cmdline);
	char table_name[8];
	char * show_routes_buffer = NULL;
	int size_show = 0;

	if (!strcmp(args->argv[4],"main"))
	sprintf(table_name,"%s",args->argv[4]);
	else
	sprintf(table_name,"%s%s",args->argv[3],args->argv[4]);

	if ((size_show = librouter_pbr_get_show_routes_cli_size(table_name)) < 0) {
		printf("Error on show Policy-Route Routes\n");
		return;
	}

	show_routes_buffer = malloc(size_show);
	memset(show_routes_buffer,0,sizeof(show_routes_buffer));

	if (librouter_pbr_get_show_routes_cli(table_name, show_routes_buffer) < 0)
	printf("Error on show Policy-Route Routes\n");
	else
	printf("%s\n",show_routes_buffer);

	free (show_routes_buffer);
	librouter_destroy_args(args);

}
#endif
