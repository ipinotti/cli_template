/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

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
#include <linux/config.h>
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

#include "commands_acl.h"
#include "commands_mangle.h"
#include "commands_nat.h"

#include "options.h"
#include "commands.h"
#include "cish_main.h"
#include "pprintf.h"
#include "cish_config.h"
#include "commandtree.h"
#include "terminal_echo.h"

extern int _cish_aux;
extern char *tzname[2];

static char tbuf[256];
static FILE *tf;
#ifdef OPTION_IPSEC
static int total_name_len;
char separator[] = "<--->";
#endif

extern cish_command CMD_CONFIGURE[];
extern cish_command CMD_CONFIG_CRYPTO[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[];
extern cish_command CMD_CONFIG_INTERFACE_LOOPBACK[];
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL[];
extern cish_command CMD_CONFIG_ROUTER_RIP[];
extern cish_command CMD_CONFIG_ROUTER_OSPF[];
#ifdef OPTION_BGP
extern cish_command CMD_CONFIG_ROUTER_BGP[];
#endif

extern device_family *interface_edited;
extern int interface_major, interface_minor;

void show_output(void)
{
	if (!tf) return;

	while (!feof (tf))
	{
		tbuf[0] = 0;
		fgets (tbuf, 255, tf);
		tbuf[255] = 0;
		if (strlen (tbuf))
			pprintf ("%s", tbuf);
	}
}

void show_cpu(const char *cmdline)
{
	float cpu;
	long long idle, user, nice, system, iowait, irq, softirq; 
	static long long idle_old = 0, nice_old = 0, user_old = 0, system_old = 0;
	static long long iowait_old = 0, irq_old = 0, softirq_old = 0;

	float scale;
	// enough for a /proc/stat CPU line (not the intr line)
	char buf[256];

	tf=fopen("/proc/stat","r");
	if (tf)
	{
		fgets(buf, sizeof(buf), tf);
		if (sscanf(buf, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu", 
				&user, &nice, &system, &idle, &iowait, &irq, &softirq) == 7)
		{
			scale = 100.0 / (float) ( (user - user_old) + 
					(nice - nice_old) + (system - system_old) + 
					(idle - idle_old) + (iowait - iowait_old) +
					(irq - irq_old)   + (softirq - softirq_old)
 					);

			cpu = (float)( (user - user_old) + 
					(nice - nice_old) + (system - system_old) + 
					(iowait - iowait_old) + (irq - irq_old)   + 
					(softirq - softirq_old) ) * scale;
#if 0
			pprintf ("processor usage : %#5.1f%% user, %#5.1f%% system, %#5.1f%% nice, %#5.1f%% idle\n" 
				"\t%#5.1f%% iowait, %#5.1f%% irq, %#5.1f%% softirq\n", 
				(float)(user-user_old)*scale, (float)(system-system_old)*scale, 
				(float)(nice-nice_old)*scale, (float)(idle-idle_old)*scale,
				(float)(iowait-iowait_old)*scale, (float)(irq-irq_old)*scale,
				(float)(softirq-softirq_old)*scale);
				
#else
			pprintf ("processor usage : %0.1f%% system, %0.1f%% idle\n", 
					cpu, (float)(idle - idle_old) * scale);
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
	tf = fopen("/proc/cpuinfo","r");
	if (tf == NULL) {
		printf("Could not ready cpu information\n");
		return;
	}
	

	while (!feof (tf)) {
		tbuf[0] = 0;
		fgets (tbuf, 255, tf);

#ifdef CONFIG_BERLIN
		/* Don't show the following patterns */
		if (strstr(tbuf, "berlin")) continue;
		if (strstr(tbuf, "Berlin")) continue;
		if (strstr(tbuf, "BERLIN")) continue;
		if (strstr(tbuf, "Memory")) continue;
#endif

		tbuf[255] = 0;
		if (strlen (tbuf))
			pprintf ("%s", tbuf);
	}

	fclose(tf);
}

/* <7> Jan  9 23:41:40 kernel: X.25(1): TX on serial0 size=131 frametype=0x54 */
static int show_logging_file(time_t tm_start)
{
	int status;
	pid_t pid;
	time_t tm = 0;
	struct tm tm_time;

	save_termios();
	switch (pid=fork()) {
	case -1:
		fprintf(stderr, "%% No processes left\n");
		return -1;

	case 0:
		pager_init();
		signal(SIGINT, SIG_DFL);
		while (!feof(tf)) {
			if (pager_skipping())
				raise(SIGINT);
			tbuf[0] = 0;
			fgets(tbuf, 255, tf);
			tbuf[255] = 0;
			{
			char *date, *info, *p;
			char name[16];
			int last_one_was_printed=0;

			if (!strlen(tbuf))
				continue;
			tbuf[19] = 0; /* <7> Jan  9 23:41:40 */
			date = tbuf+4; /* Jan  9 23:41:40 */
			info = tbuf+20; /* kernel: X.25(1): TX on serial0 size=131 frametype=0x54 */
			if (tm_start) {
				time(&tm);
				localtime_r(&tm, &tm_time);
				strptime(date, "%b %d %T", &tm_time);
				tm = mktime(&tm_time);
				if (tm < tm_start)
					continue; /* skip! */
			}
			p = find_debug_token(info, name, 1);
			if (p != NULL) {
				last_one_was_printed = 1;
				pprintf("%s %s%s", date, name, p);
			} else {
				if ((strncmp(info, "last message repeated", 21) == 0)
				    && last_one_was_printed) {
					pprintf("%s %s", date, info);
				}
#ifdef CONFIG_DEVELOPMENT /* Show all lines... */
				else pprintf("%s %s", date, info);
#endif
			}
			last_one_was_printed = 0;
			}
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

	args=make_args(cmdline);
	if (args->argc > 2) {
		if (strcmp(args->argv[2], "tail") == 0) {
			tail = 1;
		} else {
			if (parse_time(args->argv[2], &hour, &min, &sec) < 0) {
				destroy_args(args);
				return;
			}
			time(&tm);
			localtime_r(&tm, &tm_time);
			tm_time.tm_hour = hour;
			tm_time.tm_min  = min;
			tm_time.tm_sec  = sec;
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
		for (i=199; i >= 0; i--) /* have to match syslogd configuration */
#else
		for (i=49; i >= 0; i--) /* have to match syslogd configuration */
#endif
		{
			sprintf(logname, "/var/log/messages.%d", i);
			if ((tf=fopen(logname,"r")) != NULL) {
				if (show_logging_file(tm)) {
					pprintf("%s", "\n");
					goto skip;
				}
			}
		}
	}
	strcpy(logname, "/var/log/messages");
	if ((tf=fopen(logname,"r")) != NULL) {
		if (show_logging_file(tm))
			pprintf("%s", "\n");
	}
skip:
	destroy_args(args);
}

void clear_logging(const char *cmdline) /* clear logging */
{
	int i;
	char logname[32];

#ifdef OPTION_IPSEC
	for (i=200; i >= 0; i--) /* have to match syslogd configuration */
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

static void stripws(char *string)
{
	int ln; /* string length tempvar */

	ln = strlen(string);
	while ( (ln > 0) && (string[ln-1] <= 32) )
		string[--ln] = 0;
}

void show_processes(const char *cmdline)
{
	int pid, i;
	char *t, *tt;
	short found, first = 1;

	struct {
		char *linux_name;
		char *cish_name;
	} proc_names[] = {
		{ "syslogd", 			"System Logger" },
		{ "klogd", 				"Kernel Logger" },
		{ "cish",				"Configuration Shell" },
		{ "pppd",			 	"PPP Session" },
		{ "inetd",				"Service Multiplexer" },
		{ "systtyd",			"Runtime System" },
		{ "thttpd",				"Web Server" },
#ifdef OPTION_OPENSSH
		{ "sshd",				"SSH Server" },
#else
		{ "dropbear",			"SSH Server" },
#endif
		{ "telnetd",			"Telnet Server" },
		{ "ftpd",				"FTP Server" },
		{ "snmpd",				"SNMP Agent" },
		{ "ospfd",				"OSPF Server" },
		{ "ripd",				"RIP Server" },
#ifdef OPTION_BGP
		{ "bgpd",				"BGP Server" },
#endif
#ifdef UDHCPD
		{ "udhcpd",				"DHCP Server" },
#else
		{ "dhcpd",				"DHCP Server" },
#endif
		{ "dhcrelay",			"DHCP Relay" },
		{ "rfc1356",			"RFC1356 Tunnel" },
		{ "dnsmasq",			"DNS Relay" },
#ifdef OPTION_NTPD
		{ "ntpd",				"NTP Server" },
#endif
#ifdef OPTION_IPSEC
		{ "/lib/ipsec/pluto",	"VPN Server" },
		{ "l2tpd",				"L2TP Server" },
#endif
#ifdef OPTION_PIMD
		{ "pimdd",				"PIM-DM Server" },
		{ "pimsd",				"PIM-SM Server" },
#endif
#ifdef OPTION_RMON
		{ "rmond",				"RMON Server" },
#endif
#ifdef OPTION_VRRP
		{ "keepalived",			"VRRP Server" },
#endif
#ifdef OPTION_X25MAP
		{ "x25mapd",			"X25map Server" },
#endif
#ifdef OPTION_X25XOT
		{ "xotd",				"XOT Server" },
#endif
		{ NULL,					NULL }
	};

	tf = popen("/bin/ps","r"); /* axuw */
	if (!tf)
		return;
	while (!feof(tf)) {
		tbuf[0] = 0;
		fgets(tbuf, 255, tf);
		stripws(tbuf);
		tbuf[88] = 0; /* truncate */
		if (strlen(tbuf)) {
			if (first) {
				pprintf("%s\n", tbuf+9);
				first = 0;
			}
			else {
				t = tbuf;
				while ((*t) && (*t != ' '))
					++t;
				while (*t == ' ')
					++t;
				pid = atoi(t);

				t = strchr (tbuf, ':');
				if ((t) && (tt = strchr (t+1, ':'))) {
					if ((tt - t) == 7)
						t = tt;
				}
				if (t)
					t = strchr (t, ' ');
				if (t) {
					++t;
					found = 0;
					for (i=0; proc_names[i].linux_name; i++) {
						if (strstr(t, proc_names[i].linux_name)) {
							found = 1;
							break;
						}
					}
					if (found) {
						strcpy(t, proc_names[i].cish_name);
						pprintf("%s\n", tbuf+9);
					}
				}
			}
		}
	}
	if (tf)
		pclose(tf);
}

void show_uptime(const char *cmdline)
{
	tf=popen("/bin/uptime","r");
	show_output();
	if (tf) pclose(tf);
}

const char *_WKDAY[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

const char *_MONTH[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

void show_clock(const char *cmdline)
{
	system("/bin/date");
}

char *get_linux_version(void)
{
	static struct utsname u;

	if (uname(&u)==0)
		return u.release;
	else
		return "<unknown>";
}

void show_version(const char *cmdline)
{
#ifdef CONFIG_DEVELOPMENT
	printf("Engineering prototype\n");
#endif
	printf("Bootloader version: %s\n", get_boot_version());
	printf("System version: %s\n", get_system_version());
#if 0
	printf("Owner: %s\n", get_product_owner());
	printf("Licensed: %s\n", get_product_licensed());
	printf("Serial number: %s\n", get_serial_number());
	printf("System ID: %s\n", get_system_ID(1));
#endif
}

void dump_version(FILE *out)
{
	fprintf(out, "version %s\n", get_system_version());
	fprintf(out, "!\n");
}

const char SPAC32[] = "                                ";

void show_arp(const char *cmdline)
{
	FILE	*F;
	char	*ipaddr;
	char	*hwaddr;
	char	*type;
	char	*osdev;
	char 	*cdev;
	long	flags;
	arglist *args;

	F = fopen("/proc/net/arp", "r");
	if (!F)
	{
		printf("%% Unable to read ARP table\n");
		return;
	}

	printf("Protocol  Address          Age (min)    Hardware Addr  Type   Interface\n");

	fgets (tbuf, 127, F);

	while (!feof (F))
	{
		tbuf[0] = 0;
		fgets (tbuf, 127, F);
		tbuf[127] = 0;
		striplf (tbuf);
		
		args=make_args(tbuf);
		if (args->argc>=6)
		{
			ipaddr = args->argv[0];
			hwaddr = args->argv[3];
			type   = args->argv[1];
			osdev  = args->argv[5];
			flags = strtoul(args->argv[2], 0, 16);
			
			if (flags&ATF_COM) // Entrada valida (completed)
			{
				pprintf("Internet  %s%s", ipaddr, SPAC32+16+strlen(ipaddr));
				pprintf("        0     %c%c%c%c.%c%c%c%c.%c%c%c%c ",
					tolower(hwaddr[0]),  tolower(hwaddr[1]),
					tolower(hwaddr[3]),  tolower(hwaddr[4]),
					tolower(hwaddr[6]),  tolower(hwaddr[7]),
					tolower(hwaddr[9]),  tolower(hwaddr[10]),
					tolower(hwaddr[12]), tolower(hwaddr[13]),
					tolower(hwaddr[15]), tolower(hwaddr[16]));

				if (strcmp(type, "0x1") == 0) printf("ARPA   ");
					else pprintf("other  ");
				cdev=convert_os_device(osdev, 1);
				if (cdev) pprintf("%s", cdev);
				pprintf("\n");
			}
		}
		destroy_args(args);
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

	printf("IP domain lookup is currently %sabled\n", is_domain_lookup_enabled() ? "en" : "dis");
	printf("DNS relay is currently %sabled\n", is_daemon_running(DNS_DAEMON) ? "en" : "dis");

	/* Lista servidores DNS estaticos */
	for (i=0; i < DNS_MAX_SERVERS; i++) {
		if (get_nameserver_by_type_actv_index(DNS_STATIC_NAMESERVER, 1, i, addr) < 0)
			break;
		printf("Static ip name-server %s\n", addr);
	}
	for (i=0; i < DNS_MAX_SERVERS; i++) {
		if (get_nameserver_by_type_actv_index(DNS_STATIC_NAMESERVER, 0, i, addr) < 0)
			break;
		printf("Static ip name-server %s (inactive)\n", addr);
	}

	/* Lista servidores DNS dinamicos */
	for (i=0; ; i++) {
		if (get_nameserver_by_type_actv_index(DNS_DYNAMIC_NAMESERVER, 1, i, addr) < 0)
			break;
		printf("Dynamic ip name-server %s\n", addr);
	}
	for (i=0; ; i++) {
		if (get_nameserver_by_type_actv_index(DNS_DYNAMIC_NAMESERVER, 0, i, addr) < 0)
			break;
		printf("Dynamic ip name-server %s (inactive)\n", addr);
	}
}

void show_memory(const char *cmdline)
{
	int i;

	if ((tf = fopen("/proc/meminfo", "r"))) {
		for (i=0; (i < 2) && !feof(tf); i++) {
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
	if ((tf = fopen("/proc/net/softnet_stat", "r"))) {
		for (; !feof(tf);) {
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

void dump_routing(FILE *out, int conf_format)
{
	if (conf_format) {
		zebra_dump_static_routes_conf(out);
	} else {
		zebra_dump_routes(out);
	}
}


void dump_policy_interface(FILE *out, char *intf)
{
	intf_qos_cfg_t *cfg;

	
	/* Skip sub-interfaces, except frame-relay dlci's */
	if (strchr(intf, '.') && strncmp(intf,"serial",6)) return;
	/* If qos file does not exist, create one and show default values*/
	if (get_interface_qos_config(intf, &cfg) <= 0) {
		create_interface_qos_config(intf);
		if (get_interface_qos_config(intf, &cfg) <= 0)
			return;
	}
	if (cfg) {
		fprintf(out, " bandwidth %dkbps\n", cfg->bw/1024);
		fprintf(out, " max-reserved-bandwidth %d\n", cfg->max_reserved_bw);
		if (cfg->pname[0] != 0) fprintf(out, " service-policy %s\n", cfg->pname);
		release_qos_config(cfg);
	}
}

int qsort_dump_interfaces(const void *a, const void *b)
{
	char idx;
	char if_a[16], if_b[16];

	strcpy(if_a, link_table[*(int *)a].ifname);
	if (strncmp(if_a, AUXDEV_PPP, 2) == 0) { /* ax */
		idx=if_a[2];
		strcpy(if_a, AUXDEV);
		if_a[3]=idx;
		if_a[4]=0;
	} else if (strncmp(if_a, SERIALDEV_PPP, 2) == 0) { /* sx */
		idx=if_a[2];
		strcpy(if_a, SERIALDEV);
		if_a[6]=idx;
		if_a[7]=0;
	}
	strcpy(if_b, link_table[*(int *)b].ifname);
	if (strncmp(if_b, AUXDEV_PPP, 2) == 0) { /* ax */
		idx=if_b[2];
		strcpy(if_b, AUXDEV);
		if_b[3]=idx;
		if_b[4]=0;
	} else if (strncmp(if_b, SERIALDEV_PPP, 2) == 0) { /* sx */
		idx=if_b[2];
		strcpy(if_b, SERIALDEV);
		if_b[6]=idx;
		if_b[7]=0;
	}
	return strcmp(if_a, if_b);
}


void dump_interfaces(FILE *out, int conf_format, char *intf)
{
	int i, j, ret, n, up, mtu, txqueue, running;
	int linktype, serial_no = 0;
	int phy_status = 0, minor = 0;
	struct ip_t ip;
	struct iptables_t ipt;
	char *osdev, *pppdev=NULL, *osdev_ip, *cish_dev;
	char mac_bin[6], mac[16], *description, devtmp[17];
	struct net_device_stats *st;
	int intf_sort_indexes[MAX_NUM_LINKS];

#if 0
	int vlan_cos=NONE_TO_COS;
#endif

	/* Get all information */
	ret = get_if_list();
	if (ret < 0) {
		printf("%% ERROR : Could not get interfaces information\n");
		return;
	}

	/* Sort list */
	for (i=0; i < link_table_index; i++) 
		intf_sort_indexes[i]=i;

	qsort(&intf_sort_indexes[0], link_table_index, 
		sizeof(int), qsort_dump_interfaces);

	for (j=0; j < link_table_index; j++) {

		i = intf_sort_indexes[j];
		osdev = link_table[i].ifname;
		up = link_table[i].flags & IFF_UP;
		mtu = link_table[i].mtu;
		st = &link_table[i].stats;
		linktype=link_table[i].type;
		mac[0]=0;

		if (get_mac(linktype == ARPHRD_ETHER ? 
			osdev : "ethernet0", mac_bin) == 0)
				sprintf(mac, "%02x%02x.%02x%02x.%02x%02x",
					mac_bin[0], mac_bin[1], 
					mac_bin[2], mac_bin[3], 
					mac_bin[4], mac_bin[5]);


		osdev_ip = pppdev ? pppdev : osdev;

		/* se for ethernet e estiver fazendo parte de uma bridge, le o ip da bridge */
		if (strncmp(osdev_ip, "ethernet", 8) == 0)
			osdev_ip = get_ethernet_dev(osdev_ip);

		for (n=0, ip.ipaddr[0]=0, ip.ippeer[0]=0; n < ip_addr_table_index; n++)
		{
			if (strcmp(osdev_ip, ip_addr_table[n].ifname) == 0)
			{
				strcpy(ip.ipaddr, inet_ntoa(ip_addr_table[n].local));
				ip_bitlen2mask(ip_addr_table[n].bitlen, ip.ipmask);
				if (link_table[i].flags & IFF_POINTOPOINT)
					strcpy(ip.ippeer, inet_ntoa(ip_addr_table[n].remote));
				break;
			}
		}

		cish_dev = convert_os_device(osdev, conf_format ? 0 : 1);

		if (conf_format) {
			if (intf && (
#ifdef OPTION_IPSEC
				strcasecmp(osdev+7, intf) && /* Crypto-serial0.16 */
#endif
				strcasecmp(osdev, intf)) )
				continue; /* skip not matched interfaces */
		}

		if (cish_dev == NULL) continue; /* ignora dev nao usado pelo cish */

		if (strncmp(osdev, "ipsec", 5) == 0)
			linktype=ARPHRD_TUNNEL6; /* !!! change crypto-? linktype (temp!) */
#if 0
		switch (linktype) {

			case ARPHRD_ETHER:
				phy_status=lan_get_status(osdev);
				running=(up && (phy_status & PHY_STAT_LINK) ? 1 : 0); /* vlan: interface must be up */
				if (!strncmp(osdev,"ethernet",8) && strstr(osdev,".")) /* VLAN */
					vlan_cos = get_vlan_cos(osdev);
				else
					vlan_cos = NONE_TO_COS;
				break;
			default:
				running=(link_table[i].flags & IFF_RUNNING) ? 1 : 0;
				break;
		}
#endif

		if (linktype == ARPHRD_LOOPBACK && !running)
			continue; /* !!! ignore loopback down interfaces !!! */

		if (conf_format)
		{
			memset(&ipt, 0, sizeof(struct iptables_t));
			acl_get_iface_acls(osdev, ipt.in_acl, ipt.out_acl);
			get_iface_mangle_rules(osdev, ipt.in_mangle, ipt.out_mangle);
			get_iface_nat_rules(osdev, ipt.in_nat, ipt.out_nat);

			if (linktype == ARPHRD_TUNNEL6) continue; /* skip ipsec ones... */
			fprintf (out, "interface %s\n", cish_dev);
			description = dev_get_description(osdev);
			if (description) fprintf(out, " description %s\n", description);
			switch (linktype)
			{
				case ARPHRD_ASYNCPPP:
				{
					ppp_config cfg;

					fprintf(out, " encapsulation ppp\n");
					ppp_get_config(serial_no, &cfg);
					if (ipt.in_acl[0]) fprintf(out, " ip access-group %s in\n", ipt.in_acl);
					if (ipt.out_acl[0]) fprintf(out, " ip access-group %s out\n", ipt.out_acl);
					if (ipt.in_mangle[0]) fprintf(out, " ip mark %s in\n", ipt.in_mangle);
					if (ipt.out_mangle[0]) fprintf(out, " ip mark %s out\n", ipt.out_mangle);
					if (ipt.in_nat[0]) fprintf(out, " ip nat %s in\n", ipt.in_nat);
					if (ipt.out_nat[0]) fprintf(out, " ip nat %s out\n", ipt.out_nat);

					dump_policy_interface(out, osdev);
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if ((cfg.ip_addr[0])&&(cfg.ip_mask[0]))
						fprintf(out, " ip address %s %s\n", cfg.ip_addr, cfg.ip_mask);
					else
						fprintf(out, " no ip address\n");
					if (cfg.ip_peer_addr[0])
						fprintf(out, " ip peer-address %s\n", cfg.ip_peer_addr);
					if (cfg.default_route) fprintf(out, " ip default-route\n");
					if (cfg.novj) fprintf(out, " no ip vj\n");
					else fprintf(out, " ip vj\n");

					if (cfg.echo_interval) fprintf(out, " keepalive interval %d\n", cfg.echo_interval);
					if (cfg.echo_failure) fprintf(out, " keepalive timeout %d\n", cfg.echo_failure);
					if (cfg.mtu) fprintf(out, " mtu %d\n", cfg.mtu);
					if (cfg.debug) fprintf(out, " ppp debug\n");
					if (cfg.multilink)
						fprintf(out, " ppp multilink\n");
					if (cfg.usepeerdns) fprintf(out, " ppp usepeerdns\n");

					if (cfg.speed) fprintf(out, " speed %d\n", cfg.speed);

					if (cfg.flow_control == FLOW_CONTROL_NONE)
						fprintf(out, " no flow-control\n");
					else
						fprintf(out, " flow-control %s\n", 
							cfg.flow_control==FLOW_CONTROL_RTSCTS ? 
							"rts-cts" : "xon-xoff");

					if (cfg.chat_script[0]) 
						fprintf(out, " chat-script %s\n", cfg.chat_script);
					else 
						fprintf(out, " no chat-script\n");
					fprintf(out, " %sdial-on-demand\n", cfg.dial_on_demand ? "" : "no ");
					if (cfg.holdoff)
						fprintf(out, " holdoff %d\n", cfg.holdoff);
					if (cfg.idle)
						fprintf(out, " idle %d\n", cfg.idle);

					if (cfg.auth_user[0]) fprintf(out, " authentication user %s\n", cfg.auth_user);
					if (cfg.auth_pass[0]) fprintf(out, " authentication pass %s\n", cfg.auth_pass);
					if ((!cfg.auth_user[0]) && (!cfg.auth_pass[0])) fprintf(out, " no authentication\n");
					if (cfg.server_flags & (SERVER_FLAGS_PAP|SERVER_FLAGS_CHAP)) fprintf(out, " server authentication local algorithm %s\n", cfg.server_flags&SERVER_FLAGS_PAP ? "pap" : \
						cfg.server_flags&SERVER_FLAGS_CHAP ? "chap" : "");
					if (cfg.server_auth_user[0]) fprintf(out, " server authentication local user %s\n", cfg.server_auth_user);
					if (cfg.server_auth_pass[0]) fprintf(out, " server authentication local pass %s\n", cfg.server_auth_pass);
					// radius authentication
					if (cfg.radius_authkey[0]) fprintf(out, " server authentication radius auth_key %s\n", cfg.radius_authkey);
					if (cfg.radius_retries > 0) fprintf(out, " server authentication radius retries %d\n", cfg.radius_retries);
					if (cfg.radius_sameserver > 0) fprintf(out, " server authentication radius same_server\n");
					if (cfg.radius_servers[0]) fprintf(out, " server authentication radius servers %s\n", cfg.radius_servers);
					if (cfg.radius_timeout > 0) fprintf(out, " server authentication radius timeout %d\n", cfg.radius_timeout);
					if (cfg.radius_trynextonreject > 0) fprintf(out, " server authentication radius try_next_on_reject\n");
					// tacacs authentication
					if (cfg.tacacs_authkey[0]) fprintf(out, " server authentication tacacs auth_key %s\n", cfg.tacacs_authkey);
					if (cfg.tacacs_sameserver > 0) fprintf(out, " server authentication tacacs same_server\n");
					if (cfg.tacacs_servers[0]) fprintf(out, " server authentication tacacs servers %s\n", cfg.tacacs_servers);
					if (cfg.tacacs_trynextonreject > 0) fprintf(out, " server authentication tacacs try_next_on_reject\n");
					if ((cfg.server_ip_addr[0])&&(cfg.server_ip_mask[0]))
						fprintf(out, " server ip address %s %s\n", cfg.server_ip_addr, cfg.server_ip_mask);
					if (cfg.server_ip_peer_addr[0])
						fprintf(out, " server ip peer-address %s\n", cfg.server_ip_peer_addr);
					fprintf(out, " %sserver shutdown\n", (cfg.server_flags & SERVER_FLAGS_ENABLE) ? "no " : "");
					fprintf(out, " %sshutdown\n", cfg.up ? "no " : "");
					break;
				}

				case ARPHRD_ETHER:
				{
					int k, ether_no, found;
					char *p;
					char daemon_dhcpc[32];

					if (ipt.in_acl[0]) fprintf (out, " ip access-group %s in\n", ipt.in_acl);
					if (ipt.out_acl[0]) fprintf (out, " ip access-group %s out\n", ipt.out_acl);
					if (ipt.in_mangle[0]) fprintf (out, " ip mark %s in\n", ipt.in_mangle);
					if (ipt.out_mangle[0]) fprintf (out, " ip mark %s out\n", ipt.out_mangle);
					if (ipt.in_nat[0]) fprintf (out, " ip nat %s in\n", ipt.in_nat);
					if (ipt.out_nat[0]) fprintf (out, " ip nat %s out\n", ipt.out_nat);
#ifdef OPTION_PIMD
					dump_pim_interface(out, osdev);
#endif
					dump_policy_interface(out, osdev);
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					ether_no=atoi(osdev+strlen(ETHERNETDEV));
					if ((p=strchr(osdev, '.')) != NULL) minor=atoi(p+1); /* skip '.' */
					if (minor) daemon_dhcpc[0]=0; /* dhcpc only on ethernet0 */
						else sprintf(daemon_dhcpc, DHCPC_DAEMON, osdev);
					if (strlen(daemon_dhcpc) && is_daemon_running(daemon_dhcpc)) fprintf(out, " ip address dhcp\n");
						else if (ip.ipaddr[0]) fprintf(out, " ip address %s %s\n", ip.ipaddr, ip.ipmask);
								else  fprintf(out, " no ip address\n");
					/* search for alias */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ":0");
					for (k=0, found=0; k < ip_addr_table_index; k++)
					{
						if (strcmp(devtmp, ip_addr_table[k].ifname) == 0)
						{
							strcpy(ip.ipaddr, inet_ntoa(ip_addr_table[k].local));
							ip_bitlen2mask(ip_addr_table[k].bitlen, ip.ipmask);
							fprintf (out, " ip address %s %s secondary\n", ip.ipaddr, ip.ipmask);
							found=1;
						}
					}

					if (mtu) fprintf (out, " mtu %d\n", mtu);
					if (txqueue) fprintf (out, " txqueuelen %d\n", txqueue);
					/* search for vlan */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ".");
					for (k=0; k < link_table_index; k++)
					{
						if (strncmp(link_table[k].ifname, devtmp, strlen(devtmp)) == 0)
						{
							fprintf (out, " vlan %s\n", link_table[k].ifname+strlen(devtmp));
						}
					}

					if (strchr(osdev, '.') == NULL)	{ /* Avoid vlans! */
						int bmcr;

						bmcr = lan_get_phy_reg(osdev, MII_BMCR);
						if (bmcr & BMCR_ANENABLE)
							fprintf(out, " speed auto\n");
						else {
							fprintf(out, " speed %s %s\n",
								(bmcr & BMCR_SPEED100) ? "100" : "10",
								(bmcr & BMCR_FULLDPLX) ? "full" : "half");
						}
					}
#ifdef OPTION_VRRP
					dump_vrrp_interface(out, osdev);
#endif
					fprintf (out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_LOOPBACK:
				{
					int k;

					if (ipt.in_acl[0]) fprintf (out, " ip access-group %s in\n", ipt.in_acl);
					if (ipt.out_acl[0]) fprintf (out, " ip access-group %s out\n", ipt.out_acl);
					if (ip.ipaddr[0]) fprintf(out, " ip address %s %s\n", ip.ipaddr, ip.ipmask);
						else  fprintf(out, " no ip address\n");
					/* search for alias */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ":0");
					for (k=0; k < ip_addr_table_index; k++)
					{
						if (strcmp(devtmp, ip_addr_table[k].ifname) == 0)
						{
							strcpy(ip.ipaddr, inet_ntoa(ip_addr_table[k].local));
							ip_bitlen2mask(ip_addr_table[k].bitlen, ip.ipmask);
							fprintf(out, " ip address %s %s secondary\n", ip.ipaddr, ip.ipmask);
						}
					}
					/* Doesnt need to search for backuped secondary addresses */
					fprintf (out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_TUNNEL:
				case ARPHRD_IPGRE:
				{
					int k, found;

					if (ipt.in_acl[0]) fprintf (out, " ip access-group %s in\n", ipt.in_acl);
					if (ipt.out_acl[0]) fprintf (out, " ip access-group %s out\n", ipt.out_acl);
					if (ipt.in_mangle[0]) fprintf (out, " ip mark %s in\n", ipt.in_mangle);
					if (ipt.out_mangle[0]) fprintf (out, " ip mark %s out\n", ipt.out_mangle);
					if (ipt.in_nat[0]) fprintf (out, " ip nat %s in\n", ipt.in_nat);
					if (ipt.out_nat[0]) fprintf (out, " ip nat %s out\n", ipt.out_nat);
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if (ip.ipaddr[0]) fprintf(out, " ip address %s %s\n", ip.ipaddr, ip.ipmask);
						else  fprintf(out, " no ip address\n");
					/* search for alias */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ":0");
					for (k=0, found=0; k < ip_addr_table_index; k++)
					{
						if (strcmp(devtmp, ip_addr_table[k].ifname) == 0)
						{
							strcpy(ip.ipaddr, inet_ntoa(ip_addr_table[k].local));
							ip_bitlen2mask(ip_addr_table[k].bitlen, ip.ipmask);
							fprintf (out, " ip address %s %s secondary\n", ip.ipaddr, ip.ipmask);
							found=1;
						}
					}

					if (mtu) fprintf(out, " mtu %d\n", mtu);
					if (txqueue) fprintf(out, " txqueuelen %d\n", txqueue);
					dump_tunnel_interface(out, conf_format, osdev);
					fprintf(out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				default:
				{
					printf("%% unknown link type: %d\n", linktype);
					break;
				}
			}

			/*  Generates configuration about the send of traps for every interface:
			 *    aux(0, 1 ,...)
			 *    ethernet(0, 1, ...)
			 *    serial(0, 1, ...)
			 */
			{
				char *p, buf[100], idx[20]="";
				strcpy(buf, cish_dev);
				if((p = strchr(buf, ' ')))
				{
					*p = '\0';
					for(p++; *p == ' '; p++);
					if(strlen(p) < 20)
					{
						strcpy(idx, p);
						strcat(buf, idx);
					}
					if(!strchr(buf, '.'))
					{
						if (itf_should_sendtrap(buf)) fprintf(out, " snmp trap link-status\n");
#if 0
							else fprintf(out, " no snmp trap link-status\n");
#endif
					}
				}
			}

			fprintf (out, "!\n");
		}
		else
		{
			if (intf && (
#ifdef OPTION_IPSEC
				strcasecmp(cish_dev+7, intf) && /* Crypto-serial0.16 */
#endif
				strcasecmp(cish_dev, intf)
				)) continue; /* skip not matched interfaces */

			fprintf(out, "%s is %s, line protocol is %s%s\n",
					cish_dev,
					up ? (1 ? "up" : "down") : "administratively down", //FIXME
					running & IF_STATE_UP ? "up" : "down", running & IF_STATE_LOOP ? " (looped)" : "");

			description = dev_get_description(osdev);
			if (description) fprintf(out, "  Description: %s\n",description);

			// Caso especial (mais um...) - no PPP temos as seguintes situacoes em relacao aos IPs:
			// 1. IP local configurado - nesse caso devemos sempre apresentar o IP configurado
			// 2. IP local nao configurado - nesse caso apresentamos o IP da interface, caso exista.
			//    Se nao existir eh porque a negociacao IPCP ainda nao ocorreu - nesse caso nao
			//    apresentamos nada.
			// O teste abaixo eh para cobrir o caso 1.
			if ((linktype==ARPHRD_PPP) || (linktype==ARPHRD_ASYNCPPP))
			{
				ppp_config cfg;

				ppp_get_config(serial_no, &cfg);
				if (cfg.ip_addr[0]) { strncpy(ip.ipaddr, cfg.ip_addr, 16); ip.ipaddr[15]=0; }
				if (cfg.ip_mask[0]) { strncpy(ip.ipmask, cfg.ip_mask, 16); ip.ipmask[15]=0; }
				if (cfg.ip_peer_addr[0]) { strncpy(ip.ippeer, cfg.ip_peer_addr, 16); ip.ippeer[15]=0; }
				if (cfg.dial_on_demand && !running) { /* filtra enderecos aleatorios atribuidos pelo pppd */
					ip.ipaddr[0]=0;
					ip.ippeer[0]=0;
				}
				if (cfg.ip_unnumbered != -1) /* Verifica a flag ip_unnumbered do cfg e exibe a mensagem correta */
					fprintf(out, "  Interface is unnumbered. Using address of ethernet %d (%s)\n", cfg.ip_unnumbered, ip.ipaddr);
				else
					if (ip.ipaddr[0]) fprintf(out, "  Internet address is %s %s\n", ip.ipaddr, ip.ipmask);
			}
				else if (ip.ipaddr[0]) fprintf (out, "  Internet address is %s %s\n", ip.ipaddr, ip.ipmask);
				/* Secondary address search */		
				strncpy(devtmp, osdev, 14);
				strcat(devtmp, ":0");
				for (i=0; i < ip_addr_table_index; i++) {
					if (strcmp(devtmp, ip_addr_table[i].ifname) == 0)  {
						strcpy(ip.ipaddr, inet_ntoa(ip_addr_table[i].local));
						ip_bitlen2mask(ip_addr_table[i].bitlen, ip.ipmask);
						fprintf (out, "  Secondary internet address is %s %s\n", ip.ipaddr, ip.ipmask);
					}
				}

			if (ip.ippeer[0] && !(linktype == ARPHRD_TUNNEL || linktype == ARPHRD_IPGRE))
				fprintf (out, "  Peer address is %s\n", ip.ippeer);
			fprintf (out, "  MTU is %i bytes\n", mtu);
			if (txqueue) fprintf (out, "  Output queue size: %i\n", txqueue);

			switch (linktype)
			{
				case ARPHRD_PPP:
				case ARPHRD_ASYNCPPP:
				{
						ppp_config cfg;

						ppp_get_config(serial_no, &cfg);
						fprintf(out, "  Encapsulation PPP");
						if (cfg.echo_interval) fprintf(out, ", echo interval %d", cfg.echo_interval);
						if (cfg.echo_failure) fprintf(out, ", echo failure %d", cfg.echo_failure);
						fprintf(out, "\n");
				}
				break;

				case ARPHRD_ETHER:
				{
					if (mac[0]) fprintf (out, "  Hardware address is %s\n", mac);
					if (running)
					{
						int bmcr, pgsr, pssr;

						bmcr = lan_get_phy_reg(osdev, MII_BMCR);
						if (bmcr & BMCR_ANENABLE) {
							fprintf(out, "  Auto-sense");
							if (phy_status & PHY_STAT_ANC) {
								switch (phy_status & PHY_STAT_SPMASK) {
									case PHY_STAT_10HDX: fprintf(out, " 10Mbps, Half-Duplex"); break;
									case PHY_STAT_10FDX: fprintf(out, " 10Mbps, Full-Duplex"); break;
									case PHY_STAT_100HDX: fprintf(out, " 100Mbps, Half-Duplex"); break;
									case PHY_STAT_100FDX: fprintf(out, " 100Mbps, Full-Duplex"); break;
								}
							} else {
								fprintf(out, " waiting...");
							}
						} else {
							fprintf(out, "  Forced");
							fprintf(out, " %sMbps, %s-Duplex",
								(bmcr & BMCR_SPEED100) ? "100" : "10",
								(bmcr & BMCR_FULLDPLX) ? "Full" : "Half");

						}
						if (phy_status & PHY_STAT_FAULT) {
							fprintf(out, ", Remote Fault Detect!\n");
						} else {
							fprintf(out, "\n");
						}

						pgsr = lan_get_phy_reg(osdev, MII_ADM7001_PGSR);
						pssr = lan_get_phy_reg(osdev, MII_ADM7001_PSSR);
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
							else fprintf(out, ", length below 40m");
#ifdef CONFIG_DEVELOPMENT
							fprintf(out, " (cblen=%d)\n", pgsr & MII_ADM7001_PGSR_CBLEN);
#else
							fprintf(out, "\n");
#endif
						} else {
							fprintf(out, "\n");
						}
					}
					break;
				}

				case ARPHRD_LOOPBACK:
					break;

				case ARPHRD_TUNNEL:
				case ARPHRD_IPGRE:
					dump_tunnel_interface(out, conf_format, osdev);
					break;

				case ARPHRD_TUNNEL6: /* ipsec decoy! */
					break;

				default:
					fprintf(stderr, "%% unknown link type: %d\n", linktype);
					break;
			}
			fprintf(out, "     %lu packets input, %lu bytes\n", st->rx_packets, st->rx_bytes);
			fprintf(out, "     %lu input errors, %lu dropped, %lu overruns, %lu frame, %lu crc, %lu fifo\n", 
				st->rx_errors, st->rx_dropped, st->rx_over_errors, st->rx_frame_errors, st->rx_crc_errors, st->rx_fifo_errors);
#ifdef CONFIG_DEVELOPMENT
			fprintf(out, "     %lu length, %lu missed\n", st->rx_length_errors, st->rx_missed_errors);
			fprintf(out, "     %lu enable int, %lu max worked\n", st->rx_enable_int, st->rx_max_worked);

#endif
			fprintf(out, "     %lu packets output, %lu bytes\n", st->tx_packets, st->tx_bytes);
			fprintf(out, "     %lu output errors, %lu collisions, %lu dropped, %lu carrier, %lu fifo\n", 
				st->tx_errors, st->collisions, st->tx_dropped, st->tx_carrier_errors, st->tx_fifo_errors);
#ifdef CONFIG_DEVELOPMENT
			fprintf(out, "     %lu aborted, %lu heartbeat, %lu window\n", 
				st->tx_aborted_errors, st->tx_heartbeat_errors, st->tx_window_errors);
			fprintf(out, "     %lu enable int, %lu max worked\n", st->tx_enable_int, st->tx_max_worked);
			fprintf(out, "     %lu stopped, %lu restarted\n", st->tx_stopped, st->tx_restarted);
#endif


#if 0
			if (modem_info != -1) {
				fprintf(out, "     ");
				if (serial_no < MAX_WAN_INTF) /* serial[ 0-1 ] */
					fprintf(out, "DCD=%s  ", modem_info & TIOCM_CD?"up":"down");
				fprintf(out, "DSR=%s  DTR=%s  RTS=%s  CTS=%s\n", 
					modem_info & TIOCM_DSR ? "up" : "down",
					modem_info & TIOCM_DTR ? "up" : "down", 
					modem_info & TIOCM_RTS ? "up" : "down", 
					modem_info & TIOCM_CTS ? "up" : "down");
			}
#endif
			fprintf(out, "\n");
		}
	}
}


void dump_chatscripts(FILE *out)
{
	FILE *f;
	int printed_something = 0;
	struct dirent **namelist;
	int n;
	char filename[64];
	
	n = scandir(PPP_CHAT_DIR, &namelist, 0, alphasort);

	if (n < 0) {
		printf("%% cannot open dir "PPP_CHAT_DIR"\n");
		return;
	}
	
	while(n--) 
	{
		if (namelist[n]->d_name[0] != '.')
		{
			sprintf(filename, "%s%s", PPP_CHAT_DIR, namelist[n]->d_name);
			f = fopen(filename, "r");
			if (f)
			{
				fgets (buf, 1024, f); buf[1023] = 0;
				fprintf(out, "chatscript %s %s\n", namelist[n]->d_name, buf); 
				fclose(f);
				printed_something = 1;
			}
		}
		free(namelist[n]);
	}
	free(namelist);

	if (printed_something) fprintf(out, "!\n");
}

void dump_hostname(FILE *out)
{
	gethostname(buf, sizeof(buf)-1);
	buf[sizeof(buf)-1]=0;
	fprintf(out, "hostname %s\n!\n", buf);
}

void dump_clock(FILE *out)
{
	int hours, mins;
	char name[16];

	if (get_timezone(name, &hours, &mins)==0)
	{
		fprintf(out, "clock timezone %s %d", name, hours);
		if (mins > 0) fprintf(out, " %d\n", mins);
			else fprintf(out, "\n");
		fprintf(out, "!\n");
	}
}

void dump_ntp(FILE *out)
{
#ifdef OPTION_NTPD
	int i, printed_something=0;
	FILE *f;
	arglist *args;
	char *p, line[200];

#ifdef OPTION_NTPD_authenticate
	if (is_ntp_auth_used()) fprintf(out, "ntp authenticate\n");
		else fprintf(out, "no ntp authenticate\n");
#endif

	if((f=fopen(FILE_NTP_CONF, "r")))
	{
		while(fgets(line, 200, f))
		{
			if ((p=strchr(line, '\n'))) *p='\0';
			if (strlen(line))
			{
				args=make_args(line);
				if (!strcmp(args->argv[0], "restrict")) /* restrict <ipaddr> mask <mask> */
				{
					if (args->argc >= 4) {
						printed_something=1;
						fprintf(out, "ntp restrict %s %s\n", args->argv[1], args->argv[3]);
					}
				}
				destroy_args(args);
			}
		}
		fseek(f, 0, SEEK_SET);
		while(fgets(line, 200, f))
		{
			if((p=strchr(line, '\n')))
				*p = '\0';
			if(strlen(line))
			{
				args=make_args(line);
				if(!strcmp(args->argv[0], "trustedkey"))
				{
					printed_something=1;
					if (args->argc > 1)
					{
						for(i=1; i < args->argc; i++)
							fprintf(out, "ntp trusted-key %s\n", args->argv[i]);
					}
						else fprintf(out, "no ntp trusted-key\n");
				}
				destroy_args(args);
			}
		}
		fseek(f, 0, SEEK_SET);
		while(fgets(line, 200, f))
		{
			if((p=strchr(line, '\n')))
				*p='\0';
			if(strlen(line))
			{
				args=make_args(line);
				if(args->argc >= 2 && !strcmp(args->argv[0], "server")) /* server <ipaddr> iburst [key 1-16] */
				{
					printed_something=1;
					fprintf(out, "ntp server %s", args->argv[1]);
					if (args->argc >= 5 && !strcmp(args->argv[3], "key")) fprintf(out, " key %s\n", args->argv[4]);
						else fprintf(out, "\n");
				}
				destroy_args(args);
			}
		}
		fclose(f);
		if (printed_something)
			fprintf(out, "!\n");
	}
#endif /* OPTION_NTPD */
}

void dump_secret(FILE *out)
{
	int printed_something = 0;

	if (cish_cfg->enable_secret[0])
	{
		fprintf(out, "secret enable hash %s\n", cish_cfg->enable_secret);
		printed_something = 1;
	}

	if (cish_cfg->login_secret[0])
	{
		fprintf(out, "secret login hash %s\n", cish_cfg->login_secret);
		printed_something = 1;
	}

	if (printed_something) fprintf(out, "!\n");
}

void show_routingtables(const char *cmdline)
{
	dump_routing(stdout, 0);
}

void write_config(FILE *f)
{
	fprintf(f, "!\n");
	dump_version(f);
	dump_terminal(f);
	dump_secret(f);
	dump_aaa(f);
	dump_hostname(f);
	dump_log(f, 1);
#ifdef OPTION_BGP
	dump_router_bgp(f,0);
#endif
	dump_ip(f, 1);
	dump_snmp(f, 1);
#ifdef OPTION_RMON
	dump_rmon(f);
#endif

	dump_chatscripts(f);
	acl_dump_policy(f);
	acl_dump(0, f, 1);
	dump_nat(0, f, 1);
	dump_mangle(0, f, 1);
	dump_qos_config(f);
	dump_nat_helper(f);
	dump_router_rip(f);
	dump_router_ospf(f);
#ifdef OPTION_BGP
	dump_router_bgp(f, 1);
#endif
	dump_routing(f, 1);
#ifdef OPTION_SMCROUTE
	dump_mroute(f);
#endif
	dump_interfaces(f, 1, NULL);
	dump_clock(f);
	dump_ntp(f);
	dump_ip_servers(f, 1);
	dump_arp(f);
#ifdef OPTION_IPSEC
	dump_crypto(f);
#endif
}

void show_running_config(const char *cmdline)
{
	FILE *f;

	f = fopen(TMP_CFG_FILE, "wt");
	if (!f)
	{
		fprintf(stderr, "%% Can't build configuration\n");
		return;
	}
	printf("Building configuration...\n");
	write_config (f);
	fclose(f);

	tf = fopen (TMP_CFG_FILE,"r");
	show_output ();
	if (tf) fclose (tf);
	unlink(TMP_CFG_FILE);
}

void show_level_running_config(const char *cmdline)
{
	FILE *f;

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
		acl_dump(0, f, 1);
		dump_nat(0, f, 1);
		dump_mangle(0, f, 1);
		dump_nat_helper(f);
		dump_routing(f, 1);
#ifdef OPTION_SMCROUTE
		dump_mroute(f);
#endif
		dump_clock(f);
		dump_ntp(f);
		dump_ip_servers(f, 1);
		dump_arp(f);
	}
	else if (command_root == CMD_CONFIG_CRYPTO) {
#ifdef OPTION_IPSEC
		dump_crypto(f);
#endif
	}
	else if ((command_root == CMD_CONFIG_INTERFACE_ETHERNET)
			|| (command_root == CMD_CONFIG_INTERFACE_ETHERNET_VLAN)
			|| (command_root == CMD_CONFIG_INTERFACE_LOOPBACK)
			|| (command_root == CMD_CONFIG_INTERFACE_TUNNEL) ) {
		char *intf = convert_device(interface_edited->cish_string, interface_major, interface_minor);

		dump_interfaces(f, 1, intf);
		free(intf);
	}
	else if (command_root == CMD_CONFIG_ROUTER_RIP)
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
	show_output();
	if (tf)
		fclose(tf);
	unlink(TMP_CFG_FILE);
}

void show_startup_config(const char *cmdline)
{
	if (load_configuration(STARTUP_CFG_FILE) > 0)
	{
		tf=fopen(STARTUP_CFG_FILE, "r");
		show_output();
		if (tf) fclose(tf);
	}
}

void show_previous_config(const char *cmdline)
{
	if (load_previous_configuration(TMP_CFG_FILE) > 0)
	{
		tf=fopen(TMP_CFG_FILE, "r");
		show_output();
		if (tf) fclose(tf);
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
	printf(  "----------------- show processes -----------------\n\n");
	show_processes("");
	printf("\n");
}

void cmd_copy(const char *cmdline)
{
	char *in=NULL;
	arglist *args;
	char from, to;
	char *host=NULL, *filename=NULL;

	args=make_args(cmdline);
	from = args->argv[1][0];
	to   = args->argv[2][0];
	if ((from=='t')||(to=='t'))
	{
		host = args->argv[3];
		filename = args->argv[4];
	}
	switch (from)
	{
		case 'p':
		{
			if (load_previous_configuration(TMP_CFG_FILE) == 0)
			{
				fprintf(stderr, "%% No previous configuration\n");
				destroy_args(args);
				return;
			}
			in=TMP_CFG_FILE;
		}
		break;

		case 'r':
		{
			FILE *f;
			f=fopen(TMP_CFG_FILE, "wt");
			if (!f)
			{
				fprintf(stderr, "%% Can't build configuration\n");
				destroy_args(args);
				return;
			}
			printf("Building configuration...\n");
			write_config(f);
			fclose(f);
			in=TMP_CFG_FILE;
		}
		break;
	
		case 's':
		{
			if (load_configuration(STARTUP_CFG_FILE) == 0)
			{
				fprintf(stderr, "%% Configuration not saved\n");
				destroy_args(args);
				return;
			}
			in=STARTUP_CFG_FILE;
		}
		break;

		case 't':
		{
			char buf[128];
			FILE *f;
			char *s;
			sprintf(buf, "/bin/tftp -g -l %s -r %s %s 2> "TMP_TFTP_OUTPUT_FILE, TFTP_CFG_FILE, filename, host);
			system(buf);
			f=fopen(TMP_TFTP_OUTPUT_FILE, "rt");
			if (!f)
			{
				fprintf(stderr, "%% Can't read output\n");
				destroy_args(args);
				return;
			}
			fgets(buf, 127, f);
			fclose(f);
			s=strstr(buf, "tftp: ");
			if (s)
			{
				fprintf(stderr, "%% TFTP:%s", s+5);
				destroy_args(args);
				return;
			}
			in=TFTP_CFG_FILE;
		}
		break;
	}

	switch (to)
	{
		case 'r':
		{
			extern int _cish_booting;
			_cish_booting = 1;
			_cish_enable = 2; /* Enable special commands! */
			config_file(in);
			_cish_enable = 1; /* Restore enable level! */
			_cish_booting = 0;
		}
		break;

		case 's':
		{
			if (save_configuration(in) < 0)
			{
				fprintf(stderr, "%% Error writing configuration\n");
				destroy_args(args);
				return;
			}
		}
		break;

		case 't':
		{
			char buf[128];
			FILE *f;
			char *s;
			sprintf(buf, "/bin/tftp -p -l %s -r %s %s 2> "TMP_TFTP_OUTPUT_FILE, in, filename, host);
			system(buf);
			f = fopen(TMP_TFTP_OUTPUT_FILE, "rt");
			if (!f)
			{
				fprintf(stderr, "%% Can't read output\n");
				destroy_args(args);
				return;
			}
			fgets(buf, 127, f);
			fclose(f);
			s=strstr(buf, "tftp: ");
			if (s)
			{
				fprintf(stderr, "%% TFTP:%s", s+5);
				destroy_args(args);
				return;
			}
		}
		break;
	}
	printf("[OK]\n");
	unlink(TMP_CFG_FILE);
	unlink(TFTP_CFG_FILE);
	destroy_args(args);
}

void config_memory(const char *cmdline)
{
	cmd_copy("copy startup-config running-config");
}

void erase_cfg(const char *cmdline)
{
	FILE *f;

	f=fopen(STARTUP_CFG_FILE, "wt");
	fclose(f); /* zero size! */
	save_configuration(STARTUP_CFG_FILE);
}

void show_privilege (const char *cmdline)
{
	printf("Current privilege level is %i\n", _cish_enable);
}

void show_interfaces(const char *cmdline) /* show interfaces [aux|ethernet|loopback|serial|tunnel] [0-?] */
{
	arglist *args;
	char intf[100];

	// Melhorar esta parte - nao perdi tempo agora porque a parte de interfaces vai mudar !!!
	args=make_args(cmdline);
	if (args->argc > 2)
	{
		strncpy(intf, args->argv[2], 99);
		if (args->argc > 3) strncat(intf, args->argv[3], 99);
		dump_interfaces(stdout, 0, intf);
	}
		else dump_interfaces(stdout, 0, NULL);
	destroy_args(args);
}

void show_accesslists(const char *cmdline)
{
	arglist *args;

	args=make_args(cmdline);
	acl_dump((args->argc == 3) ? args->argv[2] : NULL, stdout, 0);
	destroy_args(args);
}

void show_manglerules(const char *cmdline)
{
	arglist *args;

	args=make_args(cmdline);
	dump_mangle((args->argc == 3) ? args->argv[2] : NULL, stdout, 0);
	destroy_args(args);
}

void show_natrules(const char *cmdline)
{
	arglist *args;

	args=make_args(cmdline);
	dump_nat((args->argc == 3) ? args->argv[2] : NULL, stdout, 0);
	destroy_args(args);
}

void show_performance(const char *cmdline)
{
	pid_t pid;
	arglist *args;

	args = make_args(cmdline);
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
	destroy_args(args);
}

void show_qos(const char *cmdline)
{
	qos_dump_interfaces();
}

#ifdef OPTION_IPSEC
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
	if (!(*net_flag))
	{
		printf("\033[3C%s\033[%dC%s\033[%dC%s\033[%dC%s", name, total_name_len-strlen(name), local, len-strlen(local)+(shift-len)/2, separator, second_shift, remote);
		printf("\033[%dC", third_shift-strlen(remote));
		if (strlen(authby)) printf("%s+", authby);
		if (strlen(authproto)) printf("%s+", authproto);
		if (strlen(esp_c)) printf("%s+", esp_c);
		if (strlen(pfs)) printf("%s+", pfs);
		printf("\033[1D ");
		printf("\033[5C");
		if (state == CONN_UP) printf("tunnel established");
			else if (state == CONN_DOWN) printf("tunnel not established");
			else if (state == CONN_INCOMPLETE) printf("incomplete configuration");
			else if (state == CONN_SHUTDOWN) printf("shutdown");
			else if (state == CONN_WAIT) printf("waiting...");
		*net_flag=1;
	}
		else printf("\033[%dC%s\033[%dC%s", total_name_len+3, local, shift-strlen(local), remote);
	printf("\n");
}

static int show_conn_specific(char *name, int state)
{
	int ret, len, len2, net_flag=0, shift=0, second_shift=0, third_shift=0;
	char *p, mask[20], authby[10], authproto[10], esp_c[20], pfs[5], tmp[300];
	char addr_l[MAX_ADDR_SIZE], cidr_l[20], id_l[MAX_ADDR_SIZE], nexthop_l[20];
	char addr_r[MAX_ADDR_SIZE], cidr_r[20], id_r[MAX_ADDR_SIZE], nexthop_r[20];

	// Busca id local
	tmp[0] = '\0';
	id_l[0] = '\0';
	if (get_ipsec_id(LOCAL, name, tmp) >= 0)
	{
		if(strlen(tmp)>0 && strlen(tmp)<MAX_ADDR_SIZE)	strcpy(id_l, tmp);
	}

	// Busca subrede local
	tmp[0] = '\0';
	addr_l[0] = '\0';
	mask[0] = '\0';
	cidr_l[0] = '\0';
	if (get_ipsec_subnet(LOCAL, name, tmp) >= 0)
	{
		if (strlen(tmp)>0)
		{
			if ((p=strchr(tmp, ' ')))
			{
				strncpy(addr_l, tmp, p-tmp);
				*(addr_l+(p-tmp))= '\0';
				p++;
				for(; *p==' '; p++);
				if(strlen(p)>0)
				{
					strcpy(mask, p);
					if(classic_to_cidr(addr_l, mask, cidr_l) != 0)	cidr_l[0] = '\0';
				}
			}
		}
	}

	// Busca endereco local
	tmp[0] = '\0';
	addr_l[0] = '\0';
	ret=get_ipsec_local_addr(name, tmp);
	if (ret >= 0)
	{
		if (ret>0 && strlen(tmp)<MAX_ADDR_SIZE)
		{
			if (ret == ADDR_DEFAULT) strcpy(addr_l, "default-route");
				else if (ret == ADDR_INTERFACE) strcpy(addr_l, tmp+1);
				else if (ret == ADDR_IP) strcpy(addr_l, tmp);
		}
	}

	// Busca nexthop local
	tmp[0] = '\0';
	nexthop_l[0] = '\0';
	ret=get_ipsec_nexthop(LOCAL, name, tmp);
	if(ret >= 0)
	{
		if (strlen(tmp)>0 && strlen(tmp)<20) strcpy(nexthop_l, tmp);
	}
	
	// Busca id remoto
	tmp[0] = '\0';
	id_r[0] = '\0';
	if (get_ipsec_id(REMOTE, name, tmp) >= 0)
	{
		if (strlen(tmp)>0 && strlen(tmp)<MAX_ADDR_SIZE)	strcpy(id_r, tmp);
	}
	
	// Busca subrede do remoto
	tmp[0] = '\0';
	addr_r[0] = '\0';
	mask[0] = '\0';
	cidr_r[0] = '\0';
	ret=get_ipsec_subnet(REMOTE, name, tmp);
	if (ret >= 0)
	{
		if (strlen(tmp)>0)
		{
			if ((p=strchr(tmp, ' ')))
			{
				strncpy(addr_r, tmp, p-tmp);
				*(addr_r+(p-tmp))= '\0';
				p++;
				for(; *p==' '; p++);
				if(strlen(p)>0)
				{
					strcpy(mask, p);
					if(classic_to_cidr(addr_r, mask, cidr_r) != 0)	cidr_r[0] = '\0';
				}
			}
		}
	}
	
	// Busca endereco remoto
	tmp[0] = '\0';
	addr_r[0] = '\0';
	ret=get_ipsec_remote_addr(name, tmp);
	if (ret >= 0)
	{
		if (ret>0 && strlen(tmp)<MAX_ADDR_SIZE)
		{
			if (ret == ADDR_ANY) strcpy(addr_r, "any");
				else strcpy(addr_r, tmp);
		}
			else addr_r[0] = '\0';
	}
		else addr_r[0] = '\0';

	// Busca nexthop remoto
	tmp[0] = '\0';
	nexthop_r[0] = '\0';
	ret=get_ipsec_nexthop(REMOTE, name, tmp);
	if (ret >= 0)
	{
		if (strlen(tmp)>0 && strlen(tmp)<20)	strcpy(nexthop_r, tmp);
	}
	
	// Busca tipo de autenticacao
	tmp[0] = '\0';
	authby[0] = '\0';
	switch (get_ipsec_auth(name, tmp))
	{
		case SECRET:
			strcpy(authby, "SECRET");
			break;
		case RSA:
			strcpy(authby, "RSA");
			break;
	}
	
	// Busca tipo de protocolo de autenticacao
	tmp[0] = '\0';
	esp_c[0] = '\0';
	authproto[0] = '\0';
	switch(get_ipsec_ike_authproto(name))
	{
		case ESP:
			strcat(authproto, "ESP");
			switch(get_ipsec_esp(name, tmp))
			{
				case 1:
					if (strlen(tmp)>0 && strlen(tmp)<10)
					{
						if (!strncmp(tmp, "des", 3)) strcpy(esp_c, "DES");
							else if (!strncmp(tmp, "3des", 4)) strcpy(esp_c, "3DES");
							else if (!strncmp(tmp, "aes", 3)) strcpy(esp_c, "AES");
							else if (!strncmp(tmp, "null", 4)) strcpy(esp_c, "NULL");
						if (strstr(tmp, "md5")) strcat(esp_c, "+MD5");
							else if (strstr(tmp, "sha1")) strcat(esp_c, "+SHA1");
					}
					break;
				default:
					//strcat(authproto, "+NOCRYPT");
					break;
			}
			break;
		case AH:
			break;
	}
	
	// Busca PFS
	pfs[0] = '\0';
	ret=get_ipsec_pfs(name);
	if(ret >= 0)
	{
		if(ret>0)	strcpy(pfs, "PFS");
	}
	
	// Busca tamanho do maior dado a ser exibido
	if ((len=strlen(addr_l))>shift) shift = len;
	if ((len=strlen(cidr_l))>shift) shift = len;
	if ((len=strlen(id_l))>shift) shift = len;
	if ((len=strlen(nexthop_l))>shift) shift = len;
	len = shift;

	if ((len2=strlen(addr_r))>third_shift) third_shift = len2;
	if ((len2=strlen(cidr_r))>third_shift) third_shift = len2;
	if ((len2=strlen(id_r))>third_shift) third_shift = len2;
	if ((len2=strlen(nexthop_r))>third_shift) third_shift = len2;

	shift += 23;
	if (((shift-len)%2) > 0) shift++;
	second_shift = ((shift-len)/2)-strlen(separator);
	third_shift += 8;

	// Comeca exibicao dos dados
	if (strlen(id_l) || strlen(id_r))
	{
		print_ipsec_show_line(name, id_l, id_r, authby, authproto, esp_c, pfs, len, shift, second_shift, third_shift, state, &net_flag);
	}
	if (strlen(addr_l) || strlen(addr_r))
	{
		print_ipsec_show_line(name, addr_l, addr_r, authby, authproto, esp_c, pfs, len, shift, second_shift, third_shift, state, &net_flag);
	}
	if (strlen(cidr_l) || strlen(cidr_r))
	{
		print_ipsec_show_line(name, cidr_l, cidr_r, authby, authproto, esp_c, pfs, len, shift, second_shift, third_shift, state, &net_flag);
	}
	if (strlen(nexthop_l) || strlen(nexthop_r))
	{
		print_ipsec_show_line(name, nexthop_l, nexthop_r, authby, authproto, esp_c, pfs, len, shift, second_shift, third_shift, state, &net_flag);
	}
	if (!net_flag)
	{
		printf("\033[3C%s\033[%dC", name, total_name_len-strlen(name));
		if (strlen(authby)) printf("%s+", authby);
		if (strlen(authproto)) printf("%s+", authproto);
		if (strlen(esp_c)) printf("%s+", esp_c);
		if (strlen(pfs)) printf("%s+", pfs);
		printf("\033[1D ");
		printf("\033[5C");
		printf("incomplete configuration\n");
	}
	return 1;
}

void show_crypto(const char *cmdline)
{
	int i, ret;
	arglist *args;
	char *p, *rsa, **list=NULL, **list_ini=NULL, line[1024];
	FILE *output;

	args=make_args(cmdline);
	if (args->argc == 3)
	{
		if (get_ipsec()) /* Wait pluto start! */
		{
			char search_str[MAX_CMD_LINE];

			output=popen("/lib/ipsec/whack --status", "r");
			if (!output) return;
			sprintf(search_str, "\"%s\"", args->argv[2]);
			while (fgets(line, 1024, output))
			{
				if (strstr(line, search_str))
					fputs(line, stdout);
			}
			pclose(output);
		}
		destroy_args(args);
		return;
	}
	destroy_args(args);

	total_name_len=0;
#if 0
	if (get_ipsec_interface(iface, 20) < 1)
	{
		printf("%% Not possible to show ipsec interface\n");
		return;
	}
	printf("interface %s\n", iface);
#endif
	if ((ret=get_ipsec_autoreload()) > 0) printf("auto-reload in %d seconds\n", ret);
	if ((ret=get_ipsec_nat_traversal()) >= 0)
	{
		if (ret) printf("NAT-Traversal on\n");
			else printf("NAT-Traversal off\n");
	}
	if ((ret=get_ipsec_overridemtu()) > 0) printf("overridemtu %d\n", ret);
	// chave rsa publica
	if ((rsa=get_rsakeys_from_nv()))
	{
		if((p=strstr(rsa, "#pubkey=")))
		{
			p += 8;
			for(; *p==' '; p++);
			if(strchr(p, '\n'))
			{
				*(strchr(p, '\n')) = '\0';
				printf("public local rsa key %s\n", p);
			}
		}
		free(rsa);
	}
		else printf("You have to generate rsa keys!\n");
	// busca todas as conexoes existentes
	if (list_all_ipsec_names(&list_ini) < 1)
	{
		printf("%% Not possible to show ipsec connections\n");
		return;
	}
	if (*list_ini != NULL)
	{
		printf("Connections:\n");
		for(i=0, list=list_ini; i < MAX_CONN; i++, list++)
		{
			if (*list)
			{
				if (strlen(*list) > total_name_len) total_name_len=strlen(*list);
			}
		}
		total_name_len += 9;

		if (get_ipsec()) /* Wait pluto start! */
		{
			if (!(output=popen("/lib/ipsec/whack --status", "r")))
			{
				printf("%% Not possible to show ipsec connections\n");
				goto go_error;
			}
			/* 000 caca 192.168.2.0/24===10.0.0.1[@server]...10.0.0.2[@roadwarrior]===192.168.1.0/24 RSASIG+ENCRYPT+TUNNEL+PFS "erouted" */
			/* 000 caca 192.168.2.0/24===10.0.0.1[@server]---10.0.0.2...%any[@roadwarrior]===192.168.1.0/24 RSASIG+ENCRYPT+TUNNEL+PFS "unrouted"  */
			while (fgets(line, 1024, output))
			{
				int flag=CONN_INCOMPLETE;
	

				if (!strstr(line, "===")) continue;
				if (strlen(line) == 0) break;
				args=make_args(line);
			
				if (args->argc == 7)
				{
					if (!strstr(args->argv[2], "...%any")) /* skip roadwarrior master! */
					{
						for (i=0, list=list_ini; i < MAX_CONN; i++, list++)
						{
							if (*list) {
								char name[64];
								sprintf(name, "\"%s\"", *list);
								if (strstr(args->argv[1], name)) {
									if (strstr(args->argv[3], "erouted")) 
										flag = CONN_UP;
									else if (strstr(args->argv[3], "unrouted")) 
										flag = CONN_DOWN;

									if (show_conn_specific(*list, flag) < 1) 
										goto go_error;

									printf("\n");
									free(*list);
									*list=NULL;
									break;
								}
							}
						}
					}
				}
				destroy_args(args);
			}
			pclose(output);
		}
		for (i=0, list=list_ini; i < MAX_CONN; i++, list++)
		{
			if (*list)
			{
				switch (get_ipsec_auto(*list))
				{
					case AUTO_IGNORE:
						if (show_conn_specific(*list, CONN_SHUTDOWN) < 1) goto go_error;
						break;
					case AUTO_START:
						if (show_conn_specific(*list, CONN_DOWN) < 1) goto go_error;
						break;
					case AUTO_ADD:
						if (show_conn_specific(*list, CONN_WAIT) < 1) goto go_error;
						break;
				}
				printf("\n");
				free(*list);
				*list=NULL;
			}
		}
go_error:
		for (i=0, list=list_ini; i < MAX_CONN; i++, list++)
		{
			if (*list) free(*list);
		}
		free(list_ini);
	}
		else printf("No connections configured!\n"); /*\033[30C*/
#if 0
	ret=get_if_list();
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
}

void show_l2tp(const char *cmdline)
{
	struct sockaddr_un addr;
	int fd;
	int n;
	char buf[4096];
	char dump[]="dump-sessions";
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
    v[0].iov_base = (char *)dump;
    v[0].iov_len = strlen(dump);
    v[1].iov_base = "\n";
    v[1].iov_len = 1;
    writev(fd, v, 2);
	for(;;) {
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

#if defined(CONFIG_BERLIN_MU0)
	for (i=0; i < 2; i++)
#elif defined(CONFIG_BERLIN_SATROUTER)
	for (i=0; i < ((get_board_hw_id() == BOARD_HW_ID_1) ? 1 : 2); i++)
#else
	for (i=0; i < 1; i++)
#endif
	{
		if (kick_udhcpd(i) == 0) {
			sprintf(filename, FILE_DHCPDLEASES, i);
			tf=fopen(filename, "r");
			if (!tf) continue;
			fclose(tf);
			sprintf(filename, "/bin/dumpleases -f "FILE_DHCPDLEASES, i);
			tf=popen(filename, "r");
			if (tf)
			{
				pprintf("interface ethernet%d\n", i);
				show_output();
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

	if((f=fopen(FILE_NTPD_KEYS, "r")))
	{
		while(fgets(line, 200, f))
		{
			if ((p=strchr(line, '\n'))) *p='\0';
			if (strlen(line))
			{
				args=make_args(line);
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

	if( !is_daemon_running(NTP_DAEMON) )
		return;

	/* Inicialmente temos que descobrir quais enderecos das interfaces locais estao operando com NTP */
	if( !(f = popen("ntpq -c opeers 0.0.0.0", "r")) )
		return;
	for( ; ; ) {
		fgets(buf, 255, f);
		buf[255] = 0;
		if( feof(f) )
			break;
		if( parse_args_din(buf, &argl) == 10 ) {
			if( inet_aton(argl[1], &inp) == 1 ) {
				for( i=0, used=0; (i < n_local_addr) && (i < 16); i++ ) {
					if( strcmp(argl[1], local_addr[i]) == 0 ) {
						used = 1;
						break;
					}
				}
				if( used == 0 )
					strcpy(local_addr[n_local_addr++], argl[1]);
			}
		}
		free_args_din(&argl);
	}
	pclose(f);

	if( n_local_addr == 0 )
		return;

	/* Exibimos todos os peers */
	printf("PEERS:\n");
	for( i=0; i < n_local_addr; i++ ) {
		sprintf(buf, "ntpq -c opeers %s", local_addr[i]);
		system(buf);
	}
	printf("\nASSOCIATIONS:\n");
	for( i=0; i < n_local_addr; i++ ) {
		sprintf(buf, "ntpq -c associations %s", local_addr[i]);
		system(buf);
	}
	printf("\n");
}
#endif /* OPTION_NTPD */

#ifdef OPTION_PIMD
void show_mroute(const char *cmdline) /* !!! */
{
#if 0
	if ((tf=fopen("/proc/net/dev_mcast","r")))
	{
		show_output();
		fclose(tf);
	}
#endif
	pprintf("Multicast Interfaces:\n");
	if ((tf=fopen("/proc/net/ip_mr_vif","r")))
	{
		show_output();
		fclose(tf);
	}
	pprintf("\nMulticast Group Cache:\n");
	if ((tf=fopen("/proc/net/ip_mr_cache","r")))
	{
		show_output();
		fclose(tf);
	}
}
#endif

#ifdef OPTION_RMON
void dump_rmon(FILE *out)
{
	int i, k;
	struct rmon_config *shm_rmon_p;
	char tp[10], result[MAX_OID_LEN * 10];

	if( get_access_rmon_config(&shm_rmon_p) == 1 ) {
		for( i=0; i < NUM_EVENTS; i++ ) {
			if( shm_rmon_p->events[i].index > 0 ) {
				fprintf(out, "rmon event %d", shm_rmon_p->events[i].index);
				if( shm_rmon_p->events[i].do_log )
					fprintf(out, " log");
				if( shm_rmon_p->events[i].community[0] != 0 )
					fprintf(out, " trap %s", shm_rmon_p->events[i].community);
				if( shm_rmon_p->events[i].description[0] != 0 )
					fprintf(out, " description %s", shm_rmon_p->events[i].description);
				if( shm_rmon_p->events[i].owner[0] != 0 )
					fprintf(out, " owner %s", shm_rmon_p->events[i].owner);
				fprintf(out, "\n");
			}
		}
		for( i=0; i < NUM_ALARMS; i++ ) {
			if( shm_rmon_p->alarms[i].index > 0 ) {
				result[0] = '\0';
				for( k=0; k < shm_rmon_p->alarms[i].oid_len; k++ ) {
					sprintf(tp, "%lu.", shm_rmon_p->alarms[i].oid[k]);
					strcat(result, tp);
				}
				*(result + strlen(result) - 1) = '\0';

				fprintf(out, "rmon alarm %d %s %d", shm_rmon_p->alarms[i].index, result, shm_rmon_p->alarms[i].interval);
				switch( shm_rmon_p->alarms[i].sample_type ) {
					case SAMPLE_ABSOLUTE:
						fprintf(out, " absolute");
						break;

					case SAMPLE_DELTA:
						fprintf(out, " delta");
						break;
				}
				if( shm_rmon_p->alarms[i].rising_threshold ) {
					fprintf(out, " rising-threshold %d", shm_rmon_p->alarms[i].rising_threshold);
					if( shm_rmon_p->alarms[i].rising_event_index )
						fprintf(out, " %d", shm_rmon_p->alarms[i].rising_event_index);
				}
				if( shm_rmon_p->alarms[i].falling_threshold ) {
					fprintf(out, " falling-threshold %d", shm_rmon_p->alarms[i].falling_threshold);
					if( shm_rmon_p->alarms[i].falling_event_index )
						fprintf(out, " %d", shm_rmon_p->alarms[i].falling_event_index);
				}
				if( shm_rmon_p->alarms[i].owner[0] != 0 )
					fprintf(out, " owner %s", shm_rmon_p->alarms[i].owner);
				fprintf(out, "\n");
			}
		}
		loose_access_rmon_config(&shm_rmon_p);
	}
	if( is_daemon_running(RMON_DAEMON) )
		fprintf(out, "rmon agent\n");
	else
		fprintf(out, "no rmon agent\n");
	fprintf(out, "!\n");
}
#endif

#ifdef OPTION_VRRP
void show_vrrp(const char *cmdline)
{
	dump_vrrp_status();

	if (!(tf = fopen(VRRP_SHOW_FILE,"r"))) /* Open vrrp show file */
		return;
	show_output(); /* Print file */
	fclose(tf);
}
#endif
