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
#include <linux/hdlc.h>
#include <linux/ipx.h>
#include <linux/mii.h>
#include <asm/ucc_hdlc.h>
#include <syslog.h>
#ifdef CONFIG_SPPP_NETLINK
#include <net/sppp.h>
#endif
#ifdef CONFIG_IPHC
#include <linux/iphc.h>
#endif
#define __USE_XOPEN
#include <time.h>
#include <linux/if_vlan.h>	/* 802.1p mappings */
#ifdef CONFIG_HDLC_FR_EEK
#include <linux/eek.h>
#endif

#include <libconfig/acl.h>
#include <libconfig/args.h>
#include <libconfig/cish_defines.h>
#include <libconfig/device.h>
#include <libconfig/typedefs.h>
#include <libconfig/ip.h>
#include <libconfig/dev.h>
#include <libconfig/dhcp.h>
#include <libconfig/dns.h>
#include <libconfig/ipx.h>
#include <libconfig/wan.h>
#include <libconfig/lan.h>
#include <libconfig/ppp.h>
#include <libconfig/chdlc.h>
#include <libconfig/fr.h>
#include <libconfig/str.h>
#include <libconfig/bridge.h>
#include <libconfig/time.h>
#include <libconfig/ntp.h>
#include <libconfig/nv.h>
#include <libconfig/pim.h>
#include <libconfig/defines.h>
#include <libconfig/version.h>
#include <libconfig/debug.h>
#include <libconfig/qos.h>
#include <libconfig/ipsec.h>
#include <libconfig/exec.h>
#include <libconfig/process.h>
#include <libconfig/quagga.h>
#include <libconfig/snmp.h>
#include <libconfig/ppcio.h>
#ifdef OPTION_SMCROUTE
#include <libconfig/smcroute.h>
#endif
#include <libconfig/tunnel.h>
#include <libconfig/vrrp.h>
#include <libconfig/sppp.h>
#include <libconfig/system.h>
#include <libconfig/vlan.h>
#include <libconfig/x25.h>

#include "acl.h"
#include "options.h"
#include "commands.h"
#include "cish_main.h"
#include "pprintf.h"
#include "cish_config.h"
#include "mangle.h"
#include "nat.h"
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
extern cish_command CMD_CONFIG_INTERFACE_SERIAL[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_FR[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP[];
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
	int num;
	unsigned long long user, nice, system, idle;
	static unsigned long long user_old=0, nice_old=0, system_old=0, idle_old=0;
	float scale;
	// enough for a /proc/stat CPU line (not the intr line)
	char buf[256];

	tf=fopen("/proc/stat","r");
	if (tf)
	{
		fgets(buf, sizeof(buf), tf);
		num = sscanf(buf, "cpu %Lu %Lu %Lu %Lu", &user, &nice, &system, &idle);
		if (num == 4)
		{
			scale=100.0 / (float)((user-user_old)+(nice-nice_old)+(system-system_old)+(idle-idle_old));
			#if 0
			pprintf ("processor usage : %#5.1f%% user, %#5.1f%% system, %#5.1f%% nice, %#5.1f%% idle\n", (float)(user-user_old)*scale, (float)(system-system_old)*scale, (float)(nice-nice_old)*scale, (float)(idle-idle_old)*scale);
			#else
			pprintf ("processor usage : %0.1f%% system, %0.1f%% idle\n", (float)((user-user_old)+(nice-nice_old)+(system-system_old))*scale, (float)(idle-idle_old)*scale);
			#endif
			user_old=user; nice_old=nice; system_old=system; idle_old=idle;
		}
		fclose(tf);
	}
	tf=fopen("/proc/cpuinfo","r");
	show_output();
	if (tf) fclose(tf);
}

#ifdef CONFIG_BERLIN_SATROUTER
void show_logging_file(void)
{
	arg_list argl = NULL;
	int n_args, last_one_was_printed;
	char *p, *info, date[24], name[16];
#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_LOG_CONSOLE)
	unsigned int ch;
#endif

	while( !feof(tf) ) {
		tbuf[0] = 0;
		fgets(tbuf, 255, tf);
		tbuf[255] = 0;
		last_one_was_printed = 0;
		if( strlen(tbuf) == 0 )
			continue;

		n_args = parse_args_din(tbuf, &argl);
		if( (n_args < 6) || ((info = strstr(tbuf, argl[5])) == NULL) ) {
			free_args_din(&argl);
			continue;
		}
		snprintf(date, 23, "%s  %s %s", argl[0], argl[1], argl[2]);
		date[23] = 0;
#if 0
#ifdef CONFIG_DMVIEW_MGNT
		#warning ******************* MICROCOM DEBUG MESSAGES ENABLED *******************
		if( (strcmp(argl[5], "microcom:") == 0) && (strlen(info) > strlen(argl[5])) )
			pprintf("%s %s", date, info + strlen(argl[5]));
#endif
#endif
#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_LOG_CONSOLE)
		if( n_args == 9 ) {
			if( (strcmp(argl[5], "kernel:") == 0) && (strcmp(argl[6], "ConsoleDebug:") == 0) ) {
				sscanf(argl[8]+2, "%x", &ch);
				if( strcmp(argl[7], "TX") == 0 ) {
					if( isprint(ch) != 0 )
						pprintf("%s console debug: TX '%c' %s\n", date, (char)ch, argl[8]);
					else
						pprintf("%s console debug: TX     %s\n", date, argl[8]);
				}
				else {
					if( isprint(ch) != 0 )
						pprintf("%s console debug:                RX '%c' %s\n", date, (char)ch, argl[8]);
					else
						pprintf("%s console debug:                RX     %s\n", date, argl[8]);
				}
			}
		}
#endif
		p = find_debug_token(info, name, 1);
		if( p != NULL ) {
			last_one_was_printed = 1;
			pprintf("%s %s%s", date, name, p);
		}
		else {
			if( (strncmp(info, "last message repeated", 21) == 0) && last_one_was_printed )
				pprintf("%s %s", date, info);
#if 0 /* Show all lines... */
			else
				pprintf("%s %s", date, info);
#endif
		}
		last_one_was_printed = 0;
		free_args_din(&argl);
	}
	fclose(tf);
}


void showlog_signal(int signal)
{
	printf("\n");
	exit(0);
}
#else /* CONFIG_BERLIN_SATROUTER */

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

#endif /* CONFIG_BERLIN_SATROUTER */

void show_logging(const char *cmdline) /* show logging [tail] */
{
	int i;
	arglist *args;
	char logname[32];

#ifdef CONFIG_BERLIN_SATROUTER
	pid_t pid;
	int tail = 0;

	args = make_args(cmdline);
	if( (args->argc == 3) && (strcmp(args->argv[2], "tail") == 0) )
		tail = 1;
	destroy_args(args);
	switch( (pid = fork()) ) {
		case -1:
			fprintf(stderr, "%% No processes left\n");
			return;

		case 0:
			signal(SIGINT, showlog_signal);
			if( tail == 0 ) {
				for( i=29; i >= 0; i-- ) { /* have to match syslogd configuration */
					sprintf(logname, "/var/log/messages.%d", i);
					if( (tf = fopen(logname,"r")) != NULL )
						show_logging_file();
				}
			}
			strcpy(logname, "/var/log/messages");
			if( (tf = fopen(logname,"r")) != NULL )
				show_logging_file();
			exit(0);

		default:
			waitpid(pid, NULL, 0);
			return;
	}
#else /* CONFIG_BERLIN_SATROUTER */
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
#endif /* CONFIG_BERLIN_SATROUTER */
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
	char *p;

#ifdef CONFIG_DEVELOPMENT
	printf("Engineering prototype\n");
#endif
	printf("Bootloader version: %s\n", get_boot_version());
	p=get_system_version();
	if (p)
		printf("System version: %s\n", p);
#ifdef I2C_HC08_OWNER
	p=get_product_owner();
	if (p)
		printf("Owner: %s\n", p);
#endif
#ifdef I2C_HC08_LICENSED
	p=get_product_licensed();
	if (p)
		printf("Licensed: %s\n", p);
#endif
#ifdef I2C_HC08_SERIAL_ADDR
	p=get_serial_number();
	if (p)
		printf("Serial number: %s\n", p);
#endif
#ifdef I2C_HC08_ID_ADDR
	p=get_system_ID(1);
	if (p)
		printf("System ID: %s\n", p);
#endif
}

void dump_version(FILE *out)
{
	pfprintf(out, "version %s\n", get_system_version());
	pfprintf(out, "!\n");
}

#ifdef CONFIG_BERLIN_SATROUTER

void show_motherboard_info(const char *cmdline)
{
	int i, n;
	char buf[64];
	arglist *args;
	arg_list argl=NULL;
	unsigned char ok=0;

	args = make_args(cmdline);
	if(args->argc == 2) {
		if( !strcmp(args->argv[1], "manufacturer") ) {
			if( get_mb_info(MBINFO_VENDOR, buf, 64) > 0 ) {
				n = parse_args_din(buf, &argl);
				if( n == 1 )
					strcpy(buf, argl[0]);
				else if( n > 1 ) {
					buf[0] = 0;
					for( i=0; i < n; i++ ) {
						if( (strlen(buf) + strlen(argl[i])) >= 64 )
							break;
						strcat(buf, argl[i]);
					}
				}
				free_args_din(&argl);
				ok++;
			}
		}
	}
	destroy_args(args);
	if( ok > 0 )
		printf("%s\n", buf);
	else
		printf("%% Not possible to show manufacturer\n");
}

void show_satrouter_info(const char *cmdline)
{
	arglist *args;
	unsigned char *p, buf[((MODEM_SN_LEN > SATR_SN_LEN) ? MODEM_SN_LEN : SATR_SN_LEN) + 1];

	args = make_args(cmdline);
	if( args->argc >= 2 ) {
		if(!strcmp(args->argv[1], "serial-number")) {
			if( get_mb_info(MBINFO_SN, (char *)buf, MODEM_SN_LEN+1) ) {
				for( p=buf; *p; p++ ) {
					if( *p != '0' )
						break;
				}
				memmove((char *)buf, p, strlen((char *)p)+1);
				printf("%s\n", buf);
			}
		}
		else if(!strcmp(args->argv[1], "serial-number-router")) {
			if( get_uboot_env("serial#", (char *)buf, SATR_SN_LEN+1) > 0 ) {
				for( p=buf; *p; p++ ) {
					if( *p != '0' )
						break;
				}
				memmove(buf, p, strlen((char *)p)+1);
				printf("%s\n", buf);
			}
		}
		else
			printf("%% Not possible to show serial number\n");
	}
	else
		printf("%% Not possible to show serial number\n");
	destroy_args(args);
}

void show_release_date(const char *cmdline)
{
	if( print_image_date() < 0 )
		printf("%% Not possible to print firmware date\n");
	printf("\n");
}

#endif

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

	tf=fopen("/proc/meminfo", "r");
	if (!tf) return;
	for (i=0; i < 2 && !feof (tf); i++)
	{
		tbuf[0]=0;
		fgets(tbuf, 255, tf);
		tbuf[255]=0;
		if (strlen(tbuf))
			pprintf("%s", tbuf);
	}
	if (tf) fclose(tf);
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
	if (conf_format)
	{
		zebra_dump_static_routes_conf(out);
	}
	else
	{
		zebra_dump_routes(out);
	}
}
#ifdef CONFIG_HDLC_FR_EEK
void dump_fr_eek(FILE *out, char *intf)
{
	fr_proto_pvc cfg;

	if (fr_eek_get_cfg(intf, &cfg) < 0) return;

	if (cfg.eek.mode)
		fprintf(out, " frame-relay end-to-end keepalive mode %s\n", 
			cfg.eek.mode == EEK_MODE_BIDIRECTION ? "bidirectional" :
			cfg.eek.mode == EEK_MODE_REQUEST ? "request" :
			cfg.eek.mode == EEK_MODE_REPLY ? "reply" : "passive-reply");

	/* Default values are not shown */
	if (cfg.eek.recv_timeout != 15) 
		fprintf(out, " frame-relay end-to-end keepalive timer recv %d\n", 
				cfg.eek.recv_timeout);
	if (cfg.eek.recv_err != 2) 
		fprintf(out, " frame-relay end-to-end keepalive error-threshold recv %d\n", 
				cfg.eek.recv_err);
	if (cfg.eek.recv_success != 2) 
		fprintf(out, " frame-relay end-to-end keepalive success-events recv %d\n", 
				cfg.eek.recv_success);
	if (cfg.eek.recv_window != 3) 
		fprintf(out, " frame-relay end-to-end keepalive event-window recv %d\n", 
				cfg.eek.recv_window);
	if (cfg.eek.send_timeout != 10) 
		fprintf(out, " frame-relay end-to-end keepalive timer send %d\n", 
				cfg.eek.recv_timeout);
	if (cfg.eek.send_err != 2) 
		fprintf(out, " frame-relay end-to-end keepalive error-threshold send %d\n", 
				cfg.eek.send_err);
	if (cfg.eek.send_success != 2) 
		fprintf(out, " frame-relay end-to-end keepalive success-events send %d\n", 
				cfg.eek.send_success);
	if (cfg.eek.send_window != 3) 
		fprintf(out, " frame-relay end-to-end keepalive event-window send %d\n", 
				cfg.eek.send_window);
}
#endif

void dump_frts_interface(FILE *out, char *intf)
{
	frts_cfg_t *cfg;
	int n, i;

	n=get_frts_cfg(intf, &cfg);
	for (i=0; i < n; i++)
	{
		if (cfg[i].eir)
		{
			fprintf(out, " frame-relay traffic-rate %d %d\n", cfg[i].cir, cfg[i].eir);
		}
		else
		{
			fprintf(out, " frame-relay traffic-rate %d\n", cfg[i].cir);
		}
	}
	release_frts_cfg(cfg, n);
}

void dump_policy_interface(FILE *out, char *intf)
{
#ifdef OPTION_NEW_QOS_CONFIG
	intf_qos_cfg_t *cfg;

	/* Skip X25 */
	if (!strncmp(intf,"serial",6)) {
		if (wan_get_protocol(interface_major) == IF_PROTO_X25) return;
	}

	
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
#else
	qos_cfg_t *cfg;
	int n, i;

	n=get_qos_cfg(intf, &cfg);
	for (i=0; i < n; i++)
	{
		if (cfg[i].bandwidth_bps)
		{
			fprintf(out, " ip policy %ld %d %dbps", cfg[i].mark, cfg[i].prio, cfg[i].bandwidth_bps);
		}
		else
		{
			fprintf(out, " ip policy %ld %d %d%%", cfg[i].mark, cfg[i].prio, cfg[i].bandwidth_perc);
		}
		if (cfg[i].burst) fprintf(out, " %dbytes", cfg[i].burst);
		if (cfg[i].queue == queue_sfq) {
			if (cfg[i].sfq_perturb) fprintf(out, " queue sfq %d\n", cfg[i].sfq_perturb);
				else fprintf(out, " queue sfq\n");
		} else if (cfg[i].queue == queue_red) {
			fprintf(out, " queue red %d %d %s\n", cfg[i].red_latency, cfg[i].red_probability, cfg[i].red_ecn ? "ecn" : "");
		} else if (cfg[i].queue == queue_wfq) {
			fprintf(out, " queue wfq %d\n", cfg[i].wfq_hold_queue);
		} else {
			if (cfg[i].fifo_limit) fprintf(out, " queue fifo %d\n", cfg[i].fifo_limit);
				else fprintf(out, " queue fifo\n");
		}
	}
	release_qos_cfg(cfg, n);
#endif
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
	int linktype, serial_no=0, sync_nasync, clk_rate;
	int detected_rate, clk_type, clk_inv_tx, phy_status=0, minor=0;
#ifndef CONFIG_BERLIN_SATROUTER
	int ignore=0;
#endif
	/* IP Tables variables */
	char in_acl[101], out_acl[101];
	char in_mangle[101], out_mangle[101];
	char in_nat[101], out_nat[101];
	char *osdev, *pppdev=NULL, *osdev_ip, *cish_dev;
	char ipaddr[16], ipmask[16], ippeer[16];
	char mac_bin[6], mac[16], *description, devtmp[17];
	struct net_device_stats *st;
	ipx_intf_t ipx_intf;
	int intf_sort_indexes[MAX_NUM_LINKS];
	sync_serial_settings sst;
	const char *clock_type[5]={"invalid","external", "internal", "txint", "txfromrx"};
#ifdef CONFIG_DEVELOPMENT_TST
	struct scc_hdlc_stat stat;
#endif
	int vlan_cos=NONE_TO_COS;

	/* Get all information */
	ret=get_if_list();
	if (ret < 0) {
		printf("%% ERROR : Could not get interfaces information\n");
		return;
	}

	/*
	 *  Caso especial - aux0-1 down: neste caso elas nao irao
	 * aparecer na lista de interfaces - temos que "falsificar" as entradas
	 */
	if (_cish_aux) {
		for (i=0; i < link_table_index; i++) 
			if (strncmp(link_table[i].ifname, 
				AUXDEV"0", sizeof(AUXDEV)+1) == 0) break;

		if (i == link_table_index) {
			i=link_table_index++;
			memset(&link_table[i], 0, sizeof(link_table[i]));
			strcpy(link_table[i].ifname, AUXDEV_PPP"0");
			link_table[i].type=ARPHRD_ASYNCPPP;
		}

		for (i=0; i < link_table_index; i++) 
			if (strncmp(link_table[i].ifname, 
				AUXDEV"1", sizeof(AUXDEV)+1) == 0) break;

		if (i == link_table_index) {
			i=link_table_index++;
			memset(&link_table[i], 0, sizeof(link_table[i]));
			strcpy(link_table[i].ifname, AUXDEV_PPP"1");
			link_table[i].type=ARPHRD_ASYNCPPP;
		}
	}

	/* Sort list */
	for (i=0; i < link_table_index; i++) 
		intf_sort_indexes[i]=i;

	qsort(&intf_sort_indexes[0], link_table_index, 
		sizeof(int), qsort_dump_interfaces);
	
	for (j=0; j < link_table_index; j++) {
		i=intf_sort_indexes[j];
		osdev=link_table[i].ifname;
		up=link_table[i].flags & IFF_UP;
		mtu=link_table[i].mtu;
		st=&link_table[i].stats;
		sync_nasync=clk_type=clk_rate=detected_rate=-1;
		clk_inv_tx=0;
		linktype=link_table[i].type;
		mac[0]=0;
		if (get_mac(linktype == ARPHRD_ETHER ? 
			osdev : "ethernet0", mac_bin) == 0)
				sprintf(mac, "%02x%02x.%02x%02x.%02x%02x",
					mac_bin[0], mac_bin[1], 
					mac_bin[2], mac_bin[3], 
					mac_bin[4], mac_bin[5]);

		/*
		 * Caso especial para ppp - interface 'sx0' - neste caso
		 * lemos a configuracao atraves de ppp_get_device e 
		 * renomeamos 'osdev' para 'serial0'.
		 */
		if (strncmp(osdev, SERIALDEV_PPP, strlen(SERIALDEV_PPP)) == 0) { /* 'sx0' */
			ppp_config cfg;

			serial_no=atoi(osdev+strlen(SERIALDEV_PPP));
			sync_nasync=wan_get_physical(serial_no);
			ppp_get_config(serial_no, &cfg);
			if (cfg.up || (cfg.server_flags & SERVER_FLAGS_INCOMING)) {
				int k;

				sprintf(devtmp, "%s%d", SERIALDEV, serial_no); /* 'serial0' */
				for (k=0; k < link_table_index; k++)
					if (strcmp(link_table[k].ifname, devtmp) == 0) break;
				
				if (k < link_table_index) {
					if (sync_nasync) {
						unsigned long tx_dropped = link_table[k].stats.tx_dropped; /* backup! */
						unsigned long rx_dropped = link_table[k].stats.rx_dropped; /* backup! */
						memcpy(&link_table[k].stats, st, sizeof(struct net_device_stats)); /* Overwrite 'serial0' stats with 'sx0' */
						link_table[k].stats.tx_dropped += tx_dropped; /* add tx_dropped from 'serial0' */
						link_table[k].stats.rx_dropped += rx_dropped; /* add rx_dropped from 'serial0' */
					}
					continue; // If pppd running, ignore this entry!
				}
			}

			/* 
			 * Se a interface estiver no modo sincrono, 
			 * podemos ler a configuracao de clock
			*/ 
			if (sync_nasync == 1)
			{
				wan_get_sst(serial_no, &sst);
				clk_rate = sst.clock_rate;
				clk_type = sst.clock_type;
				clk_inv_tx = sst.inv_tx;
				detected_rate = sst.detected_rate;
#ifdef CONFIG_DEVELOPMENT_TST
				wan_get_stat(serial_no, &stat);
#endif
#ifndef CONFIG_BERLIN_SATROUTER
				ignore=wan_get_ignore(serial_no);
#endif
			}
			up=cfg.up;
			mtu=cfg.mtu ? cfg.mtu : 1500;
			txqueue=0;
			linktype=ARPHRD_PPP;
			pppdev=ppp_get_pppdevice(serial_no); // para ler o IP
			sprintf(osdev, "%s%d", SERIALDEV, serial_no);
		}
		else if (strncmp(osdev, AUXDEV_PPP, strlen(AUXDEV_PPP)) == 0) /* 'ax0' */
		{
			ppp_config cfg;

			serial_no=atoi(osdev+strlen(AUXDEV_PPP))+MAX_WAN_INTF; /* offset */
			sync_nasync=0; /* async */
			ppp_get_config(serial_no, &cfg);
			up=cfg.up;
			mtu=cfg.mtu ? cfg.mtu : 1500;
			txqueue=0;
			linktype=ARPHRD_ASYNCPPP;
			pppdev=ppp_get_pppdevice(serial_no); // para ler o IP
			sprintf(osdev, "%s%d", AUXDEV, serial_no-MAX_WAN_INTF); /* offset */
		}
		else if (strncmp(osdev, SERIALDEV, strlen(SERIALDEV)) == 0)
		{
			long protocol;
			char *p;
			ppp_config cfg;

			serial_no=atoi(osdev+strlen(SERIALDEV));
			if ((p=strchr(osdev, '.')) != NULL) minor=atoi(p+1); /* skip '.' */
			sync_nasync=wan_get_physical(serial_no);
			// Se a interface estiver no modo sincrono, podemos ler a configuracao de clock
			if (sync_nasync == 1)
			{
				wan_get_sst(serial_no, &sst);
				clk_rate = sst.clock_rate;
				clk_type = sst.clock_type;
				clk_inv_tx = sst.inv_tx;
				detected_rate = sst.detected_rate;
#ifdef CONFIG_DEVELOPMENT_TST
				wan_get_stat(serial_no, &stat);
#endif
#ifndef CONFIG_BERLIN_SATROUTER
				ignore=wan_get_ignore(serial_no);
#endif
			}

			/* 
			 * Caso normal: le o tipo de encapsulamento 
			 */
			if ((protocol=wan_get_protocol(serial_no)) == SCC_PROTO_MLPPP)
			{
				ppp_get_config(serial_no, &cfg);
				up=(cfg.up | (cfg.server_flags & SERVER_FLAGS_ENABLE));
				mtu=cfg.mtu ? cfg.mtu : 1500;
			}
			txqueue=dev_get_qlen(osdev);

			/*
			 *  Caso especial: subinterface de frame-relay no modo bridge.
			 * Neste caso o 'linktype' eh ARPHRD_ETHER, pois estamos emulando
			 * uma interface ethernet. Assim, forcamos o 'linktype' para
			 * ARPHRD_DLCI/ARPHRD_CISCO para que o tratamento no 'case' 
			 * abaixo seja o correto.
			 */
			if ((protocol==IF_PROTO_FR) && (linktype==ARPHRD_ETHER))
				linktype=ARPHRD_DLCI;
			if ((protocol==IF_PROTO_CISCO) && (linktype==ARPHRD_ETHER))
				linktype=ARPHRD_CISCO;
		}
		else if (strncmp(osdev, AUXDEV, strlen(AUXDEV)) == 0)
		{
			ppp_config cfg;

			serial_no=atoi(osdev+strlen(AUXDEV))+MAX_WAN_INTF; /* offset */
			ppp_get_config(serial_no, &cfg);
			sync_nasync=0; /* async */
			up=(cfg.up | (cfg.server_flags & SERVER_FLAGS_ENABLE));
			txqueue=dev_get_qlen(osdev);
			linktype=ARPHRD_ASYNCPPP;
			pppdev=ppp_get_pppdevice(serial_no); // para ler o IP
		}
		else
		{
			txqueue=dev_get_qlen(osdev);
		}

		osdev_ip = pppdev ? pppdev : osdev;

		// se for ethernet e estiver fazendo parte de uma bridge, le o ip da bridge
		if (strncmp(osdev_ip, "ethernet", 8) == 0) osdev_ip=get_ethernet_dev(osdev_ip);

		for (n=0, ipaddr[0]=0, ippeer[0]=0; n < ip_addr_table_index; n++)
		{
			if (strcmp(osdev_ip, ip_addr_table[n].ifname) == 0)
			{
				strcpy(ipaddr, inet_ntoa(ip_addr_table[n].local));
				ip_bitlen2mask(ip_addr_table[n].bitlen, ipmask);
				if (link_table[i].flags & IFF_POINTOPOINT)
					strcpy(ippeer, inet_ntoa(ip_addr_table[n].remote));
				break;
			}
		}

		cish_dev=convert_os_device(osdev, conf_format ? 0 : 1);

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

		switch (linktype) {
			case ARPHRD_DLCI:
				running = (up && link_table[i].flags & IFF_RUNNING);
				break;
			case ARPHRD_FRAD:
				running=fr_get_state(serial_no);
#ifdef CONFIG_BERLIN_SATROUTER
				running = (running < 0) ? 0 : ((running && get_led_state("wan_status")) ? 1 : 0);
#endif
				break;
			case ARPHRD_CISCO:
				running = chdlc_get_state(serial_no);
#ifdef CONFIG_BERLIN_SATROUTER
				running = (running < 0) ? 0 : ((running && get_led_state("wan_status")) ? 1 : 0);
#endif
				break;
#ifdef OPTION_X25
			case ARPHRD_X25:
				running=x25_get_state(serial_no);
				break;
			case ARPHRD_RFC1356:
				running=(x25_get_state(serial_no) && link_table[i].flags & IFF_RUNNING);
				break;
#endif
			case ARPHRD_PPP: /* IF_PROTO_PPP && SCC_PROTO_MLPPP */
				if (wan_get_protocol(serial_no) == IF_PROTO_PPP) {
					running = sppp_get_state(serial_no);
#ifdef CONFIG_BERLIN_SATROUTER
					running = (running < 0) ? 0 : ((running && get_led_state("wan_status")) ? 1 : 0);
#endif
					break;
				}
				/* Fall... */
			case ARPHRD_ASYNCPPP:
				running=ppp_get_state(serial_no);
#ifdef CONFIG_BERLIN_SATROUTER
				running = (running < 0) ? 0 : ((running && get_led_state("wan_status")) ? 1 : 0);
#endif
				break;
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

		if (linktype == ARPHRD_LOOPBACK && !running)
			continue; /* !!! ignore loopback down interfaces !!! */

		ipx_get_intf(osdev_ip, &ipx_intf);

		if (conf_format)
		{
			in_acl[0]=out_acl[0]=in_mangle[0]=out_mangle[0]=in_nat[0]=out_nat[0]=0;
			get_iface_acls(osdev, in_acl, out_acl);
			get_iface_mangle_rules(osdev, in_mangle, out_mangle);
			get_iface_nat_rules(osdev, in_nat, out_nat);

			if (linktype == ARPHRD_TUNNEL6) continue; /* skip ipsec ones... */
			pfprintf (out, "interface %s\n", cish_dev);
			description = dev_get_description(osdev);
			if (description) pfprintf(out, " description %s\n", description);
			switch (linktype)
			{
				case ARPHRD_FRAD:
				{
					fr_proto fr;
					char devname[IFNAMSIZ];
					int len, n;
#ifndef CONFIG_BERLIN_SATROUTER
					ppp_config cfg;

					pfprintf (out, " physical-layer %ssynchronous\n", sync_nasync ? "" : "a");
#endif
					pfprintf (out, " encapsulation frame-relay\n");
#ifndef CONFIG_BERLIN_SATROUTER
					if (clk_rate > 0) {
						pfprintf(out, " clock rate %d\n", clk_rate);
					} else {
						pfprintf(out, " no clock rate\n");
					}
					pfprintf(out, " clock type %s\n", clock_type[clk_type]);

					if (ignore & UCC_IGNORE_CTS)
						pfprintf(out, " %signore cts\n", (ignore & UCC_IGNORE_CTS) ? "" : "no ");
					if (ignore & UCC_IGNORE_DCD)
						pfprintf(out, " %signore dcd\n", (ignore & UCC_IGNORE_DCD) ? "" : "no ");

#endif
					pfprintf(out, " %sinvert txclock\n", clk_inv_tx ? "" : "no ");
//#ifndef CONFIG_BERLIN_SATROUTER
					if (sst.loopback) pfprintf(out, " loopback\n");
//#endif
#ifdef OPTION_NEW_QOS_CONFIG
					dump_policy_interface(out, osdev);
#endif
					fr_get_config(serial_no, &fr);
					strcpy(devname, osdev); strcat(devname, ".");
					len=strlen(devname);
					for (n=0; n < link_table_index; n++)
					{
						if (strncmp(devname, link_table[n].ifname, len)==0)
						{
							pfprintf (out, " frame-relay dlci %s\n", link_table[n].ifname+len);
						}
					}
#ifdef CONFIG_HDLC_FR_LFI
					for( n=0; n<CONFIG_MAX_LFI_PRIORITY_MARKS && fr.priomarks[n]!=0; n++ )
						pfprintf(out, " frame-relay interleave priority-mark %d\n", fr.priomarks[n]);
#endif
					pfprintf (out, " frame-relay intf-type %s\n", fr.dce ? "dce" : "dte");
					pfprintf (out, " frame-relay lmi-n391 %d\n", fr.n391);
					pfprintf (out, " frame-relay lmi-n392 %d\n", fr.n392);
					pfprintf (out, " frame-relay lmi-n393 %d\n", fr.n393);
					pfprintf (out, " frame-relay lmi-t391 %d\n", fr.t391);
					pfprintf (out, " frame-relay lmi-t392 %d\n", fr.t392);
					pfprintf (out, " frame-relay lmi-type %s\n", 
						  (fr.lmi==LMI_ANSI)  ? "ansi" :
						  (fr.lmi==LMI_CCITT) ? "q933a" :
						  (fr.lmi==LMI_CISCO) ? "cisco" : "none");
#ifndef CONFIG_BERLIN_SATROUTER
					if (_cish_aux)
					{
						ppp_get_config(serial_no, &cfg);
						if (cfg.backup) 
							pfprintf (out, " backup %s %d %d\n", 
								cfg.backup == 1 ? "aux0" : "aux1", 
								cfg.activate_delay, cfg.deactivate_delay);
						else 
							pfprintf (out, " no backup\n");
					}
#endif
					if (ipaddr[0]) pfprintf (out, " ip address %s %s\n", ipaddr, ipmask);
							else  pfprintf (out, " no ip address\n");
					pfprintf (out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_DLCI:
				{
					int n;

					if (in_acl[0]) pfprintf (out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf (out, " ip access-group %s out\n", out_acl);
					if (in_mangle[0]) pfprintf (out, " ip mark %s in\n", in_mangle);
					if (out_mangle[0]) pfprintf (out, " ip mark %s out\n", out_mangle);
					if (in_nat[0]) pfprintf (out, " ip nat %s in\n", in_nat);
					if (out_nat[0]) pfprintf (out, " ip nat %s out\n", out_nat);
#ifdef OPTION_PIMD
					dump_pim_interface(out, osdev);
#endif
#ifdef CONFIG_HDLC_FR_LFI
					switch( (n = fr_pvc_get_fragment(osdev)) ) {
						case -1:
						case 0:
							pfprintf (out, " no frame-relay fragment\n");
							break;
						default:
							pfprintf (out, " frame-relay fragment %d end-to-end\n", n);
							break;
					}
#endif
					dump_frts_interface(out, osdev);
					dump_policy_interface(out, osdev);
#ifdef CONFIG_HDLC_FR_EEK
					dump_fr_eek(out, osdev);
#endif
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if (ipaddr[0]) pfprintf (out, " ip address %s %s %s\n", ipaddr, ippeer, ipmask);
						else  pfprintf (out, " no ip address\n");
#ifdef CONFIG_FR_IPHC
					{
						fr_proto_pvc_info info;

						if (fr_pvc_get_info(osdev, &info) == 0) {
							if (info.iphc_maxperiod != IPHC_MAXPERIOD_DFLT)
								pfprintf(out, " ip header-compression max-period %d\n", info.iphc_maxperiod);
							if (info.iphc_maxtime != IPHC_MAXTIME_DFLT)
								pfprintf(out, " ip header-compression max-time %d\n", info.iphc_maxtime);
							if (info.iphc_maxheader != IPHC_MAXHEADER_DFLT)
								pfprintf(out, " ip header-compression max-header %d\n", info.iphc_maxheader);
							if (info.iphc_tcp_mode != IPHC_MODE_OFF)
								pfprintf(out, " ip header-compression tcp%s\n", (info.iphc_tcp_mode == IPHC_MODE_ON_PASSIVE) ?
												" passive" : "");
							if (info.iphc_tcp_contexts != IPHC_TCP_CONTEXTS_DFLT)
								pfprintf(out, " ip header-compression tcp contexts %d\n", info.iphc_tcp_contexts);
							if (info.iphc_udp_mode != IPHC_MODE_OFF)
								pfprintf(out, " ip header-compression udp %s%s\n", (info.iphc_udp_format == UDP_COMP_FORMAT_IETF) ?
												"ietf-format" : "iphc-format",
												(info.iphc_udp_mode == IPHC_MODE_ON_PASSIVE) ? " passive" : "");
							if (info.iphc_udp_contexts != IPHC_UDP_CONTEXTS_DFLT)
								pfprintf(out, " ip header-compression udp %s contexts %d\n",
												(info.iphc_udp_format == UDP_COMP_FORMAT_IETF) ? "ietf-format" : "iphc-format",
												info.iphc_udp_contexts);
							if (info.iphc_rtp_mode != IPHC_MODE_OFF)
								pfprintf(out, " ip header-compression rtp%s\n",
												(info.iphc_rtp_mode == IPHC_MODE_ON_PASSIVE) ? " passive" : "");
							if (info.iphc_rtp_checksum_period != IPHC_RTP_CHECKSUM_PERIOD_DFLT)
								pfprintf(out, " ip header-compression rtp checksum-period %d\n", info.iphc_rtp_checksum_period);
							for (n=0; (n < CONFIG_MAX_IPHC_CRTP_MARKS) && (info.iphc_crtp_marks[n] != 0); n++)
								pfprintf(out, " ip header-compression rtp mark %d\n", info.iphc_crtp_marks[n]);
						}
					}
#endif
					if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
						pfprintf(out, " ipx network %08lX\n", 
								ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE]);
					else pfprintf(out, " no ipx network\n");
					if (mtu) pfprintf (out, " mtu %i\n", mtu);
					if (txqueue) pfprintf (out, " txqueuelen %i\n", txqueue);
					for (n=1; n <= MAX_BRIDGE; n++)
					{
						char brname[32];
						sprintf(brname, "%s%d", BRIDGE_NAME, n);
						if (br_checkif(brname, osdev))
							pfprintf(out, " bridge-group %d\n", n);
					}
					pfprintf (out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_CISCO:
				{
					cisco_proto cisco;
#ifndef CONFIG_BERLIN_SATROUTER
					ppp_config cfg;

					pfprintf (out, " physical-layer %ssynchronous\n", sync_nasync ? "" : "a");
#endif
					pfprintf (out, " encapsulation hdlc\n");
#ifndef CONFIG_BERLIN_SATROUTER
					if (clk_rate > 0) {
						pfprintf(out, " clock rate %d\n", clk_rate);
					} else {
						pfprintf(out, " no clock rate\n");
					}
					pfprintf(out, " clock type %s\n", clock_type[clk_type]);

					if (ignore & UCC_IGNORE_CTS)
						pfprintf(out, " %signore cts\n", (ignore & UCC_IGNORE_CTS) ? "" : "no ");
					if (ignore & UCC_IGNORE_DCD)
						pfprintf(out, " %signore dcd\n", (ignore & UCC_IGNORE_DCD) ? "" : "no ");
#endif
					pfprintf(out, " %sinvert txclock\n", clk_inv_tx ? "" : "no ");
//#ifndef CONFIG_BERLIN_SATROUTER
					if (sst.loopback) pfprintf(out, " loopback\n");
//#endif
					chdlc_get_config(serial_no, &cisco);
					if (in_acl[0]) pfprintf (out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf (out, " ip access-group %s out\n", out_acl);
					if (in_mangle[0]) pfprintf (out, " ip mark %s in\n", in_mangle);
					if (out_mangle[0]) pfprintf (out, " ip mark %s out\n", out_mangle);
					if (in_nat[0]) pfprintf (out, " ip nat %s in\n", in_nat);
					if (out_nat[0]) pfprintf (out, " ip nat %s out\n", out_nat);
#ifdef OPTION_PIMD
					dump_pim_interface(out, osdev);
#endif
					dump_policy_interface(out, osdev);
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if (ipaddr[0]) pfprintf (out, " ip address %s %s %s\n", ipaddr, ippeer, ipmask);
						else  pfprintf (out, " no ip address\n");
					if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
						pfprintf(out, " ipx network %08lX\n", 
								ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE]);
					else pfprintf(out, " no ipx network\n");
					pfprintf(out, " keepalive interval %d\n", cisco.interval);
					pfprintf(out, " keepalive timeout %d\n", cisco.timeout);
					if (mtu) pfprintf (out, " mtu %i\n", mtu);
					if (txqueue) pfprintf (out, " txqueuelen %i\n", txqueue);
#ifndef CONFIG_BERLIN_SATROUTER
					if (_cish_aux)
					{
						ppp_get_config(serial_no, &cfg);
						if (cfg.backup) pfprintf (out, " backup %s %d %d\n", cfg.backup == 1 ? "aux0" : "aux1", cfg.activate_delay, cfg.deactivate_delay);
							else pfprintf (out, " no backup\n");
					}
#endif
					for (n=1; n <= MAX_BRIDGE; n++)
					{
						char brname[32];
						sprintf(brname, "%s%d", BRIDGE_NAME, n);
						if (br_checkif(brname, osdev))
							pfprintf(out, " bridge-group %d\n", n);
					}
					pfprintf (out, " %sshutdown\n", up ? "no " : "");
					break;
				}

#ifdef OPTION_X25
					case ARPHRD_X25:
					{
						char devname[IFNAMSIZ];
						int len, n;
						ppp_config cfg;
						x25_proto x25;

						pfprintf (out, " physical-layer %ssynchronous\n", sync_nasync ? "" : "a");
						pfprintf (out, " encapsulation x25\n");
						if (clk_rate > 0) {
							pfprintf(out, " clock rate %d\n", clk_rate);
						} else {
							pfprintf(out, " no clock rate\n");
						}
						pfprintf(out, " clock type %s\n", clock_type[clk_type]);
						if (ignore & UCC_IGNORE_CTS)
							pfprintf(out, " %signore cts\n", (ignore & UCC_IGNORE_CTS) ? "" : "no ");
						if (ignore & UCC_IGNORE_DCD)
							pfprintf(out, " %signore dcd\n", (ignore & UCC_IGNORE_DCD) ? "" : "no ");
						pfprintf(out, " %sinvert txclock\n", clk_inv_tx ? "" : "no ");
						x25_get_config(serial_no, &x25);
						if (x25.lapb_mode != 0)
							pfprintf(out, " lapb mode %s %s %s\n",
								x25.lapb_mode&LAPB_DCE ? "DCE" : "DTE",
								x25.lapb_mode&LAPB_EXTENDED ? "extended" : "standard",
								x25.lapb_mode&LAPB_MLP ? "MLP" : "SLP");
						if (x25.lapb_n2 != 10) pfprintf(out, " lapb n2 %d\n", x25.lapb_n2);
						if (x25.lapb_t1 != 5) pfprintf(out, " lapb t1 %d\n", x25.lapb_t1);
						if (x25.lapb_t2 != 1) pfprintf(out, " lapb t2 %d\n", x25.lapb_t2);
						if (x25.lapb_window != 7) pfprintf(out, " lapb window %d\n", x25.lapb_window);
						if (sst.loopback) pfprintf(out, " loopback\n");
#ifdef CONFIG_DEVELOPMENT
// 						if (sst.fse) pfprintf(out, " hdlc fse\n");
// 						if (sst.mff) pfprintf(out, " hdlc mff\n");
// 						if (sst.nof) pfprintf(out, " hdlc nof %d\n", sst.nof);
// 						if (sst.rtsm) pfprintf(out, " hdlc rtsm\n");
#endif
						dump_x25_config(out, osdev); /* x25 address, facility & modulo */
#ifdef OPTION_X25MAP
						dump_x25_map(out, osdev);
#endif
						strcpy(devname, osdev); strcat(devname, ".");
						len=strlen(devname);
						for (n=0; n < link_table_index; n++)
						{
							if (strncmp(devname, link_table[n].ifname, len)==0)
							{
								pfprintf (out, " x25 svc %s\n", link_table[n].ifname+len);
							}
						}
						if (_cish_aux)
						{
							ppp_get_config(serial_no, &cfg);
							if (cfg.backup != -1) pfprintf (out, " backup aux%d %d %d\n", cfg.backup-MAX_WAN_INTF, cfg.activate_delay, cfg.deactivate_delay);
								else pfprintf (out, " no backup\n");
						}
						pfprintf (out, " %sshutdown\n", up ? "no " : "");
						break;
					}

#endif

				case ARPHRD_RFC1356:
				{
#ifdef OPTION_X25
					struct rfc1356_config cfg;
#endif

					if (in_acl[0]) pfprintf (out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf (out, " ip access-group %s out\n", out_acl);
					if (in_mangle[0]) pfprintf (out, " ip mark %s in\n", in_mangle);
					if (out_mangle[0]) pfprintf (out, " ip mark %s out\n", out_mangle);
					if (in_nat[0]) pfprintf (out, " ip nat %s in\n", in_nat);
					if (out_nat[0]) pfprintf (out, " ip nat %s out\n", out_nat);
#ifdef OPTION_PIMD
					dump_pim_interface(out, osdev);
#endif
					dump_policy_interface(out, osdev);
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if (ipaddr[0]) pfprintf (out, " ip address %s %s %s\n", ipaddr, ippeer, ipmask);
						else  pfprintf (out, " no ip address\n");
					#if 0
					if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
						pfprintf(out, " ipx network %08lX\n", 
								ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE]);
					else pfprintf(out, " no ipx network\n");
					#endif
					if (mtu) pfprintf (out, " mtu %i\n", mtu);
					if (txqueue) pfprintf (out, " txqueuelen %i\n", txqueue);
#ifdef OPTION_X25
					/* x25 address map */
					rfc1356_get_config(serial_no, minor, &cfg);
					if (cfg.local.x25_addr[0]) pfprintf(out, " x25 address %s\n", cfg.local.x25_addr);
					if (cfg.ip_peer_addr[0] && cfg.remote.x25_addr[0]) pfprintf(out, " x25 map ip %s %s\n", cfg.ip_peer_addr, cfg.remote.x25_addr);
						else if (cfg.ip_peer_addr[0]) pfprintf(out, " x25 map ip %s passive\n", cfg.ip_peer_addr);
#endif
					pfprintf(out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_PPP:
				{
					ppp_config cfg;

					ppp_get_config(serial_no, &cfg);
#ifndef CONFIG_BERLIN_SATROUTER
					pfprintf(out, " physical-layer %ssynchronous\n", sync_nasync ? "" : "a");
#endif
					if (wan_get_protocol(serial_no) == IF_PROTO_PPP)
						pfprintf(out, " encapsulation ppp\n");
					if (sync_nasync == 1)
					{
#ifndef CONFIG_BERLIN_SATROUTER
						if (clk_rate > 0) {
							pfprintf(out, " clock rate %d\n", clk_rate);
						} else {
							pfprintf(out, " no clock rate\n");
						}
						pfprintf(out, " clock type %s\n", clock_type[clk_type]);
						if (ignore & UCC_IGNORE_CTS)
							pfprintf(out, " %signore cts\n", 
								(ignore & UCC_IGNORE_CTS) ? "" : "no ");
						if (ignore & UCC_IGNORE_DCD)
							pfprintf(out, " %signore dcd\n", 
								(ignore & UCC_IGNORE_DCD) ? "" : "no ");
#endif
						pfprintf(out, " %sinvert txclock\n", clk_inv_tx ? "" : "no ");
						if (sst.loopback) pfprintf(out, " loopback\n");
					}
					if (in_acl[0]) pfprintf(out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf(out, " ip access-group %s out\n", out_acl);
					if (in_mangle[0]) pfprintf(out, " ip mark %s in\n", in_mangle);
					if (out_mangle[0]) pfprintf(out, " ip mark %s out\n", out_mangle);
					if (in_nat[0]) pfprintf(out, " ip nat %s in\n", in_nat);
					if (out_nat[0]) pfprintf(out, " ip nat %s out\n", out_nat);
#ifdef OPTION_PIMD
					dump_pim_interface(out, osdev);
#endif
					dump_policy_interface(out, osdev);
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if (wan_get_protocol(serial_no) == IF_PROTO_PPP) { /* sppp */
						ppp_proto ppp;

						sppp_get_config(serial_no, &ppp);
						if (ipaddr[0])
							pfprintf (out, " ip address %s %s %s\n", ipaddr, ippeer, ipmask);
						else 
							pfprintf (out, " no ip address\n");
#ifdef CONFIG_SPPP_VJ
						if (ppp.vj)
							pfprintf(out, " ip vj\n");
#endif
#ifdef CONFIG_SPPP_IPHC
						if (ppp.iphc_maxperiod != IPHC_MAXPERIOD_DFLT)
							pfprintf(out, " ip header-compression max-period %d\n", ppp.iphc_maxperiod);
						if (ppp.iphc_maxtime != IPHC_MAXTIME_DFLT)
							pfprintf(out, " ip header-compression max-time %d\n", ppp.iphc_maxtime);
						if (ppp.iphc_maxheader != IPHC_MAXHEADER_DFLT)
							pfprintf(out, " ip header-compression max-header %d\n", ppp.iphc_maxheader);
						if (ppp.iphc_tcp_mode != IPHC_MODE_OFF)
							pfprintf(out, " ip header-compression tcp%s\n",
											(ppp.iphc_tcp_mode == IPHC_MODE_ON_PASSIVE) ? " passive" : "");
						if (ppp.iphc_tcp_contexts != IPHC_TCP_CONTEXTS_DFLT)
							pfprintf(out, " ip header-compression tcp contexts %d\n", ppp.iphc_tcp_contexts);
						if (ppp.iphc_udp_mode != IPHC_MODE_OFF)
							pfprintf(out, " ip header-compression udp %s%s\n",
											(ppp.iphc_udp_format == UDP_COMP_FORMAT_IETF) ? "ietf-format" : "iphc-format",
											(ppp.iphc_udp_mode == IPHC_MODE_ON_PASSIVE) ? " passive" : "");
						if (ppp.iphc_udp_contexts != IPHC_UDP_CONTEXTS_DFLT)
							pfprintf(out, " ip header-compression udp %s contexts %d\n",
											(ppp.iphc_udp_format == UDP_COMP_FORMAT_IETF) ? "ietf-format" : "iphc-format",
											ppp.iphc_udp_contexts);
						if (ppp.iphc_rtp_mode != IPHC_MODE_OFF)
							pfprintf(out, " ip header-compression rtp%s\n",
											(ppp.iphc_rtp_mode == IPHC_MODE_ON_PASSIVE) ? " passive" : "");
						if (ppp.iphc_rtp_checksum_period != IPHC_RTP_CHECKSUM_PERIOD_DFLT)
							pfprintf(out, " ip header-compression rtp checksum-period %d\n", ppp.iphc_rtp_checksum_period);
						for (n=0; (n < CONFIG_MAX_IPHC_CRTP_MARKS) && (ppp.iphc_crtp_marks[n] != 0); n++)
							pfprintf(out, " ip header-compression rtp mark %d\n", ppp.iphc_crtp_marks[n]);
#endif
						if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
							pfprintf(out, " ipx network %08lX\n", ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE]);
						else
							pfprintf(out, " no ipx network\n");
						pfprintf(out, " keepalive interval %d\n", ppp.interval);
						pfprintf(out, " keepalive timeout %d\n", ppp.timeout);
						if (ppp.debug)
							pfprintf(out, " ppp debug\n");
#ifdef CONFIG_SPPP_NETLINK
						switch (ppp.req_auth) {
							case SPPP_REQ_CHAP_AUTH:
							{
								char auth_name[64], auth_pass[64];

								if (sppp_get_chap_auth_secret(auth_name, auth_pass, 64) >= 0)
									pfprintf(out, " ppp authentication algorithm chap auth-name %s auth-pass %s\n", auth_name, auth_pass);
								break;
							}
							case SPPP_REQ_PAP_AUTH:
								pfprintf(out, " ppp authentication algorithm pap\n");
								break;
						}
						if (ppp.req_dns)
							pfprintf(out, " ppp usepeerdns\n");
						switch (ppp.supply_dns) {
							case SPPP_SUPPLY_DNS_NONE:
								break;
							case SPPP_SUPPLY_DNS_STATIC:
								pfprintf(out, " ppp supplypeerdns");
								if (strlen((char *)ppp.supply_dns_addrs[0]))
									pfprintf(out, " %s", ppp.supply_dns_addrs[0]);
								if (strlen((char *)ppp.supply_dns_addrs[1]))
									pfprintf(out, " %s", ppp.supply_dns_addrs[1]);
								pfprintf(out, "\n");
								break;
							case SPPP_SUPPLY_DNS_DYNAMIC:
								pfprintf(out, " ppp supplypeerdns dynamic\n");
								break;
						}
						if (ppp.supply_nbns) {
							pfprintf(out, " ppp supplypeernbns");
							if (strlen((char *)ppp.supply_nbns_addrs[0]))
								pfprintf(out, " %s", ppp.supply_nbns_addrs[0]);
							if (strlen((char *)ppp.supply_nbns_addrs[1]))
								pfprintf(out, " %s", ppp.supply_nbns_addrs[1]);
							pfprintf(out, "\n");
						}
#endif
#ifdef CONFIG_SPPP_PPPH_COMP
						if (ppp.ppph_comp)
							pfprintf(out, " ppp header-compression\n");
#endif
#ifdef CONFIG_SPPP_MULTILINK
						if (ppp.mlp)
							pfprintf(out, " ppp multilink\n");
						if (ppp.mlp_frag_size > 0)
							pfprintf(out, " ppp multilink fragment %d\n", ppp.mlp_frag_size);
#ifdef CONFIG_HDLC_SPPP_LFI
						for (n=0; n<CONFIG_MAX_LFI_PRIORITY_MARKS && ppp.priomarks[n]!=0; n++)
							pfprintf(out, " ppp multilink interleave priority-mark %d\n", ppp.priomarks[n]);
#endif
						if (ppp.mlp)
							pfprintf(out, " ppp multilink mrru %d\n", ppp.mlp_mrru);
#endif
#ifdef CONFIG_SPPP_NETLINK
						{
							char pcname[64], pcpasswd[64];

							if (sppp_get_chap_secret(pcname, pcpasswd, 64) >= 0)
								pfprintf(out, " ppp chap sent-hostname %s password %s\n", pcname, pcpasswd);
							if (sppp_get_pap_secret(pcname, pcpasswd, 64) >= 0)
								pfprintf(out, " ppp pap sent-username %s password %s\n", pcname, pcpasswd);
						}
#endif
						if (mtu)
							pfprintf(out, " mtu %i\n", mtu);
						if (txqueue)
							pfprintf(out, " txqueuelen %i\n", txqueue);
#ifdef CONFIG_DEVELOPMENT
						//if ((n = dev_get_weight(osdev)) > 0)
						//	pfprintf(out, " weight %d\n", n);
#endif
						pfprintf(out, " %sshutdown\n", up ? "no " : "");
					} else { /* SCC_PROTO_MLPPP */
						if (cfg.ip_unnumbered != -1) { /* exibir ip unnumbered no show running config */
							pfprintf(out, " ip unnumbered ethernet %d\n", cfg.ip_unnumbered);
						} else {
							if ((cfg.ip_addr[0])&&(cfg.ip_mask[0]))
								pfprintf(out, " ip address %s %s\n", cfg.ip_addr, cfg.ip_mask);
							else
								pfprintf(out, " no ip address\n");
						}
						if (cfg.ipx_enabled)
							pfprintf(out, " ipx network %08lX\n", cfg.ipx_network);
						else
							pfprintf(out, " no ipx network\n");
						if (cfg.ip_peer_addr[0])
							pfprintf(out, " ip peer-address %s\n", cfg.ip_peer_addr);
						if (cfg.default_route) pfprintf(out, " ip default-route\n");
						if (cfg.novj) pfprintf(out, " no ip vj\n");
						else pfprintf(out, " ip vj\n");

						if (cfg.echo_interval) pfprintf(out, " keepalive interval %d\n", cfg.echo_interval);
						if (cfg.echo_failure) pfprintf(out, " keepalive timeout %d\n", cfg.echo_failure);
						if (cfg.mtu) pfprintf(out, " mtu %d\n", cfg.mtu);
						if (cfg.debug) pfprintf(out, " ppp debug\n");
#ifdef CONFIG_HDLC_SPPP_LFI
						if (cfg.multilink) {
							if ((cfg.fragment_size != 0) || (cfg.priomarks[0] != 0)) {
								if (cfg.fragment_size != 0)
									pfprintf(out, " ppp multilink fragment %d\n", cfg.fragment_size);
								for (n=0; n<CONFIG_MAX_LFI_PRIORITY_MARKS && cfg.priomarks[n]!=0; n++)
									pfprintf(out, " ppp multilink interleave priority-mark %d\n", cfg.priomarks[n]);
							}
							else
								pfprintf(out, " ppp multilink\n");
						}
#else
						if (cfg.multilink)
							pfprintf(out, " ppp multilink\n");
#endif
						if (cfg.usepeerdns) pfprintf(out, " ppp usepeerdns\n");
						if (cfg.auth_user[0]) pfprintf(out, " authentication user %s\n", cfg.auth_user);
						if (cfg.auth_pass[0]) pfprintf(out, " authentication pass %s\n", cfg.auth_pass);
						if ((!cfg.auth_user[0])&&(!cfg.auth_pass[0])) pfprintf(out, " no authentication\n");
						/* Requires authentication from peer? */
						if (cfg.server_flags & (SERVER_FLAGS_PAP|SERVER_FLAGS_CHAP)) 
								pfprintf(out, " ppp authentication algorithm %s\n", 
								cfg.server_flags & SERVER_FLAGS_PAP ? "pap" : \
								cfg.server_flags & SERVER_FLAGS_CHAP ? "chap" : "");
						/* Hostname and password used when this NAS is required to authenticate */
						if (cfg.server_auth_user[0]) pfprintf(out, " ppp authentication hostname %s\n", cfg.server_auth_user);
						if (cfg.server_auth_pass[0]) pfprintf(out, " ppp authentication password %s\n", cfg.server_auth_pass);
						if (sync_nasync == 0)
						{
#ifndef CONFIG_BERLIN_SATROUTER
							if (cfg.speed) pfprintf(out, " speed %d\n", cfg.speed);
#endif
							if (cfg.flow_control == FLOW_CONTROL_NONE)
								pfprintf(out, " no flow-control\n");
							else
								pfprintf(out, " flow-control %s\n", 
									cfg.flow_control == FLOW_CONTROL_RTSCTS ? 
									"rts-cts" : "xon-xoff");
#ifndef CONFIG_BERLIN_SATROUTER
							if (cfg.chat_script[0]) 
								pfprintf(out, " chat-script %s\n", cfg.chat_script);
							else 
								pfprintf(out, " no chat-script\n");
							pfprintf(out, " %sdial-on-demand\n", cfg.dial_on_demand ? "" : "no ");
							if (cfg.holdoff)
								pfprintf(out, " holdoff %d\n", cfg.holdoff);
							if (cfg.idle)
								pfprintf(out, " idle %d\n", cfg.idle);
#endif
							if (cfg.server_flags & (SERVER_FLAGS_PAP|SERVER_FLAGS_CHAP)) pfprintf(out, " server authentication local algorithm %s\n", cfg.server_flags&SERVER_FLAGS_PAP ? "pap" : \
								cfg.server_flags&SERVER_FLAGS_CHAP ? "chap" : "");
							if (cfg.server_auth_user[0]) pfprintf(out, " server authentication local user %s\n", cfg.server_auth_user);
							if (cfg.server_auth_pass[0]) pfprintf(out, " server authentication local pass %s\n", cfg.server_auth_pass);
							// radius authentication
							if (cfg.radius_authkey[0]) pfprintf(out, " server authentication radius auth_key %s\n", cfg.radius_authkey);
							if (cfg.radius_retries > 0) pfprintf(out, " server authentication radius retries %d\n", cfg.radius_retries);
							if (cfg.radius_sameserver > 0) pfprintf(out, " server authentication radius same_server\n");
							if (cfg.radius_servers[0]) pfprintf(out, " server authentication radius servers %s\n", cfg.radius_servers);
							if (cfg.radius_timeout > 0) pfprintf(out, " server authentication radius timeout %d\n", cfg.radius_timeout);
							if (cfg.radius_trynextonreject > 0) pfprintf(out, " server authentication radius try_next_on_reject\n");
							// tacacs authentication
							if (cfg.tacacs_authkey[0]) pfprintf(out, " server authentication tacacs auth_key %s\n", cfg.tacacs_authkey);
							if (cfg.tacacs_sameserver > 0) pfprintf(out, " server authentication tacacs same_server\n");
							if (cfg.tacacs_servers[0]) pfprintf(out, " server authentication tacacs servers %s\n", cfg.tacacs_servers);
							if (cfg.tacacs_trynextonreject > 0) pfprintf(out, " server authentication tacacs try_next_on_reject\n");
							if ((cfg.server_ip_addr[0])&&(cfg.server_ip_mask[0]))
							pfprintf(out, " server ip address %s %s\n", cfg.server_ip_addr, cfg.server_ip_mask);
							if (cfg.server_ip_peer_addr[0])
								pfprintf(out, " server ip peer-address %s\n", cfg.server_ip_peer_addr);
							pfprintf(out, " %sserver shutdown\n", (cfg.server_flags & SERVER_FLAGS_ENABLE) ? "no " : "");
						}
#ifndef CONFIG_BERLIN_SATROUTER
						if (_cish_aux)
						{
							if (cfg.backup) pfprintf(out, " backup %s %d %d\n", cfg.backup == 1 ? "aux0" : "aux1", cfg.activate_delay, cfg.deactivate_delay);
								else pfprintf(out, " no backup\n");
						}
#endif
						pfprintf(out, " %sshutdown\n", cfg.up ? "no " : "");
					}
					break;
				}

				case ARPHRD_ASYNCPPP:
				{
					ppp_config cfg;

					pfprintf(out, " encapsulation ppp\n");
					ppp_get_config(serial_no, &cfg);
					if (in_acl[0]) pfprintf(out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf(out, " ip access-group %s out\n", out_acl);
					if (in_mangle[0]) pfprintf(out, " ip mark %s in\n", in_mangle);
					if (out_mangle[0]) pfprintf(out, " ip mark %s out\n", out_mangle);
					if (in_nat[0]) pfprintf(out, " ip nat %s in\n", in_nat);
					if (out_nat[0]) pfprintf(out, " ip nat %s out\n", out_nat);
					dump_policy_interface(out, osdev);
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if ((cfg.ip_addr[0])&&(cfg.ip_mask[0]))
						pfprintf(out, " ip address %s %s\n", cfg.ip_addr, cfg.ip_mask);
					else
						pfprintf(out, " no ip address\n");
					if (cfg.ipx_enabled)
						pfprintf(out, " ipx network %08lX\n", cfg.ipx_network);
					else
						pfprintf(out, " no ipx network\n");
					if (cfg.ip_peer_addr[0])
						pfprintf(out, " ip peer-address %s\n", cfg.ip_peer_addr);
					if (cfg.default_route) pfprintf(out, " ip default-route\n");
					if (cfg.novj) pfprintf(out, " no ip vj\n");
					else pfprintf(out, " ip vj\n");

					if (cfg.echo_interval) pfprintf(out, " keepalive interval %d\n", cfg.echo_interval);
					if (cfg.echo_failure) pfprintf(out, " keepalive timeout %d\n", cfg.echo_failure);
					if (cfg.mtu) pfprintf(out, " mtu %d\n", cfg.mtu);
					if (cfg.debug) pfprintf(out, " ppp debug\n");
#ifdef CONFIG_HDLC_SPPP_LFI
					if (cfg.multilink) {
						if ((cfg.fragment_size != 0) || (cfg.priomarks[0] != 0)) {
							if (cfg.fragment_size != 0)
								pfprintf(out, " ppp multilink fragment %d\n", cfg.fragment_size);
							for (n=0; n<CONFIG_MAX_LFI_PRIORITY_MARKS && cfg.priomarks[n]!=0; n++)
								pfprintf(out, " ppp multilink interleave priority-mark %d\n", cfg.priomarks[n]);
						}
						else
							pfprintf(out, " ppp multilink\n");
					}
#else
					if (cfg.multilink)
						pfprintf(out, " ppp multilink\n");
#endif
					if (cfg.usepeerdns) pfprintf(out, " ppp usepeerdns\n");
#ifndef CONFIG_BERLIN_SATROUTER
					if (cfg.speed) pfprintf(out, " speed %d\n", cfg.speed);
#endif
					if (cfg.flow_control == FLOW_CONTROL_NONE)
						pfprintf(out, " no flow-control\n");
					else
						pfprintf(out, " flow-control %s\n", 
							cfg.flow_control==FLOW_CONTROL_RTSCTS ? 
							"rts-cts" : "xon-xoff");
#ifndef CONFIG_BERLIN_SATROUTER
					if (cfg.chat_script[0]) 
						pfprintf(out, " chat-script %s\n", cfg.chat_script);
					else 
						pfprintf(out, " no chat-script\n");
					pfprintf(out, " %sdial-on-demand\n", cfg.dial_on_demand ? "" : "no ");
					if (cfg.holdoff)
						pfprintf(out, " holdoff %d\n", cfg.holdoff);
					if (cfg.idle)
						pfprintf(out, " idle %d\n", cfg.idle);
#endif
					if (cfg.auth_user[0]) pfprintf(out, " authentication user %s\n", cfg.auth_user);
					if (cfg.auth_pass[0]) pfprintf(out, " authentication pass %s\n", cfg.auth_pass);
					if ((!cfg.auth_user[0]) && (!cfg.auth_pass[0])) pfprintf(out, " no authentication\n");
					if (cfg.server_flags & (SERVER_FLAGS_PAP|SERVER_FLAGS_CHAP)) pfprintf(out, " server authentication local algorithm %s\n", cfg.server_flags&SERVER_FLAGS_PAP ? "pap" : \
						cfg.server_flags&SERVER_FLAGS_CHAP ? "chap" : "");
					if (cfg.server_auth_user[0]) pfprintf(out, " server authentication local user %s\n", cfg.server_auth_user);
					if (cfg.server_auth_pass[0]) pfprintf(out, " server authentication local pass %s\n", cfg.server_auth_pass);
					// radius authentication
					if (cfg.radius_authkey[0]) pfprintf(out, " server authentication radius auth_key %s\n", cfg.radius_authkey);
					if (cfg.radius_retries > 0) pfprintf(out, " server authentication radius retries %d\n", cfg.radius_retries);
					if (cfg.radius_sameserver > 0) pfprintf(out, " server authentication radius same_server\n");
					if (cfg.radius_servers[0]) pfprintf(out, " server authentication radius servers %s\n", cfg.radius_servers);
					if (cfg.radius_timeout > 0) pfprintf(out, " server authentication radius timeout %d\n", cfg.radius_timeout);
					if (cfg.radius_trynextonreject > 0) pfprintf(out, " server authentication radius try_next_on_reject\n");
					// tacacs authentication
					if (cfg.tacacs_authkey[0]) pfprintf(out, " server authentication tacacs auth_key %s\n", cfg.tacacs_authkey);
					if (cfg.tacacs_sameserver > 0) pfprintf(out, " server authentication tacacs same_server\n");
					if (cfg.tacacs_servers[0]) pfprintf(out, " server authentication tacacs servers %s\n", cfg.tacacs_servers);
					if (cfg.tacacs_trynextonreject > 0) pfprintf(out, " server authentication tacacs try_next_on_reject\n");
					if ((cfg.server_ip_addr[0])&&(cfg.server_ip_mask[0]))
						pfprintf(out, " server ip address %s %s\n", cfg.server_ip_addr, cfg.server_ip_mask);
					if (cfg.server_ip_peer_addr[0])
						pfprintf(out, " server ip peer-address %s\n", cfg.server_ip_peer_addr);
					pfprintf(out, " %sserver shutdown\n", (cfg.server_flags & SERVER_FLAGS_ENABLE) ? "no " : "");
					pfprintf(out, " %sshutdown\n", cfg.up ? "no " : "");
					break;
				}

				case ARPHRD_ETHER:
				{
					int k, n, ipx_set, ether_no, found;
					char *p;
					char *ipx_encaps[] = {"snap", "802.2", "ethernet_II", "802.3"};
					char daemon_dhcpc[32];

					if (in_acl[0]) pfprintf (out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf (out, " ip access-group %s out\n", out_acl);
					if (in_mangle[0]) pfprintf (out, " ip mark %s in\n", in_mangle);
					if (out_mangle[0]) pfprintf (out, " ip mark %s out\n", out_mangle);
					if (in_nat[0]) pfprintf (out, " ip nat %s in\n", in_nat);
					if (out_nat[0]) pfprintf (out, " ip nat %s out\n", out_nat);
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
					if (strlen(daemon_dhcpc) && is_daemon_running(daemon_dhcpc)) pfprintf(out, " ip address dhcp\n");
						else if (ipaddr[0]) pfprintf(out, " ip address %s %s\n", ipaddr, ipmask);
								else  pfprintf(out, " no ip address\n");
					/* search for alias */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ":0");
					for (k=0, found=0; k < ip_addr_table_index; k++)
					{
						if (strcmp(devtmp, ip_addr_table[k].ifname) == 0)
						{
							strcpy(ipaddr, inet_ntoa(ip_addr_table[k].local));
							ip_bitlen2mask(ip_addr_table[k].bitlen, ipmask);
							pfprintf (out, " ip address %s %s secondary\n", ipaddr, ipmask);
							found=1;
						}
					}
#if 0
					if (!found)
					{ /* Search for backuped secondary addresses */
						for (k=0; ip_addr_table_backup[k].ifname[0] != 0 && k < MAX_NUM_IPS; k++)
						{
							if (strcmp(devtmp, ip_addr_table_backup[k].ifname) == 0)
							{
								strcpy(ipaddr, inet_ntoa(ip_addr_table_backup[k].local));
								ip_bitlen2mask(ip_addr_table_backup[k].bitlen, ipmask);
								pfprintf (out, " ip address %s %s secondary\n", ipaddr, ipmask);
							}
						}
					}
#endif
					/* IPX */
					ipx_set=0;
					for (k=FIRST_FRAME_TYPE; k <= LAST_FRAME_TYPE; k++)
					{
						if (ipx_intf.network_set[k-FIRST_FRAME_TYPE])
						{
							ipx_set=1;
							pfprintf(out, " ipx network %08lX encapsulation %s\n", 
								ipx_intf.network[k-FIRST_FRAME_TYPE],
								ipx_encaps[k-FIRST_FRAME_TYPE]);
						}
					}
					if (!ipx_set) pfprintf(out, " no ipx network\n");
					if (mtu) pfprintf (out, " mtu %d\n", mtu);
					if (txqueue) pfprintf (out, " txqueuelen %d\n", txqueue);
					for (n=1; n <= MAX_BRIDGE; n++)
					{
						char brname[32];
						sprintf(brname, "%s%d", BRIDGE_NAME, n);
						if (br_checkif(brname, osdev))
							pfprintf(out, " bridge-group %d\n", n);
					}
					/* search for vlan */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ".");
					for (k=0; k < link_table_index; k++)
					{
						if (strncmp(link_table[k].ifname, devtmp, strlen(devtmp)) == 0)
						{
							pfprintf (out, " vlan %s\n", link_table[k].ifname+strlen(devtmp));
						}
					}
#ifdef CONFIG_BERLIN_SATROUTER
					/* Nao existe o comando speed para as subinterfaces VLAN */
					if( strncmp(osdev, "ethernet0.", strlen("ethernet0.")) && strncmp(osdev, "ethernet1.", strlen("ethernet1.")) )
					{
						int result;
						unsigned short bmcr;
						
						/* Se a interface estiver down, entao precisamos coloca-la
						 * em up para poder buscar as informacoes do phy. Depois o
						 * estado original eh restaurado.
						 */
						if( !up )
							dev_set_link_up(osdev);

						if((result = lan_get_phy_reg(osdev, MII_BMCR)) < 0)
							pfprintf(out, " speed auto\n");
						else
						{
							bmcr = (unsigned short) result;
							if( bmcr & BMCR_ANENABLE )
								pfprintf(out, " speed auto\n");
							else
								pfprintf(out, " speed %s %s\n",	(bmcr & BMCR_SPEED100) ? "100" : "10",
																(bmcr & BMCR_FULLDPLX) ? "full" : "half");
						}
						/* Devolve estado original */
						if( !up )
							dev_set_link_down(osdev);
					}
#endif
#ifdef OPTION_VRRP
					dump_vrrp_interface(out, osdev);
#endif
					pfprintf (out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_LOOPBACK:
				{
					int k;

					if (in_acl[0]) pfprintf (out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf (out, " ip access-group %s out\n", out_acl);
					if (ipaddr[0]) pfprintf(out, " ip address %s %s\n", ipaddr, ipmask);
						else  pfprintf(out, " no ip address\n");
					/* search for alias */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ":0");
					for (k=0; k < ip_addr_table_index; k++)
					{
						if (strcmp(devtmp, ip_addr_table[k].ifname) == 0)
						{
							strcpy(ipaddr, inet_ntoa(ip_addr_table[k].local));
							ip_bitlen2mask(ip_addr_table[k].bitlen, ipmask);
							pfprintf(out, " ip address %s %s secondary\n", ipaddr, ipmask);
						}
					}
					/* Doesnt need to search for backuped secondary addresses */
					pfprintf (out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_TUNNEL:
				case ARPHRD_IPGRE:
				{
					int k, found;

					if (in_acl[0]) pfprintf (out, " ip access-group %s in\n", in_acl);
					if (out_acl[0]) pfprintf (out, " ip access-group %s out\n", out_acl);
					if (in_mangle[0]) pfprintf (out, " ip mark %s in\n", in_mangle);
					if (out_mangle[0]) pfprintf (out, " ip mark %s out\n", out_mangle);
					if (in_nat[0]) pfprintf (out, " ip nat %s in\n", in_nat);
					if (out_nat[0]) pfprintf (out, " ip nat %s out\n", out_nat);
#ifndef OPTION_NEW_QOS_CONFIG
					dump_policy_interface(out, osdev);
#endif
					dump_rip_interface(out, osdev);
					dump_ospf_interface(out, osdev);
					if (ipaddr[0]) pfprintf(out, " ip address %s %s\n", ipaddr, ipmask);
						else  pfprintf(out, " no ip address\n");
					/* search for alias */
					strncpy(devtmp, osdev, 14);
					strcat(devtmp, ":0");
					for (k=0, found=0; k < ip_addr_table_index; k++)
					{
						if (strcmp(devtmp, ip_addr_table[k].ifname) == 0)
						{
							strcpy(ipaddr, inet_ntoa(ip_addr_table[k].local));
							ip_bitlen2mask(ip_addr_table[k].bitlen, ipmask);
							pfprintf (out, " ip address %s %s secondary\n", ipaddr, ipmask);
							found=1;
						}
					}
#if 0
					if (!found)
					{ /* Search for backuped secondary addresses */
						for (k=0; ip_addr_table_backup[k].ifname[0] != 0 && k < MAX_NUM_IPS; k++)
						{
							if (strcmp(devtmp, ip_addr_table_backup[k].ifname) == 0)
							{
								strcpy(ipaddr, inet_ntoa(ip_addr_table_backup[k].local));
								ip_bitlen2mask(ip_addr_table_backup[k].bitlen, ipmask);
								pfprintf (out, " ip address %s %s secondary\n", ipaddr, ipmask);
							}
						}
					}
#endif 
					if (mtu) pfprintf(out, " mtu %d\n", mtu);
					if (txqueue) pfprintf(out, " txqueuelen %d\n", txqueue);
					for (k=1; k <= MAX_BRIDGE; k++)
					{
						char brname[32];

						sprintf(brname, "%s%d", BRIDGE_NAME, k);
						if (br_checkif(brname, osdev))
							pfprintf(out, " bridge-group %d\n", k);
					}
					dump_tunnel_interface(out, conf_format, osdev);
					pfprintf(out, " %sshutdown\n", up ? "no " : "");
					break;
				}

				case ARPHRD_RAWHDLC:
					break;

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
						if (itf_should_sendtrap(buf)) pfprintf(out, " snmp trap link-status\n");
#if 0
							else pfprintf(out, " no snmp trap link-status\n");
#endif
					}
				}
			}
#ifdef CONFIG_BERLIN_SATROUTER
			if(!intf)	pfprintf (out, "!\n");
#else
			pfprintf (out, "!\n");
#endif
		}
		else
		{
			int dte_ndce, v28_nv35, cablelogic, cabledetect;
#ifndef CONFIG_BERLIN_SATROUTER
			int modem_info=-1;
#endif

			if (intf && (
#ifdef OPTION_IPSEC
				strcasecmp(cish_dev+7, intf) && /* Crypto-serial0.16 */
#endif
				strcasecmp(cish_dev, intf)
				)) continue; /* skip not matched interfaces */

			if (serial_no < MAX_WAN_INTF)
				wan_get_cable(serial_no, &cabledetect, &dte_ndce, &v28_nv35, &cablelogic);
			if (sync_nasync >= 0)
			{
#if 0 /* #ifndef CONFIG_BERLIN_SATROUTER */
				if (sync_nasync)
				{
					modem_info=wan_get_sync_modem_info(serial_no);
				}
				else
				{
					modem_info=wan_get_async_modem_info(serial_no);
					cablelogic=modem_info&TIOCM_CTS; /* Detect modem presence! */
				}
#endif
			}
				else cablelogic=1; /* demais casos... */

#ifdef CONFIG_BERLIN_SATROUTER
			pfprintf(out, "%s is %s, line protocol is %s%s\n",
					cish_dev,
					up ? "up" : "administratively down",
					running&IF_STATE_UP ? "up" : "down", running&IF_STATE_LOOP ? " (looped)" : "");
#else
			pfprintf(out, "%s is %s, line protocol is %s%s\n",
					cish_dev,
					up ? (cablelogic ? "up" : "down") : "administratively down",
					running & IF_STATE_UP ? "up" : "down", running & IF_STATE_LOOP ? " (looped)" : "");
#endif
			description=dev_get_description(osdev);
			if (description) pfprintf(out, "  Description: %s\n",description);
			if (sync_nasync >= 0 && serial_no < MAX_WAN_INTF) /* serialx */
			{
#ifndef CONFIG_BERLIN_SATROUTER
				pfprintf (out, "  physical-layer is %ssynchronous\n", sync_nasync ? "" : "a");
				if (cabledetect)
					pfprintf (out, "  interface is %s, cable type is %s\n", dte_ndce ? "DTE" : "DCE", v28_nv35 ? "V.28" : "V.35");
				else
					pfprintf (out, "  cable not detected\n");
#endif
				if (clk_type >= 0)
				{
#ifdef CONFIG_BERLIN_SATROUTER
					if(clk_inv_tx)	pfprintf(out, "  tx clock is inverted,");
					pfprintf(out, "  clock type is %s, detected rate is %d bps\n", clock_type[clk_type], detected_rate);
#else
					pfprintf(out, "  clock type is %s", clock_type[clk_type]);
					if (clk_inv_tx)
						pfprintf(out, ", tx clock is inverted");
					if (clk_rate > 0)
						pfprintf(out, ", %srate is %d bps\n", dte_ndce ? "specified " : "", clk_rate);
					else if (clk_type == CLOCK_EXT || clk_type == CLOCK_TXFROMRX)
						pfprintf(out, ", detected rate is %d bps\n", detected_rate);
					else
						pfprintf(out, ", no clock rate\n");
#endif
				}
			}

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
				if (cfg.ip_addr[0]) { strncpy(ipaddr, cfg.ip_addr, 16); ipaddr[15]=0; }
				if (cfg.ip_mask[0]) { strncpy(ipmask, cfg.ip_mask, 16); ipmask[15]=0; }
				if (cfg.ip_peer_addr[0]) { strncpy(ippeer, cfg.ip_peer_addr, 16); ippeer[15]=0; }
#ifndef CONFIG_BERLIN_SATROUTER
				if (cfg.dial_on_demand && !running) { /* filtra enderecos aleatorios atribuidos pelo pppd */
					ipaddr[0]=0;
					ippeer[0]=0;
				}
#endif
				if (cfg.ip_unnumbered != -1) /* Verifica a flag ip_unnumbered do cfg e exibe a mensagem correta */
					pfprintf(out, "  Interface is unnumbered. Using address of ethernet %d (%s)\n", cfg.ip_unnumbered, ipaddr);
				else
					if (ipaddr[0]) pfprintf(out, "  Internet address is %s %s\n", ipaddr, ipmask);
			}
				else if (ipaddr[0]) pfprintf (out, "  Internet address is %s %s\n", ipaddr, ipmask);
				/* Secondary address search */		
				strncpy(devtmp, osdev, 14);
				strcat(devtmp, ":0");
				for (i=0; i < ip_addr_table_index; i++) {
					if (strcmp(devtmp, ip_addr_table[i].ifname) == 0)  {
						strcpy(ipaddr, inet_ntoa(ip_addr_table[i].local));
						ip_bitlen2mask(ip_addr_table[i].bitlen, ipmask);
						pfprintf (out, "  Secondary internet address is %s %s\n", ipaddr, ipmask);
					}
				}
#ifdef CONFIG_BERLIN_SATROUTER
			switch (linktype) {
				case ARPHRD_PPP:
				case ARPHRD_ASYNCPPP:
					if( wan_get_protocol(serial_no) == IF_PROTO_PPP ) { /* sppp */
						IP in_addr;
						ppp_state state;

						in_addr.s_addr = (sppp_get_state_all(serial_no, &state) >= 0) ? state.dest_addr : 0;
						strcpy(ippeer, inet_ntoa(in_addr));
					}
					break;
			}
#endif
			if (ippeer[0] && !(linktype == ARPHRD_TUNNEL || linktype == ARPHRD_IPGRE))
				pfprintf (out, "  Peer address is %s\n", ippeer);
			pfprintf (out, "  MTU is %i bytes\n", mtu);
			if (txqueue) pfprintf (out, "  Output queue size: %i\n", txqueue);
			switch (linktype)
			{
				case ARPHRD_FRAD:
				{
					int i;
					fr_proto fr;
					fr_get_config(serial_no, &fr);
					pfprintf (out, "  Encapsulation frame-relay IETF, LMI type is %s, frame relay %s\n",
						  (fr.lmi==LMI_ANSI)  ? "ANSI T1.617 Annex D" : 
						  (fr.lmi==LMI_CCITT) ? "ITU-T Q.933 Annex A" : 
						  (fr.lmi==LMI_CISCO) ? "CISCO" : "NONE",
						  fr.dce ? "DCE" : "DTE");
					if (!fr.dce && fr.dlci[0]) {
						if (fr.dlci[0])
							pfprintf(out, "  Incoming dlci(s): %d", fr.dlci[0]);
						for (i=1; i < MAX_FR_DLCI && fr.dlci[i]; i++)
							pfprintf(out, ", %d", fr.dlci[i]);
						if (i == MAX_FR_DLCI) pfprintf(out, "...\n");
							else pfprintf(out, "\n");
					}
#ifdef CONFIG_HDLC_FR_LFI
					if( fr.interleave == 1 )
						pfprintf(out, "  Interleaving enabled on TX\n");
#endif
#ifdef CONFIG_DEVELOPMENT_TST
					pfprintf(out, "     %lu dcd ON, %lu dcd OFF\n", stat.dcdon, stat.dcdoff);
					pfprintf(out, "     %lu GLT, %lu GLR\n", stat.glt, stat.glr);
#endif
					break;
				}

				case ARPHRD_DLCI:
				{
					pfprintf (out, "  Encapsulation frame-relay\n");
#ifdef CONFIG_HDLC_FR_LFI
					if( fr_pvc_get_fragment(osdev) > 0 )
						pfprintf(out, "  Fragmentation enabled on TX\n");
#endif
#ifdef CONFIG_FR_IPHC
					{
						fr_proto_pvc_info info;

						if( (fr_pvc_get_iphc_stats(osdev, &info) >= 0)
							&& (info.iphc_stats.st_negot == FRIHCP_ST_OPERATIONAL)
							&& (fr_pvc_get_info(osdev, &info) == 0) ) {
							if( info.iphc_tcp_mode != IPHC_MODE_OFF )
								pfprintf(out, "  IP/TCP header compression enabled on TX\n");
							if( info.iphc_udp_mode != IPHC_MODE_OFF )
								pfprintf(out, "  IP/UDP%s header compression enabled on TX\n", (info.iphc_rtp_mode != IPHC_MODE_OFF) ? "/RTP" : "");
						}
					}
#endif
					if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
						pfprintf(out, "  IPX address is %lX%s%s\n", 
								ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE], 
								mac[0] ? "." : "", 
								mac);
					break;
				}

				case ARPHRD_CISCO:
				{
					cisco_proto cisco;
					chdlc_get_config(serial_no, &cisco);
					pfprintf (out, "  Encapsulation Cisco HDLC, keepalive interval %d, keepalive timeout %d\n",
						  cisco.interval, cisco.timeout);
					if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
						pfprintf(out, "  IPX address is %lX%s%s\n", 
								ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE],
								mac[0] ? "." : "", 
								mac);
#ifdef CONFIG_DEVELOPMENT_TST
					pfprintf(out, "     %lu dcd ON, %lu dcd OFF\n", stat.dcdon, stat.dcdoff);
					pfprintf(out, "     %lu GLT, %lu GLR\n", stat.glt, stat.glr);
#endif
					break;
				}

#ifdef OPTION_X25
				case ARPHRD_X25:
				{
					x25_proto x25;
					struct x25_intf_config conf;
					int t2, t20, t21, t22, t23;

					pfprintf (out, "  Encapsulation X.25\n");
					x25_get_config(serial_no, &x25);
					pfprintf(out, "  LAPB mode %s, modulo %d, %s, window %d\n",
						x25.lapb_mode&LAPB_DCE ? "DCE" : "DTE",
						x25.lapb_mode&LAPB_EXTENDED ? 128 : 8,
						x25.lapb_mode&LAPB_MLP ? "MLP" : "SLP",
						x25.lapb_window);
					pfprintf(out, "  LAPB n2=%d, t1=%d, t2=%d\n",
						x25.lapb_n2, x25.lapb_t1, x25.lapb_t2);
					x25_get_devconfig(cish_dev, &conf);
					if (conf.x121local.x25_addr[0])
						pfprintf(out, "  X.25 address %s\n", conf.x121local.x25_addr);
					pfprintf(out, "  X.25 modulo %d, packet size %d, window %d\n",
						conf.subscrip.extended ? 128 : 8, 1<<conf.facilities.pacsize_out, conf.facilities.winsize_out);
					t2 = get_procx25_val("acknowledgement_hold_back_timeout") / HZ;
					t20 = get_procx25_val("restart_request_timeout") / HZ;
					t21 = get_procx25_val("call_request_timeout") / HZ;
					t22 = get_procx25_val("reset_request_timeout") / HZ;
					t23 = get_procx25_val("clear_request_timeout") / HZ;
					pfprintf(out, "  X.25 t2=%d, t20=%d, t21=%d, t22=%d, t23=%d\n", t2, t20, t21, t22, t23);
#ifdef SHOW_EXTRA_HDLC_STAT
					pfprintf(out, "     %lu dcd ON, %lu dcd OFF\n", stat.dcdon, stat.dcdoff);
					pfprintf(out, "     %lu GLT, %lu GLR\n", stat.glt, stat.glr);
#endif
					break;
#endif

#ifdef OPTION_X25
				case ARPHRD_RFC1356:
				{
					struct rfc1356_config cfg;

					pfprintf (out, "  Encapsulation IP over X.25 (RFC1356)\n");
					rfc1356_get_config(serial_no, minor, &cfg);
					if (cfg.local.x25_addr[0]) pfprintf(out, "  X25 address %s\n", cfg.local.x25_addr);
					pfprintf(out, "  X25 facilities ips %d ops %d win %d wout %d\n",
						1<<cfg.facilities.pacsize_in, 1<<cfg.facilities.pacsize_out,
						cfg.facilities.winsize_in, cfg.facilities.winsize_out);
#if 0
					if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
						pfprintf(out, "  IPX address is %lX%s%s\n", 
								ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE],
								mac[0] ? "." : "", 
								mac);
#endif
					break;
				}
#endif
				case ARPHRD_PPP:
				case ARPHRD_ASYNCPPP:
					if (wan_get_protocol(serial_no) == IF_PROTO_PPP) { /* sppp */
						ppp_proto ppp;

						pfprintf(out, "  Encapsulation PPP");
						sppp_get_config(serial_no, &ppp);
						pfprintf (out, ", keepalive interval %d, keepalive timeout %d", ppp.interval, ppp.timeout);
						pfprintf(out, "\n");
						if (ipx_intf.network_set[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE])
							pfprintf(out, "  IPX address is %lX%s%s\n",
									ipx_intf.network[IPX_FRAME_ETHERII-FIRST_FRAME_TYPE],
									mac[0] ? "." : "",
									mac);
#ifdef CONFIG_SPPP_MULTILINK
#ifdef CONFIG_HDLC_SPPP_LFI
						if (ppp.mlp) {
							if ((ppp.mlp_frag_size != 0) && (ppp.priomarks[0] != 0))
								pfprintf(out, "  Fragmentation and Interleaving enabled on TX\n");
							else if (ppp.mlp_frag_size > 0)
								pfprintf(out, "  Fragmentation enabled on TX\n");
							else if (ppp.priomarks[0] != 0)
								pfprintf(out, "  Interleaving enabled on TX\n");
						}
#else
						if (ppp.mlp && (ppp.mlp_frag_size > 0))
							pfprintf(out, "  Fragmentation enabled on TX\n");
#endif
#endif
#ifdef CONFIG_SPPP_PPPH_COMP
						if (ppp.ppph_comp)
							pfprintf(out, "  PPP header compression enabled\n");
#endif
#ifdef CONFIG_SPPP_IPHC
						{
							struct _iphc_compressing_stats iphc_stats;

							if ((sppp_get_iphc_stats(osdev, &iphc_stats) >= 0) && (iphc_stats.st_negot == IPHC_NEGOT_ST_OPENED)) {
								if (ppp.iphc_tcp_mode != IPHC_MODE_OFF)
									pfprintf(out, "  IP/TCP header compression enabled on TX\n");
								if (ppp.iphc_udp_mode != IPHC_MODE_OFF)
									pfprintf(out, "  IP/UDP%s header compression enabled on TX\n",
													(ppp.iphc_rtp_mode != IPHC_MODE_OFF) ? "/RTP" : "");
							}
						}
#endif
					} else { /* SCC_PROTO_MLPPP */
						ppp_config cfg;

						ppp_get_config(serial_no, &cfg);
						pfprintf(out, "  Encapsulation PPP");
						if (cfg.echo_interval) pfprintf(out, ", echo interval %d", cfg.echo_interval);
						if (cfg.echo_failure) pfprintf(out, ", echo failure %d", cfg.echo_failure);
						pfprintf(out, "\n");
						if (cfg.ipx_enabled)
							pfprintf(out, "  IPX address is %lX%s%s\n", 
									cfg.ipx_network,
									mac[0] ? "." : "", 
									mac);
#ifdef CONFIG_HDLC_SPPP_LFI
						if (cfg.multilink) {
							if ((cfg.fragment_size != 0) && (cfg.priomarks[0] != 0))
								pfprintf(out, "  Fragmentation and Interleaving enabled on TX\n");
							else if (cfg.fragment_size != 0)
								pfprintf(out, "  Fragmentation enabled on TX\n");
							else if (cfg.priomarks[0] != 0)
								pfprintf(out, "  Interleaving enabled on TX\n");
						}
#endif
					}
#ifdef CONFIG_DEVELOPMENT_TST
					if (serial_no < MAX_WAN_INTF) {
						pfprintf(out, "     %lu dcd ON, %lu dcd OFF\n", stat.dcdon, stat.dcdoff);
						pfprintf(out, "     %lu GLT, %lu GLR\n", stat.glt, stat.glr);
					}
#endif
					break;

				case ARPHRD_ETHER:
				{
					char *ipx_encaps[] = {"snap", "802.2", "ethernet_II", "802.3"};
					int i, first=1;

					if (mac[0]) pfprintf (out, "  Hardware address is %s\n", mac);
					if (running)
					{
#ifdef CONFIG_BERLIN_SATROUTER
						switch( get_board_hw_id() )
						{
							case 0x02:
							if( !strcmp(osdev, "ethernet1") )
							{
								int pdata;
								unsigned short status;

								for(i=0; i < 4; i++)
								{
									pdata = i;
									if( eth_switch_port_get_status(osdev, &pdata) >= 0 )
									{
										status = (unsigned short) pdata;
										if( !(status & 0x8000) )
										{
											pfprintf (out, "  %s-Duplex, %sMbit\n",	(status & 0x0100) ? "Full" : "Half",
											(status & 0x2000) ? "100" : "10");
											break;
										}
									}
								}
							}
							else
							{
								switch (phy_status & PHY_STAT_SPMASK)
								{
								case PHY_STAT_10HDX: pfprintf (out, "  Half-Duplex, 10Mbit\n"); break;
								case PHY_STAT_10FDX: pfprintf (out, "  Full-Duplex, 10Mbit\n"); break;
								case PHY_STAT_100HDX: pfprintf (out, "  Half-Duplex, 100Mbit\n"); break;
								case PHY_STAT_100FDX: pfprintf (out, "  Full-Duplex, 100Mbit\n"); break;
								}
							}
							break;
						case 0x00:
						case 0x01:
						case 0x03:
						case 0x04:
							switch (phy_status & PHY_STAT_SPMASK)
							{
							case PHY_STAT_10HDX: pfprintf (out, "  Half-Duplex, 10Mbit\n"); break;
							case PHY_STAT_10FDX: pfprintf (out, "  Full-Duplex, 10Mbit\n"); break;
							case PHY_STAT_100HDX: pfprintf (out, "  Half-Duplex, 100Mbit\n"); break;
							case PHY_STAT_100FDX: pfprintf (out, "  Full-Duplex, 100Mbit\n"); break;
							}
							break;
						}
#else /* CONFIG_BERLIN_SATROUTER */
						int bmcr, pgsr, pssr;

						bmcr = lan_get_phy_reg(osdev, MII_BMCR);
						if (bmcr & BMCR_ANENABLE) {
							pfprintf(out, "  Auto-sense");
							if (phy_status & PHY_STAT_ANC) {
								switch (phy_status & PHY_STAT_SPMASK) {
									case PHY_STAT_10HDX: pfprintf(out, " 10Mbps, Half-Duplex"); break;
									case PHY_STAT_10FDX: pfprintf(out, " 10Mbps, Full-Duplex"); break;
									case PHY_STAT_100HDX: pfprintf(out, " 100Mbps, Half-Duplex"); break;
									case PHY_STAT_100FDX: pfprintf(out, " 100Mbps, Full-Duplex"); break;
								}
							} else {
								pfprintf(out, " waiting...");
							}
						} else {
							pfprintf(out, "  Forced");
							pfprintf(out, " %sMbps, %s-Duplex",
								(bmcr & BMCR_SPEED100) ? "100" : "10",
								(bmcr & BMCR_FULLDPLX) ? "Full" : "Half");

						}
						if (phy_status & PHY_STAT_FAULT) {
							pfprintf(out, ", Remote Fault Detect!\n");
						} else {
							pfprintf(out, "\n");
						}

						pgsr = lan_get_phy_reg(osdev, MII_ADM7001_PGSR);
						pssr = lan_get_phy_reg(osdev, MII_ADM7001_PSSR);
						if (pgsr & MII_ADM7001_PGSR_XOVER) {
							pfprintf(out, "  Cable MDIX");
						} else {
							pfprintf(out, "  Cable MDI");
						}
						if (pssr & MII_ADM7001_PSSR_SPD) {
							if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0xab)
								pfprintf(out, ", length over 140m");
							else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0xa2)
								pfprintf(out, ", length over 120m");
							else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x9a)
								pfprintf(out, ", length over 100m");
							else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x94)
								pfprintf(out, ", length over 80m");
							else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x22)
								pfprintf(out, ", length over 60m");
							else if ((pgsr & MII_ADM7001_PGSR_CBLEN) > 0x1a)
								pfprintf(out, ", length over 40m");
							else pfprintf(out, ", length below 40m");
#ifdef CONFIG_DEVELOPMENT
							pfprintf(out, " (cblen=%d)\n", pgsr & MII_ADM7001_PGSR_CBLEN);
#else
							pfprintf(out, "\n");
#endif
						} else {
							pfprintf(out, "\n");
						}
#endif /* CONFIG_BERLIN_SATROUTER */
					}
					for (i=FIRST_FRAME_TYPE; i <= LAST_FRAME_TYPE; i++)
					{
						if (ipx_intf.network_set[i-FIRST_FRAME_TYPE])
						{
							pfprintf(out, "  %14s %lX%s%s, %s\n", 
								first ? "IPX address is" : "",
								ipx_intf.network[i-FIRST_FRAME_TYPE],
								mac[0] ? "." : "", 
								mac,
								ipx_encaps[i-FIRST_FRAME_TYPE]);
							first=0;
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
			pfprintf(out, "     %lu packets input, %lu bytes\n", st->rx_packets, st->rx_bytes);
			pfprintf(out, "     %lu input errors, %lu dropped, %lu overruns, %lu frame, %lu crc, %lu fifo\n", st->rx_errors, st->rx_dropped, st->rx_over_errors, st->rx_frame_errors, st->rx_crc_errors, st->rx_fifo_errors);
#ifdef CONFIG_DEVELOPMENT
			pfprintf(out, "     %lu length, %lu missed\n", st->rx_length_errors, st->rx_missed_errors);
#endif
			pfprintf(out, "     %lu packets output, %lu bytes\n", st->tx_packets, st->tx_bytes);
			pfprintf(out, "     %lu output errors, %lu collisions, %lu dropped, %lu carrier, %lu fifo\n", st->tx_errors, st->collisions, st->tx_dropped, st->tx_carrier_errors, st->tx_fifo_errors);

#ifdef CONFIG_BERLIN_SATROUTER
			switch( get_board_hw_id() )
			{
				case BOARD_HW_ID_0:
					break;
				case BOARD_HW_ID_1:
				case BOARD_HW_ID_2:
					break;
				case BOARD_HW_ID_3:
				case BOARD_HW_ID_4:
					if( linktype == ARPHRD_ETHER )
					{
						if( !strcmp(osdev, "ethernet1") )
						{
							int pdata, prt=0;
							unsigned short status;

							for(i=0; i < 4; i++)
							{
								pdata = i;
								if( eth_switch_port_get_status(osdev, &pdata) >= 0 )
								{
									status = (unsigned short) pdata;
									if( !(status & 0x8000) )
									{
										if( !prt )
										{
											pfprintf(out, "  Switch ports with link:\n");
											prt = 1;
										}
										pfprintf (out, "   %d: %s-Duplex, %sMbit\n",	i+1,
																						(status & 0x0100) ? "Full" : "Half",
																						(status & 0x2000) ? "100" : "10");
									}
								}
							}
						}
					}
					break;
			}
#endif

#ifndef CONFIG_BERLIN_SATROUTER
			if (modem_info != -1)
			{
				pfprintf(out, "     ");
				if (serial_no < MAX_WAN_INTF) /* serial[0-1] */
					pfprintf(out, "DCD=%s  ", modem_info&TIOCM_CD?"up":"down");
				pfprintf(out, "DSR=%s  DTR=%s  RTS=%s  CTS=%s\n", modem_info&TIOCM_DSR?"up":"down",	modem_info&TIOCM_DTR?"up":"down",
					modem_info&TIOCM_RTS?"up":"down", modem_info&TIOCM_CTS?"up":"down");
			}
#endif
			pfprintf(out, "\n");
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
	if (n < 0)
	{
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
				pfprintf(out, "chatscript %s %s\n", namelist[n]->d_name, buf); 
				fclose(f);
				printed_something = 1;
			}
		}
		free(namelist[n]);
	}
	free(namelist);

	if (printed_something) pfprintf(out, "!\n");
}

void dump_hostname(FILE *out)
{
	gethostname(buf, sizeof(buf)-1);
	buf[sizeof(buf)-1]=0;
	pfprintf(out, "hostname %s\n!\n", buf);
}

void dump_clock(FILE *out)
{
	int hours, mins;
	char name[16];

	if (get_timezone(name, &hours, &mins)==0)
	{
		pfprintf(out, "clock timezone %s %d", name, hours);
		if (mins > 0) pfprintf(out, " %d\n", mins);
			else pfprintf(out, "\n");
		pfprintf(out, "!\n");
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
	if (is_ntp_auth_used()) pfprintf(out, "ntp authenticate\n");
		else pfprintf(out, "no ntp authenticate\n");
#endif
#if 0 /* show ntp keys */
	if((f=fopen(FILE_NTPD_KEYS, "r")))
	{
		while(fgets(line, 200, f))
		{
			if ((p = strchr(line, '\n'))) *p = '\0';
			if (strlen(line))
			{
				args=make_args(line);
				if (args->argc >= 3) /* 1 MD5 4+?PD7j5a$0jdy7@ # MD5 key */
				{
					if (!strcmp(args->argv[1], "MD5")) {
						printed_something=1;
						pfprintf(out, "ntp authentication-key %s md5 %s\n", args->argv[0], args->argv[2]);
					}
				}
				destroy_args(args);
			}
		}
		fclose(f);
	}
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
						pfprintf(out, "ntp restrict %s %s\n", args->argv[1], args->argv[3]);
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
							pfprintf(out, "ntp trusted-key %s\n", args->argv[i]);
					}
						else pfprintf(out, "no ntp trusted-key\n");
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
					pfprintf(out, "ntp server %s", args->argv[1]);
					if (args->argc >= 5 && !strcmp(args->argv[3], "key")) pfprintf(out, " key %s\n", args->argv[4]);
						else pfprintf(out, "\n");
				}
				destroy_args(args);
			}
		}
		fclose(f);
		if (printed_something)
			pfprintf(out, "!\n");
	}

#else /* Old way! ntpclient */

	int ntp_timeout;
	char ntp_ip[16];

	if (ntp_get(&ntp_timeout, ntp_ip) < 0)
	{
		pfprintf(out, "no ntp-sync\n!\n");
	}
	else
	{
		pfprintf(out, "ntp-sync %d %s\n!\n", ntp_timeout, ntp_ip);
	}
#endif
}

#ifdef CONFIG_BERLIN_SATROUTER

void dump_secret(FILE *out)
{
	if( cish_cfg->enable_secret[0] )
		pfprintf(out, "enable secret hash %s\n", cish_cfg->enable_secret);
	else
		pfprintf(out, "no enable secret\n");
	pfprintf(out, "!\n");
}

#else

void dump_secret(FILE *out)
{
	int printed_something = 0;

	if (cish_cfg->enable_secret[0])
	{
		pfprintf(out, "secret enable hash %s\n", cish_cfg->enable_secret);
		printed_something = 1;
	}

	if (cish_cfg->login_secret[0])
	{
		pfprintf(out, "secret login hash %s\n", cish_cfg->login_secret);
		printed_something = 1;
	}

	if (printed_something) pfprintf(out, "!\n");
}

#endif

void show_routingtables(const char *cmdline)
{
	dump_routing(stdout, 0);
}

void write_config(FILE *f)
{
	pfprintf(f, "!\n");
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
	dump_ipx(f, 1);
#ifdef OPTION_X25
	dump_x25(f);
#endif
	dump_snmp(f, 1);
#ifdef OPTION_RMON
	dump_rmon(f);
#endif
	dump_bridge(f);
#ifndef CONFIG_BERLIN_SATROUTER
	dump_chatscripts(f);
#endif
	dump_policy(f);
	dump_acl(0, f, 1);
	dump_nat(0, f, 1);
	dump_mangle(0, f, 1);
#ifdef OPTION_NEW_QOS_CONFIG
	dump_qos_config(f);
#endif
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
	dump_ipx_routes(f, 1);
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
		dump_ipx(f, 1);
#ifdef OPTION_X25
		dump_x25(f);
#endif
		dump_snmp(f, 1);
#ifdef OPTION_RMON
		dump_rmon(f);
#endif
		dump_bridge(f);
#ifndef CONFIG_BERLIN_SATROUTER
		dump_chatscripts(f);
#endif
		dump_policy(f);
		dump_acl(0, f, 1);
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
		dump_ipx_routes(f, 1);
	}
	else if (command_root == CMD_CONFIG_CRYPTO) {
#ifdef OPTION_IPSEC
		dump_crypto(f);
#endif
	}
	else if ((command_root == CMD_CONFIG_INTERFACE_ETHERNET)
			|| (command_root == CMD_CONFIG_INTERFACE_ETHERNET_VLAN)
			|| (command_root == CMD_CONFIG_INTERFACE_LOOPBACK)
			|| (command_root == CMD_CONFIG_INTERFACE_SERIAL)
			|| (command_root == CMD_CONFIG_INTERFACE_SERIAL_CHDLC)
			|| (command_root == CMD_CONFIG_INTERFACE_SERIAL_SPPP)
			|| (command_root == CMD_CONFIG_INTERFACE_SERIAL_FR)
			|| (command_root == CMD_CONFIG_INTERFACE_SERIAL_SUBFR)
			|| (command_root == CMD_CONFIG_INTERFACE_SERIAL_PPP)
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

	exclude_last_line_from_file_if_excl(TMP_CFG_FILE);
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

#if 0
#ifdef CONFIG_DEVELOPMENT
void show_slot_config(const char *cmdline) /* show slotX-config */
{
	arglist *args;

	args=make_args(cmdline);
	if (load_slot_configuration(TMP_CFG_FILE, args->argv[1][4]-'0') > 0)
	{
		tf=fopen(TMP_CFG_FILE, "r");
		show_output();
		if (tf) fclose(tf);
	}
	destroy_args(args);
}
#endif
#endif

#ifdef CONFIG_BERLIN_SATROUTER
void show_modem_info(void)
{
	FILE *f;
	char line[1024];

	if( (f = fopen(MOTHERBOARD_INFO_FILE, "r")) == NULL )
		return;
	for( ; !feof(f); ) {
		if( fgets(line, 1023, f) != line )
			break;
		line[1023] = 0;
		printf("%s", line);
	}
	fclose(f);
}
#endif

void show_techsupport(const char *cmdline)
{
	printf("\n------------------ show version ------------------\n\n");
	show_version("");
#ifdef CONFIG_BERLIN_SATROUTER
	printf("\n--------------- show release-date ----------------\n\n");
	show_release_date("");
	printf("---------------- show modem info -----------------\n\n");
	show_modem_info();
#endif
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
#if 0
#ifdef CONFIG_DEVELOPMENT
			if (args->argv[1][1] == 'l') /* slotX-config */
			{
				if (load_slot_configuration(STARTUP_CFG_FILE, args->argv[1][4]-'0') == 0)
				{
					fprintf(stderr, "%% Configuration not saved\n");
					destroy_args(args);
					return;
				}
			}
			else
#endif
#endif
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
#if 0
#ifdef CONFIG_DEVELOPMENT
			if (args->argv[2][1] == 'l') /* slotX-config */
			{
				if (save_slot_configuration(in, args->argv[2][4]-'0') < 0)
				{
					fprintf(stderr, "%% Error writing configuration\n");
					destroy_args(args);
					return;
				}
			}
			else
#endif
#endif
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
	dump_acl((args->argc == 3) ? args->argv[2] : NULL, stdout, 0);
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
	arglist *args;
	pid_t pid;

	args=make_args(cmdline);
	switch (pid = fork())
	{
		case -1:
			fprintf (stderr, "%% No processes left\n");
			return;
			
		case 0:
			execv("/bin/bwmon", args->argv);
			fprintf (stderr, "%% bwmon exec error!\n");
			break;
			
		default:
			waitpid(pid, NULL, 0);
			destroy_args(args);
			break;
	}
}

#ifdef OPTION_X25XOT
void show_x25_forward(const char *cmdline)
{
	tf=fopen("/proc/net/x25/forward", "r");
	if (!tf)
	{
		printf ("%% Unable to read X.25 forward table\n");
		return;
	}
	show_output();
	if (tf) pclose(tf);
}
#endif

#ifdef OPTION_X25MAP
void show_x25_map(const char *cmdline)
{
	int fd;
	struct flock fl;

	x25_map_show(); /* kick SIGUSR1 to x25mapd */
	sleep(1);

	tf=fopen(X25MAP_DUMP, "r");
	if (!tf)
		return;
	fd = fileno(tf);
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_type = F_RDLCK;
	fcntl(fd, F_SETLKW, &fl); /* Advisory read locking! */
	show_output();
	fl.l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &fl); /* Release lock! */
	fclose(tf);
	unlink(X25MAP_DUMP);
}

void show_x25_routes(const char *cmdline)
{
#if 0
	tf=fopen("/proc/net/x25_routes", "r");
#else
	tf=fopen("/proc/net/x25/route", "r");
#endif
	if (!tf)
	{
		printf ("%% Unable to read X.25 route table\n");
		return;
	}
	show_output();
	if (tf) pclose(tf);
}

void show_x25_svc(const char *cmdline)
{
#if 0
	tf = fopen ("/proc/net/x25", "r");
#else
	tf = fopen ("/proc/net/x25/socket", "r");
#endif
	if (!tf)
	{
		printf ("%% Unable to read X.25 svc table\n");
		return;
	}
	show_output ();
	if (tf) pclose (tf);
}
#endif /* OPTION_X25 */

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
			if (!(output=popen("/lib/ipsec/whack --statusconn", "r")))
			{
				printf("%% Not possible to show ipsec connections\n");
				goto go_error;
			}
			/* 000 caca 192.168.2.0/24===10.0.0.1[@server]...10.0.0.2[@roadwarrior]===192.168.1.0/24 RSASIG+ENCRYPT+TUNNEL+PFS "erouted" */
			/* 000 caca 192.168.2.0/24===10.0.0.1[@server]---10.0.0.2...any[@roadwarrior]===192.168.1.0/24 RSASIG+ENCRYPT+TUNNEL+PFS "unrouted"  */
			while (fgets(line, 1024, output))
			{
				int flag=CONN_INCOMPLETE;

				if (strlen(line) == 0) break;
				args=make_args(line);
				if (args->argc == 5)
				{
					if (!strstr(args->argv[2], "...any")) /* skip roadwarrior master! */
					{
						for (i=0, list=list_ini; i < MAX_CONN; i++, list++)
						{
							if (*list)
							{
								if (strcmp(args->argv[1], *list) == 0)
								{
									if (strstr(args->argv[4], "erouted")) flag=CONN_UP;
										else if (strstr(args->argv[4], "unrouted")) flag=CONN_DOWN;
									if (show_conn_specific(args->argv[1], flag) < 1) goto go_error;
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

#ifdef CONFIG_BERLIN_SATROUTER
	/* Buscamos os servidores configurados */
	if( (f = fopen(FILE_NTP_CONF, "r")) ) {
		for( ; ; ) {
			fgets(buf, 255, f);
			buf[255] = 0;
			if( feof(f) )
				break;
			if( parse_args_din(buf, &argl) >= 2 ) {
				if( strcmp(argl[0], "server") == 0 ) {
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
			}
			free_args_din(&argl);
		}
		fclose(f);
	}
#else
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
#endif
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
#endif

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
	struct rmon_data *shm_rmon_p;
	char tp[10], result[MAX_OID_LEN * 10];

	if(is_daemon_running(RMON_DAEMON)) pfprintf(out, "rmon agent\n");
		else pfprintf(out, "no rmon agent\n");

	if(get_access_rmon_data(&shm_rmon_p))
	{
		for(i=0; i < NUM_EVENTS; i++)
		{
			if(shm_rmon_p->events[i].index)
			{
				pfprintf(out, "rmon event %d", shm_rmon_p->events[i].index);
				if(shm_rmon_p->events[i].do_log)	pfprintf(out, " log");
				if(shm_rmon_p->events[i].community)	pfprintf(out, " trap %s", shm_rmon_p->events[i].community);
				if(shm_rmon_p->events[i].description)	pfprintf(out, " description %s", shm_rmon_p->events[i].description);
				if(shm_rmon_p->events[i].owner)		pfprintf(out, " owner %s", shm_rmon_p->events[i].owner);
				pfprintf(out, "\n");
			}
		}
		for(i=0; i < NUM_ALARMS; i++)
		{
			if(shm_rmon_p->alarms[i].index)
			{
				result[0] = '\0';
				for(k=0; k < shm_rmon_p->alarms[i].oid_len; k++)
				{
					sprintf(tp, "%lu.", shm_rmon_p->alarms[i].oid[k]);
					strcat(result, tp);
				}
				*(result + strlen(result) - 1) = '\0';

				pfprintf(out, "rmon alarm %d %s %d", shm_rmon_p->alarms[i].index, result, shm_rmon_p->alarms[i].interval);
				switch(shm_rmon_p->alarms[i].sample_type)
				{
					case SAMPLE_ABSOLUTE:
						pfprintf(out, " absolute");
						break;
					case SAMPLE_DELTA:
						pfprintf(out, " delta");
						break;
				}
				if(shm_rmon_p->alarms[i].rising_threshold)
				{
					pfprintf(out, " rising-threshold %d", shm_rmon_p->alarms[i].rising_threshold);
					if(shm_rmon_p->alarms[i].rising_event_index)	pfprintf(out, " %d", shm_rmon_p->alarms[i].rising_event_index);
				}
				if(shm_rmon_p->alarms[i].falling_threshold)
				{
					pfprintf(out, " falling-threshold %d", shm_rmon_p->alarms[i].falling_threshold);
					if(shm_rmon_p->alarms[i].falling_event_index)	pfprintf(out, " %d", shm_rmon_p->alarms[i].falling_event_index);
				}
				if(shm_rmon_p->alarms[i].owner)	pfprintf(out, " owner %s", shm_rmon_p->alarms[i].owner);
				pfprintf(out, "\n");
			}
		}
		loose_access_rmon_data(&shm_rmon_p);
	}
	pfprintf(out, "!\n");
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

#ifdef CONFIG_IPHC
void show_iphc_stats(const char *cmdline) /* show ip header-compression serial <number> */
{
	arglist *args;
	u8 *cish_dev, dev[64];
	fr_proto_pvc_info fr_info;
	int i, type, iphc_negotiated = 0;
	u32 enabled_features, do_rx, do_tx;
	struct _iphc_compressing_stats ppp_info_tcp_stats, *all_stats = NULL;

	if( get_if_list() < 0 ) {
		printf("%% Not possible to show IP header-compression statistics\n");
		return;
	}
	args = make_args(cmdline);
	if( args->argc != 5 ) {
		printf("%% Not possible to show IP header-compression statistics\n");
		destroy_args(args);
		return;
	}
	sprintf((char *)dev, "%s%s", args->argv[3], args->argv[4]);
	cish_dev = (u8 *)convert_os_device((char *)dev, 1);
	for(i=0, type=0; i < link_table_index; i++) {
		if( strcmp((char *)link_table[i].ifname, (char *)dev) == 0 ) {
			if( link_table[i].flags & IFF_UP )
				type = link_table[i].type;
			else {
				printf("%% %s is down\n", cish_dev);
				destroy_args(args);
				return;
			}
			break;
		}
	}
	switch( type ) {
		case ARPHRD_DLCI:
			if( fr_pvc_get_iphc_stats((char *)dev, &fr_info) < 0 ) {
				printf("%% Not possible to show IP header-compression statistics for interface %s\n", cish_dev);
				destroy_args(args);
				return;
			}
			all_stats = &fr_info.iphc_stats;
			iphc_negotiated = (all_stats->st_negot == FRIHCP_ST_OPERATIONAL) ? 1 : 0;
			enabled_features = all_stats->enabled_features;
			break;

		case ARPHRD_PPP:
			if( sppp_get_iphc_stats((char *)dev, &ppp_info_tcp_stats) < 0 ) {
				printf("%% Not possible to show IP header-compression statistics for interface %s\n", cish_dev);
				destroy_args(args);
				return;
			}
			all_stats = &ppp_info_tcp_stats;
			iphc_negotiated = (all_stats->st_negot == IPHC_NEGOT_ST_OPENED) ? 1 : 0;
			enabled_features = ppp_info_tcp_stats.enabled_features;
			break;

		case ARPHRD_CISCO:
		default:
			printf("%% IP header-compression statistics not available for interface %s\n", cish_dev);
			destroy_args(args);
			return;
	}
	if( all_stats != NULL ) {
		/* Informacoes da compressao TCP */
		switch( iphc_negotiated ) {
			case 1:
				do_rx = ((enabled_features & IPHC_RX_TCP) != 0) ? 1 : 0;
				do_tx = ((enabled_features & IPHC_TX_TCP) != 0) ? 1 : 0;
				break;
			default:
				do_rx = do_tx = 0;
				break;
		}
		printf("TCP/IP header compression statistics:\n");
		switch( iphc_negotiated ) {
			case 1:
				if( do_rx != 0 ) {
					printf("  Reception:    %lu total, %lu compressed, %lu full header\n", all_stats->ctcp.rx.total_pkts, all_stats->ctcp.rx.compressed_pkts, all_stats->ctcp.rx.fullheader_pkts);
					printf("                %lu context state, %lu errors\n", all_stats->ctcp.rx.contextstate_pkts, all_stats->ctcp.rx.errors);
					printf("                %lu active context(s)\n", all_stats->ctcp.rx.active_units);
				}
				if( do_tx != 0 ) {
					printf("  Transmission: %lu total, %lu compressed, %lu full header\n", all_stats->ctcp.tx.total_pkts, all_stats->ctcp.tx.compressed_pkts, all_stats->ctcp.tx.fullheader_pkts);
					printf("                %lu context state\n", all_stats->ctcp.tx.contextstate_pkts);
					printf("                %lu bytes saved, %lu bytes sent\n", all_stats->ctcp.tx.saved_bytes, all_stats->ctcp.tx.sent_bytes);
					printf("                %s efficiency improvement factor\n", all_stats->ctcp.tx.efficiency);
					printf("                %lu active context(s)\n", all_stats->ctcp.tx.active_units);
				}
				break;
			default:
				printf(" * Not yet negotiated *\n");
				break;
		}
		printf("\n");

		/* Informacoes da compressao UDP e RTP */
		do_rx = do_tx = 0;
		if( iphc_negotiated == 1 ) {
			if( (enabled_features & IPHC_RX_UDP) || (enabled_features & IPHC_RX_RTP) )
				do_rx = 1;
			if( (enabled_features & IPHC_TX_UDP) || (enabled_features & IPHC_TX_RTP) )
				do_tx = 1;
		}
		printf("%sUDP/IP header compression statistics:\n", (all_stats->crtp.conf_mode != IPHC_MODE_OFF) ? "RTP/" : "");
		switch( iphc_negotiated ) {
			case 1:
				if( do_rx != 0 ) {
					printf("  Reception:    %lu total, %lu compressed, %lu full header\n", all_stats->cudp.rx.total_pkts+all_stats->crtp.rx.total_pkts, all_stats->cudp.rx.compressed_pkts+all_stats->crtp.rx.compressed_pkts, all_stats->cudp.rx.fullheader_pkts+all_stats->crtp.rx.fullheader_pkts);
					printf("                %lu context state, %lu errors\n", all_stats->cudp.rx.contextstate_pkts+all_stats->crtp.rx.contextstate_pkts, all_stats->cudp.rx.errors+all_stats->crtp.rx.errors);
					printf("                %lu active context(s)\n", all_stats->cudp.rx.active_units+all_stats->crtp.rx.active_units);
				}
				if( do_tx != 0 ) {
					printf("  Transmission: %lu total, %lu compressed, %lu full header\n", all_stats->cudp.tx.total_pkts+all_stats->crtp.tx.total_pkts, all_stats->cudp.tx.compressed_pkts+all_stats->crtp.tx.compressed_pkts, all_stats->cudp.tx.fullheader_pkts+all_stats->crtp.tx.fullheader_pkts);
					printf("                %lu context state\n", all_stats->cudp.tx.contextstate_pkts+all_stats->crtp.tx.contextstate_pkts);
					printf("                %lu bytes saved, %lu bytes sent\n", all_stats->cudp.tx.saved_bytes+all_stats->crtp.tx.saved_bytes, all_stats->cudp.tx.sent_bytes+all_stats->crtp.tx.sent_bytes);
					printf("                %s udp efficiency improvement factor\n", all_stats->cudp.tx.efficiency);
					printf("                %s rtp efficiency improvement factor\n", all_stats->crtp.tx.efficiency);
					printf("                %lu active context(s)\n", all_stats->cudp.tx.active_units+all_stats->crtp.tx.active_units);
				}
				break;
			default:
				printf(" * Not yet negotiated *\n");
				break;
		}
		printf("\n");
	}
	destroy_args(args);
}
#endif /* CONFIG_IPHC */

void show_fr_pvc(const char *cmdline) /* show frame-relay pvc */
{
	FILE *f = NULL;
	char buf[256];

	f = fopen ("/proc/net/fr/pvc", "r");
	if (!f) return;
	while (fgets(buf,256,f)) printf("%s", buf); 
	fclose(f);
	printf("\n");
}

