/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cish_main.h" /* buf */
#include "options.h"
#include "pprintf.h"
#include <libconfig/acl.h>
#include <libconfig/args.h>
#include <libconfig/exec.h>
#include <libconfig/device.h>
#include <libconfig/ip.h>
#include <libconfig/system.h>

extern device_family *interface_edited;
extern int interface_major, interface_minor;

//#define DEBUG_CMD(x) printf("cmd = %s\n", x)
#define DEBUG_CMD(x)

void set_ports(const char *ports, char *str)
{
	char *p;

	if (ports)
	{
		p=strchr(ports, ':');
		if (!p)
		{
			if (ports[0] == '!')
				sprintf (str, "neq %s", ports+1);
			else
				sprintf (str, "eq %s", ports);
		}
		else
		{
			int from, to;

			from=atoi(ports);
			to=atoi(p+1);
			if (from == 0)
				sprintf(str, "lt %d", to);
			else if (to == 65535)
				sprintf(str, "gt %d", from);
			else
				sprintf(str, "range %d %d", from, to);
		}
	}
}

void print_flags(FILE *out, char *flags)
{
	char flags_ascii[6][4]={"FIN","SYN","RST","PSH","ACK","URG"};
	int i, print;
	long int flag, flag_bit;

	flag=strtol(flags, NULL, 16);
	if (flag == 0x3f) pfprintf(out, "ALL");
	else
	{
		for (print=0, i=0, flag_bit=0x01; i < 6; i++, flag_bit<<=1)
			if (flag & flag_bit) { pfprintf(out, "%s%s", print?",":"", flags_ascii[i]); print=1; }
	}
}

static void print_rule(const char *action, const char *proto, const char *src,
		 const char *dst, const char *sports, const char *dports,
		 char *acl, FILE *out, int conf_format, int mc, char *flags,
		 char *tos, char *state, char *icmp_type, char *icmp_type_code, char *tcpmss, char *mac)
{
	char src_ports[32];
	char dst_ports[32];
	char *_src;
	char *_dst;
	const char *src_netmask;
	const char *dst_netmask;

	_src=strdup(src);
	_dst=strdup(dst);
	src_ports[0]=0;
	dst_ports[0]=0;
	src_netmask=extract_mask(_src);
	dst_netmask=extract_mask(_dst);
	set_ports(sports, src_ports);
	set_ports(dports, dst_ports);
	if (conf_format) pfprintf(out, "access-list ");
	if (conf_format) pfprintf(out, "%s ", acl);
		else pfprintf(out, "    ");
	if (strcmp(action, "ACCEPT") == 0) pfprintf(out, "accept ");
	else if (strcmp(action, "DROP") == 0) pfprintf(out, "drop ");
	else if (strcmp(action, "REJECT") == 0) pfprintf(out, "reject ");
	else if (strcmp(action, "LOG") == 0) pfprintf(out, "log ");
	else if (strcmp(action, "TCPMSS") == 0 && tcpmss)
	{
		if (strcmp(tcpmss, "PMTU") == 0) pfprintf(out, "tcpmss pmtu ");
			else pfprintf(out, "tcpmss %s ", tcpmss);
	}
		else pfprintf(out, "???? ");
	if (mac)
	{
		pfprintf(out, "mac %s ", mac);
		if (!conf_format) pfprintf (out, " (%i matches)", mc);
		pfprintf(out, "\n");
		return;
	}
	if (strcmp(proto, "all") == 0) pfprintf (out, "ip ");
		else pfprintf (out, "%s ", proto);
	if (icmp_type)
	{
		if (icmp_type_code) pfprintf(out, "type %s %s ", icmp_type, icmp_type_code);
			else pfprintf(out, "type %s ", icmp_type);
	}
	if (strcasecmp (src, "0.0.0.0/0") == 0) pfprintf (out, "any ");
	else if (strcmp (src_netmask, "255.255.255.255") == 0) pfprintf (out, "host %s ", _src);
	else pfprintf (out, "%s %s ", _src, ciscomask(src_netmask));
	if (*src_ports) pfprintf (out, "%s ", src_ports);
	if (strcasecmp (dst, "0.0.0.0/0") == 0) pfprintf (out, "any ");
	else if (strcmp (dst_netmask, "255.255.255.255") == 0) pfprintf (out, "host %s ", _dst);
	else pfprintf (out, "%s %s ", _dst, ciscomask(dst_netmask));
	if (*dst_ports) pfprintf (out, "%s ", dst_ports);
	if (flags)
	{
		if (strncmp(flags, "0x16/0x02", 9))
		{
			char *t;

			t=strtok(flags, "/");
			if (t != NULL)
			{
				pfprintf(out, "flags ");
				print_flags(out, t);
				pfprintf(out, "/");
				t=strtok(NULL, "/");
				print_flags(out, t);
				pfprintf(out, " ");
			}
		}
			else pfprintf(out, "flags syn ");
	}
	if (tos) pfprintf(out, "tos %d ", strtol(tos, NULL, 16));
	if (state)
	{
		if (strstr(state, "ESTABLISHED")) pfprintf(out, "established ");
		if (strstr(state, "NEW")) pfprintf(out, "new ");
		if (strstr(state, "RELATED")) pfprintf(out, "related ");
	}
	if (!conf_format) pfprintf (out, " (%i matches)", mc);
	pfprintf(out, "\n");
}

#define trimcolumn(x) tmp=strchr(x, ' '); if (tmp != NULL) *tmp=0;
void dump_acl(char *xacl, FILE *F, int conf_format)
{
	FILE *ipc;
	char *tmp;
	char acl[101];
	char *type=NULL;
	char *prot=NULL;
	char *input=NULL;
	char *output=NULL;
	char *source=NULL;
	char *dest=NULL;
	char *sports=NULL;
	char *dports=NULL;
	char *flags=NULL;
	char *tos=NULL;
	char *state=NULL;
	char *icmp_type=NULL;
	char *icmp_type_code=NULL;
	char *tcpmss=NULL;
	char *mac=NULL;
	char *mcount;
	int aclp=1;
	FILE *procfile;
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	procfile = fopen("/proc/net/ip_tables_names", "r");
	if (!procfile)
	{
		if (conf_format) pfprintf(F, "!\n"); /* ! for next: router rip */
		return;
	}
	fclose(procfile);

	acl[0]=0;

#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -L -nv");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	ipc=popen(iptline, "r");
#else
	ipc=popen("/bin/iptables -L -nv", "r");
#endif
	if (!ipc)
	{
		fprintf (stderr, "%% ACL subsystem not found\n");
		return;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% ACL subsystem not found\n");
		pclose(ipc);
		return;
	}
#endif
	while (!feof(ipc))
	{
		buf[0]=0;
		fgets(buf, 1023, ipc);
		tmp=strchr(buf, '\n');
		if (tmp) *tmp=0;

		if (strncmp (buf, "Chain ", 6) == 0)
		{
			//if ((conf_format)&&(aclp)) pfprintf(F, "!\n");
			trimcolumn(buf+6);
			strncpy(acl, buf+6, 100); acl[100]=0;
			aclp=0;
		}
		else if (strncmp (buf, " pkts", 5) != 0) /*  pkts bytes target     prot opt in     out     source               destination */
		{
			if (strlen(buf) && ((xacl==NULL) || (strcmp(xacl, acl) == 0)))
			{
				arglist	*args;
				char *p;

				p=buf; while ((*p)&&(*p==' ')) p++;
				args=make_args(p);
				if (args->argc < 9) /*     0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0          tcp flags:0x16/0x02 */
				{
					destroy_args(args);
					continue;
				}
				type=args->argv[2];
				prot=args->argv[3];
				input=args->argv[5];
				output=args->argv[6];
				source=args->argv[7];
				dest=args->argv[8];
				sports=strstr(buf, "spts:");
				if (sports)	sports += 5;
				else
				{
					sports=strstr(buf, "spt:");
					if (sports) sports += 4;
				}
				dports=strstr(buf, "dpts:");
				if (dports) dports += 5;
				else
				{
					dports=strstr(buf, "dpt:");
					if (dports) dports += 4;
				}
				if ((flags=strstr(buf, "tcp flags:"))) flags += 10;
				if ((tos=strstr(buf, "TOS match 0x"))) tos += 12;
				if ((state = strstr(buf, "state "))) state += 6;
				if ((icmp_type=strstr(buf, "icmp type ")))
				{
					icmp_type += 10;
					if ((icmp_type_code=strstr(buf, "code "))) icmp_type_code += 5;
				}
				if ((tcpmss=strstr(buf, "TCPMSS clamp to "))) tcpmss += 16;
					else if ((tcpmss=strstr(buf, "TCPMSS set "))) tcpmss += 11;
				if ((mac=strstr(buf, "MAC "))) mac += 4;
				if (flags) trimcolumn(flags);
				if (sports) trimcolumn(sports);
				if (dports) trimcolumn(dports);
				if (tos) trimcolumn(tos);
				if (state) trimcolumn(state);
				if (icmp_type) trimcolumn(icmp_type);
				if (icmp_type_code) trimcolumn(icmp_type_code);
				if (tcpmss) trimcolumn(tcpmss);
				if (mac) trimcolumn(mac);

				if ((strcmp(type, "ACCEPT") == 0) ||
					(strcmp(type, "DROP") == 0) ||
					(strcmp(type, "REJECT") == 0) ||
					(strcmp(type, "LOG") == 0) ||
					(strcmp(type, "TCPMSS") == 0))
				{
					if (strcmp(acl, "INPUT") != 0 && strcmp(acl, "OUTPUT") != 0 && strcmp(acl, "FORWARD") != 0) /* filter CHAINs */
					{
						if ((!aclp)&&(!conf_format))
						{
							pfprintf(F, "IP access list %s\n", acl);
						}
						aclp=1;
						mcount=buf;
						if (!conf_format)
						{
							while (*mcount == ' ') ++mcount;
						}
						print_rule(type,prot,source,dest,sports,dports,acl,F,conf_format,atoi(mcount),flags,tos,state,icmp_type,icmp_type_code,tcpmss,mac);
					}
				}
				else
				{
					if (!conf_format)
					{
						if (strcmp(acl, "FORWARD")) /* INTPUT || OUTPUT */
						{
							if (strcmp(input, "*") && !strstr(input, "ipsec")) pfprintf(F, "interface %s in access-list %s\n", input, type);
							if (strcmp(output, "*") && !strstr(output, "ipsec")) pfprintf(F, "interface %s out access-list %s\n", output, type);
						}
					}
				}
				destroy_args(args);
			}
		}
	}
	pclose(ipc);
}

void dump_policy(FILE *F)
{
	FILE *ipc;
	char *p;
	FILE *procfile;
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	procfile = fopen("/proc/net/ip_tables_names", "r");
	if (!procfile)
	{
		pfprintf(F, "access-policy accept\n");
		return;
	}
	fclose(procfile);

#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -L -nv");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	ipc=popen(iptline, "r");
#else
	ipc=popen("/bin/iptables -L -nv", "r");
#endif
	if (!ipc)
	{
		fprintf(stderr, "%% ACL subsystem not found\n");
		return;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% ACL subsystem not found\n");
		pclose(ipc);
		return;
	}
#endif
	while (!feof(ipc))
	{
		buf[0]=0;
		fgets(buf, 1023, ipc);
		p=strstr(buf, "policy");
		if (p)
		{
			if (strncasecmp(p+7, "accept", 6) == 0)
			{
				pfprintf(F, "access-policy accept\n");
				break;
			}
			else if (strncasecmp(p+7, "drop", 4)==0)
			{
				pfprintf(F, "access-policy drop\n");
				break;
			}
		}
	}
	pclose (ipc);
}

typedef enum {acl_accept,acl_drop,acl_reject,acl_log,acl_tcpmss} acl_action;
typedef enum {ip=0, icmp=1, tcp=6, udp=17} proto;
typedef enum {add_acl,insert_acl,remove_acl} acl_mode;
typedef enum {st_established=0x1, st_new=0x2, st_related=0x4} acl_state;
void do_accesslist(const char *cmdline)
{
	arglist *args;
	char src_address[32];
	char dst_address[32];
	char src_portrange[32];
	char dst_portrange[32];
	int src_cidr;
	int dst_cidr;
	char *acl;
	acl_action action;
	proto protocol;
	int crsr;
	char cmd[256];
	acl_mode mode;
	char *tos=NULL;
	char *icmp_type=NULL;
	char *icmp_type_code=NULL;
	char *flags=NULL;
	char *tcpmss=NULL;
	acl_state state;
	int ruleexists=0;
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif
	int i, found;
	char *p;

	src_address[0] = 0;
	dst_address[0] = 0;
	src_portrange[0] = 0;
	dst_portrange[0] = 0;

	mode=add_acl;
	args=make_args(cmdline);

	/* Algumas verificacoes basicas antes de seguir adiante */
	if( args->argc > 6 ) {
		if( strcmp(args->argv[2], "tcpmss") == 0 ) {
			for( i=7, found=0; i < args->argc; i++ ) {
				if( strcmp(args->argv[i], "flags") == 0 ) {
					if( ++i < args->argc ) {
						if( strcasecmp(args->argv[i], "syn") == 0 ) {
							found = 1;
							break;
						}
						else if( (p = strchr(args->argv[i], '/')) != NULL ) {
							if( strstr(p, "SYN") != NULL ) {
								found = 1;
								break;
							}
						}
					}
				}
			}
			if( found == 0 ) {
				fprintf(stderr, "%% Invalid command, you should also include flags argument with bit SYN in test!\n");
				destroy_args(args);
				return;
			}
		}
	}

	acl=args->argv[1];
	if (!acl_exists(acl))
	{
		sprintf(cmd, "/bin/iptables -N %s", acl);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
		system(cmd);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			fprintf (stderr, "%% Not possible to add rule\n");
			destroy_args(args);
			return;
		}
#endif
	}
	crsr=2;
	if (strcmp(args->argv[crsr], "insert") == 0)
	{
		mode = insert_acl;
		++crsr;
	}
	else if (strcmp(args->argv[crsr], "no") == 0)
	{
		mode = remove_acl;
		++crsr;
	}
	if (strcmp(args->argv[crsr], "accept") == 0) action=acl_accept;
	else if (strcmp(args->argv[crsr], "drop") == 0) action=acl_drop;
	else if (strcmp(args->argv[crsr], "reject") == 0) action=acl_reject;
	else if (strcmp(args->argv[crsr], "log") == 0) action=acl_log;
	else if (strcmp(args->argv[crsr], "tcpmss") == 0) action=acl_tcpmss;
	else
	{
		fprintf(stderr, "%% Illegal action type, use accept, drop, reject, log or tcpmss\n");
		destroy_args(args);
		return;
	}
	++crsr;
	if (action == acl_tcpmss)
	{
		if (crsr >= args->argc)
		{
			fprintf(stderr, "%% Missing tcpmss action\n");
			destroy_args(args);
			return;
		}
		tcpmss=args->argv[crsr];
		++crsr;
	}
	if (strcmp(args->argv[crsr], "tcp") == 0) protocol=tcp;
	else if (strcmp(args->argv[crsr], "udp") == 0) protocol=udp;
	else if (strcmp(args->argv[crsr], "icmp") == 0) protocol=icmp;
	else if (strcmp(args->argv[crsr], "ip") == 0) protocol=ip;
	else protocol=atoi(args->argv[crsr]);
	++crsr;
	if (protocol == icmp)
	{
		if (strcmp(args->argv[crsr], "type") == 0)
		{
			++crsr;
			if (crsr >= args->argc)
			{
				fprintf(stderr, "%% Missing icmp type\n");
				destroy_args(args);
				return;
			}
			icmp_type=args->argv[crsr];
			++crsr;
			if (strcmp(icmp_type, "destination-unreachable") == 0 || strcmp(icmp_type, "redirect") == 0
				|| strcmp(icmp_type, "time-exceeded") == 0 || strcmp(icmp_type, "parameter-problem") == 0)
			{
				if (crsr >= args->argc)
				{
					fprintf(stderr, "%% Missing icmp type code\n");
					destroy_args(args);
					return;
				}
				if (strcmp(args->argv[crsr], "any")) icmp_type_code=args->argv[crsr];
				++crsr;
			}
		}
	}
	if (strcmp(args->argv[crsr], "any") == 0)
	{
		strcpy(src_address, "0.0.0.0/0 ");
		++crsr;
	}
	else if (strcmp(args->argv[crsr], "host") == 0)
	{
		if ((crsr+1) > args->argc)
		{
			fprintf(stderr, "%% Missing ip-address\n");
			destroy_args(args);
			return;
		}
		++crsr;
		sprintf(src_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	}
	else
	{
		if ((crsr+2) > args->argc)
		{
			fprintf(stderr, "%% Missing netmask\n");
			destroy_args(args);
			return;
		}
		src_cidr=netmask2cidr (args->argv[crsr+1]);
		if (src_cidr < 0)
		{
			fprintf(stderr, "%% Invalid netmask\n");
			destroy_args(args);
			return;
		}
		sprintf(src_address, "%s/%i ", args->argv[crsr], src_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc)
	{
		fprintf(stderr, "%% Not enough arguments\n");
		destroy_args(args);
		return;
	}
	if (strcmp(args->argv[crsr], "eq") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "%s ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "neq") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "! %s ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "gt") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "%s: ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "lt") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, ":%s ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "range") == 0)
	{
		if ((crsr+2) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr+1]) > atoi(args->argv[crsr+2]))
		{
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) || !is_valid_port(args->argv[crsr+2]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "%s:%s ", args->argv[crsr+1], args->argv[crsr+2]);
		crsr += 3;
	}
	else
	{
		src_portrange[0]=0;
	}
	if (strcmp(args->argv[crsr], "any") == 0)
	{
		strcpy(dst_address, "0.0.0.0/0 ");
		++crsr;
	}
	else if (strcmp(args->argv[crsr], "host") == 0)
	{
		++crsr;
		sprintf(dst_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	}
	else
	{
		if ((crsr+2) > args->argc)
		{
			fprintf(stderr, "%% Missing netmask\n");
			destroy_args(args);
			return;
		}
		dst_cidr=netmask2cidr(args->argv[crsr+1]);
		if (dst_cidr<0)
		{
			fprintf (stderr, "%% Invalid netmask\n");
			destroy_args (args);
			return;
		}
		sprintf(dst_address, "%s/%i ", args->argv[crsr], dst_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc)
	{
		dst_portrange[0]=0;
	}
	else if (strcmp(args->argv[crsr], "eq") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "%s ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "neq") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "! %s ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "gt") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "%s: ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "lt") == 0)
	{
		if ((crsr+1) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf (dst_portrange, ":%s ", args->argv[crsr+1]);
		crsr += 2;
	}
	else if (strcmp(args->argv[crsr], "range") == 0)
	{
		if ((crsr+2) >= args->argc)
		{
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr+1]) > atoi(args->argv[crsr+2]))
		{
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			destroy_args(args);
			return;
		}
		if( !is_valid_port(args->argv[crsr+1]) || !is_valid_port(args->argv[crsr+2]) )
		{
			fprintf(stderr, "%% Ivalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "%s:%s ", args->argv[crsr+1], args->argv[crsr+2]);
		crsr += 3;
	}
	else
	{
		dst_portrange[0]=0;
	}
	state=0;
	while (crsr < args->argc)
	{
		if (strcmp(args->argv[crsr], "established") == 0)
			state |= st_established;
		else if (strcmp(args->argv[crsr], "new") == 0)
			state |= st_new;
		else if (strcmp(args->argv[crsr], "related") == 0)
			state |= st_related;
		else if (strcmp(args->argv[crsr], "tos") == 0)
		{
			crsr++;
			if (crsr >= args->argc)
			{
				fprintf(stderr, "%% Not enough arguments\n");
				destroy_args(args);
				return;
			}
			tos=args->argv[crsr];
		}
		else if (strcmp(args->argv[crsr], "flags") == 0)
		{
			crsr++;
			if (crsr >= args->argc)
			{
				fprintf(stderr, "%% Not enough arguments\n");
				destroy_args(args);
				return;
			}
			flags=args->argv[crsr];
		}
		crsr++;
	};

	/* Se a acao for TCPMSS, entao somos obrigados a ter na linha de comando o argumento 'flags' */
	if( action == acl_tcpmss )
	{
		if( !flags )
		{
			fprintf(stderr, "%% For use 'tcpmss' you must define 'flags'\n");
			destroy_args(args);
			return;
		}
	}

	sprintf(cmd, "/bin/iptables ");
	switch(mode)
	{
		case insert_acl: strcat (cmd, "-I "); break;
		case remove_acl: strcat (cmd, "-D "); break;
		default: strcat (cmd, "-A "); break;
	}
	strcat(cmd, acl);
	strcat(cmd, " ");
	switch (protocol)
	{
		case tcp: strcat(cmd, "-p tcp "); break;
		case udp: strcat(cmd, "-p udp "); break;
		case icmp:
			strcat(cmd, "-p icmp ");
			if (icmp_type)
			{
				if (icmp_type_code) sprintf(cmd+strlen(cmd), "--icmp-type %s ", icmp_type_code);
					else sprintf(cmd+strlen(cmd), "--icmp-type %s ", icmp_type);
			}
			break;
		default:
			sprintf(cmd+strlen(cmd), "-p %d ", protocol);
			break;
	}
	if (strcmp(src_address, "0.0.0.0/0"))
	{
		sprintf(cmd+strlen(cmd), "-s %s ", src_address);
	}
	if (strlen(src_portrange))
	{
		sprintf(cmd+strlen(cmd), "--sport %s ", src_portrange);
	}
	if (strcmp(dst_address, "0.0.0.0/0"))
	{
		sprintf(cmd+strlen(cmd), "-d %s ", dst_address);
	}
	if (strlen(dst_portrange))
	{
		sprintf(cmd+strlen(cmd), "--dport %s ", dst_portrange);
	}
	if (flags)
	{
		if (strcmp(flags, "syn") == 0) strcat(cmd, "--syn ");
		else
		{
			char *tmp;

			tmp=strchr(flags, '/'); if (tmp != NULL) *tmp=' ';
			sprintf(cmd+strlen(cmd), "--tcp-flags %s ", flags);
		}
	}
	if (tos)
	{
		sprintf(cmd+strlen(cmd), "-m tos --tos %s ", tos);
	}
	if (state)
	{
		int comma=0;
		strcat(cmd, "-m state --state ");
		if (state & st_established) { strcat(cmd, "ESTABLISHED"); comma=1; }
		if (state & st_new)
		{
			if (comma) strcat(cmd, ",");
				else comma=1;
			strcat(cmd, "NEW");
		}
		if (state & st_related)
		{
			if (comma) strcat(cmd, ",");
			strcat(cmd, "RELATED");
		}
		strcat(cmd, " ");
	}
	switch (action)
	{
		case acl_accept: strcat(cmd, "-j ACCEPT"); break;
		case acl_drop:   strcat(cmd, "-j DROP");   break;
		case acl_reject: strcat(cmd, "-j REJECT"); break;
		case acl_log:    strcat(cmd, "-j LOG");    break;
		case acl_tcpmss:
			strcat(cmd, "-j TCPMSS ");
			if (strcmp(tcpmss, "pmtu") == 0) strcat(cmd, "--clamp-mss-to-pmtu");
				else sprintf(cmd+strlen(cmd), "--set-mss %s", tcpmss);
			break;
	}

	/* Verificamos se a regra existe no sistema */
	{
		FILE *f;
		arg_list argl=NULL;
		int k, l, n, insert=0;
		unsigned char buf[512];
		
		if(!strcmp(args->argv[2], "insert"))	insert = 1;
		if((f = fopen(TMP_CFG_FILE, "w+")))
		{
			dump_acl(0, f, 1);
			fseek(f, 0, SEEK_SET);
			while(fgets((char *)buf, 511, f))
			{
				if((n = parse_args_din((char *)buf, &argl)) > 3)
				{
					if(n == (args->argc - insert))
					{
						if(!strcmp(args->argv[0], "access-list"))
						{
							for(k=0, l=0, ruleexists=1; k < args->argc; k++, l++)
							{
								if(k==2 && insert)
								{
									l--;
									continue;
								}
								if(strcmp(args->argv[k], argl[l]))
								{
									ruleexists = 0;
									break;
								}
							}
							if(ruleexists)
							{
								free_args_din(&argl);
								break;
							}
						}
					}
				}
				free_args_din(&argl);
			}
			fclose(f);
		}
	}
	if(ruleexists)
		printf("%% Rule already exists\n");
	else
	{
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
		DEBUG_CMD(cmd);
		system(cmd);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			fprintf (stderr, "%% Not possible to add rule\n");
			destroy_args(args);
			return;
		}
#endif
	}
	destroy_args(args);
}

void do_accesslist_mac(const char *cmdline)
{
	int crsr;
	arglist *args;
	acl_mode mode;
	acl_action action;
	char *acl, cmd[256];
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	mode = add_acl;
	args = make_args(cmdline);
	acl = args->argv[1];
	if(!acl_exists(acl))
	{
		sprintf(cmd, "/bin/iptables -N %s", acl);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
		system(cmd);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			fprintf (stderr, "%% Not possible to add rule\n");
			destroy_args(args);
			return;
		}
#endif
	}
	crsr=2;
	if(!strcmp(args->argv[crsr], "insert"))
	{
		mode = insert_acl;
		++crsr;
	}
	else if(!strcmp(args->argv[crsr], "no"))
	{
		mode = remove_acl;
		++crsr;
	}
	if(!strcmp(args->argv[crsr], "accept"))		action = acl_accept;
	else if(!strcmp(args->argv[crsr], "drop"))	action = acl_drop;
	else if(!strcmp(args->argv[crsr], "reject"))	action = acl_reject;
	else if(!strcmp(args->argv[crsr], "log"))	action = acl_log;
	else
	{
		fprintf(stderr, "%% Illegal action type, use accept, drop, reject, log or tcpmss\n");
		destroy_args(args);
		return;
	}
	crsr += 2;
	sprintf(cmd, "/bin/iptables ");
	switch(mode)
	{
		case insert_acl:
			strcat(cmd, "-I ");
			break;
		case remove_acl:
			strcat(cmd, "-D ");
			break;
		default:
			strcat(cmd, "-A ");
			break;
	}
	strcat(cmd, acl);
	strcat(cmd, " -m mac --mac-source ");
	strcat(cmd, args->argv[crsr]);
	switch(action)
	{
		case acl_accept:
			strcat(cmd, " -j ACCEPT");
			break;
		case acl_drop:
			strcat(cmd, " -j DROP");
			break;
		case acl_reject:
			strcat(cmd, " -j REJECT");
			break;
		case acl_log:
			strcat(cmd, " -j LOG");
			break;
		case acl_tcpmss:
			break;
	}
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	DEBUG_CMD(cmd);
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% Not possible to add rule\n");
		destroy_args(args);
		return;
	}
#endif
	destroy_args(args);
}

void do_accesslist_policy (const char *cmdline)
{
	arglist *args;
	char	*target;
	char	cmd[256];
	FILE *procfile;
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	procfile = fopen("/proc/net/ip_tables_names", "r");

	args = make_args (cmdline);
	if (strcmp(args->argv[1], "accept")==0) {
		target = "ACCEPT";
		if (!procfile) goto bailout; /* doesnt need to load modules! */
	} else {
		if (strcmp(args->argv[1], "drop")==0) {
			target = "DROP";
		} else target = "REJECT";
	}
	if (procfile) fclose(procfile);

	sprintf(cmd, "/bin/iptables -P INPUT %s", target);
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	DEBUG_CMD(cmd);
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% Not possible to set policy\n");
		destroy_args(args);
		return;
	}
#endif

	sprintf(cmd, "/bin/iptables -P OUTPUT %s", target);
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	DEBUG_CMD(cmd);
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% Not possible to set policy\n");
		destroy_args(args);
		return;
	}
#endif

	sprintf(cmd, "/bin/iptables -P FORWARD %s", target);
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	DEBUG_CMD(cmd);
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% Not possible to set policy\n");
		destroy_args(args);
		return;
	}
#endif

bailout:
	destroy_args(args);
}

void no_accesslist(const char *cmdline)
{
	arglist *args;
	char *acl;
	char cmd[256];
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	args=make_args (cmdline);
	acl=args->argv[2];
	if (!acl_exists(acl))
	{
		destroy_args (args);
		return;
	}
	if (get_acl_refcount(acl))
	{
		printf("%% Access-list in use, can't delete\n");
		destroy_args (args);
		return;
	}
	sprintf(cmd, "/bin/iptables -F %s", acl); /* flush */
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		printf ("%% Not possible to remove\n");
		destroy_args(args);
		return;
	}
#endif

	sprintf(cmd, "/bin/iptables -X %s", acl); /* delete */
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		printf ("%% Not possible to remove\n");
		destroy_args(args);
		return;
	}
#endif
	destroy_args (args);
}

void interface_acl(const char *cmdline) /* ip access-group <acl> <in|out> */
{
	arglist *args;
	char *dev;
	acl_chain chain=chain_in;
	char *listno;
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	listno=args->argv[2];
	if (strcasecmp (args->argv[3], "in") == 0) chain=chain_in;
		else if (strcasecmp (args->argv[3], "out") == 0) chain=chain_out;
	if (!acl_exists(listno))
	{
		printf("%% access-list %s undefined\n", listno);
		free(dev);
		destroy_args(args);
		return;
	}
	if ((chain == chain_in) && (matched_acl_exists(0, dev, 0, "INPUT")
		|| matched_acl_exists(0, dev, 0, "FORWARD")))
	{
		printf ("%% inbound access-list already defined.\n");
		free(dev);
		destroy_args(args);
		return;
	}
	if ((chain == chain_out) && (matched_acl_exists(0, 0, dev, "OUTPUT")
		|| matched_acl_exists(0, 0, dev, "FORWARD")))
	{
		printf ("%% outbound access-list already defined.\n");
		free(dev);
		destroy_args(args);
		return;
	}
	if (chain == chain_in)
	{
		sprintf(buf, "/bin/iptables -A INPUT -i %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
		DEBUG_CMD(buf);
		system(buf);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			fprintf (stderr, "%% Not possible to apply\n");
			free(dev);
			destroy_args(args);
			return;
		}
#endif

		sprintf(buf, "/bin/iptables -A FORWARD -i %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
		DEBUG_CMD(buf);
		system(buf);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			fprintf (stderr, "%% Not possible to apply\n");
			free(dev);
			destroy_args(args);
			return;
		}
#endif
	}
	else
	{
		sprintf(buf, "/bin/iptables -A OUTPUT -o %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
		DEBUG_CMD(buf);
		system(buf);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			fprintf (stderr, "%% Not possible to apply\n");
			free(dev);
			destroy_args(args);
			return;
		}
#endif

		sprintf(buf, "/bin/iptables -A FORWARD -o %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
		DEBUG_CMD(buf);
		system(buf);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			fprintf (stderr, "%% Not possible to apply\n");
			free(dev);
			destroy_args(args);
			return;
		}
#endif
	}
	#ifdef OPTION_IPSEC 
	interface_ipsec_acl(1, chain, dev, listno);
	#endif
	destroy_args(args);
	free(dev);
}

void interface_no_acl(const char *cmdline) /* no ip access-group <acl> [in|out] */
{
	arglist *args;
	char *dev;
	acl_chain chain=chain_in;
	char *listno;
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	listno=args->argv[3];
	if (args->argc == 4) chain=chain_both;
	else
	{
		if (strcasecmp(args->argv[4], "in") == 0) chain=chain_in;
			else if (strcasecmp(args->argv[4], "out") == 0) chain=chain_out;
	}
	if ((chain == chain_in) || (chain == chain_both))
	{
		if (matched_acl_exists(listno, dev, 0, "INPUT"))
		{
			sprintf(buf, "/bin/iptables -D INPUT -i %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
			connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
			DEBUG_CMD(buf);
			system(buf);
#ifdef CHECK_IPTABLES_EXEC
			if( !is_iptables_exec_valid(randomfile) )
			{
				fprintf (stderr, "%% Not possible to remove\n");
				free(dev);
				destroy_args(args);
				return;
			}
#endif
		}
		if (matched_acl_exists(listno, dev, 0, "FORWARD"))
		{
			sprintf(buf, "/bin/iptables -D FORWARD -i %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
			connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
			DEBUG_CMD(buf);
			system(buf);
#ifdef CHECK_IPTABLES_EXEC
			if( !is_iptables_exec_valid(randomfile) )
			{
				fprintf (stderr, "%% Not possible to remove\n");
				free(dev);
				destroy_args(args);
				return;
			}
#endif
		}
	}
	if ((chain == chain_out) || (chain == chain_both))
	{
		if (matched_acl_exists(listno, 0, dev, "OUTPUT"))
		{
			sprintf(buf, "/bin/iptables -D OUTPUT -o %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
			connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
			DEBUG_CMD(buf);
			system(buf);
#ifdef CHECK_IPTABLES_EXEC
			if( !is_iptables_exec_valid(randomfile) )
			{
				fprintf (stderr, "%% Not possible to remove\n");
				free(dev);
				destroy_args(args);
				return;
			}
#endif
		}
		if (matched_acl_exists(listno, 0, dev, "FORWARD"))
		{
			sprintf(buf, "/bin/iptables -D FORWARD -o %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
			connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
			DEBUG_CMD(buf);
			system(buf);
#ifdef CHECK_IPTABLES_EXEC
			if( !is_iptables_exec_valid(randomfile) )
			{
				fprintf (stderr, "%% Not possible to remove\n");
				free(dev);
				destroy_args(args);
				return;
			}
#endif
		}
	}
	#ifdef OPTION_IPSEC 
	interface_ipsec_acl(0, chain, dev, listno);
	#endif
	destroy_args(args);
	free(dev);
}

