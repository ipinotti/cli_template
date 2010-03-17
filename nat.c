#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <libconfig/args.h>
#include <libconfig/exec.h>
#include <libconfig/device.h>
#include <libconfig/ip.h>
#include <libconfig/str.h>
#include <libconfig/system.h>

#include "options.h"
#include "commands.h"
#include "pprintf.h"
#include "nat.h"
#include "acl.h"
#include "cish_main.h"

extern device_family *interface_edited;
extern int interface_major, interface_minor;

//#define DEBUG_CMD(x) printf("cmd = %s\n", cmd)
#define DEBUG_CMD(x)

void print_nat_rule(const char *action, const char *proto, const char *src, 
		 const char *dst, const char *sports, const char *dports,
		 char *acl, FILE *out, int conf_format, int mc, char *to, 
		 char *masq_ports)
{
	char src_ports[32];
	char dst_ports[32];
	char *nat_addr1=NULL;
	char *nat_addr2=NULL;
	char *nat_port1=NULL;
	char *nat_port2=NULL;
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
	if (conf_format) pfprintf (out, "nat-rule ");
	if (conf_format) pfprintf (out, "%s ", acl);
		else pfprintf (out, "    ");
	if (strcmp (proto, "all") == 0) pfprintf (out, "ip ");
		else pfprintf (out, "%s ", proto);
	if (strcasecmp (src, "0.0.0.0/0") == 0) pfprintf (out, "any ");
		else if (strcmp (src_netmask, "255.255.255.255") == 0) pfprintf (out, "host %s ", _src);
			else pfprintf (out, "%s %s ", _src, ciscomask(src_netmask));
	if (*src_ports) pfprintf (out, "%s ", src_ports);
	if (strcasecmp (dst, "0.0.0.0/0") == 0) pfprintf (out, "any ");
		else if (strcmp (dst_netmask, "255.255.255.255") == 0) pfprintf (out, "host %s ", _dst);
			else pfprintf (out, "%s %s ", _dst, ciscomask(dst_netmask));
	if (*dst_ports) pfprintf (out, "%s ", dst_ports);
	if (to)
	{
		char *p;

		nat_addr1 = to;
		p = strchr(to, ':');
		if (p)
		{
			*p = 0;
			nat_port1 = p+1;
			p = strchr(nat_port1, '-');
			if (p)
			{
				*p = 0;
				nat_port2 = p+1;
			}
		}
		p = strchr(to, '-');
		if (p)
		{
			*p = 0;
			nat_addr2 = p+1;
		}
	}
	if (masq_ports)
	{
		char *p;
		
		nat_port1 = masq_ports;
		
		p = strchr(masq_ports, '-');
		if (p)
		{
			*p = 0;
			nat_port2 = p+1;
		}
	}
	if (strcasecmp (action, "dnat") == 0)
		pfprintf (out, "change-destination-to ");
	else if (strcasecmp (action, "snat") == 0)
		pfprintf (out, "change-source-to ");
	else if (strcasecmp (action, "masquerade") == 0)
		pfprintf (out, "change-source-to interface-address ");
	if (nat_addr1)
	{	
		if (nat_addr2)
			pfprintf (out, "pool %s %s ", nat_addr1, nat_addr2);
		else
			pfprintf (out, "%s ", nat_addr1);
	}
	if (nat_port1)
	{
		if (nat_port2)
			pfprintf (out, "port range %s %s ", nat_port1, nat_port2);
		else
			pfprintf (out, "port %s ", nat_port1);
	}
	if (!conf_format) pfprintf (out, " (%i matches)", mc);
	pfprintf (out, "\n");
}

#define trimcolumn(x) tmp=strchr(x, ' '); if (tmp != NULL) *tmp=0;
void dump_nat(char *xacl, FILE *F, int conf_format)
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
	char *to=NULL;
	char *masq_ports=NULL;
	char *mcount;
	int aclp=1;
	FILE *procfile;
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	procfile = fopen("/proc/net/ip_tables_names", "r");
	if (!procfile) return;
	fclose(procfile);

	acl[0]=0;
#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -t nat -L -nv");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	ipc=popen(iptline, "r");
#else
	ipc=popen("/bin/iptables -t nat -L -nv", "r");
#endif
	if (!ipc)
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		return;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
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

		if (strncmp(buf, "Chain ", 6) == 0)
		{
			//if (conf_format && aclp) pfprintf(F, "!\n");
			trimcolumn(buf+6);
			strncpy(acl, buf+6, 100); acl[100]=0;
			aclp=0;
		}
		else if (strncmp(buf, " pkts", 5) != 0)
		{
			if ((strlen(buf)) && ((xacl == NULL) || (strcmp(xacl,acl) == 0)))
			{
				arglist	*args;
				char *p;

				p=buf; while ((*p)&&(*p==' ')) p++;
				args=make_args(p);
				if (args->argc < 9)
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
					if (sports)	sports += 4;
				}
				dports=strstr(buf, "dpts:");
				if (dports) dports += 5;
				else
				{
					dports=strstr(buf, "dpt:");
					if (dports)	dports += 4;
				}
				to=strstr(buf, "to:");
				if (to)	to += 3;
				masq_ports=strstr(buf, "masq ports: ");
				if (masq_ports) masq_ports += 12;

				if (sports) trimcolumn(sports);
				if (dports) trimcolumn(dports);
				if (to) trimcolumn(to);
				if (masq_ports) trimcolumn(masq_ports);

				if ((strcmp(type, "MASQUERADE") == 0) ||
					(strcmp(type, "DNAT") == 0) ||
					(strcmp(type, "SNAT") == 0))
				{
					if (strcmp(acl, "INPUT") != 0 && strcmp(acl, "PREROUTING") != 0 && strcmp(acl, "OUTPUT") != 0 && strcmp(acl, "POSTROUTING") != 0) /* filter CHAINs */
					{
						if ((!aclp) && (!conf_format))
						{
							pfprintf (F, "NAT rule %s\n", acl);
						}
						aclp=1;
						mcount=buf;
						if (!conf_format)
						{
							while (*mcount == ' ') ++mcount;
						}
						print_nat_rule(type,prot,source,dest,sports,dports,acl,F,conf_format,atoi(mcount),to,masq_ports);
					}
				}
				else
				{
					if (!conf_format)
					{
						if (strstr(acl, "ROUTING")) /* PRE|POST ROUTING */
						{
							if (strcmp(input, "*")) pfprintf(F, "interface %s in nat-rule %s\n", input, type);
							if (strcmp(output, "*")) pfprintf(F, "interface %s out nat-rule %s\n", output, type);
						}
					}
				}
				destroy_args(args);
			}
		}
	}
	pclose (ipc);
}

/* Verifica se o valor estah dentro do intervalo 0-255 */
static unsigned int is_valid_protocolnumber(char *data)
{
	char *p;

	if( !data )
		return 0;
	for( p=data; *p; p++ )
	{
		if( isdigit(*p) == 0 )
			return 0;
	}
	if( atoi(data)<0 || atoi(data)>255 )
		return 0;
	return 1;
}

typedef enum {ip=0, icmp=1, tcp=6, udp=17} proto;
typedef enum {snat, dnat} act;
typedef enum {add_nat,insert_nat,remove_nat} nat_mode;

void do_nat_rule(const char *cmdline) /* nat-rule <acl> ... */
{
	arglist *args;
	char src_address[32];
	char dst_address[32];
	char src_portrange[32];
	char dst_portrange[32];
	char nat_addr1[32];
	char nat_addr2[32];
	char nat_port1[32];
	char nat_port2[32];
	int src_cidr;
	int dst_cidr;
	proto protocol;
	act action;
	int crsr;
	char cmd[256];
	char *nat_rule;
	int masquerade=0;
	nat_mode mode;
	int ruleexists=0;
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	/* !!! Inicializar arrays antes de usa-los eh uma boa pratica !!! */
	src_portrange[0] = 0;
	dst_portrange[0] = 0;
	nat_addr1[0] = 0;
	nat_addr2[0] = 0;
	nat_port1[0] = 0;
	nat_port2[0] = 0;

	mode = add_nat;
	args = make_args(cmdline);
	nat_rule = args->argv[1];
	if (!nat_rule_exists(nat_rule))
	{
		sprintf(cmd, "/bin/iptables -t nat -N %s", nat_rule);
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

	crsr = 2;
	if (strcmp(args->argv[crsr], "insert") == 0)
	{
		mode = insert_nat;
		++crsr;
	}
	else if (strcmp(args->argv[crsr], "no") == 0)
	{
		mode = remove_nat;
		++crsr;
	}
	if (strcmp(args->argv[crsr], "tcp") == 0) protocol = tcp;
	else if (strcmp(args->argv[crsr], "udp") == 0) protocol = udp;
	else if (strcmp(args->argv[crsr], "icmp") == 0) protocol = icmp;
	else if (strcmp(args->argv[crsr], "ip") == 0) protocol = ip;
	else
	{
		if( !is_valid_protocolnumber(args->argv[crsr]) )
		{
			fprintf(stderr, "%% Invalid protocol number\n");
			destroy_args(args);
			return;
		}
		protocol=atoi(args->argv[crsr]);
	}
	++crsr;
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

		src_cidr = netmask2cidr(args->argv[crsr+1]);
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
			fprintf(stderr, "%% Invalid argument\n");
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
			fprintf(stderr, "%% Invalid argument\n");
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
			fprintf(stderr, "%% Invalid argument\n");
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
			fprintf(stderr, "%% Invalid argument\n");
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
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "%s:%s ", args->argv[crsr+1], args->argv[crsr+2]);
		crsr += 3;
	}
	else
	{
		src_portrange[0] = 0;
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

		dst_cidr = netmask2cidr (args->argv[crsr+1]);
		if (dst_cidr < 0)
		{
			fprintf(stderr, "%% Invalid netmask\n");
			destroy_args(args);
			return;
		}

		sprintf (dst_address, "%s/%i ", args->argv[crsr], dst_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc)
	{
		dst_portrange[0] = 0;
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
			fprintf(stderr, "%% Invalid argument\n");
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
			fprintf(stderr, "%% Invalid argument\n");
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
			fprintf(stderr, "%% Invalid argument\n");
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
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, ":%s ", args->argv[crsr+1]);
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
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "%s:%s ", args->argv[crsr+1], args->argv[crsr+2]);
		crsr += 3;
	}
	else
	{
		dst_portrange[0] = 0;
	}

	if (strcmp(args->argv[crsr], "change-source-to") == 0)
	{
		action = snat;
	}
	else if (strcmp(args->argv[crsr], "change-destination-to") == 0)
	{
		action = dnat;
	}
	else
	{
		fprintf(stderr, "%% Invalid action\n");
		destroy_args(args);
		return;
	}
	crsr++;
	
	if (strcmp(args->argv[crsr], "pool") == 0)
	{
		strcpy(nat_addr1, args->argv[++crsr]);
		strcpy(nat_addr2, args->argv[++crsr]);
	}
	else if (strcmp(args->argv[crsr], "interface-address") == 0)
	{
		masquerade = 1;
	}
	else
	{
		strcpy(nat_addr1, args->argv[crsr]);
		nat_addr2[0]=0;
	}
	crsr++;

	if (crsr >= args->argc)
	{
		nat_port1[0] = 0;
		nat_port2[0] = 0;
	}
	else if (strcmp(args->argv[crsr], "port") == 0)
	{
		crsr++;
		if (strcmp(args->argv[crsr], "range") == 0)
		{
			strcpy(nat_port1, args->argv[++crsr]);
			strcpy(nat_port2, args->argv[++crsr]);

			if (atoi(nat_port1) > atoi(nat_port2))
			{
				fprintf(stderr, "%% Invalid port range (min > max)\n");
				destroy_args(args);
				return;
			}
		}
		else
		{
			strcpy(nat_port1, args->argv[crsr]);
			nat_port2[0]=0;
		}
	}

	sprintf (cmd, "/bin/iptables -t nat ");
	switch (mode)
	{
		case insert_nat: strcat (cmd, "-I "); break;
		case remove_nat: strcat (cmd, "-D "); break;
		default: strcat (cmd, "-A "); break;
	}
	strcat(cmd, nat_rule);
	strcat(cmd, " ");

	switch (protocol)
	{
		case tcp: strcat(cmd, "-p tcp "); break;
		case udp: strcat(cmd, "-p udp "); break;
		case icmp: strcat(cmd, "-p icmp "); break;
		default: sprintf(cmd+strlen(cmd), "-p %d ", protocol);
	}
	if (strcmp(src_address, "0.0.0.0/0"))
	{
		sprintf(cmd+strlen(cmd), "-s %s", src_address);
	}
	if (strlen(src_portrange))
	{
		sprintf(cmd+strlen(cmd), "--sport %s ", src_portrange);
	}
	if (strcmp(dst_address, "0.0.0.0/0"))
	{
		sprintf(cmd+strlen(cmd), "-d %s", dst_address);
	}
	if (strlen(dst_portrange))
	{
		sprintf(cmd+strlen(cmd), "--dport %s ", dst_portrange);
	}

	if (masquerade)
	{
		if (action != snat)
		{
			fprintf(stderr, "%% Change to interface-address is valid only with source NAT\n");
			destroy_args(args);
			return;
		}
		strcat(cmd, "-j MASQUERADE ");
		if (nat_port1[0])
			sprintf(cmd+strlen(cmd), "--to-ports %s", nat_port1);
		if (nat_port2[0])
			sprintf(cmd+strlen(cmd), "-%s", nat_port2);
	}
	else
	{
		sprintf(cmd+strlen(cmd), "-j %cNAT --to %s", (action==snat) ? 'S' : 'D', nat_addr1);
		if (nat_addr2[0])
			sprintf(cmd+strlen(cmd), "-%s", nat_addr2);
		if (nat_port1[0])
			sprintf(cmd+strlen(cmd), ":%s", nat_port1);
		if (nat_port2[0])
			sprintf(cmd+strlen(cmd), "-%s", nat_port2);
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
			dump_nat(0, f, 1);
			fseek(f, 0, SEEK_SET);
			while(fgets((char *)buf, 511, f))
			{
				if((n = parse_args_din((char *)buf, &argl)) > 3)
				{
					if(n == (args->argc - insert))
					{
						if(!strcmp(args->argv[0], "nat-rule"))
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
	if (ruleexists)
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
	destroy_args (args);
}

void no_nat_rule(const char *cmdline) /* no nat-rule <acl> */
{
	arglist		*args;
	char		*nat_rule;
	char		 cmd[256];
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	args=make_args(cmdline);
	nat_rule=args->argv[2];
	if (!nat_rule_exists(nat_rule))
	{
		destroy_args (args);
		return;
	}
	if (get_nat_rule_refcount(nat_rule))
	{
		printf("%% NAT rule in use, can't delete\n");
		destroy_args (args);
		return;
	}
	sprintf(cmd, "/bin/iptables -t nat -F %s", nat_rule); /* flush */
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	DEBUG_CMD(cmd);
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% Not possible to remove\n");
		destroy_args(args);
		return;
	}
#endif

	sprintf(cmd, "/bin/iptables -t nat -X %s", nat_rule); /* delete */
#ifdef CHECK_IPTABLES_EXEC
	connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
	DEBUG_CMD(cmd);
	system(cmd);
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% Not possible to remove\n");
		destroy_args(args);
		return;
	}
#endif
	destroy_args(args);
}

int nat_rule_exists(char *nat_rule)
{
	FILE *F;
	char *tmp, buf[256];
	int nat_rule_exists=0;
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -t nat -L -n");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	F=popen(iptline, "r");
#else
	F=popen("/bin/iptables -t nat -L -n", "r");
#endif
	if (!F)
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		return 0;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		pclose(F);
		return 0;
	}
#endif
	while (!feof(F))
	{
		buf[0]=0;
		fgets(buf, 255, F);
		buf[255]=0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0)
		{
			tmp=strchr(buf+6, ' ');
			if (tmp) {
				*tmp=0;
				if (strcmp(buf+6, nat_rule) == 0) {
					nat_rule_exists=1;
					break;
				}
			}
		}
	}
	pclose(F);
	return nat_rule_exists;
}

int matched_nat_rule_exists(char *acl, char *iface_in, char *iface_out, char *chain)
{
	FILE *F;
	char *tmp, buf[256];
	int acl_exists = 0;
	int in_chain = 0;
	char *iface_in_, *iface_out_, *target;
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -t nat -L -nv");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	F=popen(iptline, "r");
#else
	F = popen ("/bin/iptables -t nat -L -nv", "r");
#endif
	if (!F)
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		return 0;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		pclose(F);
		return 0;
	}
#endif
	while (!feof (F))
	{
		buf[0]=0;
		fgets(buf, 255, F);
		buf[255]=0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0)
		{
			if (in_chain)
				break; // chegou `a proxima chain sem encontrar - finaliza
			tmp=strchr(buf+6, ' ');
			if (tmp) {
				*tmp=0;
				if (strcmp(buf+6, chain) == 0)
					in_chain=1;
			}
		}
		else if ((in_chain)&&(strncmp(buf, " pkts", 5)!=0)&&(strlen(buf)>40))
		{
			arglist *args;
			char *p;
			p = buf; while ((*p)&&(*p==' ')) p++;
			args = make_args (p);

			if (args->argc<7)
			{
				destroy_args(args);
				continue;
			}

			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];

			if ( ( (iface_in==NULL) ||(strcmp(iface_in_,  iface_in )==0) ) &&
			     ( (iface_out==NULL)||(strcmp(iface_out_, iface_out)==0) ) &&
			     ( (acl==NULL)      ||(strcmp(target,     acl      )==0) ) )
			{
				acl_exists = 1;
				destroy_args (args);
				break;
			}
			
			destroy_args (args);
		}
	}
	pclose (F);
	return acl_exists;
}

int get_iface_nat_rules(char *iface, char *in_acl, char *out_acl)
{
	typedef enum {chain_in, chain_out, chain_other} acl_chain;
	FILE *F;
	char buf[256];
	acl_chain chain=chain_other;
	char *iface_in_, *iface_out_, *target;
	char *acl_in = NULL, *acl_out = NULL;
	FILE *procfile;
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	procfile = fopen("/proc/net/ip_tables_names", "r");
	if (!procfile) return 0;
	fclose(procfile);

#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -t nat -L -nv");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	F=popen(iptline, "r");
#else
	F = popen ("/bin/iptables -t nat -L -nv", "r");
#endif
	if (!F)
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		return 0;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		pclose(F);
		return 0;
	}
#endif
	while (!feof (F))
	{
		buf[0] = 0;
		fgets (buf, 255, F);
		buf[255] = 0;
		striplf (buf);
		if (strncmp (buf, "Chain ", 6) == 0)
		{
			if (strncmp (buf+6, "PREROUTING", 10) == 0) chain = chain_in;
			else if (strncmp (buf+6, "POSTROUTING", 11) == 0) chain = chain_out;
			else chain = chain_other;
		}
		else if ((strncmp(buf, " pkts", 5)!=0)&&(strlen(buf)>40))
		{
			arglist	*args;
			char *p;
			p = buf; while ((*p)&&(*p==' ')) p++;
			args = make_args (p);

			if (args->argc<7)
			{
				destroy_args(args);
				continue;
			}

			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];
			
			if ((chain==chain_in)&&(strcmp(iface, iface_in_ )==0))
			{
				acl_in = target;
				strncpy(in_acl, acl_in, 100); in_acl[100] = 0;
			}
			
			if ((chain==chain_out)&&(strcmp(iface, iface_out_ )==0))
			{
				acl_out = target;
				strncpy(out_acl, acl_out, 100); out_acl[100] = 0;
			}
			if (acl_in&&acl_out) break;

			destroy_args (args);
		}
	}
	pclose (F);
	return 0;
}

int get_nat_rule_refcount(char *nat_rule)
{
	FILE *F;
	char *tmp;
	char buf[256];
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -t nat -L -n");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	F=popen(iptline, "r");
#else
	F=popen("/bin/iptables -t nat -L -n", "r");
#endif
	if (!F)
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		return 0;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		pclose(F);
		return 0;
	}
#endif
	while (!feof(F))
	{
		buf[0]=0;
		fgets(buf, 255, F);
		buf[255]=0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0)
		{
			tmp=strchr(buf+6, ' ');
			if (tmp) {
				*tmp=0;
				if (strcmp(buf+6, nat_rule) == 0) {
					tmp=strchr(tmp+1, '(');
					if (!tmp)
						return 0;
					tmp++;
					return atoi(tmp);
				}
			}
		}
	}
	pclose (F);
	return 0;
}

int clean_iface_nat_rules(char *iface)
{
	FILE *F;
	char buf[256];
	char cmd[256];
	char chain[16];
	char *p, *iface_in_, *iface_out_, *target;
	FILE *procfile;
#ifdef CHECK_IPTABLES_EXEC
	char iptline[256], randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	procfile = fopen("/proc/net/ip_tables_names", "r");
	if (!procfile) return 0;
	fclose(procfile);

#ifdef CHECK_IPTABLES_EXEC
	/* Temporary file for errors */
	strcpy(iptline, "/bin/iptables -t nat -L -nv");
	connect_error_file(iptline, randomfile); /* Temporary file for errors */
	F=popen(iptline, "r");
#else
	F=popen("/bin/iptables -t nat -L -nv", "r");
#endif
	if (!F)
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		return 0;
	}
#ifdef CHECK_IPTABLES_EXEC
	if( !is_iptables_exec_valid(randomfile) )
	{
		fprintf (stderr, "%% NAT subsystem not found\n");
		pclose(F);
		return 0;
	}
#endif
	while (!feof(F))
	{
		buf[0]=0;
		fgets(buf, 255, F);
		buf[255]=0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0)
		{
			p=strchr(buf+6, ' ');
			if (p)
			{
				*p=0;
				strncpy(chain, buf+6, 16);
				chain[15]=0;
			}
		}
		else if ((strncmp(buf, " pkts", 5) != 0)&&(strlen(buf) > 40))
		{
			arglist	*args;

			p=buf; while ((*p)&&(*p==' ')) p++;
			args=make_args(p);
			if (args->argc < 7)
			{
				destroy_args(args);
				continue;
			}
			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];
			if (strncmp(iface, iface_in_, strlen(iface)) == 0)
			{
				sprintf(cmd, "/bin/iptables -t nat -D %s -i %s -j %s", chain, iface_in_, target);
#ifdef CHECK_IPTABLES_EXEC
				connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
				sprintf(cmd, "/bin/iptables -t nat -D %s -i %s -j %s", chain, iface_in_, target);
				DEBUG_CMD(cmd);
				system(cmd);
#ifdef CHECK_IPTABLES_EXEC
				if( !is_iptables_exec_valid(randomfile) )
				{
					fprintf (stderr, "%% Not possible to remove\n");
					destroy_args(args);
					pclose(F);
					return 0;
				}
#endif
			}
			if (strncmp(iface, iface_out_, strlen(iface)) == 0)
			{
				sprintf(cmd, "/bin/iptables -t nat -D %s -o %s -j %s", chain, iface_out_, target);
#ifdef CHECK_IPTABLES_EXEC
				connect_error_file(cmd, randomfile); /* Temporary file for errors */
#endif
				DEBUG_CMD(cmd);
				system(cmd);
#ifdef CHECK_IPTABLES_EXEC
				if( !is_iptables_exec_valid(randomfile) )
				{
					fprintf (stderr, "%% Not possible to remove\n");
					destroy_args(args);
					pclose(F);
					return 0;
				}
#endif
			}
			destroy_args(args);
		}
	}
	pclose(F);
	return 0;
}

typedef enum {chain_in, chain_out, chain_both} acl_chain;
void interface_nat(const char *cmdline) /* ip nat <acl> <in|out> */
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
	if (strcasecmp(args->argv[3], "in") == 0) chain=chain_in;
	else if (strcasecmp (args->argv[3], "out") == 0) chain=chain_out;

	if (!nat_rule_exists(listno))
	{
		printf("%% nat-rule %s undefined\n", listno);
		free(dev);
		destroy_args(args);
		return;
	}

	if ((chain == chain_in)&&(matched_nat_rule_exists(0, dev, 0, "PREROUTING")))
	{
		printf("%% inbound NAT rule already defined.\n");
		free(dev);
		destroy_args(args);
		return;
	}

	if ((chain == chain_out)&&(matched_nat_rule_exists(0, 0, dev, "POSTROUTING")))
	{
		printf("%% outbound NAT rule already defined.\n");
		free(dev);
		destroy_args(args);
		return;
	}

	if (!nat_rule_exists(listno))
	{
		sprintf(buf, "/bin/iptables -t nat -N %s", listno);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
		system(buf);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			printf ("%% Not possible to execute action\n");
			destroy_args(args);
			free(dev);
			return;
		}
#endif
	}

	if (chain == chain_in)
	{
		sprintf(buf, "/bin/iptables -t nat -A PREROUTING -i %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
		DEBUG_CMD(buf);
		system(buf);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			printf ("%% Not possible to execute action\n");
			destroy_args(args);
			free(dev);
			return;
		}
#endif
	}
	else
	{
		sprintf(buf, "/bin/iptables -t nat -A POSTROUTING -o %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
		connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
		DEBUG_CMD(buf);
		system(buf);
#ifdef CHECK_IPTABLES_EXEC
		if( !is_iptables_exec_valid(randomfile) )
		{
			printf ("%% Not possible to execute action\n");
			destroy_args(args);
			free(dev);
			return;
		}
#endif
	}

	destroy_args(args);
	free(dev);
}

void interface_no_nat(const char *cmdline) /* no ip nat <acl> [in|out] */
{
	arglist		*args;
	char		*dev;
	acl_chain	 chain=chain_in;
	char		*listno;
#ifdef CHECK_IPTABLES_EXEC
	char randomfile[FILE_TMP_IPT_ERRORS_LEN];
#endif

	dev = convert_device (interface_edited->cish_string, interface_major, interface_minor);
	args = make_args (cmdline);
	listno = args->argv[3];

	if (args->argc==4) chain = chain_both;
	else
	{
		if (strcasecmp (args->argv[4], "in") == 0) chain = chain_in;
		else if (strcasecmp (args->argv[4], "out") == 0) chain = chain_out;
	}

	if ((chain==chain_in)||(chain==chain_both))
	{
		if (matched_nat_rule_exists(listno, dev, 0, "PREROUTING"))
		{
			sprintf(buf, "/bin/iptables -t nat -D PREROUTING -i %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
			connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
			DEBUG_CMD(buf);
			system(buf);
#ifdef CHECK_IPTABLES_EXEC
			if( !is_iptables_exec_valid(randomfile) )
			{
				printf ("%% Not possible to remove\n");
				destroy_args(args);
				free(dev);
				return;
			}
#endif
		}
	}
	
	if ((chain==chain_out)||(chain==chain_both))
	{
		if (matched_nat_rule_exists(listno, 0, dev, "POSTROUTING"))
		{
			sprintf(buf, "/bin/iptables -t nat -D POSTROUTING -o %s -j %s", dev, listno);
#ifdef CHECK_IPTABLES_EXEC
			connect_error_file(buf, randomfile); /* Temporary file for errors */
#endif
			DEBUG_CMD(buf);
			system(buf);
#ifdef CHECK_IPTABLES_EXEC
			if( !is_iptables_exec_valid(randomfile) )
			{
				printf ("%% Not possible to remove\n");
				destroy_args(args);
				free(dev);
				return;
			}
#endif
		}
	}
	destroy_args (args);
	free(dev);
}
