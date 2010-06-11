#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"
#include "cish_main.h"

//#define DEBUG_CMD(x) printf("cmd = %s\n", cmd)
#define DEBUG_CMD(x)

/* Verifica se o valor estah dentro do intervalo 0-255 */
static unsigned int is_valid_protocolnumber(char *data)
{
	char *p;

	if (!data)
		return 0;
	for (p = data; *p; p++) {
		if (isdigit(*p) == 0)
			return 0;
	}
	if (atoi(data) < 0 || atoi(data) > 255)
		return 0;
	return 1;
}

typedef enum {
	snat, dnat
} act;

typedef enum {
	add_nat, insert_nat, remove_nat
} nat_mode;

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
	acl_proto protocol;
	act action;
	int crsr;
	char cmd[256];
	char *nat_rule;
	int masquerade = 0;
	nat_mode mode;
	int ruleexists = 0;

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
	if (!nat_rule_exists(nat_rule)) {
		sprintf(cmd, "/bin/iptables -t nat -N %s", nat_rule);

		DEBUG_CMD(cmd);
		system(cmd);
	}

	crsr = 2;
	if (strcmp(args->argv[crsr], "insert") == 0) {
		mode = insert_nat;
		++crsr;
	} else if (strcmp(args->argv[crsr], "no") == 0) {
		mode = remove_nat;
		++crsr;
	}
	if (strcmp(args->argv[crsr], "tcp") == 0)
		protocol = tcp;
	else if (strcmp(args->argv[crsr], "udp") == 0)
		protocol = udp;
	else if (strcmp(args->argv[crsr], "icmp") == 0)
		protocol = icmp;
	else if (strcmp(args->argv[crsr], "ip") == 0)
		protocol = ip;
	else {
		if (!is_valid_protocolnumber(args->argv[crsr])) {
			fprintf(stderr, "%% Invalid protocol number\n");
			destroy_args(args);
			return;
		}
		protocol = atoi(args->argv[crsr]);
	}
	++crsr;
	if (strcmp(args->argv[crsr], "any") == 0) {
		strcpy(src_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp(args->argv[crsr], "host") == 0) {
		if ((crsr + 1) > args->argc) {
			fprintf(stderr, "%% Missing ip-address\n");
			destroy_args(args);
			return;
		}
		++crsr;
		sprintf(src_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf(stderr, "%% Missing netmask\n");
			destroy_args(args);
			return;
		}

		src_cidr = netmask2cidr(args->argv[crsr + 1]);
		if (src_cidr < 0) {
			fprintf(stderr, "%% Invalid netmask\n");
			destroy_args(args);
			return;
		}

		sprintf(src_address, "%s/%i ", args->argv[crsr], src_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc) {
		fprintf(stderr, "%% Not enough arguments\n");
		destroy_args(args);
		return;
	}
	if (strcmp(args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr + 1]) > atoi(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1]) || !is_valid_port(
		                args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(src_portrange, "%s:%s ", args->argv[crsr + 1],
		                args->argv[crsr + 2]);
		crsr += 3;
	} else {
		src_portrange[0] = 0;
	}
	if (strcmp(args->argv[crsr], "any") == 0) {
		strcpy(dst_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp(args->argv[crsr], "host") == 0) {
		++crsr;
		sprintf(dst_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf(stderr, "%% Missing netmask\n");
			destroy_args(args);
			return;
		}

		dst_cidr = netmask2cidr(args->argv[crsr + 1]);
		if (dst_cidr < 0) {
			fprintf(stderr, "%% Invalid netmask\n");
			destroy_args(args);
			return;
		}

		sprintf(dst_address, "%s/%i ", args->argv[crsr], dst_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc) {
		dst_portrange[0] = 0;
	} else if (strcmp(args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr + 1]) > atoi(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1]) || !is_valid_port(
		                args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid argument\n");
			destroy_args(args);
			return;
		}
		sprintf(dst_portrange, "%s:%s ", args->argv[crsr + 1],
		                args->argv[crsr + 2]);
		crsr += 3;
	} else {
		dst_portrange[0] = 0;
	}

	if (strcmp(args->argv[crsr], "change-source-to") == 0) {
		action = snat;
	} else if (strcmp(args->argv[crsr], "change-destination-to") == 0) {
		action = dnat;
	} else {
		fprintf(stderr, "%% Invalid action\n");
		destroy_args(args);
		return;
	}
	crsr++;

	if (strcmp(args->argv[crsr], "pool") == 0) {
		strcpy(nat_addr1, args->argv[++crsr]);
		strcpy(nat_addr2, args->argv[++crsr]);
	} else if (strcmp(args->argv[crsr], "interface-address") == 0) {
		masquerade = 1;
	} else {
		strcpy(nat_addr1, args->argv[crsr]);
		nat_addr2[0] = 0;
	}
	crsr++;

	if (crsr >= args->argc) {
		nat_port1[0] = 0;
		nat_port2[0] = 0;
	} else if (strcmp(args->argv[crsr], "port") == 0) {
		crsr++;
		if (strcmp(args->argv[crsr], "range") == 0) {
			strcpy(nat_port1, args->argv[++crsr]);
			strcpy(nat_port2, args->argv[++crsr]);

			if (atoi(nat_port1) > atoi(nat_port2)) {
				fprintf(stderr,
				                "%% Invalid port range (min > max)\n");
				destroy_args(args);
				return;
			}
		} else {
			strcpy(nat_port1, args->argv[crsr]);
			nat_port2[0] = 0;
		}
	}

	sprintf(cmd, "/bin/iptables -t nat ");
	switch (mode) {
	case insert_nat:
		strcat(cmd, "-I ");
		break;
	case remove_nat:
		strcat(cmd, "-D ");
		break;
	default:
		strcat(cmd, "-A ");
		break;
	}
	strcat(cmd, nat_rule);
	strcat(cmd, " ");

	switch (protocol) {
	case tcp:
		strcat(cmd, "-p tcp ");
		break;
	case udp:
		strcat(cmd, "-p udp ");
		break;
	case icmp:
		strcat(cmd, "-p icmp ");
		break;
	default:
		sprintf(cmd + strlen(cmd), "-p %d ", protocol);
	}
	if (strcmp(src_address, "0.0.0.0/0")) {
		sprintf(cmd + strlen(cmd), "-s %s", src_address);
	}
	if (strlen(src_portrange)) {
		sprintf(cmd + strlen(cmd), "--sport %s ", src_portrange);
	}
	if (strcmp(dst_address, "0.0.0.0/0")) {
		sprintf(cmd + strlen(cmd), "-d %s", dst_address);
	}
	if (strlen(dst_portrange)) {
		sprintf(cmd + strlen(cmd), "--dport %s ", dst_portrange);
	}

	if (masquerade) {
		if (action != snat) {
			fprintf(stderr,
			                "%% Change to interface-address is valid only with source NAT\n");
			destroy_args(args);
			return;
		}
		strcat(cmd, "-j MASQUERADE ");
		if (nat_port1[0])
			sprintf(cmd + strlen(cmd), "--to-ports %s", nat_port1);
		if (nat_port2[0])
			sprintf(cmd + strlen(cmd), "-%s", nat_port2);
	} else {
		sprintf(cmd + strlen(cmd), "-j %cNAT --to %s",
		                (action == snat) ? 'S' : 'D', nat_addr1);
		if (nat_addr2[0])
			sprintf(cmd + strlen(cmd), "-%s", nat_addr2);
		if (nat_port1[0])
			sprintf(cmd + strlen(cmd), ":%s", nat_port1);
		if (nat_port2[0])
			sprintf(cmd + strlen(cmd), "-%s", nat_port2);
	}

	/* Verificamos se a regra existe no sistema */
	{
		FILE *f;
		arg_list argl = NULL;
		int k, l, n, insert = 0;
		unsigned char buf[512];

		if (!strcmp(args->argv[2], "insert"))
			insert = 1;
		if ((f = fopen(TMP_CFG_FILE, "w+"))) {
			lconfig_nat_dump(0, f, 1);
			fseek(f, 0, SEEK_SET);
			while (fgets((char *) buf, 511, f)) {
				if ((n = parse_args_din((char *) buf, &argl))
				                > 3) {
					if (n == (args->argc - insert)) {
						if (!strcmp(args->argv[0],
						                "nat-rule")) {
							for (k = 0, l = 0, ruleexists
							                = 1; k
							                < args->argc; k++, l++) {
								if (k == 2
								                && insert) {
									l--;
									continue;
								}
								if (strcmp(
								                args->argv[k],
								                argl[l])) {
									ruleexists
									                = 0;
									break;
								}
							}
							if (ruleexists) {
								free_args_din(
								                &argl);
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
	else {
		DEBUG_CMD(cmd);
		system(cmd);
	}
	destroy_args(args);
}

void no_nat_rule(const char *cmdline) /* no nat-rule <acl> */
{
	arglist *args;
	char *nat_rule;
	char cmd[256];

	args = make_args(cmdline);
	nat_rule = args->argv[2];
	if (!nat_rule_exists(nat_rule)) {
		destroy_args(args);
		return;
	}
	if (get_nat_rule_refcount(nat_rule)) {
		printf("%% NAT rule in use, can't delete\n");
		destroy_args(args);
		return;
	}
	sprintf(cmd, "/bin/iptables -t nat -F %s", nat_rule); /* flush */

	DEBUG_CMD(cmd);
	system(cmd);

	sprintf(cmd, "/bin/iptables -t nat -X %s", nat_rule); /* delete */

	DEBUG_CMD(cmd);
	system(cmd);

	destroy_args(args);
}

int nat_rule_exists(char *nat_rule)
{
	FILE *F;
	char *tmp, buf[256];
	int nat_rule_exists = 0;

	F = popen("/bin/iptables -t nat -L -n", "r");

	if (!F) {
		fprintf(stderr, "%% NAT subsystem not found\n");
		return 0;
	}

	while (!feof(F)) {
		buf[0] = 0;
		fgets(buf, 255, F);
		buf[255] = 0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0) {
			tmp = strchr(buf + 6, ' ');
			if (tmp) {
				*tmp = 0;
				if (strcmp(buf + 6, nat_rule) == 0) {
					nat_rule_exists = 1;
					break;
				}
			}
		}
	}
	pclose(F);
	return nat_rule_exists;
}

int matched_nat_rule_exists(char *acl,
                            char *iface_in,
                            char *iface_out,
                            char *chain)
{
	FILE *F;
	char *tmp, buf[256];
	int acl_exists = 0;
	int in_chain = 0;
	char *iface_in_, *iface_out_, *target;

	F = popen("/bin/iptables -t nat -L -nv", "r");

	if (!F) {
		fprintf(stderr, "%% NAT subsystem not found\n");
		return 0;
	}

	while (!feof(F)) {
		buf[0] = 0;
		fgets(buf, 255, F);
		buf[255] = 0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0) {
			if (in_chain)
				break; // chegou `a proxima chain sem encontrar - finaliza
			tmp = strchr(buf + 6, ' ');
			if (tmp) {
				*tmp = 0;
				if (strcmp(buf + 6, chain) == 0)
					in_chain = 1;
			}
		} else if ((in_chain) && (strncmp(buf, " pkts", 5) != 0)
		                && (strlen(buf) > 40)) {
			arglist *args;
			char *p;
			p = buf;
			while ((*p) && (*p == ' '))
				p++;
			args = make_args(p);

			if (args->argc < 7) {
				destroy_args(args);
				continue;
			}

			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];

			if (((iface_in == NULL) || (strcmp(iface_in_, iface_in)
			                == 0))
			                && ((iface_out == NULL) || (strcmp(
			                                iface_out_, iface_out)
			                                == 0))
			                && ((acl == NULL) || (strcmp(target,
			                                acl) == 0))) {
				acl_exists = 1;
				destroy_args(args);
				break;
			}

			destroy_args(args);
		}
	}
	pclose(F);
	return acl_exists;
}

int get_nat_rule_refcount(char *nat_rule)
{
	FILE *F;
	char *tmp;
	char buf[256];

	F = popen("/bin/iptables -t nat -L -n", "r");

	if (!F) {
		fprintf(stderr, "%% NAT subsystem not found\n");
		return 0;
	}

	while (!feof(F)) {
		buf[0] = 0;
		fgets(buf, 255, F);
		buf[255] = 0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0) {
			tmp = strchr(buf + 6, ' ');
			if (tmp) {
				*tmp = 0;
				if (strcmp(buf + 6, nat_rule) == 0) {
					tmp = strchr(tmp + 1, '(');
					if (!tmp)
						return 0;
					tmp++;
					return atoi(tmp);
				}
			}
		}
	}
	pclose(F);
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

	procfile = fopen("/proc/net/ip_tables_names", "r");
	if (!procfile)
		return 0;
	fclose(procfile);

	F = popen("/bin/iptables -t nat -L -nv", "r");

	if (!F) {
		fprintf(stderr, "%% NAT subsystem not found\n");
		return 0;
	}

	while (!feof(F)) {
		buf[0] = 0;
		fgets(buf, 255, F);
		buf[255] = 0;
		striplf(buf);
		if (strncmp(buf, "Chain ", 6) == 0) {
			p = strchr(buf + 6, ' ');
			if (p) {
				*p = 0;
				strncpy(chain, buf + 6, 16);
				chain[15] = 0;
			}
		} else if ((strncmp(buf, " pkts", 5) != 0)
		                && (strlen(buf) > 40)) {
			arglist *args;

			p = buf;
			while ((*p) && (*p == ' '))
				p++;
			args = make_args(p);
			if (args->argc < 7) {
				destroy_args(args);
				continue;
			}
			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];
			if (strncmp(iface, iface_in_, strlen(iface)) == 0) {
				sprintf(
				                cmd,
				                "/bin/iptables -t nat -D %s -i %s -j %s",
				                chain, iface_in_, target);

				sprintf(
				                cmd,
				                "/bin/iptables -t nat -D %s -i %s -j %s",
				                chain, iface_in_, target);
				DEBUG_CMD(cmd);
				system(cmd);
			}
			if (strncmp(iface, iface_out_, strlen(iface)) == 0) {
				sprintf(
				                cmd,
				                "/bin/iptables -t nat -D %s -o %s -j %s",
				                chain, iface_out_, target);

				DEBUG_CMD(cmd);
				system(cmd);
			}
			destroy_args(args);
		}
	}
	pclose(F);
	return 0;
}

void interface_nat(const char *cmdline) /* ip nat <acl> <in|out> */
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *listno;

	dev = convert_device(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = make_args(cmdline);
	listno = args->argv[2];
	if (strcasecmp(args->argv[3], "in") == 0)
		chain = chain_in;
	else if (strcasecmp(args->argv[3], "out") == 0)
		chain = chain_out;

	if (!nat_rule_exists(listno)) {
		printf("%% nat-rule %s undefined\n", listno);
		free(dev);
		destroy_args(args);
		return;
	}

	if ((chain == chain_in) && (matched_nat_rule_exists(0, dev, 0,
	                "PREROUTING"))) {
		printf("%% inbound NAT rule already defined.\n");
		free(dev);
		destroy_args(args);
		return;
	}

	if ((chain == chain_out) && (matched_nat_rule_exists(0, 0, dev,
	                "POSTROUTING"))) {
		printf("%% outbound NAT rule already defined.\n");
		free(dev);
		destroy_args(args);
		return;
	}

	if (!nat_rule_exists(listno)) {
		sprintf(buf, "/bin/iptables -t nat -N %s", listno);

		system(buf);
	}

	if (chain == chain_in) {
		sprintf(buf, "/bin/iptables -t nat -A PREROUTING -i %s -j %s",
		                dev, listno);

		DEBUG_CMD(buf);
		system(buf);
	} else {
		sprintf(buf, "/bin/iptables -t nat -A POSTROUTING -o %s -j %s",
		                dev, listno);
		DEBUG_CMD(buf);
		system(buf);
	}

	destroy_args(args);
	free(dev);
}

void interface_no_nat(const char *cmdline) /* no ip nat <acl> [in|out] */
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *listno;

	dev = convert_device(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = make_args(cmdline);
	listno = args->argv[3];

	if (args->argc == 4)
		chain = chain_both;
	else {
		if (strcasecmp(args->argv[4], "in") == 0)
			chain = chain_in;
		else if (strcasecmp(args->argv[4], "out") == 0)
			chain = chain_out;
	}

	if ((chain == chain_in) || (chain == chain_both)) {
		if (matched_nat_rule_exists(listno, dev, 0, "PREROUTING")) {
			sprintf(
			                buf,
			                "/bin/iptables -t nat -D PREROUTING -i %s -j %s",
			                dev, listno);
			DEBUG_CMD(buf);
			system(buf);
		}
	}

	if ((chain == chain_out) || (chain == chain_both)) {
		if (matched_nat_rule_exists(listno, 0, dev, "POSTROUTING")) {
			sprintf(
			                buf,
			                "/bin/iptables -t nat -D POSTROUTING -o %s -j %s",
			                dev, listno);
			DEBUG_CMD(buf);
			system(buf);
		}
	}
	destroy_args(args);
	free(dev);
}
