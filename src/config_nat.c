#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"
#include "cish_main.h"

#ifdef OPTION_NAT
/**
 * is_valid_protocolnumber	Check if network protocol number is valid
 *
 * @param data
 * @return 1 if valid, 0 otherwise
 */
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

/**
 * do_nat_rule		Apply nat-rule command
 *
 * @param cmdline
 */
void do_nat_rule(const char *cmdline)
{
	arglist *args;
	struct nat_config n;
	int crsr = 1, src_cidr, dst_cidr;

	memset(&n, 0, sizeof(n));

	args = librouter_make_args(cmdline);

	/* Rule Name */
	n.name = args->argv[crsr];
	++crsr;

	/* Mode */
	if (strcmp(args->argv[crsr], "insert") == 0) {
		n.mode = insert_nat;
		++crsr;
	} else if (strcmp(args->argv[crsr], "no") == 0) {
		n.mode = remove_nat;
		++crsr;
	} else
		n.mode = add_nat;

	/* Protocol */
	if (strcmp(args->argv[crsr], "tcp") == 0)
		n.protocol = proto_tcp;
	else if (strcmp(args->argv[crsr], "udp") == 0)
		n.protocol = proto_udp;
	else if (strcmp(args->argv[crsr], "icmp") == 0)
		n.protocol = proto_icmp;
	else if (strcmp(args->argv[crsr], "ip") == 0)
		n.protocol = proto_ip;
	else {
		if (!is_valid_protocolnumber(args->argv[crsr])) {
			fprintf(stderr, "%% Invalid protocol number\n");
			librouter_destroy_args(args);
			return;
		}
		n.protocol = atoi(args->argv[crsr]);
	}
	++crsr;

	/* Source */
	if (strcmp(args->argv[crsr], "any") == 0) {
		strcpy(n.src_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp(args->argv[crsr], "host") == 0) {
		if ((crsr + 1) > args->argc) {
			fprintf(stderr, "%% Missing ip-address\n");
			librouter_destroy_args(args);
			return;
		}
		++crsr;
		sprintf(n.src_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf(stderr, "%% Missing netmask\n");
			librouter_destroy_args(args);
			return;
		}

		src_cidr = librouter_ip_netmask2cidr(args->argv[crsr + 1]);
		if (src_cidr < 0) {
			fprintf(stderr, "%% Invalid netmask\n");
			librouter_destroy_args(args);
			return;
		}

		sprintf(n.src_address, "%s/%i ", args->argv[crsr], src_cidr);
		crsr += 2;
	}

	/* Source port */
	if (crsr >= args->argc) {
		fprintf(stderr, "%% Not enough arguments\n");
		librouter_destroy_args(args);
		return;
	}
	if (strcmp(args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.src_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.src_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.src_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.src_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr + 1]) > atoi(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])
		                || !librouter_ip_is_valid_port(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.src_portrange, "%s:%s ", args->argv[crsr + 1], args->argv[crsr + 2]);
		crsr += 3;
	}

	/* Destination */
	if (strcmp(args->argv[crsr], "any") == 0) {
		strcpy(n.dst_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp(args->argv[crsr], "host") == 0) {
		++crsr;
		sprintf(n.dst_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf(stderr, "%% Missing netmask\n");
			librouter_destroy_args(args);
			return;
		}

		dst_cidr = librouter_ip_netmask2cidr(args->argv[crsr + 1]);
		if (dst_cidr < 0) {
			fprintf(stderr, "%% Invalid netmask\n");
			librouter_destroy_args(args);
			return;
		}

		sprintf(n.dst_address, "%s/%i ", args->argv[crsr], dst_cidr);
		crsr += 2;
	}

	/* Destination Port */
	if (crsr >= args->argc) {
		n.dst_portrange[0] = 0;
	} else if (strcmp(args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.dst_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.dst_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.dst_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.dst_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			librouter_destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr + 1]) > atoi(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			librouter_destroy_args(args);
			return;
		}
		if (!librouter_ip_is_valid_port(args->argv[crsr + 1])
		                || !librouter_ip_is_valid_port(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid argument\n");
			librouter_destroy_args(args);
			return;
		}
		sprintf(n.dst_portrange, "%s:%s ", args->argv[crsr + 1], args->argv[crsr + 2]);
		crsr += 3;
	}

	/* Action */
	if (strcmp(args->argv[crsr], "change-source-to") == 0) {
		n.action = snat;
	} else if (strcmp(args->argv[crsr], "change-destination-to") == 0) {
		n.action = dnat;
	} else {
		fprintf(stderr, "%% Invalid action\n");
		librouter_destroy_args(args);
		return;
	}
	crsr++;

	if (strcmp(args->argv[crsr], "pool") == 0) {
		strcpy(n.nat_addr1, args->argv[++crsr]);
		strcpy(n.nat_addr2, args->argv[++crsr]);
	} else if (strcmp(args->argv[crsr], "interface-address") == 0)
		n.masquerade = 1;
	else
		strcpy(n.nat_addr1, args->argv[crsr]);
	crsr++;
	if ((args->argc > crsr) && (strcmp(args->argv[crsr], "port") == 0)) {
		crsr++;
		if (strcmp(args->argv[crsr], "range") == 0) {
			strcpy(n.nat_port1, args->argv[++crsr]);
			strcpy(n.nat_port2, args->argv[++crsr]);

			if (atoi(n.nat_port1) > atoi(n.nat_port2)) {
				fprintf(stderr, "%% Invalid port range (min > max)\n");
				librouter_destroy_args(args);
				return;
			}
		} else
			strcpy(n.nat_port1, args->argv[crsr]);
	}

	librouter_nat_apply_rule(&n);
	librouter_destroy_args(args);
}

void no_nat_rule(const char *cmdline) /* no nat-rule <acl> */
{
	arglist *args;
	char *nat_rule;


	args = librouter_make_args(cmdline);
	nat_rule = args->argv[2];
	if (!librouter_nat_rule_exists(nat_rule)) {
		librouter_destroy_args(args);
		return;
	}
	if (librouter_nat_rule_refcount(nat_rule)) {
		printf("%% NAT rule in use, can't delete\n");
		librouter_destroy_args(args);
		return;
	}

	librouter_nat_delete_rule(nat_rule);

	librouter_destroy_args(args);
}

void interface_nat(const char *cmdline) /* ip nat <acl> <in|out> */
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *rulename;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	rulename = args->argv[2];

	if (strcasecmp(args->argv[3], "in") == 0)
		chain = chain_in;
	else if (strcasecmp(args->argv[3], "out") == 0)
		chain = chain_out;

	if (!librouter_nat_rule_exists(rulename)) {
		printf("%% nat-rule %s undefined\n", rulename);
		free(dev);
		librouter_destroy_args(args);
		return;
	}

	if ((chain == chain_in) && (librouter_nat_check_interface_rule(0, dev, 0, "PREROUTING"))) {
		printf("%% inbound NAT rule already defined.\n");
		free(dev);
		librouter_destroy_args(args);
		return;
	} else if ((chain == chain_out) && (librouter_nat_check_interface_rule(0, 0, dev, "POSTROUTING"))) {
		printf("%% outbound NAT rule already defined.\n");
		free(dev);
		librouter_destroy_args(args);
		return;
	}

	librouter_nat_bind_interface_to_rule(dev, rulename, chain);

	librouter_destroy_args(args);
	free(dev);
}

void interface_no_nat(const char *cmdline) /* no ip nat <acl> [in|out] */
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *rulename;

	dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = librouter_make_args(cmdline);
	rulename = args->argv[3];

	if (args->argc == 4)
		chain = chain_both;
	else {
		if (strcasecmp(args->argv[4], "in") == 0)
			chain = chain_in;
		else if (strcasecmp(args->argv[4], "out") == 0)
			chain = chain_out;
	}

	if ((chain == chain_in) || (chain == chain_both)) {
		if (librouter_nat_check_interface_rule(rulename, dev, 0, "PREROUTING")) {
			sprintf(buf, "/bin/iptables -t nat -D PREROUTING -i %s -j %s", dev, rulename);
			system(buf);
		}
	}

	if ((chain == chain_out) || (chain == chain_both)) {
		if (librouter_nat_check_interface_rule(rulename, 0, dev, "POSTROUTING")) {
			sprintf(buf, "/bin/iptables -t nat -D POSTROUTING -o %s -j %s", dev, rulename);
			system(buf);
		}
	}
	librouter_destroy_args(args);
	free(dev);
}
#endif /* OPTION_NAT */
