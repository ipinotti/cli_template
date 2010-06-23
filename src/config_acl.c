/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h" /* buf */
#include "pprintf.h"

#include <libconfig/acl.h>
#include <libconfig/args.h>
#include <libconfig/exec.h>
#include <libconfig/device.h>
#include <libconfig/ip.h>

//#define DEBUG_CMD(x) printf("cmd = %s\n", x)
#define DEBUG_CMD(x)

void do_accesslist(const char *cmdline)
{
	arglist *args;
	int crsr;
	struct acl_config acl;

	int i;
	int found;
	char *p;

	/* Initialize configuration structure */
	memset(&acl, 0, sizeof(struct acl_config));

	acl.mode = add_acl;
	args = libconfig_make_args(cmdline);

	if (args->argc > 6) {
		if (strcmp(args->argv[2], "tcpmss") == 0) {
			for (i = 7, found = 0; i < args->argc; i++) {
				if (strcmp(args->argv[i], "flags") == 0) {
					if (++i < args->argc) {
						if (strcasecmp(args->argv[i],
						                "syn") == 0) {
							found = 1;
							break;
						} else if ((p = strchr(
						                args->argv[i],
						                '/')) != NULL) {
							if (strstr(p, "SYN")
							                != NULL) {
								found = 1;
								break;
							}
						}
					}
				}
			}

			if (found == 0) {
				fprintf(stderr,
				                "%% Invalid command, you should also "
					                "include flags argument with bit SYN in test!\n");
				libconfig_destroy_args(args);
				return;
			}
		}
	}

	acl.name = args->argv[1];

	/* Create new ACL if one does not exist */
	if (!libconfig_acl_exists(acl.name))
		libconfig_acl_create_new(acl.name);

	crsr = 2;

	if (strcmp(args->argv[crsr], "insert") == 0) {
		acl.mode = insert_acl;
		++crsr;
	} else if (strcmp(args->argv[crsr], "no") == 0) {
		acl.mode = remove_acl;
		++crsr;
	}

	if (strcmp(args->argv[crsr], "accept") == 0)
		acl.action = acl_accept;
	else if (strcmp(args->argv[crsr], "drop") == 0)
		acl.action = acl_drop;
	else if (strcmp(args->argv[crsr], "reject") == 0)
		acl.action = acl_reject;
	else if (strcmp(args->argv[crsr], "log") == 0)
		acl.action = acl_log;
	else if (strcmp(args->argv[crsr], "tcpmss") == 0)
		acl.action = acl_tcpmss;
	else {
		fprintf(stderr,
		                "%% Illegal action type, use accept, drop, reject, log or tcpmss\n");
		libconfig_destroy_args(args);
		return;
	}
	++crsr;

	if (acl.action == acl_tcpmss) {
		if (crsr >= args->argc) {
			fprintf(stderr, "%% Missing tcpmss action\n");
			libconfig_destroy_args(args);
			return;
		}
		acl.tcpmss = args->argv[crsr];
		++crsr;
	}

	/* Check for protocol */
	if (strcmp(args->argv[crsr], "tcp") == 0)
		acl.protocol = tcp;
	else if (strcmp(args->argv[crsr], "udp") == 0)
		acl.protocol = udp;
	else if (strcmp(args->argv[crsr], "icmp") == 0)
		acl.protocol = icmp;
	else if (strcmp(args->argv[crsr], "ip") == 0)
		acl.protocol = ip;
	else
		acl.protocol = atoi(args->argv[crsr]);
	++crsr;

	if (acl.protocol == icmp) {
		if (strcmp(args->argv[crsr], "type") == 0) {
			++crsr;
			if (crsr >= args->argc) {
				fprintf(stderr, "%% Missing icmp type\n");
				libconfig_destroy_args(args);
				return;
			}
			acl.icmp_type = args->argv[crsr];
			++crsr;
			if (strcmp(acl.icmp_type, "destination-unreachable")
			                == 0 || strcmp(acl.icmp_type,
			                "redirect") == 0 || strcmp(
			                acl.icmp_type, "time-exceeded") == 0
			                || strcmp(acl.icmp_type,
			                                "parameter-problem")
			                                == 0) {
				if (crsr >= args->argc) {
					fprintf(stderr,
					                "%% Missing icmp type code\n");
					libconfig_destroy_args(args);
					return;
				}

				if (strcmp(args->argv[crsr], "any"))
					acl.icmp_type_code = args->argv[crsr];
				++crsr;
			}
		}
	}

	if (strcmp(args->argv[crsr], "any") == 0) {
		strcpy(acl.src_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp(args->argv[crsr], "host") == 0) {
		if ((crsr + 1) > args->argc) {
			fprintf(stderr, "%% Missing ip-address\n");
			libconfig_destroy_args(args);
			return;
		}
		++crsr;
		sprintf(acl.src_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf(stderr, "%% Missing netmask\n");
			libconfig_destroy_args(args);
			return;
		}
		acl.src_cidr = netmask2cidr(args->argv[crsr + 1]);
		if (acl.src_cidr < 0) {
			fprintf(stderr, "%% Invalid netmask\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.src_address, "%s/%i ", args->argv[crsr],
		                acl.src_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc) {
		fprintf(stderr, "%% Not enough arguments\n");
		libconfig_destroy_args(args);
		return;
	}
	if (strcmp(args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.src_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.src_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.src_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.src_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr + 1]) > atoi(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1]) || !is_valid_port(
		                args->argv[crsr + 2])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.src_portrange, "%s:%s ", args->argv[crsr + 1],
		                args->argv[crsr + 2]);
		crsr += 3;
	} else {
		acl.src_portrange[0] = 0;
	}
	if (strcmp(args->argv[crsr], "any") == 0) {
		strcpy(acl.dst_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp(args->argv[crsr], "host") == 0) {
		++crsr;
		sprintf(acl.dst_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf(stderr, "%% Missing netmask\n");
			libconfig_destroy_args(args);
			return;
		}
		acl.dst_cidr = netmask2cidr(args->argv[crsr + 1]);
		if (acl.dst_cidr < 0) {
			fprintf(stderr, "%% Invalid netmask\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.dst_address, "%s/%i ", args->argv[crsr],
		                acl.dst_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc) {
		acl.dst_portrange[0] = 0;
	} else if (strcmp(args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.dst_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.dst_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.dst_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.dst_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp(args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf(stderr, "%% Not enough arguments\n");
			libconfig_destroy_args(args);
			return;
		}
		if (atoi(args->argv[crsr + 1]) > atoi(args->argv[crsr + 2])) {
			fprintf(stderr, "%% Invalid port range (min > max)\n");
			libconfig_destroy_args(args);
			return;
		}
		if (!is_valid_port(args->argv[crsr + 1]) || !is_valid_port(
		                args->argv[crsr + 2])) {
			fprintf(stderr, "%% Ivalid argument\n");
			libconfig_destroy_args(args);
			return;
		}
		sprintf(acl.dst_portrange, "%s:%s ", args->argv[crsr + 1],
		                args->argv[crsr + 2]);
		crsr += 3;
	} else {
		acl.dst_portrange[0] = 0;
	}
	acl.state = 0;
	while (crsr < args->argc) {
		if (strcmp(args->argv[crsr], "established") == 0)
			acl.state |= st_established;
		else if (strcmp(args->argv[crsr], "new") == 0)
			acl.state |= st_new;
		else if (strcmp(args->argv[crsr], "related") == 0)
			acl.state |= st_related;
		else if (strcmp(args->argv[crsr], "tos") == 0) {
			crsr++;
			if (crsr >= args->argc) {
				fprintf(stderr, "%% Not enough arguments\n");
				libconfig_destroy_args(args);
				return;
			}
			acl.tos = args->argv[crsr];
		} else if (strcmp(args->argv[crsr], "flags") == 0) {
			crsr++;
			if (crsr >= args->argc) {
				fprintf(stderr, "%% Not enough arguments\n");
				libconfig_destroy_args(args);
				return;
			}
			acl.flags = args->argv[crsr];
		}
		crsr++;
	};

	/* Se a acao for TCPMSS, entao somos obrigados a ter na linha de comando o argumento 'flags' */
	if (acl.action == acl_tcpmss) {
		if (!acl.flags) {
			fprintf(stderr,
			                "%% For use 'tcpmss' you must define 'flags'\n");
			libconfig_destroy_args(args);
			return;
		}
	}

	/* Apply the access list */
	libconfig_acl_apply(&acl);

	libconfig_destroy_args(args);
}

void do_accesslist_mac(const char *cmdline)
{
	int crsr;
	arglist *args;
	acl_mode mode;
	acl_action action;
	char *acl, cmd[256];

	mode = add_acl;
	args = libconfig_make_args(cmdline);
	acl = args->argv[1];
	if (!libconfig_acl_exists(acl)) {
		sprintf(cmd, "/bin/iptables -N %s", acl);
		system(cmd);
	}
	crsr = 2;
	if (!strcmp(args->argv[crsr], "insert")) {
		mode = insert_acl;
		++crsr;
	} else if (!strcmp(args->argv[crsr], "no")) {
		mode = remove_acl;
		++crsr;
	}
	if (!strcmp(args->argv[crsr], "accept"))
		action = acl_accept;
	else if (!strcmp(args->argv[crsr], "drop"))
		action = acl_drop;
	else if (!strcmp(args->argv[crsr], "reject"))
		action = acl_reject;
	else if (!strcmp(args->argv[crsr], "log"))
		action = acl_log;
	else {
		fprintf(stderr,
		                "%% Illegal action type, use accept, drop, reject, log or tcpmss\n");
		libconfig_destroy_args(args);
		return;
	}
	crsr += 2;
	sprintf(cmd, "/bin/iptables ");
	switch (mode) {
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
	switch (action) {
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
	} DEBUG_CMD(cmd);
	system(cmd);
	libconfig_destroy_args(args);
}

void do_accesslist_policy(const char *cmdline)
{
	arglist *args;
	char *target;
	char cmd[256];
	FILE *procfile;

	procfile = fopen("/proc/net/ip_tables_names", "r");

	args = libconfig_make_args(cmdline);
	if (strcmp(args->argv[1], "accept") == 0) {
		target = "ACCEPT";
		if (!procfile)
			goto bailout;
		/* doesnt need to load modules! */
	} else {
		if (strcmp(args->argv[1], "drop") == 0) {
			target = "DROP";
		} else
			target = "REJECT";
	}
	if (procfile)
		fclose(procfile);

	sprintf(cmd, "/bin/iptables -P INPUT %s", target);
	DEBUG_CMD(cmd);
	system(cmd);

	sprintf(cmd, "/bin/iptables -P OUTPUT %s", target);
	DEBUG_CMD(cmd);
	system(cmd);

	sprintf(cmd, "/bin/iptables -P FORWARD %s", target);
	DEBUG_CMD(cmd);
	system(cmd);

	bailout: libconfig_destroy_args(args);
}

void no_accesslist(const char *cmdline)
{
	arglist *args;
	char *acl;
	char cmd[256];

	args = libconfig_make_args(cmdline);
	acl = args->argv[2];
	if (!libconfig_acl_exists(acl)) {
		libconfig_destroy_args(args);
		return;
	}
	if (libconfig_acl_get_refcount(acl)) {
		printf("%% Access-list in use, can't delete\n");
		libconfig_destroy_args(args);
		return;
	}
	sprintf(cmd, "/bin/iptables -F %s", acl); /* flush */

	system(cmd);

	sprintf(cmd, "/bin/iptables -X %s", acl); /* delete */

	system(cmd);

	libconfig_destroy_args(args);
}

void interface_acl(const char *cmdline) /* ip access-group <acl> <in|out> */
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *listno;

	dev = libconfig_device_convert(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = libconfig_make_args(cmdline);
	listno = args->argv[2];
	if (strcasecmp(args->argv[3], "in") == 0)
		chain = chain_in;
	else if (strcasecmp(args->argv[3], "out") == 0)
		chain = chain_out;
	if (!libconfig_acl_exists(listno)) {
		printf("%% access-list %s undefined\n", listno);
		free(dev);
		libconfig_destroy_args(args);
		return;
	}
	if ((chain == chain_in) && (libconfig_acl_matched_exists(0, dev, 0, "INPUT")
	                || libconfig_acl_matched_exists(0, dev, 0, "FORWARD"))) {
		printf("%% inbound access-list already defined.\n");
		free(dev);
		libconfig_destroy_args(args);
		return;
	}
	if ((chain == chain_out) && (libconfig_acl_matched_exists(0, 0, dev, "OUTPUT")
	                || libconfig_acl_matched_exists(0, 0, dev, "FORWARD"))) {
		printf("%% outbound access-list already defined.\n");
		free(dev);
		libconfig_destroy_args(args);
		return;
	}
	if (chain == chain_in) {
		sprintf(buf, "/bin/iptables -A INPUT -i %s -j %s", dev, listno);

		DEBUG_CMD(buf);
		system(buf);

		sprintf(buf, "/bin/iptables -A FORWARD -i %s -j %s", dev,
		                listno);

		DEBUG_CMD(buf);
		system(buf);

	} else {
		sprintf(buf, "/bin/iptables -A OUTPUT -o %s -j %s", dev, listno);

		DEBUG_CMD(buf);
		system(buf);

		sprintf(buf, "/bin/iptables -A FORWARD -o %s -j %s", dev,
		                listno);

		DEBUG_CMD(buf);
		system(buf);
	}
#ifdef OPTION_IPSEC
	libconfig_acl_interface_ipsec(1, chain, dev, listno);
#endif
	libconfig_destroy_args(args);
	free(dev);
}

void interface_no_acl(const char *cmdline) /* no ip access-group <acl> [in|out] */
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *listno;

	dev = libconfig_device_convert(interface_edited->cish_string, interface_major,
	                interface_minor);
	args = libconfig_make_args(cmdline);
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
		if (libconfig_acl_matched_exists(listno, dev, 0, "INPUT")) {
			sprintf(buf, "/bin/iptables -D INPUT -i %s -j %s", dev,
			                listno);

			DEBUG_CMD(buf);
			system(buf);
		}
		if (libconfig_acl_matched_exists(listno, dev, 0, "FORWARD")) {
			sprintf(buf, "/bin/iptables -D FORWARD -i %s -j %s",
			                dev, listno);

			DEBUG_CMD(buf);
			system(buf);
		}
	}
	if ((chain == chain_out) || (chain == chain_both)) {
		if (libconfig_acl_matched_exists(listno, 0, dev, "OUTPUT")) {
			sprintf(buf, "/bin/iptables -D OUTPUT -o %s -j %s",
			                dev, listno);

			DEBUG_CMD(buf);
			system(buf);
		}
		if (libconfig_acl_matched_exists(listno, 0, dev, "FORWARD")) {
			sprintf(buf, "/bin/iptables -D FORWARD -o %s -j %s",
			                dev, listno);

			DEBUG_CMD(buf);
			system(buf);
		}
	}
#ifdef OPTION_IPSEC
	libconfig_acl_interface_ipsec(0, chain, dev, listno);
#endif
	libconfig_destroy_args(args);
	free(dev);
}

