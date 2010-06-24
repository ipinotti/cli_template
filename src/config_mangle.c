#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"
#include "cish_main.h"

//#define DEBUG_CMD(x) printf("cmd = %s\n", x)
#define DEBUG_CMD(x)

/* Algum valor dentro do intervalo 1-2000000000 */
static unsigned int is_valid_mark (char *data)
{
	char *p;

	if (!data)
		return 0;
	for (p = data; *p; p++) {
		if (isdigit(*p) == 0)
			return 0;
	}
	if (atoi (data) < 1 || atoi (data) > 2000000000)
		return 0;
	return 1;
}

typedef enum {
	mangle_dscp, mangle_dscp_class, mangle_mark
} mangle_action;

typedef enum {
	add_mangle, insert_mangle, remove_mangle
} mangle_mode;

void do_mangle (const char *cmdline)
{
	arglist *args;
	char src_address[32];
	char dst_address[32];
	char src_portrange[32];
	char dst_portrange[32];
	int src_cidr;
	int dst_cidr;
	char *mangle;
	mangle_action action;
	acl_proto protocol;
	int crsr;
	char cmd[256];
	mangle_mode mode;
	acl_state state;
	char *tos = NULL, *dscp = NULL, *dscp_class = NULL;
	char *icmp_type = NULL, *icmp_type_code = NULL, *flags = NULL;
	char *action_param = NULL;
	int ruleexists = 0;

	src_address[0] = 0;
	dst_address[0] = 0;
	src_portrange[0] = 0;
	dst_portrange[0] = 0;

	mode = add_mangle;
	args = libconfig_make_args (cmdline);
	mangle = args->argv[1];
	if (!mangle_exists (mangle)) {
		sprintf (cmd, "/bin/iptables -t mangle -N %s", mangle);

		system (cmd);

	}
	crsr = 2;
	if (strcmp (args->argv[crsr], "insert") == 0) {
		mode = insert_mangle;
		++crsr;
	} else if (strcmp (args->argv[crsr], "no") == 0) {
		mode = remove_mangle;
		++crsr;
	}
	if (strcmp (args->argv[crsr], "dscp") == 0) {
		if (strcmp (args->argv[crsr + 1], "class") == 0) {
			crsr += 2;
			action = mangle_dscp_class;
		} else {
			crsr += 1;
			action = mangle_dscp;
		}
	} else if (strcmp (args->argv[crsr], "mark") == 0) {
		action = mangle_mark;
		crsr += 1;
		if (!is_valid_mark (args->argv[crsr])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
	} else {
		fprintf (stderr, "%% Illegal action type, use dscp or mark\n");
		libconfig_destroy_args (args);
		return;
	}
	action_param = args->argv[crsr]; /* mark; dscp; dscp_class; */
	crsr++;
	if (strcmp (args->argv[crsr], "tcp") == 0)
		protocol = tcp;
	else if (strcmp (args->argv[crsr], "udp") == 0)
		protocol = udp;
	else if (strcmp (args->argv[crsr], "icmp") == 0)
		protocol = icmp;
	else if (strcmp (args->argv[crsr], "ip") == 0)
		protocol = ip;
	else
		protocol = atoi (args->argv[crsr]);
	++crsr;
	if (protocol == icmp) {
		if (strcmp (args->argv[crsr], "type") == 0) {
			++crsr;
			if (crsr >= args->argc) {
				fprintf (stderr, "%% Missing icmp type\n");
				libconfig_destroy_args (args);
				return;
			}
			icmp_type = args->argv[crsr];
			++crsr;
			if (strcmp (icmp_type, "destination-unreachable") == 0
			                || strcmp (icmp_type, "redirect") == 0
			                || strcmp (icmp_type, "time-exceeded")
			                                == 0 || strcmp (
			                icmp_type, "parameter-problem") == 0) {
				if (crsr >= args->argc) {
					fprintf (stderr,
					                "%% Missing icmp type code\n");
					libconfig_destroy_args (args);
					return;
				}
				if (strcmp (args->argv[crsr], "any"))
					icmp_type_code = args->argv[crsr];
				++crsr;
			}
		}
	}
	if (strcmp (args->argv[crsr], "any") == 0) {
		strcpy (src_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp (args->argv[crsr], "host") == 0) {
		if ((crsr + 1) > args->argc) {
			fprintf (stderr, "%% Missing ip-address\n");
			libconfig_destroy_args (args);
			return;
		}
		++crsr;
		sprintf (src_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf (stderr, "%% Missing netmask\n");
			libconfig_destroy_args (args);
			return;
		}
		src_cidr = libconfig_ip_netmask2cidr (args->argv[crsr + 1]);
		if (src_cidr < 0) {
			fprintf (stderr, "%% Invalid netmask\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (src_address, "%s/%i ", args->argv[crsr], src_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc) {
		fprintf (stderr, "%% Not enough arguments\n");
		libconfig_destroy_args (args);
		return;
	}
	if (strcmp (args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (src_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (src_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (src_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (src_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (atoi (args->argv[crsr + 1]) > atoi (args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid port range (min > max)\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1]) || !libconfig_ip_is_valid_port (
		                args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (src_portrange, "%s:%s ", args->argv[crsr + 1],
		                args->argv[crsr + 2]);
		crsr += 3;
	} else {
		src_portrange[0] = 0;
	}
	if (strcmp (args->argv[crsr], "any") == 0) {
		strcpy (dst_address, "0.0.0.0/0 ");
		++crsr;
	} else if (strcmp (args->argv[crsr], "host") == 0) {
		++crsr;
		sprintf (dst_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf (stderr, "%% Missing netmask\n");
			libconfig_destroy_args (args);
			return;
		}

		dst_cidr = libconfig_ip_netmask2cidr (args->argv[crsr + 1]);
		if (dst_cidr < 0) {
			fprintf (stderr, "%% Invalid netmask\n");
			libconfig_destroy_args (args);
			return;
		}

		sprintf (dst_address, "%s/%i ", args->argv[crsr], dst_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc) {
		dst_portrange[0] = 0;
	} else if (strcmp (args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (dst_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (dst_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (dst_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (dst_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			libconfig_destroy_args (args);
			return;
		}
		if (atoi (args->argv[crsr + 1]) > atoi (args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid port range (min > max)\n");
			libconfig_destroy_args (args);
			return;
		}
		if (!libconfig_ip_is_valid_port (args->argv[crsr + 1]) || !libconfig_ip_is_valid_port (
		                args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid argument\n");
			libconfig_destroy_args (args);
			return;
		}
		sprintf (dst_portrange, "%s:%s ", args->argv[crsr + 1],
		                args->argv[crsr + 2]);
		crsr += 3;
	} else {
		dst_portrange[0] = 0;
	}
	state = 0;
	while (crsr < args->argc) {
		if (strcmp (args->argv[crsr], "established") == 0)
			state |= st_established;
		else if (strcmp (args->argv[crsr], "new") == 0)
			state |= st_new;
		else if (strcmp (args->argv[crsr], "related") == 0)
			state |= st_related;
		else if (strcmp (args->argv[crsr], "tos") == 0) {
			if ((crsr + 1) >= args->argc) {
				fprintf (stderr, "%% Not enough arguments\n");
				libconfig_destroy_args (args);
				return;
			}
			tos = args->argv[crsr + 1];
			crsr++;
		} else if (strcmp (args->argv[crsr], "flags") == 0) {
			crsr++;
			if (crsr >= args->argc) {
				fprintf (stderr, "%% Not enough arguments\n");
				libconfig_destroy_args (args);
				return;
			}
			flags = args->argv[crsr];
		} else if (strcmp (args->argv[crsr], "dscp") == 0) {
			if ((crsr + 1) >= args->argc) {
				fprintf (stderr, "%% Not enough arguments\n");
				libconfig_destroy_args (args);
				return;
			}
			if (strcmp (args->argv[crsr + 1], "class") == 0) {
				crsr += 2;
				dscp_class = args->argv[crsr];
			} else {
				crsr += 1;
				dscp = args->argv[crsr];
			}
		}
		crsr++;
	};

	sprintf (cmd, "/bin/iptables -t mangle ");
	switch (mode) {
	case insert_mangle:
		strcat (cmd, "-I ");
		break;
	case remove_mangle:
		strcat (cmd, "-D ");
		break;
	default:
		strcat (cmd, "-A ");
		break;
	}
	strcat (cmd, mangle);
	strcat (cmd, " ");
	switch (protocol) {
	case tcp:
		strcat (cmd, "-p tcp ");
		break;
	case udp:
		strcat (cmd, "-p udp ");
		break;
	case icmp:
		strcat (cmd, "-p icmp ");
		if (icmp_type) {
			if (icmp_type_code)
				sprintf (cmd + strlen (cmd), "--icmp-type %s ",
				                icmp_type_code);
			else
				sprintf (cmd + strlen (cmd), "--icmp-type %s ",
				                icmp_type);
		}
		break;
	default:
		sprintf (cmd + strlen (cmd), "-p %d ", protocol);
		break;
	}
	if (strcmp (src_address, "0.0.0.0/0")) {
		sprintf (cmd + strlen (cmd), "-s %s", src_address);
	}
	if (strlen (src_portrange)) {
		sprintf (cmd + strlen (cmd), "--sport %s ", src_portrange);
	}
	if (strcmp (dst_address, "0.0.0.0/0")) {
		sprintf (cmd + strlen (cmd), "-d %s", dst_address);
	}
	if (strlen (dst_portrange)) {
		sprintf (cmd + strlen (cmd), "--dport %s ", dst_portrange);
	}
	if (flags) {
		if (strcmp (flags, "syn") == 0)
			strcat (cmd, "--syn ");
		else {
			char *tmp;

			tmp = strchr (flags, '/');
			if (tmp != NULL)
				*tmp = ' ';
			sprintf (cmd + strlen (cmd), "--tcp-flags %s ", flags);
		}
	}
	if (tos) {
		sprintf (cmd + strlen (cmd), "-m tos --tos %s ", tos);
	}
	if (dscp) {
		sprintf (cmd + strlen (cmd), "-m dscp --dscp %s ", dscp);
	}
	if (dscp_class) {
		sprintf (cmd + strlen (cmd), "-m dscp --dscp-class %s ",
		                dscp_class);
	}
	if (state) {
		int comma = 0;
		strcat (cmd, "-m state --state ");
		if (state & st_established) {
			strcat (cmd, "ESTABLISHED");
			comma = 1;
		}
		if (state & st_new) {
			if (comma)
				strcat (cmd, ",");
			else
				comma = 1;
			strcat (cmd, "NEW");
		}
		if (state & st_related) {
			if (comma)
				strcat (cmd, ",");
			strcat (cmd, "RELATED");
		}
		strcat (cmd, " ");
	}
	switch (action) {
	case mangle_dscp:
		strcat (cmd, "-j DSCP --set-dscp ");
		break;
	case mangle_dscp_class:
		strcat (cmd, "-j DSCP --set-dscp-class ");
		break;
	case mangle_mark:
		strcat (cmd, "-j MARK --set-mark ");
		break;
	default:
		fprintf (stderr, "%% Invalid action\n");
		libconfig_destroy_args (args);
		return;
	}
	strcat (cmd, action_param); /* mark; dscp; dscp_class; */

	/* Verificamos se a regra existe no sistema */
	{
		FILE *f;
		arg_list argl = NULL;
		int k, l, n, insert = 0;
		unsigned char buf[512];

		if (!strcmp (args->argv[2], "insert"))
			insert = 1;
		if ((f = fopen (TMP_CFG_FILE, "w+"))) {
			lconfig_mangle_dump (0, f, 1);
			fseek (f, 0, SEEK_SET);
			while (fgets ((char *) buf, 511, f)) {
				if ((n = libconfig_parse_args_din ((char *) buf, &argl))
				                > 3) {
					if (n == (args->argc - insert)) {
						if (!strcmp (args->argv[0],
						                "mark-rule")) {
							for (k = 0, l = 0, ruleexists
							                = 1; k
							                < args->argc; k++, l++) {
								if (k == 2
								                && insert) {
									l--;
									continue;
								}
								if (strcmp (
								                args->argv[k],
								                argl[l])) {
									ruleexists
									                = 0;
									break;
								}
							}
							if (ruleexists) {
								libconfig_destroy_args_din (
								                &argl);
								break;
							}
						}
					}
				}
				libconfig_destroy_args_din (&argl);
			}
			fclose (f);
		}
	}
	if (ruleexists)
		printf ("%% Rule already exists\n");
	else {
		DEBUG_CMD(cmd);
		system (cmd);
	}
	libconfig_destroy_args (args);
}

void no_mangle_rule (const char *cmdline)
{
	arglist *args;
	char *mangle;
	char cmd[256];

	args = libconfig_make_args (cmdline);
	mangle = args->argv[2]; /* no mark-rule <name> */
	if (!mangle_exists (mangle)) {
		libconfig_destroy_args (args);
		return;
	}
	if (get_mangle_refcount (mangle)) {
		printf ("%% mark-rule in use, can't delete\n");
		libconfig_destroy_args (args);
		return;
	}
	sprintf (cmd, "/bin/iptables -t mangle -F %s", mangle); /* flush */
	system (cmd);

	sprintf (cmd, "/bin/iptables -t mangle -X %s", mangle); /* delete */

	system (cmd);

	libconfig_destroy_args (args);
}

int mangle_exists (char *mangle)
{
	FILE *F;
	char *tmp, buf[256];
	int mangle_exists = 0;

	F = popen ("/bin/iptables -t mangle -L -n", "r");

	if (!F) {
		fprintf (stderr, "%% ACL subsystem not found\n");
		return 0;
	}

	while (!feof (F)) {
		buf[0] = 0;
		fgets (buf, 255, F);
		buf[255] = 0;
		libconfig_str_striplf (buf);
		if (strncmp (buf, "Chain ", 6) == 0) {
			tmp = strchr (buf + 6, ' ');
			if (tmp) {
				*tmp = 0;
				if (strcmp (buf + 6, mangle) == 0) {
					mangle_exists = 1;
					break;
				}
			}
		}
	}
	pclose (F);
	return mangle_exists;
}

int matched_mangle_exists (char *mangle,
                           char *iface_in,
                           char *iface_out,
                           char *chain)
{
	FILE *F;
	char *tmp, buf[256];
	int mangle_exists = 0;
	int in_chain = 0;
	char *iface_in_, *iface_out_, *target;

	F = popen ("/bin/iptables -t mangle -L -nv", "r");

	if (!F) {
		fprintf (stderr, "%% ACL subsystem not found\n");
		return 0;
	}

	while (!feof (F)) {
		buf[0] = 0;
		fgets (buf, 255, F);
		buf[255] = 0;
		libconfig_str_striplf (buf);
		if (strncmp (buf, "Chain ", 6) == 0) {
			if (in_chain)
				break; // chegou `a proxima chain sem encontrar - finaliza
			tmp = strchr (buf + 6, ' ');
			if (tmp) {
				*tmp = 0;
				if (strcmp (buf + 6, chain) == 0)
					in_chain = 1;
			}
		} else if ((in_chain) && (strncmp (buf, " pkts", 5) != 0)
		                && (strlen (buf) > 40)) {
			arglist *args;
			char *p;
			p = buf;
			while ((*p) && (*p == ' '))
				p++;
			args = libconfig_make_args (p);

			if (args->argc < 7) {
				libconfig_destroy_args (args);
				continue;
			}
			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];
			if (((iface_in == NULL)
			                || (strcmp (iface_in_, iface_in) == 0))
			                && ((iface_out == NULL) || (strcmp (
			                                iface_out_, iface_out)
			                                == 0)) && ((mangle
			                == NULL) || (strcmp (target, mangle)
			                == 0))) {
				mangle_exists = 1;
				libconfig_destroy_args (args);
				break;
			}
			libconfig_destroy_args (args);
		}
	}
	pclose (F);
	return mangle_exists;
}

int get_mangle_refcount (char *mangle)
{
	FILE *F;
	char *tmp;
	char buf[256];

	F = popen ("/bin/iptables -t mangle -L -n", "r");

	if (!F) {
		fprintf (stderr, "%% ACL subsystem not found\n");
		return 0;
	}

	while (!feof (F)) {
		buf[0] = 0;
		fgets (buf, 255, F);
		buf[255] = 0;
		libconfig_str_striplf (buf);
		if (strncmp (buf, "Chain ", 6) == 0) {
			tmp = strchr (buf + 6, ' ');
			if (tmp) {
				*tmp = 0;
				if (strcmp (buf + 6, mangle) == 0) {
					tmp = strchr (tmp + 1, '(');
					if (!tmp)
						return 0;
					tmp++;
					return atoi (tmp);
				}
			}
		}
	}
	pclose (F);
	return 0;
}

int clean_iface_mangle_rules (char *iface)
{
	FILE *F;
	char buf[256];
	char cmd[256];
	char chain[16];
	char *p, *iface_in_, *iface_out_, *target;
	FILE *procfile;

	procfile = fopen ("/proc/net/ip_tables_names", "r");
	if (!procfile)
		return 0;
	fclose (procfile);

	F = popen ("/bin/iptables -t mangle -L -nv", "r");

	if (!F) {
		fprintf (stderr, "%% ACL subsystem not found\n");
		return 0;
	}

	while (!feof (F)) {
		buf[0] = 0;
		fgets (buf, 255, F);
		buf[255] = 0;
		libconfig_str_striplf (buf);
		if (strncmp (buf, "Chain ", 6) == 0) {
			p = strchr (buf + 6, ' ');
			if (p) {
				*p = 0;
				strncpy (chain, buf + 6, 16);
				chain[15] = 0;
			}
		} else if ((strncmp (buf, " pkts", 5) != 0) && (strlen (buf)
		                > 40)) {
			arglist *args;

			p = buf;
			while ((*p) && (*p == ' '))
				p++;
			args = libconfig_make_args (p);
			if (args->argc < 7) {
				libconfig_destroy_args (args);
				continue;
			}
			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];
			if (strncmp (iface, iface_in_, strlen (iface)) == 0) {
				sprintf (
				                cmd,
				                "/bin/iptables -t mangle -D %s -i %s -j %s",
				                chain, iface_in_, target);
				DEBUG_CMD(cmd);
				system (cmd);

			}
			if (strncmp (iface, iface_out_, strlen (iface)) == 0) {
				sprintf (
				                cmd,
				                "/bin/iptables -t mangle -D %s -o %s -j %s",
				                chain, iface_out_, target);
				DEBUG_CMD(cmd);
				system (cmd);
			}
			libconfig_destroy_args (args);
		}
	}
	pclose (F);
	return 0;
}

void interface_mangle (const char *cmdline)
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *listno;

	dev = libconfig_device_convert (interface_edited->cish_string, interface_major,
	                interface_minor);
	args = libconfig_make_args (cmdline);
	listno = args->argv[2]; /* ip mark <name> in|out */
	if (strcasecmp (args->argv[3], "in") == 0)
		chain = chain_in;
	else if (strcasecmp (args->argv[3], "out") == 0)
		chain = chain_out;
	if (!mangle_exists (listno)) {
		printf ("%% mark-rule %s undefined\n", listno);
		free (dev);
		libconfig_destroy_args (args);
		return;
	}
	if ((chain == chain_in) && (matched_mangle_exists (0, dev, 0, "INPUT")
	                || matched_mangle_exists (0, dev, 0, "PREROUTING"))) {
		printf ("%% inbound MARK rule already defined.\n");
		free (dev);
		libconfig_destroy_args (args);
		return;
	}
	if ((chain == chain_out)
	                && (matched_mangle_exists (0, 0, dev, "OUTPUT")
	                                || matched_mangle_exists (0, 0, dev,
	                                                "POSTROUTING"))) {
		printf ("%% outbound MARK rule already defined.\n");
		free (dev);
		libconfig_destroy_args (args);
		return;
	}
	if (!mangle_exists (listno)) {
		sprintf (buf, "/bin/iptables -t mangle -N %s", listno);
		system (buf);
	}
	if (chain == chain_in) {
		sprintf (buf, "/bin/iptables -t mangle -A INPUT -i %s -j %s",
		                dev, listno);
		DEBUG_CMD(buf);
		system (buf);

		sprintf (
		                buf,
		                "/bin/iptables -t mangle -A PREROUTING -i %s -j %s",
		                dev, listno);
		DEBUG_CMD(buf);
		system (buf);
	} else {
		sprintf (buf, "/bin/iptables -t mangle -A OUTPUT -o %s -j %s",
		                dev, listno);

		DEBUG_CMD(buf);
		system (buf);

		sprintf (
		                buf,
		                "/bin/iptables -t mangle -A POSTROUTING -o %s -j %s",
		                dev, listno);

		DEBUG_CMD(buf);
		system (buf);
	}
	libconfig_destroy_args (args);
	free (dev);
}

void interface_no_mangle (const char *cmdline)
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *listno;

	dev = libconfig_device_convert (interface_edited->cish_string, interface_major,
	                interface_minor);
	args = libconfig_make_args (cmdline); /* no ip mark <name> in|out */
	listno = args->argv[3];
	if (args->argc == 4)
		chain = chain_both;
	else {
		if (strcasecmp (args->argv[4], "in") == 0)
			chain = chain_in;
		else if (strcasecmp (args->argv[4], "out") == 0)
			chain = chain_out;
	}
	if ((chain == chain_in) || (chain == chain_both)) {
		if (matched_mangle_exists (listno, dev, 0, "INPUT")) {
			sprintf (
			                buf,
			                "/bin/iptables -t mangle -D INPUT -i %s -j %s",
			                dev, listno);

			DEBUG_CMD(buf);
			system (buf);
		}
		if (matched_mangle_exists (listno, dev, 0, "PREROUTING")) {
			sprintf (
			                buf,
			                "/bin/iptables -t mangle -D PREROUTING -i %s -j %s",
			                dev, listno);

			DEBUG_CMD(buf);
			system (buf);
		}
	}
	if ((chain == chain_out) || (chain == chain_both)) {
		if (matched_mangle_exists (listno, 0, dev, "OUTPUT")) {
			sprintf (
			                buf,
			                "/bin/iptables -t mangle -D OUTPUT -o %s -j %s",
			                dev, listno);

			DEBUG_CMD(buf);
			system (buf);

		}
		if (matched_mangle_exists (listno, 0, dev, "POSTROUTING")) {
			sprintf (
			                buf,
			                "/bin/iptables -t mangle -D POSTROUTING -o %s -j %s",
			                dev, listno);

			DEBUG_CMD(buf);
			system (buf);
		}
	}
	libconfig_destroy_args (args);
	free (dev);
}

