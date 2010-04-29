#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "commands.h"
#include "pprintf.h"

#include "acl.h"
#include "mangle.h"
#include "cish_main.h"

extern device_family *interface_edited;
extern int interface_major, interface_minor;

//#define DEBUG_CMD(x) printf("cmd = %s\n", x)
#define DEBUG_CMD(x)

static void print_mangle (const char *action,
                          const char *dscp,
                          const char *mark,
                          const char *proto,
                          const char *src,
                          const char *dst,
                          const char *sports,
                          const char *dports,
                          char *mangle,
                          FILE *out,
                          int conf_format,
                          int mc,
                          char *flags,
                          char *tos,
                          char *dscp_match,
                          char *state,
                          char *icmp_type,
                          char *icmp_type_code)
{
	char src_ports[32];
	char dst_ports[32];
	char *_src;
	char *_dst;
	const char *src_netmask;
	const char *dst_netmask;
	const char *dscp_class;

	_src = strdup (src);
	_dst = strdup (dst);
	src_ports[0] = 0;
	dst_ports[0] = 0;
	src_netmask = extract_mask (_src);
	dst_netmask = extract_mask (_dst);
	acl_set_ports (sports, src_ports);
	acl_set_ports (dports, dst_ports);
	if (conf_format)
		fprintf (out, "mark-rule ");
	if (conf_format)
		fprintf (out, "%s ", mangle);
	else
		fprintf (out, "    ");
	if (strcmp (action, "DSCP") == 0 && dscp) {
		dscp_class = dscp_to_name (strtol (dscp, NULL, 16));
		if (dscp_class)
			fprintf (out, "dscp class %s ", dscp_class);
		else
			fprintf (out, "dscp %d ", strtol (dscp, NULL, 16));
	} else if (strcmp (action, "MARK") == 0) {
		fprintf (out, "mark ");
		if (mark)
			fprintf (out, "%d ", strtol (mark, NULL, 16));
	} else
		fprintf (out, "???? ");
	if (strcmp (proto, "all") == 0)
		fprintf (out, "ip ");
	else
		fprintf (out, "%s ", proto);
	if (icmp_type) {
		if (icmp_type_code)
			fprintf (out, "type %s %s ", icmp_type, icmp_type_code);
		else
			fprintf (out, "type %s ", icmp_type);
	}
	if (strcasecmp (src, "0.0.0.0/0") == 0)
		fprintf (out, "any ");
	else if (strcmp (src_netmask, "255.255.255.255") == 0)
		fprintf (out, "host %s ", _src);
	else
		fprintf (out, "%s %s ", _src, ciscomask (src_netmask));
	if (*src_ports)
		fprintf (out, "%s ", src_ports);
	if (strcasecmp (dst, "0.0.0.0/0") == 0)
		fprintf (out, "any ");
	else if (strcmp (dst_netmask, "255.255.255.255") == 0)
		fprintf (out, "host %s ", _dst);
	else
		fprintf (out, "%s %s ", _dst, ciscomask (dst_netmask));
	if (*dst_ports)
		fprintf (out, "%s ", dst_ports);
	if (flags) {
		if (strncmp (flags, "0x16/0x02", 9)) {
			char *t;

			t = strtok (flags, "/");
			if (t != NULL) {
				fprintf (out, "flags ");
				acl_print_flags (out, t);
				fprintf (out, "/");
				t = strtok (NULL, "/");
				acl_print_flags (out, t);
				fprintf (out, " ");
			}
		} else
			fprintf (out, "flags syn ");
	}
	if (tos)
		fprintf (out, "tos %d ", strtol (tos, NULL, 16));
	if (dscp_match) {
		dscp_class = dscp_to_name (strtol (dscp_match, NULL, 16));
		if (dscp_class)
			fprintf (out, "dscp class %s ", dscp_class);
		else
			fprintf (out, "dscp %d ", strtol (dscp_match, NULL, 16));
	}
	if (state) {
		if (strstr (state, "ESTABLISHED"))
			fprintf (out, "established ");
		if (strstr (state, "NEW"))
			fprintf (out, "new ");
		if (strstr (state, "RELATED"))
			fprintf (out, "related ");
	}
	if (!conf_format)
		fprintf (out, " (%i matches)", mc);
	fprintf (out, "\n");
}

/*
 # iptables -n -L -v -t mangle
 Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
 0     0 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0           MARK set 0x1
 0     0 DSCP       all  --  *      *       0.0.0.0/0            0.0.0.0/0           DSCP set 0x01
 0     0 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0           DSCP match 0x01 MARK set 0x2
 */
#define trimcolumn(x) tmp=strchr(x, ' '); if (tmp != NULL) *tmp=0;
void dump_mangle (char *xmangle, FILE *F, int conf_format)
{
	FILE *ipc;
	char *tmp;
	char mangle[101];
	char *type = NULL;
	char *prot = NULL;
	char *input = NULL;
	char *output = NULL;
	char *source = NULL;
	char *dest = NULL;
	char *sports = NULL;
	char *dports = NULL;
	char *flags = NULL;
	char *tos = NULL;
	char *mark = NULL;
	char *dscp = NULL;
	char *dscp_match = NULL;
	char *state = NULL;
	char *icmp_type = NULL;
	char *icmp_type_code = NULL;
	char *mcount; /* pkts */
	int manglep = 1;
	FILE *procfile;

	procfile = fopen ("/proc/net/ip_tables_names", "r");
	if (!procfile)
		return;
	fclose (procfile);

	mangle[0] = 0;

	ipc = popen ("/bin/iptables -t mangle -L -nv", "r");

	if (!ipc) {
		fprintf (stderr, "%% ACL subsystem not found\n");
		return;
	}

	while (!feof (ipc)) {
		buf[0] = 0;
		fgets (buf, 1023, ipc);
		tmp = strchr (buf, '\n');
		if (tmp)
			*tmp = 0;

		if (strncmp (buf, "Chain ", 6) == 0) {
			//if ((conf_format) && (manglep)) pfprintf(F, "!\n");
			trimcolumn(buf+6);
			strncpy (mangle, buf + 6, 100);
			mangle[100] = 0;
			manglep = 0;
		} else if (strncmp (buf, " pkts", 5) != 0) {
			if ((strlen (buf)) && ((xmangle == NULL) || (strcmp (
			                xmangle, mangle) == 0))) {
				arglist *args;
				char *p;

				p = buf;
				while ((*p) && (*p == ' '))
					p++;
				args = make_args (p);
				if (args->argc < 9) {
					destroy_args (args);
					continue;
				}
				type = args->argv[2];
				prot = args->argv[3];
				input = args->argv[5];
				output = args->argv[6];
				source = args->argv[7];
				dest = args->argv[8];
				sports = strstr (buf, "spts:");
				if (sports)
					sports += 5;
				else {
					sports = strstr (buf, "spt:");
					if (sports)
						sports += 4;
				}
				dports = strstr (buf, "dpts:");
				if (dports)
					dports += 5;
				else {
					dports = strstr (buf, "dpt:");
					if (dports)
						dports += 4;
				}
				if ((flags = strstr (buf, "tcp flags:")))
					flags += 10;
				if ((tos = strstr (buf, "TOS match 0x")))
					tos += 12;
				if ((mark = strstr (buf, "MARK xset 0x")))
					mark += 12;
				if ((dscp = strstr (buf, "DSCP set 0x")))
					dscp += 11;
				if ((dscp_match = strstr (buf, "DSCP match 0x")))
					dscp_match += 13;
				if ((state = strstr (buf, "state ")))
					state += 6;
				if ((icmp_type = strstr (buf, "icmp type "))) {
					icmp_type += 10;
					if ((icmp_type_code = strstr (buf,
					                "code ")))
						icmp_type_code += 5;
				}
				if (flags)
					trimcolumn(flags);
				if (sports)
					trimcolumn(sports);
				if (dports)
					trimcolumn(dports);
				if (tos)
					trimcolumn(tos);
				if (mark)
					trimcolumn(mark);
				if (dscp)
					trimcolumn(dscp);
				if (dscp_match)
					trimcolumn(dscp_match);
				if (state)
					trimcolumn(state);
				if (icmp_type)
					trimcolumn(icmp_type);
				if (icmp_type_code)
					trimcolumn(icmp_type_code);

				if ((strcmp (type, "DSCP") == 0) || (strcmp (
				                type, "MARK") == 0)) {
					if (strcmp (mangle, "INPUT") != 0
					                && strcmp (mangle,
					                                "PREROUTING")
					                                != 0
					                && strcmp (mangle,
					                                "OUTPUT")
					                                != 0
					                && strcmp (mangle,
					                                "POSTROUTING")
					                                != 0) /* filter CHAINs */
					{
						if ((!manglep)
						                && (!conf_format)) {
							fprintf (
							                F,
							                "MARK rule %s\n",
							                mangle);
						}
						manglep = 1;
						mcount = buf;
						if (!conf_format) {
							while (*mcount == ' ')
								++mcount; /* pkts */
						}
						print_mangle (type, dscp, mark,
						                prot, source,
						                dest, sports,
						                dports, mangle,
						                F, conf_format,
						                atoi (mcount),
						                flags, tos,
						                dscp_match,
						                state,
						                icmp_type,
						                icmp_type_code);
					}
				} else {
					if (!conf_format) {
						if (strstr (mangle, "ROUTING")) /* PRE|POST ROUTING */
						{
							if (strcmp (input, "*"))
								fprintf (
								                F,
								                "interface %s in mark-rule %s\n",
								                input,
								                type);
							if (strcmp (output, "*"))
								fprintf (
								                F,
								                "interface %s out mark-rule %s\n",
								                output,
								                type);
						}
					}
				}
				destroy_args (args);
			}
		}
	}
	pclose (ipc);
	if (conf_format)
		fprintf (F, "!\n"); /* ! for next: router rip */
}

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
	args = make_args (cmdline);
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
			destroy_args (args);
			return;
		}
	} else {
		fprintf (stderr, "%% Illegal action type, use dscp or mark\n");
		destroy_args (args);
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
				destroy_args (args);
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
					destroy_args (args);
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
			destroy_args (args);
			return;
		}
		++crsr;
		sprintf (src_address, "%s/32 ", args->argv[crsr]);
		++crsr;
	} else {
		if ((crsr + 2) > args->argc) {
			fprintf (stderr, "%% Missing netmask\n");
			destroy_args (args);
			return;
		}
		src_cidr = netmask2cidr (args->argv[crsr + 1]);
		if (src_cidr < 0) {
			fprintf (stderr, "%% Invalid netmask\n");
			destroy_args (args);
			return;
		}
		sprintf (src_address, "%s/%i ", args->argv[crsr], src_cidr);
		crsr += 2;
	}
	if (crsr >= args->argc) {
		fprintf (stderr, "%% Not enough arguments\n");
		destroy_args (args);
		return;
	}
	if (strcmp (args->argv[crsr], "eq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (src_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (src_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (src_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (src_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (atoi (args->argv[crsr + 1]) > atoi (args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid port range (min > max)\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1]) || !is_valid_port (
		                args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
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
			destroy_args (args);
			return;
		}

		dst_cidr = netmask2cidr (args->argv[crsr + 1]);
		if (dst_cidr < 0) {
			fprintf (stderr, "%% Invalid netmask\n");
			destroy_args (args);
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
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (dst_portrange, "%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "neq") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (dst_portrange, "! %s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "gt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (dst_portrange, "%s: ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "lt") == 0) {
		if ((crsr + 1) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
			return;
		}
		sprintf (dst_portrange, ":%s ", args->argv[crsr + 1]);
		crsr += 2;
	} else if (strcmp (args->argv[crsr], "range") == 0) {
		if ((crsr + 2) >= args->argc) {
			fprintf (stderr, "%% Not enough arguments\n");
			destroy_args (args);
			return;
		}
		if (atoi (args->argv[crsr + 1]) > atoi (args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid port range (min > max)\n");
			destroy_args (args);
			return;
		}
		if (!is_valid_port (args->argv[crsr + 1]) || !is_valid_port (
		                args->argv[crsr + 2])) {
			fprintf (stderr, "%% Invalid argument\n");
			destroy_args (args);
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
				destroy_args (args);
				return;
			}
			tos = args->argv[crsr + 1];
			crsr++;
		} else if (strcmp (args->argv[crsr], "flags") == 0) {
			crsr++;
			if (crsr >= args->argc) {
				fprintf (stderr, "%% Not enough arguments\n");
				destroy_args (args);
				return;
			}
			flags = args->argv[crsr];
		} else if (strcmp (args->argv[crsr], "dscp") == 0) {
			if ((crsr + 1) >= args->argc) {
				fprintf (stderr, "%% Not enough arguments\n");
				destroy_args (args);
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
		destroy_args (args);
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
			dump_mangle (0, f, 1);
			fseek (f, 0, SEEK_SET);
			while (fgets ((char *) buf, 511, f)) {
				if ((n = parse_args_din ((char *) buf, &argl))
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
								free_args_din (
								                &argl);
								break;
							}
						}
					}
				}
				free_args_din (&argl);
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
	destroy_args (args);
}

void no_mangle_rule (const char *cmdline)
{
	arglist *args;
	char *mangle;
	char cmd[256];

	args = make_args (cmdline);
	mangle = args->argv[2]; /* no mark-rule <name> */
	if (!mangle_exists (mangle)) {
		destroy_args (args);
		return;
	}
	if (get_mangle_refcount (mangle)) {
		printf ("%% mark-rule in use, can't delete\n");
		destroy_args (args);
		return;
	}
	sprintf (cmd, "/bin/iptables -t mangle -F %s", mangle); /* flush */
	system (cmd);

	sprintf (cmd, "/bin/iptables -t mangle -X %s", mangle); /* delete */

	system (cmd);

	destroy_args (args);
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
		striplf (buf);
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
		striplf (buf);
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
			args = make_args (p);

			if (args->argc < 7) {
				destroy_args (args);
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
				destroy_args (args);
				break;
			}
			destroy_args (args);
		}
	}
	pclose (F);
	return mangle_exists;
}

int get_iface_mangle_rules (char *iface, char *in_mangle, char *out_mangle)
{
	typedef enum {
		chain_in, chain_out, chain_other
	} mangle_chain;
	FILE *F;
	char buf[256];
	mangle_chain chain = chain_in;
	char *iface_in_, *iface_out_, *target;
	char *mangle_in = NULL, *mangle_out = NULL;
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
		striplf (buf);
		if (strncmp (buf, "Chain ", 6) == 0) {
			if (strncmp (buf + 6, "INPUT", 5) == 0)
				chain = chain_in;
			else if (strncmp (buf + 6, "OUTPUT", 6) == 0)
				chain = chain_out;
			else
				chain = chain_other;
		} else if ((strncmp (buf, " pkts", 5) != 0) && (strlen (buf)
		                > 40)) {
			arglist *args;
			char *p;

			p = buf;
			while ((*p) && (*p == ' '))
				p++;
			args = make_args (p);
			if (args->argc < 7) {
				destroy_args (args);
				continue;
			}
			iface_in_ = args->argv[5];
			iface_out_ = args->argv[6];
			target = args->argv[2];
			if ((chain == chain_in) && (strcmp (iface, iface_in_)
			                == 0)) {
				mangle_in = target;
				strncpy (in_mangle, mangle_in, 100);
				in_mangle[100] = 0;
			}
			if ((chain == chain_out) && (strcmp (iface, iface_out_)
			                == 0)) {
				mangle_out = target;
				strncpy (out_mangle, mangle_out, 100);
				out_mangle[100] = 0;
			}
			if (mangle_in && mangle_out)
				break;
			destroy_args (args);
		}
	}
	pclose (F);
	return 0;
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
		striplf (buf);
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
		striplf (buf);
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
			args = make_args (p);
			if (args->argc < 7) {
				destroy_args (args);
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
			destroy_args (args);
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

	dev = convert_device (interface_edited->cish_string, interface_major,
	                interface_minor);
	args = make_args (cmdline);
	listno = args->argv[2]; /* ip mark <name> in|out */
	if (strcasecmp (args->argv[3], "in") == 0)
		chain = chain_in;
	else if (strcasecmp (args->argv[3], "out") == 0)
		chain = chain_out;
	if (!mangle_exists (listno)) {
		printf ("%% mark-rule %s undefined\n", listno);
		free (dev);
		destroy_args (args);
		return;
	}
	if ((chain == chain_in) && (matched_mangle_exists (0, dev, 0, "INPUT")
	                || matched_mangle_exists (0, dev, 0, "PREROUTING"))) {
		printf ("%% inbound MARK rule already defined.\n");
		free (dev);
		destroy_args (args);
		return;
	}
	if ((chain == chain_out)
	                && (matched_mangle_exists (0, 0, dev, "OUTPUT")
	                                || matched_mangle_exists (0, 0, dev,
	                                                "POSTROUTING"))) {
		printf ("%% outbound MARK rule already defined.\n");
		free (dev);
		destroy_args (args);
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
	destroy_args (args);
	free (dev);
}

void interface_no_mangle (const char *cmdline)
{
	arglist *args;
	char *dev;
	acl_chain chain = chain_in;
	char *listno;

	dev = convert_device (interface_edited->cish_string, interface_major,
	                interface_minor);
	args = make_args (cmdline); /* no ip mark <name> in|out */
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
	destroy_args (args);
	free (dev);
}

