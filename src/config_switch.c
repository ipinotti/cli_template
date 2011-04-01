/*
 * config_switch.c
 *
 *  Created on: Dec 6, 2010
 *      Author: Thomás Alimena Del Grande (tgrande@pd3.com.br)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/autoconf.h>
#include <linux/types.h>

#include <librouter/options.h>
#include <librouter/args.h>

#if defined (OPTION_MANAGED_SWITCH)

extern int switch_port;
extern int interface_major;
extern int interface_minor;

#if defined (CONFIG_DIGISTAR_EFM)

#include <librouter/ksz8863.h>

void sw_egress_traffic_shape(const char *cmdline)
{
	arglist *args;
	int prio, rate;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no")) {
		prio = atoi(args->argv[2]);
		librouter_ksz8863_set_egress_rate_limit(switch_port, prio, 0);
	} else {
		prio = atoi(args->argv[1]);
		rate = atoi(args->argv[2]);
		if (rate < 1000)
			fprintf(stdout, "%% Rounding value to a 64kbps multiple : %dKbps\n", (rate
			                / 64) * 64);
		else
			fprintf(stdout, "%% Rounding value to a 1Mbps multiple : %dMbps\n", rate
			                / 1000);
		librouter_ksz8863_set_egress_rate_limit(interface_major, prio, rate);
	}
	librouter_destroy_args(args);
}

void sw_ingress_rate_limit(const char *cmdline)
{
	arglist *args;
	int prio, rate;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no")) {
		prio = atoi(args->argv[2]);
		librouter_ksz8863_set_ingress_rate_limit(switch_port, prio, 0);
	} else {
		prio = atoi(args->argv[1]);
		rate = atoi(args->argv[2]);
		if (rate < 1000)
			fprintf(stdout, "%% Rounding value to a 64kbps multiple : %dKbps\n", (rate
			                / 64) * 64);
		else
			fprintf(stdout, "%% Rounding value to a 1Mbps multiple : %dMbps\n", rate
			                / 1000);
		librouter_ksz8863_set_ingress_rate_limit(switch_port, prio, rate);
	}
	librouter_destroy_args(args);
}

void sw_vlan_default(const char *cmdline)
{
	arglist *args;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		librouter_ksz8863_set_default_vid(switch_port, 0);
	else
		librouter_ksz8863_set_default_vid(switch_port, atoi(args->argv[1]));

	librouter_destroy_args(args);
	return;
}

void sw_multicast_storm_protect(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	librouter_ksz8863_set_multicast_storm_protect(enable);

	librouter_destroy_args(args);
	return;
}

void sw_broadcast_storm_protect(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	librouter_ksz8863_set_broadcast_storm_protect(enable, switch_port);

	librouter_destroy_args(args);
	return;
}

void sw_broadcast_storm_protect_rate(const char *cmdline)
{
	arglist *args;
	int perc = 1;

	args = librouter_make_args(cmdline);

	if (args->argc < 3) {
		printf("Wrong number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	perc = atoi(args->argv[2]);

	librouter_ksz8863_set_storm_protect_rate(perc);

	librouter_destroy_args(args);
	return;
}

void sw_replace_null_vid(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_ksz8863_set_replace_null_vid(enable) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;

}

void sw_enable_wfq(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_ksz8863_set_wfq(enable) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_8021q(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_ksz8863_set_8021q(enable) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_vlan_entry(const char *cmdline)
{
	arglist *args;
	struct vlan_config_t vconf;

	memset(&vconf, 0, sizeof(vconf));

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no")) {
		vconf.vid = atoi(args->argv[3]);
		librouter_ksz8863_del_table(&vconf);
	} else {
		vconf.vid = atoi(args->argv[2]);
		if (strstr(cmdline, "port-1"))
			vconf.membership |= KSZ8863REG_VLAN_MEMBERSHIP_PORT1_MSK;

		if (strstr(cmdline, "port-2"))
			vconf.membership |= KSZ8863REG_VLAN_MEMBERSHIP_PORT2_MSK;

		if (strstr(cmdline, "internal"))
			vconf.membership |= KSZ8863REG_VLAN_MEMBERSHIP_PORT3_MSK;

		librouter_ksz8863_add_table(&vconf);
	}

	librouter_destroy_args(args);
	return;
}

void sw_8021p(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	librouter_ksz8863_set_8021p(enable, switch_port);

	librouter_destroy_args(args);
	return;
}

void sw_8021p_prio(const char *cmdline)
{
	arglist *args;
	int prio, cos;

	args = librouter_make_args(cmdline);

	if (args->argc < 3) {
		printf("%% Invalid number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	cos = atoi(args->argv[2]);
	prio = atoi(args->argv[3]);

	if (librouter_ksz8863_set_cos_prio(cos, prio) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_dscp(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_ksz8863_set_diffserv(enable, switch_port) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_dscp_prio(const char *cmdline)
{
	arglist *args;
	int prio, dscp;

	args = librouter_make_args(cmdline);

	if (args->argc < 3) {
		printf("%% Invalid number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	dscp = atoi(args->argv[2]);
	prio = atoi(args->argv[3]);

	if (librouter_ksz8863_set_dscp_prio(dscp, prio) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_txqueue_split(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_ksz8863_set_txqsplit(enable, switch_port) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}
/* --- END ------- CONFIG_DIGISTAR_EFM -- */

#elif defined (CONFIG_DIGISTAR_3G)

#include <librouter/bcm53115s.h>

void sw_vlan_default(const char *cmdline)
{
	arglist *args;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		librouter_bcm53115s_set_default_vid(switch_port, 0);
	else
		librouter_bcm53115s_set_default_vid(switch_port, atoi(args->argv[1]));

	librouter_destroy_args(args);
	return;
}


void sw_drop_untagged(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	librouter_bcm53115s_set_drop_untagged(enable, switch_port);

	librouter_destroy_args(args);
	return;
}


void sw_broadcast_storm_protect(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	librouter_bcm53115s_set_broadcast_storm_protect(enable, switch_port);

	librouter_destroy_args(args);
	return;
}

void sw_broadcast_storm_protect_rate(const char *cmdline)
{
	arglist *args;
	int rate = 1;

	args = librouter_make_args(cmdline);

	if (args->argc < 2) {
		printf("Wrong number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	rate = atoi(args->argv[1]);

	librouter_bcm53115s_set_storm_protect_rate(rate, switch_port);

	librouter_destroy_args(args);
	return;
}

void sw_multicast_storm_protect(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	librouter_bcm53115s_set_multicast_storm_protect(enable, switch_port);

	librouter_destroy_args(args);
	return;
}

//TODO
#ifdef NOT_IMPLEMENTED_YET
void sw_replace_null_vid(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_bcm53115s_set_replace_null_vid(enable) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}
#endif

void sw_enable_wrr(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_bcm53115s_set_wrr(enable) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_8021q(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_bcm53115s_set_8021q(enable) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_vlan_entry(const char *cmdline)
{
	arglist *args;
	struct vlan_bcm_config_t vconf;

	memset(&vconf, 0, sizeof(vconf));

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no")) {
		if(!strcmp(args->argv[3],"all-entries")){
			if (librouter_bcm53115s_erase_all_tables() < 0)
				printf("%% Could not erase all Vlans table\n");
		}
		else {
			vconf.vid = atoi(args->argv[3]);
			if (librouter_bcm53115s_del_table(&vconf) < 0)
				printf("%% Could not remove Vlan entry\n");
		}
	}
	else {
		vconf.vid = atoi(args->argv[2]);

		if (strstr(cmdline, "p1"))
			vconf.membership |= 1 << 0;

		if (strstr(cmdline, "p2"))
			vconf.membership |= 1 << 1;

		if (strstr(cmdline, "p3"))
			vconf.membership |= 1 << 2;

		if (strstr(cmdline, "p4"))
			vconf.membership |= 1 << 3;

		if (strstr(cmdline, "pI"))
			vconf.membership |= 1 << 8;

		if (librouter_bcm53115s_add_table(&vconf) < 0){
			printf("%% Could not add Vlan entry\n");
		}

	}

	librouter_destroy_args(args);
	return;
}

void sw_8021p(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	librouter_bcm53115s_set_8021p(enable, switch_port);

	librouter_destroy_args(args);
	return;
}

void sw_8021p_prio(const char *cmdline)
{
	arglist *args;
	int prio, cos;

	args = librouter_make_args(cmdline);

	if (args->argc < 3) {
		printf("%% Invalid number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	cos = atoi(args->argv[2]);
	prio = atoi(args->argv[3]);

	if (librouter_bcm53115s_set_cos_prio(cos, prio) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_dscp(const char *cmdline)
{
	arglist *args;
	int enable = 1;

	args = librouter_make_args(cmdline);

	if (!strcmp(args->argv[0], "no"))
		enable = 0;

	if (librouter_bcm53115s_set_diffserv(enable, switch_port) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}

void sw_dscp_prio(const char *cmdline)
{
	arglist *args;
	int prio, dscp;

	args = librouter_make_args(cmdline);

	if (args->argc < 3) {
		printf("%% Invalid number of arguments\n");
		librouter_destroy_args(args);
		return;
	}

	dscp = atoi(args->argv[2]);
	prio = atoi(args->argv[3]);

	if (librouter_bcm53115s_set_dscp_prio(dscp, prio) < 0)
		printf("%% Could not execute the command\n");

	librouter_destroy_args(args);
	return;
}


/* --- END ------- CONFIG_DIGISTAR_3G -- */

#else /* CONFIG_DIGISTAR_3G */
#error "OPTION_MANAGED_SWITCH is defined, but not supported for this board"
#endif

#endif /* OPTION_MANAGED_SWITCH */
