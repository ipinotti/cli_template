/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/config.h>
#include <linux/if_arp.h>

#include "options.h"
#include "commands.h"
#include "../libconfig/cish_defines.h"
#include "../libconfig/device.h"
#include "../libconfig/args.h"
#include "../libconfig/exec.h"
#include "../libconfig/error.h"
#include "../libconfig/dev.h"
#include "../libconfig/nv.h"
#include "../libconfig/str.h"
#include "../libconfig/x25.h"
#include "pprintf.h"
#include "cish_main.h"
#include "cish_config.h"

#ifdef OPTION_X25

void x25_param(const char *_cmd) /* [no] x25 [options!] */
{
	const char	*cmd;
	const char	*dst_file;
	int  		 dst_val, no=0;
	FILE		*F;

	if (strncmp(_cmd, "no ", 3) == 0) {
		no=1;
		cmd = _cmd + 3; /* skip "no " */
	}
		else cmd = _cmd;
	dst_file	= (const char *) NULL;
	dst_val     = -1;
#ifdef OPTION_X25XOT
	if (strncmp(cmd, "x25 routing", 11) == 0)
	{
		dst_val  = no ? 0 : 1;
		dst_file = "/proc/sys/net/x25/x25_forward";
	} else
#endif
	if (strncmp(cmd, "x25 t2 ", 7) == 0)
	{
		if (no || (dst_val = atoi(cmd+7)) <= 0)
		{
			printf("%% Parameter error\n");
			return;
		}
		dst_val *= HZ;
		dst_file = "/proc/sys/net/x25/acknowledgement_hold_back_timeout";
	} else
	if (strncmp(cmd, "x25 t20 ", 8) == 0)
	{
		if (no || (dst_val = atoi(cmd+8)) <= 0)
		{
			printf("%% Parameter error\n");
			return;
		}
		dst_val *= HZ;
		dst_file = "/proc/sys/net/x25/restart_request_timeout";
	} else
	if (strncmp(cmd, "x25 t21 ", 8) == 0)
	{
		if (no || (dst_val = atoi(cmd+8)) <= 0)
		{
			printf("%% Parameter error\n");
			return;
		}
		dst_val *= HZ;
		dst_file = "/proc/sys/net/x25/call_request_timeout";
	} else
	if (strncmp(cmd, "x25 t22 ", 8) == 0)
	{
		if (no || (dst_val = atoi(cmd+8)) <= 0)
		{
			printf("%% Parameter error\n");
			return;
		}
		dst_val *= HZ;
		dst_file = "/proc/sys/net/x25/reset_request_timeout";
	} else
	if (strncmp(cmd, "x25 t23 ", 8) == 0)
	{
		if (no || (dst_val = atoi(cmd+8)) <= 0)
		{
			printf("%% Parameter error\n");
			return;
		}
		dst_val *= HZ;
		dst_file = "/proc/sys/net/x25/clear_request_timeout";
	}
	if (!dst_file)
	{
		printf("%% Error\n");
		return;
	}
	F = fopen(dst_file, "w");
	if (!F)
	{
		printf("%% Error opening %s\n", dst_file);
		return;
	}
	fprintf(F, "%d", dst_val);
	fclose(F);
}

void x25_route_interface(const char *cmdline) /* [no] x25 route <x121> interface serial <0-1> */
{
	int no=0;
	arglist *args;

	args=make_args(cmdline);
	if (strcmp(args->argv[0], "no") == 0)
		no=1;
	if (args->argc != no+6) {
		printf("%% Error\n");
		goto clean;
	}
	x25_route(no ? 0 : 1, atoi(args->argv[no+5]), args->argv[no+2]);
clean:
	destroy_args(args);
}

#ifdef OPTION_X25XOT
void x25_route_xot(const char *cmdline) /* [no] x25 route <x121> xot <ipaddress> */
{
	int no=0;
	arglist *args;

	args=make_args(cmdline);
	if (strcmp(args->argv[0], "no") == 0)
		no=1;
	if (args->argc != no+5) {
		printf("%% Error\n");
		goto clean;
	}
	x25_route_xotd(no ? 0 : 1, args->argv[no+4], args->argv[no+2]);
clean:
	destroy_args(args);
}
#endif

void dump_x25_routes(FILE *out)
{
	FILE *f;
	int i, serial_no;
	char filename[50];
	struct x25_route_database database[X25_MAX_ROUTES];
#ifdef OPTION_X25XOT
	int j;
	struct x25_xot_database xot_database[X25_XOTD_MAX_ROUTES];
#endif

	/* X.121 routes */
	for (serial_no=0; serial_no < MAX_WAN_INTF; serial_no++) {
		/* database verify */
		memset(&database[0], 0, sizeof(database));
		sprintf(filename, X25_ROUTES_FILE, SERIALDEV, serial_no);
		f=fopen(filename, "rb");
		if (f) {
			fread(&database[0], sizeof(database), 1, f);
			fclose(f);
		}
			else continue; /* next interface! */
		for (i=0; i < X25_MAX_ROUTES; i++) {
			if (database[i].valid) {
				pfprintf(out, "x25 route %s/%d interface %s %d\n", database[i].x25_route.address.x25_addr, database[i].x25_route.sigdigits, SERIALDEV, serial_no);
			}
		}
	}
#ifdef OPTION_X25XOT
	/* xot routes */
	memset(&xot_database[0], 0, sizeof(xot_database));
	sprintf(filename, X25_XOTD_FILE);
	f=fopen(filename, "rb");
	if (f) {
		fread(&xot_database[0], sizeof(xot_database), 1, f);
		fclose(f);
		for (i=0; i < X25_XOTD_MAX_TAPS; i++) {
			if (xot_database[i].valid) {
				for (j=0; j < X25_XOTD_MAX_ROUTES; j++) {
					if (xot_database[i].db[j].valid)
						pfprintf (out, "x25 route %s/%d xot %s\n",
							xot_database[i].db[j].x25_route.address.x25_addr, xot_database[i].db[j].x25_route.sigdigits,
							xot_database[i].ip_addr);
				}
			}
		}
	}
#endif
}

int get_procx25_val(const char *parm)
{
	int fid;

	sprintf(buf, "/proc/sys/net/x25/%s", parm);
	fid = open(buf, O_RDONLY);
	if (fid < 0)
	{
		printf ("%% Error opening %s\n%% %s\n", buf, strerror(errno));
		close(fid);
		return -1;
	}
	read(fid, buf, 16);
	close(fid);
	return atoi(buf);
}

void dump_x25(FILE *out)
{
	int val;

	/* routes */
	dump_x25_routes(out);
	/* proc */
#ifdef OPTION_X25XOT
	val = get_procx25_val("x25_forward");
	if (val) /* "no x25 routing\n" */
		pfprintf(out, "x25 routing\n");
#endif
	val = get_procx25_val("acknowledgement_hold_back_timeout");
#if 0
	if (val != X25_DEFAULT_T2)
		pfprintf(out, "x25 t2 %d\n", val/HZ);
	val = get_procx25_val("restart_request_timeout");
	if (val != X25_DEFAULT_T20)
		pfprintf(out, "x25 t20 %d\n", val/HZ);
	val = get_procx25_val("call_request_timeout");
	if (val != X25_DEFAULT_T21)
		pfprintf(out, "x25 t21 %d\n", val/HZ);
	val = get_procx25_val("reset_request_timeout");
	if (val != X25_DEFAULT_T22)
		pfprintf(out, "x25 t22 %d\n", val/HZ);
	val = get_procx25_val("clear_request_timeout");
	if (val != X25_DEFAULT_T23)
		pfprintf(out, "x25 t23 %d\n", val/HZ);
#else
	/* show default values */
	pfprintf(out, "x25 t2 %d\n", val/HZ);
	val = get_procx25_val("restart_request_timeout");
	pfprintf(out, "x25 t20 %d\n", val/HZ);
	val = get_procx25_val("call_request_timeout");
	pfprintf(out, "x25 t21 %d\n", val/HZ);
	val = get_procx25_val("reset_request_timeout");
	pfprintf(out, "x25 t22 %d\n", val/HZ);
	val = get_procx25_val("clear_request_timeout");
	pfprintf(out, "x25 t23 %d\n", val/HZ);
#endif
	pfprintf (out, "!\n");
}

extern device_family *interface_edited;
extern int interface_major, interface_minor;

void interface_x25_address(const char *cmdline) /* [no] x25 address <x121> */
{
	arglist *args;
	char *dev, *p;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.x121local.x25_addr[0]=0;
	} else {
		if ((p=strchr(args->argv[2], '/')) != NULL)
			*p=0;
		strcpy(conf.x121local.x25_addr, args->argv[2]);
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_debug(const char *cmdline) /* [no] x25 debug [packet] */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.debug=conf.subscrip.debug=0;
	} else {
		if (args->argc == 3 && strcmp(args->argv[2], "packet") == 0) {
			conf.debug=conf.subscrip.debug=2;
		} else {
			conf.debug=conf.subscrip.debug=1;
		}
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_facility_called_ae(const char *cmdline) /* [no] x25 facility called_ae */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.subscrip.global_facil_mask &= ~X25_MASK_CALLED_AE;
	} else {
		conf.subscrip.global_facil_mask |= X25_MASK_CALLED_AE;
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_facility_calling_ae(const char *cmdline) /* [no] x25 facility calling_ae */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.subscrip.global_facil_mask &= ~X25_MASK_CALLING_AE;
	} else {
		conf.subscrip.global_facil_mask |= X25_MASK_CALLING_AE;
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

/* 16 32 64 128 256 512 1024 2048 4096 */
void interface_x25_facility_packetsize(const char *cmdline) /* [no] x25 facility packetsize <in> <out> */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;
	int size, i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.subscrip.global_facil_mask &= ~X25_MASK_PACKET_SIZE;
	} else {
		size=atoi(args->argv[3]);
		for (i=1; 1<<i != size && i < 13; i++);
		if (i == 13) {
			printf("%% invalid packet size!\n");
			goto error;
		}
		conf.facilities.pacsize_in=i; /* 4-12 */
		size=atoi(args->argv[4]);
		for (i=1; 1<<i != size && i < 13; i++);
		if (i == 13) {
			printf("%% invalid packet size!\n");
			goto error;
		}
		conf.facilities.pacsize_out=i; /* 4-12 */
		conf.subscrip.global_facil_mask |= X25_MASK_PACKET_SIZE;
	}
	x25_set_devconfig(dev, &conf);
error:
	free(dev);
	destroy_args(args);
}

/* 0x80 for fast-call! */
void interface_x25_facility_reverse(const char *cmdline) /* [no] x25 facility reverse */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.facilities.reverse=0x00;
		conf.subscrip.global_facil_mask &= ~X25_MASK_REVERSE;
	} else {
		conf.facilities.reverse=0x01;
		conf.subscrip.global_facil_mask |= X25_MASK_REVERSE;
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_facility_throughput(const char *cmdline) /* [no] x25 facility throughput 75-192000 75-192000 */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;
	int i;
	const char throughput[][7] = { "X", "X", "X", "75", "150", "300", "600", "1200", "2400", "4800", "9600", "19200", "48000", "64000", "128000", "192000" };

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.subscrip.global_facil_mask &= ~X25_MASK_THROUGHPUT;
	} else {
		for (i=0; i < 16; i++) {
			if (strcmp(throughput[i], args->argv[3]) == 0) {
				conf.facilities.throughput = i << 4; /* input; from the called DTE */
				break;
			}
		}
		for (i=0; i < 16; i++) {
			if (strcmp(throughput[i], args->argv[4]) == 0) {
				conf.facilities.throughput |= i; /* output; from the calling DTE */
				break;
			}
		}
		conf.subscrip.global_facil_mask |= X25_MASK_THROUGHPUT;
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_facility_windowsize(const char *cmdline) /* [no] x25 facility windowsize <in> <out> */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.subscrip.global_facil_mask &= ~X25_MASK_WINDOW_SIZE;
	} else {
		conf.facilities.winsize_in=atoi(args->argv[3]);
		conf.facilities.winsize_out=atoi(args->argv[4]);
		conf.subscrip.global_facil_mask |= X25_MASK_WINDOW_SIZE;
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_idle(const char *cmdline) /* [no] x25 idle <1-1440> */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.idle=0;
	} else {
		conf.idle=atoi(args->argv[2]);
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

/* 16 32 64 128 256 512 1024 2048 4096 */
void interface_x25_ips(const char *cmdline) /* x25 ips <in> */
{
	arglist *args;
	char *dev;
	struct x25_intf_config conf;
	int size, i;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	size=atoi(args->argv[2]);
	for (i=1; 1<<i != size && i < 13; i++);
	if (i == 13) {
		printf("%% invalid packet size!\n");
		goto error;
	}
	conf.facilities.pacsize_in=i; /* 4-12 */
	x25_set_devconfig(dev, &conf);
error:
	free(dev);
	destroy_args(args);
}

void interface_x25_vc(const char *cmdline) /* x25 lic|hic|ltc|htc|loc|hoc 0-4095 */
{
	char *dev;
	arglist *args;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[1], "lic") == 0) {
		conf.subscrip.lic = atoi(args->argv[2]);
		if (conf.subscrip.lic > 4095 || (conf.subscrip.lic &&
			((conf.subscrip.hic && conf.subscrip.hic < conf.subscrip.lic) ||
			(conf.subscrip.ltc && conf.subscrip.ltc <= conf.subscrip.lic) ||
			(conf.subscrip.htc && conf.subscrip.htc <= conf.subscrip.lic) ||
			(conf.subscrip.loc && conf.subscrip.loc <= conf.subscrip.lic) ||
			(conf.subscrip.hoc && conf.subscrip.hoc <= conf.subscrip.lic)))) {
			printf("%% invalid lic value, must be in interval: lic <= hic < ltc <= htc < loc <= hoc\n");
			goto error;
		}
		if (!conf.subscrip.lic)
			conf.subscrip.hic = 0;
		else if (!conf.subscrip.hic)
				conf.subscrip.hic = conf.subscrip.lic;
	} else if (strcmp(args->argv[1], "hic") == 0) {
		conf.subscrip.hic = atoi(args->argv[2]);
		if (conf.subscrip.hic > 4095 || (conf.subscrip.hic &&
			((conf.subscrip.lic && conf.subscrip.lic > conf.subscrip.hic) ||
			(conf.subscrip.ltc && conf.subscrip.ltc <= conf.subscrip.hic) ||
			(conf.subscrip.htc && conf.subscrip.htc <= conf.subscrip.hic) ||
			(conf.subscrip.loc && conf.subscrip.loc <= conf.subscrip.hic) ||
			(conf.subscrip.hoc && conf.subscrip.hoc <= conf.subscrip.hic)))) {
			printf("%% invalid hic value, must be in interval: lic <= hic < ltc <= htc < loc <= hoc\n");
			goto error;
		}
		if (!conf.subscrip.hic)
			conf.subscrip.lic = 0;
		else if (!conf.subscrip.lic)
				conf.subscrip.lic = conf.subscrip.hic;
	} else if (strcmp(args->argv[1], "ltc") == 0) {
		conf.subscrip.ltc = atoi(args->argv[2]);
		if (conf.subscrip.ltc > 4095 || (conf.subscrip.ltc &&
			((conf.subscrip.lic && conf.subscrip.lic >= conf.subscrip.ltc) ||
			(conf.subscrip.hic && conf.subscrip.hic >= conf.subscrip.ltc) ||
			(conf.subscrip.htc && conf.subscrip.htc < conf.subscrip.ltc) ||
			(conf.subscrip.loc && conf.subscrip.loc <= conf.subscrip.ltc) ||
			(conf.subscrip.hoc && conf.subscrip.hoc <= conf.subscrip.ltc)))) {
			printf("%% invalid ltc value, must be in interval: lic <= hic < ltc <= htc < loc <= hoc\n");
			goto error;
		}
		if (!conf.subscrip.ltc)
			conf.subscrip.htc = 0;
		else if (!conf.subscrip.htc)
				conf.subscrip.htc = conf.subscrip.ltc;
	} else if (strcmp(args->argv[1], "htc") == 0) {
		conf.subscrip.htc = atoi(args->argv[2]);
		if (conf.subscrip.htc > 4095 || (conf.subscrip.htc &&
			((conf.subscrip.lic && conf.subscrip.lic >= conf.subscrip.htc) ||
			(conf.subscrip.hic && conf.subscrip.hic >= conf.subscrip.htc) ||
			(conf.subscrip.ltc && conf.subscrip.ltc > conf.subscrip.htc) ||
			(conf.subscrip.loc && conf.subscrip.loc <= conf.subscrip.htc) ||
			(conf.subscrip.hoc && conf.subscrip.hoc <= conf.subscrip.htc)))) {
			printf("%% invalid htc value, must be in interval: lic <= hic < ltc <= htc < loc <= hoc\n");
			goto error;
		}
		if (!conf.subscrip.htc)
			conf.subscrip.ltc = 0;
		else if (!conf.subscrip.ltc)
				conf.subscrip.ltc = conf.subscrip.htc;
	} else if (strcmp(args->argv[1], "loc") == 0) {
		conf.subscrip.loc = atoi(args->argv[2]);
		if (conf.subscrip.loc > 4095 || (conf.subscrip.loc &&
			((conf.subscrip.lic && conf.subscrip.lic >= conf.subscrip.loc) ||
			(conf.subscrip.hic && conf.subscrip.hic >= conf.subscrip.loc) ||
			(conf.subscrip.ltc && conf.subscrip.ltc >= conf.subscrip.loc) ||
			(conf.subscrip.htc && conf.subscrip.htc >= conf.subscrip.loc) ||
			(conf.subscrip.hoc && conf.subscrip.hoc < conf.subscrip.loc)))) {
			printf("%% invalid loc value, must be in interval: lic <= hic < ltc <= htc < loc <= hoc\n");
			goto error;
		}
		if (!conf.subscrip.loc)
			conf.subscrip.hoc = 0;
		else if (!conf.subscrip.hoc)
				conf.subscrip.hoc = conf.subscrip.loc;
	} else if (strcmp(args->argv[1], "hoc") == 0) {
		conf.subscrip.hoc = atoi(args->argv[2]);
		if (conf.subscrip.hoc > 4095 || (conf.subscrip.hoc &&
			((conf.subscrip.lic && conf.subscrip.lic >= conf.subscrip.hoc) ||
			(conf.subscrip.hic && conf.subscrip.hic >= conf.subscrip.hoc) ||
			(conf.subscrip.ltc && conf.subscrip.ltc >= conf.subscrip.hoc) ||
			(conf.subscrip.htc && conf.subscrip.htc >= conf.subscrip.hoc) ||
			(conf.subscrip.loc && conf.subscrip.loc > conf.subscrip.hoc)))) {
			printf("%% invalid hoc value, must be in interval: lic <= hic < ltc <= htc < loc <= hoc\n");
			goto error;
		}
		if (!conf.subscrip.hoc)
			conf.subscrip.loc = 0;
		else if (!conf.subscrip.loc)
				conf.subscrip.loc = conf.subscrip.hoc;
	}
	if (!conf.subscrip.lic && !conf.subscrip.hic && !conf.subscrip.ltc && !conf.subscrip.htc && !conf.subscrip.loc && !conf.subscrip.hoc) {
		printf("%% invalid, all intervals disabled!\n");
		goto error;
	}
	x25_set_devconfig(dev, &conf);
error:
	free(dev);
	destroy_args(args);
}

extern cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_OUT[];
extern cish_command CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_IN[];
extern cish_command CMD_CONFIG_INTERFACE_X25_WIN[];
extern cish_command CMD_CONFIG_INTERFACE_X25_WOUT[];

void interface_x25_modulo(const char *cmdline) /* x25 modulo 8|128 */
{
	char *dev;
	arglist *args;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[2], "128") == 0) {
		conf.subscrip.extended=1;
		CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_IN[0].name="1-127";
		CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_OUT[0].name="1-127";
		CMD_CONFIG_INTERFACE_X25_WIN[0].name="1-127";
		CMD_CONFIG_INTERFACE_X25_WOUT[0].name="1-127";
	} else {
		conf.subscrip.extended=0;
		CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_IN[0].name="1-7";
		CMD_CONFIG_INTERFACE_X25_FACILITY_WINDOWSIZE_OUT[0].name="1-7";
		CMD_CONFIG_INTERFACE_X25_WIN[0].name="1-7";
		CMD_CONFIG_INTERFACE_X25_WOUT[0].name="1-7";
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

/* 16 32 64 128 256 512 1024 2048 4096 */
void interface_x25_ops(const char *cmdline) /* x25 ops <out> */
{
	char *dev;
	int size, i;
	arglist *args;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	size=atoi(args->argv[2]);
	for (i=1; 1<<i != size && i < 13; i++);
	if (i == 13) {
		printf("%% invalid packet size!\n");
		goto error;
	}
	conf.facilities.pacsize_out=i; /* 4-12 */
	x25_set_devconfig(dev, &conf);
error:
	free(dev);
	destroy_args(args);
}

void interface_x25_suppresscallingaddress(const char *cmdline) /* [no] x25 suppress-calling-address */
{
	char *dev;
	arglist *args;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	if (strcmp(args->argv[0], "no") == 0) {
		conf.suppresscallingaddress=0;
	} else {
		conf.suppresscallingaddress=1;
	}
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_win(const char *cmdline) /* x25 win <in> */
{
	char *dev;
	arglist *args;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	conf.facilities.winsize_in=atoi(args->argv[2]);
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void interface_x25_wout(const char *cmdline) /* x25 wout <out> */
{
	char *dev;
	arglist *args;
	struct x25_intf_config conf;

	args=make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	x25_get_devconfig(dev, &conf);
	conf.facilities.winsize_out=atoi(args->argv[2]);
	x25_set_devconfig(dev, &conf);
	free(dev);
	destroy_args(args);
}

void dump_x25_config(FILE *out, char *dev)
{
	struct x25_intf_config conf;

	x25_get_devconfig(dev, &conf);
	if (conf.x121local.x25_addr[0])
		pfprintf(out, " x25 address %s\n", conf.x121local.x25_addr);
	else
		pfprintf(out, " no x25 address\n");
#if 1 /* !!! Configuracao de debug nao persistente! */
	if (conf.debug)
		pfprintf(out, " x25 debug%s\n", conf.debug == 2 ? " packet": "");
#endif
	if (conf.subscrip.global_facil_mask & X25_MASK_CALLED_AE)
		pfprintf(out, " x25 facility called_ae\n");
	else
		pfprintf(out, " no x25 facility called_ae\n");
	if (conf.subscrip.global_facil_mask & X25_MASK_CALLING_AE)
		pfprintf(out, " x25 facility calling_ae\n");
	else
		pfprintf(out, " no x25 facility calling_ae\n");
	if (conf.subscrip.global_facil_mask & X25_MASK_PACKET_SIZE)
		pfprintf(out, " x25 facility packetsize %d %d\n",
			1<<conf.facilities.pacsize_in, 1<<conf.facilities.pacsize_out);
	else
		pfprintf(out, " no x25 facility packetsize\n");
	if (conf.facilities.reverse)
		pfprintf(out, " x25 facility reverse\n");
	else
		pfprintf(out, " no x25 facility reverse\n");
	if (conf.subscrip.global_facil_mask & X25_MASK_THROUGHPUT)
		pfprintf(out, " x25 facility throughput %d\n", conf.facilities.throughput);
	else
		pfprintf(out, " no x25 facility throughput\n");
	if (conf.subscrip.global_facil_mask & X25_MASK_WINDOW_SIZE)
		pfprintf(out, " x25 facility windowsize %d %d\n",
			conf.facilities.winsize_in, conf.facilities.winsize_out);
	else
		pfprintf(out, " no x25 facility windowsize\n");
	if (conf.subscrip.hic)
		pfprintf(out, " x25 hic %d\n", conf.subscrip.hic);
	if (conf.subscrip.hoc)
		pfprintf(out, " x25 hoc %d\n", conf.subscrip.hoc);
	if (conf.subscrip.htc)
		pfprintf(out, " x25 htc %d\n", conf.subscrip.htc);
	pfprintf(out, " x25 ips %d\n", 1<<conf.facilities.pacsize_in);
	if (conf.idle)
		pfprintf(out, " x25 idle %d\n", conf.idle);
	else
		pfprintf(out, " no x25 idle\n");
	if (conf.subscrip.lic)
		pfprintf(out, " x25 lic %d\n", conf.subscrip.lic);
	if (conf.subscrip.loc)
		pfprintf(out, " x25 loc %d\n", conf.subscrip.loc);
	if (conf.subscrip.ltc)
		pfprintf(out, " x25 ltc %d\n", conf.subscrip.ltc);
	pfprintf(out, " x25 modulo %d\n", conf.subscrip.extended ? 128 : 8);
	pfprintf(out, " x25 ops %d\n", 1<<conf.facilities.pacsize_out);
	if (conf.suppresscallingaddress)
		pfprintf(out, " x25 suppress-calling-address\n");
	pfprintf(out, " x25 win %d\n", conf.facilities.winsize_in);
	pfprintf(out, " x25 wout %d\n", conf.facilities.winsize_out);
}

#ifdef OPTION_X25MAP
/*
	x25 map api-auto <x121> [cud <cud>] local port <port>
	x25 map api-auto <x121> [cud <cud>] remote host <ipaddress> port <port>
	x25 map api-manual <x121> [cud <cud>] local port <port>
	x25 map raw <x121> [cud <cud>] local port <port>
	x25 map raw <x121> [cud <cud>] remote host <ipaddress> port <port>
	x25 map rbp <x121> [cud <cud>] local port <port>
	x25 map rbp <x121> [cud <cud>] remote host <ipaddress> port <port>
*/
void interface_x25_map(const char *cmdline) /* [no] x25 map [...] */
{
	int no=0, cud=0;
	char *dev, *p;
	char *cudstring, *ipaddress, *port, *mc;
	arglist *args;

	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	args=make_args(cmdline);
	if (strcmp(args->argv[0], "no") == 0) {
		no=1;
		if (args->argc == 3) {
			x25_map_clean(dev);
			goto clean;
		}
	}
	if (strcmp(args->argv[no+4], "cud") == 0) {
		cud=2;
		cudstring=args->argv[no+5];
	} else {
		cudstring=NULL;
	}
	if (strcmp(args->argv[no+cud+4], "remote") == 0) {
		ipaddress=args->argv[no+cud+6];
		port=args->argv[no+cud+8];
		if (args->argc == no+cud+10) {
			mc=args->argv[no+cud+9];
		} else mc="";
	} else if (strcmp(args->argv[no+cud+4], "local") == 0) {
		ipaddress=NULL; /* local inbound! */
		port=args->argv[no+cud+6];
		if (args->argc == no+cud+8) {
			mc=args->argv[no+cud+7];
		} else mc="";
	} else {
		printf("%% Error\n");
		goto clean;
	}
	if ((p=strchr(args->argv[no+3], '/')) != NULL)
		*p=0;
	x25_map(no ? 0 : 1, dev, args->argv[no+2], args->argv[no+3], cudstring, ipaddress, port, mc); /* add/del, interface, type, remote, cud, ipaddress, port */
clean:
	destroy_args(args);
	free(dev);
}

void dump_x25_map(FILE *out, char *dev)
{
	FILE *f;
	int i; /* counter */
	char filename[50];
	struct x25map_config database[X25MAP_MAX];

	sprintf(filename, X25MAP_FILE, dev);
	if ((f=fopen(filename, "rb")) == NULL)
		return; /* file not found! */
	fread(&database[0], sizeof(database), 1, f);
	fclose(f);
	for (i=0; i < X25MAP_MAX; i++) {
		if (database[i].valid) {
			pfprintf(out, " x25 map %s %s", database[i].type, database[i].x121remote.x25_addr);
			if (database[i].cudstring[0])
				pfprintf(out, " cud %s", database[i].cudstring);
			if (database[i].ip_addr[0])
				pfprintf(out, " remote host %s port %d", database[i].ip_addr, database[i].ip_port);
			else
				pfprintf(out, " local port %d", database[i].ip_port);
			if (database[i].mc) pfprintf(out, " multiconnection\n");
				else pfprintf(out, "\n");
		}
	}
}
#endif /* OPTION_X25MAP */
#endif /* OPTION_X25 */
