#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <linux/hdlc.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig/typedefs.h>
#include <libconfig/fr.h>
#include <libconfig/device.h>
#include <libconfig/defines.h>
#include <libconfig/args.h>
#include <libconfig/dev.h>

#ifdef CONFIG_FR_IPHC
#include <linux/iphc.h>
#endif

#ifdef CONFIG_HDLC_FR_EEK
#include <linux/eek.h>
#endif

extern device_family *interface_edited;
extern int interface_major;
extern int interface_minor;
extern int _cish_booting;

int fr_check_if_is_up(int serial_no)
{
	char dev[16];

	sprintf(dev, "%s%d", SERIALDEV, serial_no);
	if (dev_get_link(dev) > 0)
	{
		if (!_cish_booting) printf("%% shutdown interface first\n");
		return 1;
	}
	return 0;
}

void fr_intftype_dce(const char *cmd)
{
	fr_proto fr;
	if (fr_check_if_is_up(interface_major)) return;
	fr_get_config(interface_major, &fr);
	fr.dce = 1;
	fr_set_config(interface_major, &fr);
}

void fr_intftype_dte(const char *cmd)
{
	fr_proto fr;
	if (fr_check_if_is_up(interface_major)) return;
	fr_get_config(interface_major, &fr);
	fr.dce = 0;
	fr_set_config(interface_major, &fr);
}

void fr_lmi(const char *cmd)
{
	arglist *args;
	int val;
	char *what;
	fr_proto fr;
	
	if (fr_check_if_is_up(interface_major))
		return;
	
	args = make_args (cmd);
	val = atoi(args->argv[2]);	
	what = args->argv[1];
	fr_get_config(interface_major, &fr);
	if (strcmp(what, "lmi-n391")==0) fr.n391 = val;
	else if (strcmp(what, "lmi-n392")==0) fr.n392 = val;
	else if (strcmp(what, "lmi-n393")==0) fr.n393 = val;
	else if (strcmp(what, "lmi-t391")==0) fr.t391 = val;
	else if (strcmp(what, "lmi-t392")==0) fr.t392 = val;
	destroy_args (args);
	/* Validacao da configuracao (para evitar erro no ioctl) */
	if (fr.n393 < fr.n392) {
		printf("Number of errors (lmi-n392) must be no greater than number of events (lmi-n393)\n");
		return;
	}
	fr_set_config(interface_major, &fr);
}

void fr_lmi_signalling_auto(const char *cmd)
{
	fr_proto fr;

	if (fr_check_if_is_up(interface_major))
		return;
	fr_get_config(interface_major, &fr);
	if (!fr.dce) {
		//fr.lmi = LMI_AUTO;
		fr.lmi = LMI_DEFAULT;
		fr.lmi_auto = 1;
		fr_set_config(interface_major, &fr);
	} else {
		printf("%% LMI auto only on DTE interface\n");
	}
}

void fr_lmi_signalling_ansi(const char *cmd)
{
	fr_proto fr;
	if (fr_check_if_is_up(interface_major)) return;
	fr_get_config(interface_major, &fr);
	fr.lmi = LMI_ANSI;
	fr_set_config(interface_major, &fr);
}

void fr_lmi_signalling_itu(const char *cmd)
{
	fr_proto fr;
	if (fr_check_if_is_up(interface_major)) return;
	fr_get_config(interface_major, &fr);
	fr.lmi = LMI_CCITT;
	fr_set_config(interface_major, &fr);
}

void fr_lmi_signalling_cisco(const char *cmd)
{
	fr_proto fr;
	if (fr_check_if_is_up(interface_major)) return;
	fr_get_config(interface_major, &fr);
	fr.lmi = LMI_CISCO;
	fr_set_config(interface_major, &fr);
}

void fr_lmi_signalling_none(const char *cmd)
{
	fr_proto fr;
	if (fr_check_if_is_up(interface_major)) return;
	fr_get_config(interface_major, &fr);
	fr.lmi = LMI_NONE;
	fr_set_config(interface_major, &fr);
}

void fr_dlci_add(const char *cmd)
{
	arglist *args;
	int dlci;
	
	args = make_args (cmd);
	
	dlci = atoi(args->argv[2]);	
	fr_add_dlci(interface_major, dlci, 0);
	
	destroy_args (args);
}

void fr_dlci_del(const char *cmd)
{
	arglist *args;
	int dlci;
	
	args = make_args (cmd);
	
	dlci = atoi(args->argv[3]);	
	fr_del_dlci(interface_major, dlci, 0);
	
	destroy_args (args);
}

#ifdef CONFIG_HDLC_FR_LFI
void interface_fr_interleave(const char *cmdline) /* frame-relay interleave [ priority-mark <mark-number> ] */
{
	fr_proto fr;
	arglist *args;
	int i, next, marknum;

	if (fr_check_if_is_up(interface_major))
		return;
	if (fr_get_config(interface_major, &fr) < 0 ) {
		printf("%% Not possible to enable interleave on interface\n");
		return;
	}
	fr.interleave = 1;

	args = make_args(cmdline);
	if( args->argc > 3 ) {
		marknum = atoi(args->argv[3]);
		for(i=0, next=-1; i < CONFIG_MAX_LFI_PRIORITY_MARKS; i++) {
			if( fr.priomarks[i] == marknum ) {
				printf("%% Mark %d already used as priority\n", marknum);
				destroy_args(args);
				return;
			} else {
				if (fr.priomarks[i] == 0) {
					next = i;
					break;
				}
			}
		}
		if (next == -1) {
			printf("%% Not possible to configure priority. Max number of priority marks exceeded.\n");
			destroy_args(args);
			return;
		}
		fr.priomarks[next] = marknum;
	}

	if( fr_set_config(interface_major, &fr) == -1 )
		printf("%% Not possible to configure priority\n");
	destroy_args(args);
}

void interface_fr_no_interleave(const char *cmdline) /* no frame-relay interleave [ priority-mark [<mark-number>] ] */
{
	fr_proto fr;
	arglist *args;
	int i, marknum = 0;

	if( fr_check_if_is_up(interface_major) )
		return;
	if( fr_get_config(interface_major, &fr) < 0 ) {
		printf("%% Not possible to do action\n");
		return;
	}

	args = make_args(cmdline);
	switch( args->argc ) {
		case 3:
			/* Fall down */
		case 4:
			for( i=0; i < CONFIG_MAX_LFI_PRIORITY_MARKS; i++ )
				fr.priomarks[i] = 0;
			break;
		case 5:
			marknum = atoi(args->argv[4]);
			for( i=0; i < CONFIG_MAX_LFI_PRIORITY_MARKS; i++ ) {
				if( fr.priomarks[i] == marknum ) {
					for( ; i < (CONFIG_MAX_LFI_PRIORITY_MARKS-1); i++ )
						fr.priomarks[i] = fr.priomarks[i+1];
					fr.priomarks[i] = 0;
					break;
				}
			}
			break;
		default:
			destroy_args(args);
			return;
	}

	fr.interleave = (fr.priomarks[0] == 0) ? 0 : 1;
	if( fr_set_config(interface_major, &fr) == -1 ) {
		switch( args->argc ) {
			case 3:
				printf("%% Not possible to disable interleaving with all priority marks\n");
				break;
			case 4:
				printf("%% Not possible to disable priority marks\n");
				break;
			case 5:
				printf("%% Not possible to disable priority mark %d\n", marknum);
				break;
		}
	}
	destroy_args(args);
}
#endif

#ifdef CONFIG_FR_IPHC
/*
 * Comandos:
 *  ip header-compression max-period <value>
 *  ip header-compression max-time <value>
 *  ip header-compression max-header <value>
 *  ip header-compression tcp [passive]
 *  ip header-compression tcp contexts <value>
 *  ip header-compression udp <format> [passive]
 *  ip header-compression udp <format> contexts <value>
 *  ip header-compression rtp [passive]
 *  ip header-compression rtp checksum-period <value>
 *  ip header-compression rtp mark <value>
 *  no ip header-compression
 *  no ip header-compression tcp
 *  no ip header-compression udp
 *  no ip header-compression rtp
 *  no ip header-compression rtp mark [<value>]
 */
void subfr_iphc(const char *cmdline)
{
	char *dev;
	arglist *args;
	int i, freep, marknum;
	fr_proto_pvc_info info;

	dev = convert_device(interface_edited->cish_string, interface_major, interface_minor);
	if( fr_pvc_get_info(dev, &info) < 0 ) {
		printf("%% Not possible to configure IP/UDP/RTP compression\n");
		free(dev);
		return;
	}
	args = make_args(cmdline);
	if( strcmp(args->argv[0], "no") == 0 ) {
		switch( args->argc ) {
			case 3: /* no ip header-compression */
				/* Assume valores default */
				info.iphc_maxperiod = IPHC_MAXPERIOD_DFLT;
				info.iphc_maxtime = IPHC_MAXTIME_DFLT;
				info.iphc_maxheader = IPHC_MAXHEADER_DFLT;
				info.iphc_tcp_mode = IPHC_MODE_OFF;
				info.iphc_tcp_contexts = IPHC_TCP_CONTEXTS_DFLT;
				info.iphc_udp_mode = IPHC_MODE_OFF;
				info.iphc_udp_contexts = IPHC_UDP_CONTEXTS_DFLT;
				info.iphc_rtp_mode = IPHC_MODE_OFF;
				info.iphc_rtp_checksum_period = IPHC_RTP_CHECKSUM_PERIOD_DFLT;
				for( i=0; (i < CONFIG_MAX_IPHC_CRTP_MARKS) && (info.iphc_crtp_marks[i] != 0); i++ )
					info.iphc_crtp_marks[i] = 0;
				break;
			case 4:
				if( strcmp(args->argv[3], "tcp") == 0 ) /* no ip header-compression tcp */
					info.iphc_tcp_mode = IPHC_MODE_OFF;
				else if( strcmp(args->argv[3], "udp") == 0 ) { /* no ip header-compression udp */
					info.iphc_udp_mode = IPHC_MODE_OFF;
					info.iphc_rtp_mode = IPHC_MODE_OFF;
				}
				else if( strcmp(args->argv[3], "rtp") == 0 ) /* no ip header-compression rtp */
					info.iphc_rtp_mode = IPHC_MODE_OFF;
				break;
			case 5: /* no ip header-compression rtp mark */
				for( i=0; (i < CONFIG_MAX_IPHC_CRTP_MARKS) && (info.iphc_crtp_marks[i] != 0); i++ )
					info.iphc_crtp_marks[i] = 0;
				break;
			case 6: /* no ip header-compression rtp mark value */
				for( i=0, marknum=atoi(args->argv[5]); i < CONFIG_MAX_IPHC_CRTP_MARKS; i++ ) {
					if( info.iphc_crtp_marks[i] == marknum ) {
						for( ; i < (CONFIG_MAX_IPHC_CRTP_MARKS - 1); i++ )
							info.iphc_crtp_marks[i] = info.iphc_crtp_marks[i+1];
						info.iphc_crtp_marks[i] = 0;
						break;
					}
				}
				break;
		}
	}
	else {
		if( strcmp(args->argv[2], "max-period") == 0 ) /* ip header-compression max-period value */
			info.iphc_maxperiod = atoi(args->argv[3]);
		else if( strcmp(args->argv[2], "max-time") == 0 ) /* ip header-compression max-time value */
			info.iphc_maxtime = atoi(args->argv[3]);
		else if( strcmp(args->argv[2], "max-header") == 0 ) /* ip header-compression max-header value */
			info.iphc_maxheader = atoi(args->argv[3]);
		else if( strcmp(args->argv[2], "tcp") == 0 ) {
			switch( args->argc ) {
				case 3: /* ip header-compression tcp */
					info.iphc_tcp_mode = IPHC_MODE_ON;
					break;
				case 4: /* ip header-compression tcp passive */
					info.iphc_tcp_mode = IPHC_MODE_ON_PASSIVE;
					break;
				case 5: /* ip header-compression tcp contexts value */
					info.iphc_tcp_contexts = atoi(args->argv[4]);
					break;
			}
		}
		else if( strcmp(args->argv[2], "udp") == 0 ) {
			info.iphc_udp_format = (strcmp(args->argv[3], "ietf-format") == 0) ? UDP_COMP_FORMAT_IETF : UDP_COMP_FORMAT_IPHC;
			switch( args->argc ) {
				case 4: /* ip header-compression udp <format> */
					info.iphc_udp_mode = IPHC_MODE_ON;
					break;
				case 5: /* ip header-compression udp <format> passive */
					info.iphc_udp_mode = IPHC_MODE_ON_PASSIVE;
					break;
				case 6: /* ip header-compression udp <format> contexts value */
					info.iphc_udp_contexts = atoi(args->argv[5]);
					break;
			}
		}
		else if( strcmp(args->argv[2], "rtp") == 0 ) {
			switch( args->argc ) {
				case 3: /* ip header-compression rtp */
					info.iphc_udp_mode = IPHC_MODE_ON;
					info.iphc_rtp_mode = IPHC_MODE_ON;
					break;
				case 4: /* ip header-compression rtp passive */
					info.iphc_udp_mode = IPHC_MODE_ON;
					info.iphc_rtp_mode = IPHC_MODE_ON_PASSIVE;
					break;
				case 5:
					if( strcmp(args->argv[3], "checksum-period") == 0 ) /* ip header-compression rtp checksum-period value */
						info.iphc_rtp_checksum_period = atoi(args->argv[4]);
					else if( strcmp(args->argv[3], "mark") == 0 ) { /* ip header-compression rtp mark value */
						for( i=0, freep=-1, marknum=atoi(args->argv[4]); i < CONFIG_MAX_IPHC_CRTP_MARKS; i++ ) {
							if( info.iphc_crtp_marks[i] == marknum ) {
								printf("%% Mark %d already used as priority\n", marknum);
								destroy_args(args);
								return;
							}
							else if( info.iphc_crtp_marks[i] == 0 ) {
								freep = i;
								break;
							}
						}
						if( freep == -1 ) {
							printf("%% Not possible to configure priority. Max number of priority marks exceeded.\n");
							destroy_args(args);
							return;
						}
						info.iphc_crtp_marks[freep] = marknum;
					}
					break;
			}
		}
	}
	fr_pvc_set_info(dev, &info);
	destroy_args(args);
	free(dev);
}
#endif /* CONFIG_FR_IPHC */

#ifdef CONFIG_HDLC_FR_EEK
void fr_eek_timer(const char *cmdline) 
{
	arglist *args;
	char *dev;
	unsigned int seconds = 0;
	unsigned int side;
	args = make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);

	if(args->argc != 6) {
		printf("%% Wrong number of arguments\n");
		destroy_args(args);
		return;
	}
	seconds = atoi(args->argv[5]);
	if (!strcmp(args->argv[4],"recv")) 
		side = EEK_RECEIVE_SIDE;
	else 
		side = EEK_SEND_SIDE;

	fr_eek_set_timer(seconds, side, dev);

	free(dev);
	destroy_args(args);
	return;
}

void fr_eek_events(const char *cmdline) 
{
	arglist *args;
	char *dev;
	unsigned int side, value;
	
	
	args = make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);
	
	if(args->argc != 6) {
		printf("%% Wrong number of arguments\n");
		destroy_args(args);
		return;
	}

	value = atoi(args->argv[5]);

	if (!strcmp(args->argv[4],"recv"))
		side = EEK_RECEIVE_SIDE;
	else 
		side = EEK_SEND_SIDE;

	if (!strcmp(args->argv[3],"event-window"))
		fr_eek_set_window(value, side,dev);
	else if  (!strcmp(args->argv[3],"error-threshold"))
		fr_eek_set_err_threshold(value, side,dev);
	else if (!strcmp(args->argv[3],"success-events"))
		fr_eek_set_success_events(value, side,dev);

	free(dev);
	destroy_args(args);
	return;
}

void fr_eek_mode(const char *cmdline) 
{
	arglist *args;
	char *dev;
	int mode;
	
	args = make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);

	if(args->argc < 4) {
		printf("%% Wrong number of arguments\n");
		destroy_args(args);
		return;
	}

	if (!strcmp(args->argv[0],"no"))
		mode = EEK_MODE_OFF;
	else if (!strcmp(args->argv[4],"bidirectional")) 
		mode = EEK_MODE_BIDIRECTION;
	else if (!strcmp(args->argv[4],"passive-reply")) 
		mode = EEK_MODE_PASSIVE;
	else if (!strcmp(args->argv[4],"reply")) 
		mode = EEK_MODE_REPLY;
	else 
		mode = EEK_MODE_REQUEST;

	fr_eek_set_mode(mode, dev);
	
	free(dev);
	destroy_args(args);
	return;
}

void fr_eek_disable(const char *cmdline) /* no frame-relay end-to-end keepalive */
{
	arglist *args;
	char *dev;
	int mode;
	
	args = make_args(cmdline);
	dev=convert_device(interface_edited->cish_string, interface_major, interface_minor);

	if(args->argc < 4) {
		printf("%% Wrong number of arguments\n");
		destroy_args(args);
		return;
	}

	mode = EEK_MODE_OFF;
	fr_eek_set_mode(mode, dev);
	
	free(dev);
	destroy_args(args);
	return;
}
#endif /* CONFIG_HDLC_FR_EEK */
