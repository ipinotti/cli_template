#include <linux/config.h>

#include "commands.h"
#include "commandtree.h"
#include <libconfig/args.h>
#include <libconfig/device.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <linux/hdlc.h>
#include <stdlib.h>
#include <string.h>
#include <net/sppp.h>
#ifdef CONFIG_SPPP_IPHC
#include <linux/iphc.h>
#endif

#include <libconfig/typedefs.h>
#include <libconfig/sppp.h>
#include <libconfig/dev.h>

extern int interface_major, interface_minor;

void sppp_keepalive_interval(const char *cmd) /* keepalive interval <1-100> */
{
	arglist *args;
	ppp_proto ppp;

	args=make_args(cmd);
	sppp_get_config(interface_major, &ppp);
	ppp.interval=atoi(args->argv[2]);
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}

void sppp_keepalive_timeout(const char *cmd) /* keepalive timeout <1-100> */
{
	arglist *args;
	ppp_proto ppp;

	args=make_args(cmd);
	sppp_get_config(interface_major, &ppp);
	ppp.timeout=atoi(args->argv[2]);
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}

void sppp_debug(const char *cmd) /* [no] ppp debug */
{
	arglist *args;
	ppp_proto ppp;

	args = make_args(cmd);
	sppp_get_config(interface_major, &ppp);
	ppp.debug = (strcmp(args->argv[0], "no") == 0) ? 0 : 1;
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}

#ifdef CONFIG_SPPP_MULTILINK
/*  ppp multilink
 *  ppp multilink fragment <size>
 *  ppp multilink mrru <size>
 *  ppp multilink interleave priority-mark <mark number>
 *  no ppp multilink
 *  no ppp multilink fragment
 *  no ppp multilink interleave priority-mark [<mark number>]
 */
void sppp_multilink(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;
#ifdef CONFIG_HDLC_SPPP_LFI
	int i, free, marknum;
#endif

	args = make_args(cmd);
	sppp_get_config(interface_major, &ppp);
	if( strcmp(args->argv[0], "no") == 0 ) {
		switch( args->argc ) {
			case 3: /* no ppp multilink */
				ppp.mlp = 0;
				ppp.mlp_frag_size = 0;
				break;
			case 4: /* no ppp multilink fragment */
				ppp.mlp_frag_size = 0;
				break;
			case 5: /* no ppp multilink interleave priority-mark */
				for(i=0; (i < CONFIG_MAX_LFI_PRIORITY_MARKS) && (ppp.priomarks[i] != 0); i++)
					ppp.priomarks[i] = 0;
				break;
			case 6: /* no ppp multilink interleave priority-mark <mark number> */
				for(i=0, marknum=atoi(args->argv[5]); i < CONFIG_MAX_LFI_PRIORITY_MARKS; i++) {
					if( ppp.priomarks[i] == marknum ) {
						for( ; i < (CONFIG_MAX_LFI_PRIORITY_MARKS-1); i++)
							ppp.priomarks[i] = ppp.priomarks[i+1];
						ppp.priomarks[i] = 0;
						break;
					}
				}
				break;
		}
	}
	else {
		switch( args->argc ) {
			case 2: /* ppp multilink */
				if( dev_get_hwaddr("ethernet0", ppp.mlp_mac) < 0 ) {
					printf("%% Not possible to enable multilink\n");
					destroy_args(args);
					return;
				}
				ppp.mlp = 1;
				break;
			case 4:
				if( dev_get_hwaddr("ethernet0", ppp.mlp_mac) < 0 ) {
					printf("%% Not possible to enable multilink\n");
					destroy_args(args);
					return;
				}
				ppp.mlp = 1;
				if( strcmp(args->argv[2], "fragment") == 0 ) /* ppp multilink fragment <size> */
					ppp.mlp_frag_size = atoi(args->argv[3]);
				else if( strcmp(args->argv[2], "mrru") == 0 ) /* ppp multilink mrru <size> */
					ppp.mlp_mrru = atoi(args->argv[3]);
				break;
#ifdef CONFIG_HDLC_SPPP_LFI
			case 5: /* ppp multilink interleave priority-mark <mark number> */
				if( dev_get_hwaddr("ethernet0", ppp.mlp_mac) < 0 ) {
					printf("%% Not possible to enable multilink\n");
					destroy_args(args);
					return;
				}
				ppp.mlp = 1;
				for(i=0, free=-1, marknum=atoi(args->argv[4]); i < CONFIG_MAX_LFI_PRIORITY_MARKS; i++) {
					if( ppp.priomarks[i] == marknum ) {
						printf("%% Mark %d already used as priority\n", marknum);
						destroy_args(args);
						return;
					}
					else {
						if( ppp.priomarks[i] == 0 ) {
							free = i;
							break;
						}
					}
				}
				if( free == -1 ) {
					printf("%% Not possible to configure priority. Max number of priority marks exceeded.\n");
					destroy_args(args);
					return;
				}
				ppp.priomarks[free] = marknum;
				break;
#endif
		}
	}
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}
#endif

#ifdef CONFIG_SPPP_NETLINK
/*  ppp chap sent-hostname <name> password <secret>
 *  ppp pap sent-username <name> password <secret>
 *  no ppp chap
 *  no ppp pap
 */
void sppp_papchap(const char *cmd)
{
	arglist *args;

	args = make_args(cmd);
	switch( args->argc ) {
		case 3:
			if( strcmp(args->argv[0], "no") == 0 ) {
				if( strcmp(args->argv[2], "chap") == 0 ) {
					if( sppp_set_chap_secret(NULL, NULL) < 0 ) {
						printf("%% Not possible to disable CHAP\n");
						destroy_args(args);
						return;
					}
				}
				else {
					if( sppp_set_pap_secret(NULL, NULL) < 0 ) {
						printf("%% Not possible to disable PAP\n");
						destroy_args(args);
						return;
					}
				}
			}
			break;
		case 6:
			if( strlen(args->argv[3]) > 63 ) {
				printf("%% Invalid name. Max length of 63 characters!\n");
				destroy_args(args);
				return;
			}
			if( strlen(args->argv[5]) > 63 ) {
				printf("%% Invalid password. Max length of 63 characters!\n");
				destroy_args(args);
				return;
			}
			if( strcmp(args->argv[1], "chap") == 0 ) { /* ppp chap sent-hostname <name> password <secret> */
				if( sppp_set_chap_secret(args->argv[3], args->argv[5]) < 0 ) {
					printf("%% Not possible to configure CHAP parameters\n");
					destroy_args(args);
					return;
				}
			}
			else { /* ppp pap sent-username <name> password <secret> */
				if( sppp_set_pap_secret(args->argv[3], args->argv[5]) < 0 ) {
					printf("%% Not possible to configure PAP parameters\n");
					destroy_args(args);
					return;
				}
			}
			break;
		default:
			printf("%% Invalid command!\n");
			destroy_args(args);
			return;
	}
	destroy_args(args);
}

/*  ppp authentication algorithm chap auth-name <name> auth-pass <passwd>
 *  ppp authentication algorithm pap
 *  no ppp authentication algorithm
 */
void sppp_auth_algo(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;

	args = make_args(cmd);
	if( args->argc < 4 ) {
		printf("%% Invalid command!\n");
		destroy_args(args);
		return;
	}
	sppp_get_config(interface_major, &ppp);
	if( strcmp(args->argv[0], "no") == 0 ) {
		ppp.req_auth = 0;
		if( sppp_set_chap_auth_secret(NULL, NULL) < 0 ) {
			printf("%% Not possible to disable authentication\n");
			destroy_args(args);
			return;
		}
	}
	else {
		if( strcmp(args->argv[3], "chap") == 0 ) {
			ppp.req_auth = SPPP_REQ_CHAP_AUTH;
			if( strlen(args->argv[5]) > 63 ) {
				printf("%% Invalid authenticate name. Max length of 63 characters!\n");
				destroy_args(args);
				return;
			}
			if( strlen(args->argv[7]) > 63 ) {
				printf("%% Invalid authenticate password. Max length of 63 characters!\n");
				destroy_args(args);
				return;
			}
			if( sppp_set_chap_auth_secret(args->argv[5], args->argv[7]) < 0 ) {
				printf("%% Not possible to configure CHAP parameters\n");
				destroy_args(args);
				return;
			}
		}
		else if( strcmp(args->argv[3], "pap") == 0 )
			ppp.req_auth = SPPP_REQ_PAP_AUTH;
	}
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}

/*  ppp usepeerdns
 *  no ppp usepeerdns
 */
void sppp_usepeerdns(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;

	args = make_args(cmd);
	if (args->argc < 2) {
		printf("%% Invalid command!\n");
		destroy_args(args);
		return;
	}
	sppp_get_config(interface_major, &ppp);
	ppp.req_dns = (strcmp(args->argv[0], "no") == 0) ? 0 : 1;
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}

/*  ppp supplypeerdns dynamic
 *  ppp supplypeerdns <address> [<address>]
 *  no ppp supplypeerdns [<address>]
 */
void sppp_supplypeerdns(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;
	unsigned int i;

	args = make_args(cmd);
	if (args->argc < 3) {
		printf("%% Invalid command!\n");
		destroy_args(args);
		return;
	}
	sppp_get_config(interface_major, &ppp);
	if (strcmp(args->argv[0], "no") == 0) {
		switch (args->argc) {
			case 3:
				memset(ppp.supply_dns_addrs, 0, 32);
				ppp.supply_dns = SPPP_SUPPLY_DNS_NONE;
				break;

			case 4:
				switch (ppp.supply_dns) {
					case SPPP_SUPPLY_DNS_NONE:
					case SPPP_SUPPLY_DNS_DYNAMIC:
						memset(ppp.supply_dns_addrs, 0, 32);
						ppp.supply_dns = SPPP_SUPPLY_DNS_NONE;
						break;
					case SPPP_SUPPLY_DNS_STATIC:
						for (i=0; i < 2; i++) {
							if (!strcmp((char *)ppp.supply_dns_addrs[i], args->argv[3])) {
								memset(ppp.supply_dns_addrs[i], 0, 16);
								break;
							}
						}
						if (!strlen((char *)ppp.supply_dns_addrs[0]) && strlen((char *)ppp.supply_dns_addrs[1])) {
							strcpy((char *)ppp.supply_dns_addrs[0], (char *)ppp.supply_dns_addrs[1]);
							memset(ppp.supply_dns_addrs[1], 0, 16);
						}
						if (!strlen((char *)ppp.supply_dns_addrs[0]) && !strlen((char *)ppp.supply_dns_addrs[1]))
							ppp.supply_dns =  SPPP_SUPPLY_DNS_NONE;
						break;
				}
				break;
		}
	}
	else {
		memset(ppp.supply_dns_addrs, 0, 32);
		if (strcmp(args->argv[2], "dynamic") == 0)
			ppp.supply_dns = SPPP_SUPPLY_DNS_DYNAMIC;
		else {
			ppp.supply_dns = SPPP_SUPPLY_DNS_STATIC;
			strcpy((char *)ppp.supply_dns_addrs[0], args->argv[2]);
			if (args->argc > 3)
				strcpy((char *)ppp.supply_dns_addrs[1], args->argv[3]);
		}
	}
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}

/*  ppp supplypeernbns <address> [<address>]
 *  no ppp supplypeernbns [<address>]
 */
void sppp_supplypeernbns(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;
	unsigned int i;

	args = make_args(cmd);
	if (args->argc < 3) {
		printf("%% Invalid command!\n");
		destroy_args(args);
		return;
	}
	sppp_get_config(interface_major, &ppp);
	if (strcmp(args->argv[0], "no") == 0) {
		switch (args->argc) {
			case 3:
				memset(ppp.supply_nbns_addrs, 0, 32);
				ppp.supply_nbns = 0;
				break;
			case 4:
				for (i=0; i < 2; i++) {
					if (!strcmp((char *)ppp.supply_nbns_addrs[i], args->argv[3])) {
						memset(ppp.supply_nbns_addrs[i], 0, 16);
						break;
					}
				}
				if (!strlen((char *)ppp.supply_nbns_addrs[0]) && strlen((char *)ppp.supply_nbns_addrs[1])) {
					strcpy((char *)ppp.supply_nbns_addrs[0], (char *)ppp.supply_nbns_addrs[1]);
					memset(ppp.supply_nbns_addrs[1], 0, 16);
				}
				ppp.supply_nbns = (strlen((char *)ppp.supply_nbns_addrs[0]) || strlen((char *)ppp.supply_nbns_addrs[1])) ? 1 : 0;
				break;
		}
	}
	else {
		memset(ppp.supply_nbns_addrs, 0, 32);
		strcpy((char *)ppp.supply_nbns_addrs[0], args->argv[2]);
		if (args->argc > 3)
			strcpy((char *)ppp.supply_nbns_addrs[1], args->argv[3]);
		ppp.supply_nbns = 1;
	}
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}
#endif

#ifdef CONFIG_SPPP_VJ
/*
 * Comandos:
 *  ip vj
 *  no ip vj
 */
void sppp_vj(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;

	args = make_args(cmd);
	sppp_get_config(interface_major, &ppp);
	switch( args->argc ) {
		case 2:
			ppp.vj = 1;
			break;
		case 3:
			ppp.vj = 0;
			break;
		default:
			printf("%% Invalid command!\n");
			destroy_args(args);
			return;
	}
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}
#endif

#ifdef CONFIG_SPPP_IPHC
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
void sppp_iphc(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;
	int i, free, marknum;

	args = make_args(cmd);
	sppp_get_config(interface_major, &ppp);
	if( strcmp(args->argv[0], "no") == 0 ) {
		switch( args->argc ) {
			case 3: /* no ip header-compression */
				/* Assume valores default */
				ppp.iphc_maxperiod = IPHC_MAXPERIOD_DFLT;
				ppp.iphc_maxtime = IPHC_MAXTIME_DFLT;
				ppp.iphc_maxheader = IPHC_MAXHEADER_DFLT;
				ppp.iphc_tcp_mode = IPHC_MODE_OFF;
				ppp.iphc_tcp_contexts = IPHC_TCP_CONTEXTS_DFLT;
				ppp.iphc_udp_mode = IPHC_MODE_OFF;
				ppp.iphc_udp_contexts = IPHC_UDP_CONTEXTS_DFLT;
				ppp.iphc_rtp_mode = IPHC_MODE_OFF;
				ppp.iphc_rtp_checksum_period = IPHC_RTP_CHECKSUM_PERIOD_DFLT;
				for( i=0; (i < CONFIG_MAX_IPHC_CRTP_MARKS) && (ppp.iphc_crtp_marks[i] != 0); i++ )
					ppp.iphc_crtp_marks[i] = 0;
				break;
			case 4:
				if( strcmp(args->argv[3], "tcp") == 0 ) /* no ip header-compression tcp */
					ppp.iphc_tcp_mode = IPHC_MODE_OFF;
				else if( strcmp(args->argv[3], "udp") == 0 ) { /* no ip header-compression udp */
					ppp.iphc_udp_mode = IPHC_MODE_OFF;
					ppp.iphc_rtp_mode = IPHC_MODE_OFF;
				}
				else if( strcmp(args->argv[3], "rtp") == 0 ) /* no ip header-compression rtp */
					ppp.iphc_rtp_mode = IPHC_MODE_OFF;
				break;
			case 5: /* no ip header-compression rtp mark */
				for( i=0; (i < CONFIG_MAX_IPHC_CRTP_MARKS) && (ppp.iphc_crtp_marks[i] != 0); i++ )
					ppp.iphc_crtp_marks[i] = 0;
				break;
			case 6: /* no ip header-compression rtp mark value */
				for( i=0, marknum=atoi(args->argv[5]); i < CONFIG_MAX_IPHC_CRTP_MARKS; i++ ) {
					if( ppp.iphc_crtp_marks[i] == marknum ) {
						for( ; i < (CONFIG_MAX_IPHC_CRTP_MARKS - 1); i++ )
							ppp.iphc_crtp_marks[i] = ppp.iphc_crtp_marks[i+1];
						ppp.iphc_crtp_marks[i] = 0;
						break;
					}
				}
				break;
		}
	}
	else {
		if( strcmp(args->argv[2], "max-period") == 0 ) /* ip header-compression max-period value */
			ppp.iphc_maxperiod = atoi(args->argv[3]);
		else if( strcmp(args->argv[2], "max-time") == 0 ) /* ip header-compression max-time value */
			ppp.iphc_maxtime = atoi(args->argv[3]);
		else if( strcmp(args->argv[2], "max-header") == 0 ) /* ip header-compression max-header value */
			ppp.iphc_maxheader = atoi(args->argv[3]);
		else if( strcmp(args->argv[2], "tcp") == 0 ) {
			switch( args->argc ) {
				case 3: /* ip header-compression tcp */
					ppp.iphc_tcp_mode = IPHC_MODE_ON;
					break;
				case 4: /* ip header-compression tcp passive */
					ppp.iphc_tcp_mode = IPHC_MODE_ON_PASSIVE;
					break;
				case 5: /* ip header-compression tcp contexts value */
					ppp.iphc_tcp_contexts = atoi(args->argv[4]);
					break;
			}
		}
		else if( strcmp(args->argv[2], "udp") == 0 ) {
			ppp.iphc_udp_format = (strcmp(args->argv[3], "ietf-format") == 0) ? UDP_COMP_FORMAT_IETF : UDP_COMP_FORMAT_IPHC;
			switch( args->argc ) {
				case 4: /* ip header-compression udp <format> */
					ppp.iphc_udp_mode = IPHC_MODE_ON;
					break;
				case 5: /* ip header-compression udp <format> passive */
					ppp.iphc_udp_mode = IPHC_MODE_ON_PASSIVE;
					break;
				case 6: /* ip header-compression udp <format> contexts value */
					ppp.iphc_udp_contexts = atoi(args->argv[5]);
					break;
			}
		}
		else if( strcmp(args->argv[2], "rtp") == 0 ) {
			switch( args->argc ) {
				case 3: /* ip header-compression rtp */
					ppp.iphc_udp_mode = IPHC_MODE_ON;
					ppp.iphc_rtp_mode = IPHC_MODE_ON;
					break;
				case 4: /* ip header-compression rtp passive */
					ppp.iphc_udp_mode = IPHC_MODE_ON;
					ppp.iphc_rtp_mode = IPHC_MODE_ON_PASSIVE;
					break;
				case 5:
					if( strcmp(args->argv[3], "checksum-period") == 0 ) /* ip header-compression rtp checksum-period value */
						ppp.iphc_rtp_checksum_period = atoi(args->argv[4]);
					else if( strcmp(args->argv[3], "mark") == 0 ) { /* ip header-compression rtp mark value */
						for( i=0, free=-1, marknum=atoi(args->argv[4]); i < CONFIG_MAX_IPHC_CRTP_MARKS; i++ ) {
							if( ppp.iphc_crtp_marks[i] == marknum ) {
								printf("%% Mark %d already used as priority\n", marknum);
								destroy_args(args);
								return;
							}
							else {
								if( ppp.iphc_crtp_marks[i] == 0 ) {
									free = i;
									break;
								}
							}
						}
						if( free == -1 ) {
							printf("%% Not possible to configure priority. Max number of priority marks exceeded.\n");
							destroy_args(args);
							return;
						}
						ppp.iphc_crtp_marks[free] = marknum;
					}
					break;
			}
		}
	}
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}
#endif

#ifdef CONFIG_SPPP_PPPH_COMP
/*
 * Comandos:
 *  ppp header-compression
 *  no ppp header-compression
 */
void sppp_header_compression(const char *cmd)
{
	arglist *args;
	ppp_proto ppp;

	args = make_args(cmd);
	sppp_get_config(interface_major, &ppp);
	switch( args->argc ) {
		case 2: /* ppp header-compression */
			ppp.ppph_comp = 1;
			break;
		case 3: /* no ppp header-compression */
			ppp.ppph_comp = 0;
			break;
		default:
			printf("%% Invalid command!\n");
			destroy_args(args);
			return;
	}
	sppp_set_config(interface_major, &ppp);
	destroy_args(args);
}
#endif

