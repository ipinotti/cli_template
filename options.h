#include <linux/config.h>

#if defined(CONFIG_BERLIN_SATROUTER)
/*****************************************************************************/
/* Defines for Datacom Models ************************************************/
/*****************************************************************************/

/* BGP */
#ifdef CONFIG_BERLIN_SATROUTER_LIMITED_CRCS
#undef OPTION_BGP
#else
#define OPTION_BGP
#endif /* CONFIG_BERLIN_SATROUTER_LIMITED_CRCS */

/* CGI */
#undef OPTION_CGI

/* X25 */
#undef OPTION_X25

/* QoS */
#undef OPTION_NEW_QOS_CONFIG

/* IPSec */
#define OPTION_IPSEC
#define N_IPSEC_IF 5 /* Interfaces for IPSec */

#define OPTION_FULL_CONSOLE_LOG 0

/* NTP */
#define OPTION_NTPD
#undef OPTION_NTPD_authenticate

#define OPTION_OPENSSH
#define OPTION_PIMD
#define OPTION_SMCROUTE
#define OPTION_VRRP

#undef OPTION_RMON
#define CHECK_IPTABLES_EXEC	1

#define CONFIG_LOG_CONSOLE

/* DMVIEW */
#ifdef CONFIG_BERLIN_SATROUTER_LIMITED_CRCS
#undef CONFIG_DMVIEW_MGNT
#else
#define CONFIG_DMVIEW_MGNT
#endif

#undef OPTION_FEATURE

#else /* CONFIG_BERLIN_SATROUTER */

/*****************************************************************************/
/* Defines for Aligera Models ************************************************/
/*****************************************************************************/

/* BGP */
#define OPTION_BGP

/* X25 */
#ifdef CONFIG_X25
#define OPTION_X25
#endif

/* QoS */
#define OPTION_NEW_QOS_CONFIG

/* IPSec */
#define OPTION_IPSEC 1
#define N_IPSEC_IF 5

#define OPTION_FULL_CONSOLE_LOG 0

/* FEATURE */
#define OPTION_FEATURE

/* NTP */
#define OPTION_NTPD
#undef OPTION_NTPD_authenticate

#define OPTION_OPENSSH
#define OPTION_PIMD
#define OPTION_RMON
#define OPTION_SMCROUTE
#define OPTION_VRRP
#define OPTION_HTTP

/* HTTP Server */
#ifdef CONFIG_SONAE_BS
#define HTTP_DAEMON "wnsd"
#else
#define HTTP_DAEMON "thttpd"
#endif

#endif /* CONFIG_BERLIN_SATROUTER */

/******************************************************************************/
/* Common defines (valid for all boards) **************************************/
/******************************************************************************/
#ifdef OPTION_OPENSSH
#define SSH_DAEMON "sshd"
#else
#define SSH_DAEMON "dropbear"
#endif

#define TELNET_DAEMON "telnetd"
#define FTP_DAEMON "ftpd"
#define PIMS_DAEMON "pimsd"
#define PIMD_DAEMON "pimdd"
#define SMC_DAEMON "smcroute"
