/* ==============================================================================
 * systtyd - cish system daemon for login and ppp
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <linux/config.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/hdlc.h>

#include <libconfig/acl.h>
#include <libconfig/chdlc.h>
#include <libconfig/fr.h>
#include <libconfig/dev.h>
#include <libconfig/ntp.h>
#include <libconfig/ppp.h>
#include <libconfig/qos.h>
#include <libconfig/str.h>
#include <libconfig/wan.h>
#include <libconfig/quagga.h>
#include <libconfig/shm.h>
#include <libconfig/sppp.h>
#include <libconfig/x25.h>

#include "../options.h"
#include "systtyd.h"

#undef LOGROTATE

#ifdef LOGROTATE
#include "systty_logrotate.h"
#endif

systty TTY[TTYCOUNT];
#ifdef OPTION_X25
rfc1356 TUNNEL[RFC1356_COUNT];
#endif

#ifndef OPTION_NTPD
static char TIMECMD[256];
int TIMEINTERVAL;
#endif
int CLEANUPINTERVAL=60; /* Modules cleanup interval! */

time_t DELAYS[] = {4,9,14,19,19,19,19,19}; /* 5 -> 10 -> 15 -> 20s ... */ /* 270s interval (20+70+20+70+20+70) / 10+60s CONNECT timeout, use TIMEOUT to change! */

static int new_route=-1;
static int old_route=-1;
static int route_state=-1;

int wan_get_state(int index)
{
	switch(wan_get_protocol(index))
	{
		case IF_PROTO_FR: return fr_get_state(index)&IF_STATE_UP;
		case IF_PROTO_CISCO: return chdlc_get_state(index)&IF_STATE_UP;
		case IF_PROTO_PPP: return sppp_get_state(index)&IF_STATE_UP;
#ifdef OPTION_X25
		case IF_PROTO_X25: return x25_get_state(index);
#endif
		case SCC_PROTO_MLPPP: return ppp_get_state(index);
	}
	return -1;
}

/* ==============================================================================
 * _tty_handle
 *
 * This function looks at the status information that is available about the
 * numbered tty. Dead processes belonging to ttys that should be running are
 * started. Running processes that should exit are terminated. Penguins fly.
 * ============================================================================== */
void _tty_handle(int num)
{
	pid_t pid=0;
	time_t ti;
	int running=-1;

	/* flock invalid arguments */
	if (num < 0 || num >= TTYCOUNT) return;

	/* get some values handly */
	ti = time(NULL);
	//syslog(LOG_DEBUG, "ti: %lu, holdtime: %lu\n", ti, TTY[num].holdtime);

#if 0 /* SERVER_FLAGS_INCOMING esta sendo marcado no mgetty!!! */
	/* test incoming call */
	if (TTY[num].handler == 0)
	{
		if (ppp_is_pppd_running(num))
		{
			TTY[num].admin_up |= SERVER_FLAGS_INCOMING; /* incoming call mark */
		}
			else TTY[num].admin_up &= ~SERVER_FLAGS_INCOMING; /* end if incoming call! */
	}
#endif

	/* 0:serial0 1:serial1 2:aux0 3:aux1 */
	if ((num >= MAX_WAN_INTF) && !(TTY[num].ppp.server_flags & SERVER_FLAGS_INCOMING))
	{ /* num is the backup interface for serialx; 1=aux0 2=aux1 */
		if (TTY[0].ppp.backup == num-MAX_WAN_INTF+1)
			running=wan_get_state(0); /* aux(num-MAX_WAN_INTF+1) eh backup de serial0 */
		else if (TTY[1].ppp.backup == num-MAX_WAN_INTF+1)
			running=wan_get_state(1); /* aux(num-MAX_WAN_INTF+1) eh backup de serial1 */
		/* Rota flutuante! */
		if (running >= 0) /* backup enabled! */
		{
			if ((new_route=rota_flutuante()) == -1)
			{
				route_state=-1;
			}
			else
			{
				if (old_route == 1 && new_route == 0)
				{
					syslog(LOG_NOTICE, "%s tty-handler lost dynamic default route", TTY[num].ppp.cishdevice);
					route_state=0; /* perda da rota dinamica default! */
				}
				else if (old_route == 0 && new_route == 1)
				{
					syslog(LOG_NOTICE, "%s tty-handler receive dynamic default route", TTY[num].ppp.cishdevice);
					route_state=1; /* recebeu rota dinamica default! */
				}
			}
			old_route=new_route;
			if (route_state >= 0)
				running &= route_state; /* modify running state! */
		}
		if (running > 0)
		{
			if (TTY[num].activate_delay)
			{
				TTY[num].activate_delay=0;
				syslog(LOG_NOTICE, "%s tty-handler activate abort", TTY[num].ppp.cishdevice);
			}
			if (TTY[num].running == st_running)
			{
				if (!TTY[num].deactivate_delay)
				{
					TTY[num].deactivate_delay=1;
					TTY[num].holdtime=ti + TTY[0].ppp.deactivate_delay;
					syslog(LOG_NOTICE, "%s tty-handler set deactivate delay to %d seconds", TTY[num].ppp.cishdevice, TTY[0].ppp.deactivate_delay);
				}
				if (ti > TTY[num].holdtime)
				{
					TTY[num].admin_up &= ~0x01;
					_tty_reset(num); /* hangup! */
					TTY[num].deactivate_delay=0;
				}
					else return; /* wait to deactivate! */
			}
			if (TTY[num].running != st_dying) return;
		}
		else if (running == 0)
		{
			if (TTY[num].deactivate_delay)
			{
				TTY[num].deactivate_delay=0;
				syslog(LOG_NOTICE, "%s tty-handler deactivate abort", TTY[num].ppp.cishdevice);
			}
			if ((TTY[num].running == st_down) && (TTY[num].ppp.up))
			{
				if (!TTY[num].activate_delay)
				{
					TTY[num].activate_delay=1;
					TTY[num].holdtime=ti + TTY[0].ppp.activate_delay;
					syslog(LOG_NOTICE, "%s tty-handler set activate delay to %d seconds", TTY[num].ppp.cishdevice, TTY[0].ppp.activate_delay);
				}
				if (ti <= TTY[num].holdtime)
				{
					return; /* waiting! */
				}
				else
				{
					TTY[num].admin_up |= 0x01;
					TTY[num].activate_delay=0;
				}
			}
		}
	}

	if (TTY[num].handler) /* the tty has a running process */
	{
		if (TTY[num].handler > 0) pid=waitpid(TTY[num].handler, NULL, WNOHANG); /* see if it exited */
		if ((pid > 0)) /* yes *//* || (TTY[num].handler < 0)*/
		{
			TTY[num].handler=0; /* update information */
			TTY[num].running=st_down;
			TTY[num].holdtime=0;
			if (TTY[num].admin_up && !(TTY[num].ppp.server_flags & SERVER_FLAGS_INCOMING)) /* should this be up? */
			{
				_tty_register_restart(num); /* record the time */
				syslog(LOG_NOTICE, "%s tty-handler died, scheduled restart", TTY[num].ppp.cishdevice);
			}
			else
			{
				syslog(LOG_NOTICE, "%s tty-handler exited", TTY[num].ppp.cishdevice);
			}
		}
		else if (TTY[num].running == st_dying) /* process is being terminated */ 
		{
			if (ti > TTY[num].holdtime) /* no exit-status after set timeout */
			{
				if (TTY[num].handler > 0)
				{
					//syslog(LOG_DEBUG, "tty_handler: SIGKILL %d", TTY[num].handler);
					kill(TTY[num].handler, SIGKILL); /* finish the process off */
				}
			}
		}
	}
	else /* no process */
	{
		/* should it run a process and is its execution due? */
		if ((TTY[num].admin_up == 0x01) && (ti > TTY[num].holdtime)
			&& !(TTY[num].ppp.server_flags & SERVER_FLAGS_INCOMING)) /* wait for incoming hang-up... */
		{
			pid=tty_run_handler(num); /* start the delegated handler */
			if (pid > 0) /* succesful startup */
			{
				TTY[num].handler=pid;
				TTY[num].running=st_running;
				TTY[num].holdtime=0;
			}
			else /* barfed, schedule a restart attempt */
			{
				_tty_register_restart(num);
			}
		}
	}
}

void _tunnel_handle(int num)
{
#ifdef OPTION_X25
	pid_t pid=0;

	time_t ti;

	/* get some values handly */
	ti = time(NULL);

	if (TUNNEL[num].handler) /* the tty has a running process */
	{
		if (TUNNEL[num].handler > 0) pid=waitpid(TUNNEL[num].handler, NULL, WNOHANG); /* see if it exited */
		if ((pid > 0)) /* yes *//* || (TTY[num].handler < 0)*/
		{
			TUNNEL[num].handler=0; /* update information */
			TUNNEL[num].running=st_down;
			TUNNEL[num].holdtime=0;
			if (TUNNEL[num].admin_up) /* should this be up? */
			{
				_tunnel_register_restart(num); /* record the time */
				syslog(LOG_NOTICE, "serial0.%d tunnel-handler died, scheduled restart", num);
			}
			else
			{
				syslog(LOG_NOTICE, "serial0.%d tunnel-handler exited", num);
			}
		}
		else if (TUNNEL[num].running == st_dying) /* process is being terminated */ 
		{
			if (ti > TUNNEL[num].holdtime) /* no exit-status after set timeout */
			{
				if (TUNNEL[num].handler > 0)
				{
					//syslog(LOG_DEBUG, "tty_handler: SIGKILL %d", TTY[num].handler);
					kill(TUNNEL[num].handler, SIGKILL); /* finish the process off */
				}
			}
		}
	}
	else /* no process */
	{
		/* should it run a process and is its execution due? */
		if ((TUNNEL[num].admin_up == 0x01) && (ti > TUNNEL[num].holdtime)) /* wait for incoming hang-up... */
		{
			pid=tunnel_run_handler(num); /* start the delegated handler */
			if (pid > 0) /* succesful startup */
			{
				TUNNEL[num].handler=pid;
				TUNNEL[num].running=st_running;
				TUNNEL[num].holdtime=0;
			}
			else /* barfed, schedule a restart attempt */
			{
				_tunnel_register_restart(num);
			}
		}
	}
#endif
}

/* ==============================================================================
 * _tty_reset
 *
 * Sends a TERM signal to a tty's running process and schedules it for
 * termination with SIGKILL 4 seconds later.
 * ============================================================================== */
void _tty_reset(int num)
{
	time_t ti;

	/* clean ourselves off invalid arguments *//* begone, yonder foul demonf! */
	if (num < 0 || num >= TTYCOUNT) return;

	ti = time(NULL); /* get current time */

	/* is the tty harbouring a running process? */
	if (TTY[num].running == st_running)
	{
		if (TTY[num].handler) /* it is decidedly so */
		{
			//syslog(LOG_DEBUG, "tty_reset: SIGTERM %d", TTY[num].handler);
			kill(TTY[num].handler, SIGTERM); /* make it stop */
			TTY[num].holdtime = ti + 4; /* remind ourselves to finish the job */
		}
		TTY[num].running = st_dying; /* advertise its pitiful state */
	}
}

void _tunnel_reset(int num)
{
#ifdef OPTION_X25
	time_t ti;

	ti = time(NULL); /* get current time */

	/* is the tty harbouring a running process? */
	if (TUNNEL[num].running == st_running)
	{
		if (TUNNEL[num].handler) /* it is decidedly so */
		{
			kill(TUNNEL[num].handler, SIGTERM); /* make it stop */
			TUNNEL[num].holdtime = ti + 4; /* remind ourselves to finish the job */
		}
		TUNNEL[num].running = st_dying; /* advertise its pitiful state */
	}
#endif
}

/* ==============================================================================
 * _tty_init
 *
 * Initializes the values for a numbered tty structure.
 * ============================================================================== */
void _tty_init(int num, ppp_config *cfg)
{
	int i;

	/* Loose the Spanish Inquisition on our arguments */
	if (num < 0 || num >= TTYCOUNT) return;

	/* Appearantly the bastards told the truth. Prepare a fresh systty for them */
	TTY[num].valid=1; /* Mark! */
	TTY[num].admin_up = 0;
	TTY[num].type = unassigned;
	TTY[num].running = st_down;
	TTY[num].handler = 0;
	TTY[num].holdtime = 0;
	TTY[num].restartcount = 0;
	for (i=0; i < 8; i++) TTY[num].restarts[i] = (time_t)0;
	TTY[num].activate_delay = 0;
	TTY[num].deactivate_delay = 0;
	memcpy(&TTY[num].ppp, cfg, sizeof(ppp_config));
}

void _tunnel_init(int num)
{
#ifdef OPTION_X25
	int i;

	TUNNEL[num].valid=1; /* Mark! */
	TUNNEL[num].admin_up = 0;
	TUNNEL[num].type = unassigned;
	TUNNEL[num].running = st_down;
	TUNNEL[num].handler = 0;
	TUNNEL[num].holdtime = 0;
	TUNNEL[num].restartcount = 0;
	for (i=0; i < 8; i++) TUNNEL[num].restarts[i] = (time_t)0;
	memset(&TUNNEL[num].rfc1356_cfg, 0, sizeof(struct rfc1356_config));
#endif
}

/* ==============================================================================
 * _tty_register_restart
 *
 * Registers a process restart with a tty and calculates the amount of delay
 * that should be scheduled for the process should be freshly started.
 * ============================================================================== */
void _tty_register_restart(int num)
{
	time_t ti;
	int i, cnt;

	/* sanitize argument */
	if (num < 0 || num >= TTYCOUNT) return;
	
	/* get date, record time of restart */
	ti = time(NULL);
	
	TTY[num].restarts[TTY[num].restartcount] = ti;
	TTY[num].restartcount++;
	TTY[num].restartcount&=7;
	
	cnt = 0; /* will hold the number of restarts in the last 270 seconds */
	for (i=0; i < 8; i++)
	{
		if ( (ti - TTY[num].restarts[i] > 0) &&
			 (ti - TTY[num].restarts[i] < 270) )
		{
			cnt++;
		}
	}
	
	/* apply an exponential scale to the restart count and use it as a delay
	   for sceduling a process restart */
	TTY[num].holdtime=ti + DELAYS[cnt];
}

void _tunnel_register_restart(int num)
{
#ifdef OPTION_X25
	time_t ti;
	int i, cnt;

	/* get date, record time of restart */
	ti=time(NULL);
	
	TUNNEL[num].restarts[TUNNEL[num].restartcount]=ti;
	TUNNEL[num].restartcount++;
	TUNNEL[num].restartcount&=7;
	
	cnt=0; /* will hold the number of restarts in the last 270 seconds */
	for (i=0; i < 8; i++)
	{
		if ( (ti - TUNNEL[num].restarts[i] > 0) &&
			 (ti - TUNNEL[num].restarts[i] < 270) )
		{
			cnt++;
		}
	}
	
	/* apply an exponential scale to the restart count and use it as a delay
	   for sceduling a process restart */
	TUNNEL[num].holdtime=ti + DELAYS[cnt];
#endif
}

/* ==============================================================================
 * tty_run_handler
 *
 * Executes the handler process appropriate for a tty.
 * ============================================================================== */
pid_t tty_run_handler(int node)
{
	if (node < 0 || node >= TTYCOUNT)
		return 0;

	switch (TTY[node].type)
	{
		case type_ppp:
			return _tty_ppp_handler(node);
		default:
			//TTY[node].handler=0;
			return 0;
	}
}

#define MKARG(s)  { arglist[n] = (char *)malloc(strlen(s)+1); strcpy(arglist[n], s); n++; }
#define MKARGI(i) { arglist[n] = (char *)malloc(16); sprintf(arglist[n], "%d", i); n++; }
pid_t tunnel_run_handler(int node)
{
#ifndef OPTION_X25
	return 0;
#else
	int n=0;
	pid_t result;
	char *arglist[10];

	switch (TUNNEL[node].type)
	{
		case type_rfc1356:
			MKARG("/bin/rfc1356");
			MKARG("-b");
#ifdef OPTION_X25
			MKARG(TUNNEL[node].rfc1356_cfg.local.x25_addr);
			if (TUNNEL[node].rfc1356_cfg.remote.x25_addr[0])
			{
				MKARG("-c");
				MKARG(TUNNEL[node].rfc1356_cfg.remote.x25_addr);
			}
#endif
			MKARG("-d");
			MKARGI(node);
			arglist[n]=NULL;
			switch (result=fork()) /* vfork! */
			{
				case -1:
					syslog(LOG_ALERT, "could not fork()");
					break;
				case 0:
					execv(arglist[0], arglist);
					syslog(LOG_ERR, "error starting rfc1356 on serial0.%d", node);
					return 1; /* _exit(1); */
				default:
					//syslog(LOG_NOTICE, "rfc1356 started on serial0.%d", node);
					break;
			}
			n=0;
			while(arglist[n])
			{
				free(arglist[n]);
				arglist[n++]=NULL;
			}
			return result;
		default:
			return 0;
	}
#endif
}

pid_t _tty_ppp_handler(int node)
{
	int n;
	pid_t result;
	char *arglist[100];

	ppp_pppd_arglist(arglist, &TTY[node].ppp, 0);
	switch (result=fork()) /* vfork! */
	{
		case -1:
			syslog(LOG_ALERT, "could not fork()");
			break;
			
		case 0:
#if 1
			execv("/bin/pppd", arglist);
#else
			execv("/bin/nice", arglist);
#endif
			syslog(LOG_ERR, "error starting ppp on %s", TTY[node].ppp.cishdevice);
			return 1; /* _exit(1); */
		
		default:
			syslog(LOG_NOTICE, "ppp started on %s", TTY[node].ppp.cishdevice);
			break;
	}
	n = 0;
	while(arglist[n])
	{
		free(arglist[n]);
		arglist[n++]=NULL;
	}
	return result;
}

/* ==============================================================================
 * tty_init
 *
 * Initializes all relevant structures and gets things going
 * ============================================================================== */
void tty_init (void)
{
	int i;

	for (i=0; i < TTYCOUNT; i++) TTY[i].valid=0;
#ifdef OPTION_X25
	for (i=0; i < RFC1356_COUNT; i++) TUNNEL[i].valid=0;
#endif
	openlog ("systtyd", LOG_CONS|LOG_PID, LOG_DAEMON);
	tty_loadconfig();
}

/* ==============================================================================
 * tty_loop
 *
 * Main loop
 * ============================================================================== */
void tty_loop (void)
{
	int i;
#ifdef CONFIG_BERLIN_SATROUTER
	static unsigned int time_counter=0;
#endif
#ifndef OPTION_NEW_QOS_CONFIG
	sync_serial_settings sst;
	static unsigned int clock_rate[MAX_WAN_INTF]={0,0}, count[MAX_WAN_INTF]={0,0};


	for (i=0; i < MAX_WAN_INTF; i++)
	{	/* QoS */
		if (wan_get_physical(i) && (wan_get_state(i) > 0)) /* Se a interface estiver no modo sincrono, podemos ler a configuracao de clock */
		{
			wan_get_sst(i, &sst);
			if (sst.clock_type == CLOCK_EXT || sst.clock_type == CLOCK_TXFROMRX)
			{
				if (clock_rate[i] != sst.detected_rate)
				{
					count[i]++;
					if (count[i] > 5)
					{
						count[i]=0;
						tc_add_remove_all(1); /* reconfigure QoS */
						clock_rate[i]=sst.detected_rate;
					}
				}
					else count[i]=0;
			}
		}
	}
#endif
#ifdef CONFIG_BERLIN_SATROUTER
	time_counter++;
	if( time_counter >= 5 )	{
		time_counter = 0;
		eval_devs_qos_sanity();
	}
#endif
	for (i=0; i < TTYCOUNT; i++)
		if (TTY[i].valid) _tty_handle(i);
#ifdef OPTION_X25
	for (i=0; i < RFC1356_COUNT; i++)
		if (TUNNEL[i].valid) _tunnel_handle(i);
#endif
}

/* ==============================================================================
 * tty_sighup
 *
 * SIGHUP handler
 * ============================================================================== */
void tty_sighup (int sig)
{
	tty_loadconfig();
}

/* ==============================================================================
 * tty_loadconfig
 *
 * Reads configuration commands from an opened file and evaluates whether
 * a tty's status changed in a sense that mandates resetting it.
 * ============================================================================== */
void tty_loadconfig (void)
{
	int serial_no;
	ppp_config cfg;
#ifdef OPTION_X25
	struct rfc1356_config rfc1356_cfg;
#endif
	FILE *secrets;
#ifndef OPTION_NTPD
	int ntp_timeout;
	char ntp_ip[16];
#endif

	umask(066); /* -rw------ */
	secrets = fopen("/etc/ppp/pap-secrets", "w");
	for (serial_no=0; serial_no < TTYCOUNT; serial_no++)
	{
		if (ppp_has_config(serial_no))
		{
			ppp_get_config(serial_no, &cfg);
			if (!TTY[serial_no].valid)
			{	/* fill in the proper device parameters */
				_tty_init(serial_no, &cfg);
			}
			TTY[serial_no].type = type_ppp;
			if (cfg.up) TTY[serial_no].admin_up |= 0x01;
				else TTY[serial_no].admin_up &= ~0x01;
			if (memcmp(&(TTY[serial_no].ppp), &cfg, sizeof(ppp_config)))
			{
				/* Take care of mgetty's */
				if (TTY[serial_no].ppp.speed != cfg.speed ||
				    (TTY[serial_no].ppp.server_flags & SERVER_FLAGS_ENABLE) != (cfg.server_flags & SERVER_FLAGS_ENABLE))
					notify_mgetty(serial_no); /* reload mgetty... */

				memcpy(&(TTY[serial_no].ppp), &cfg, sizeof(ppp_config));
				if (!(TTY[serial_no].ppp.server_flags & SERVER_FLAGS_INCOMING)) {
					syslog(LOG_NOTICE, "reconfiguring %s", TTY[serial_no].ppp.cishdevice);
					_tty_reset(serial_no);
				}
			}
			if (secrets)
			{
				/* Hostname and password to authenticate us to a peer */
				if (cfg.server_auth_user[0] && cfg.server_auth_pass[0]) { 
					/* hostname peername <passwd> <ipaddress> */
					fprintf(secrets, "%s\t%s\t%s\t%s\n", 
						cfg.server_auth_user, 
						cfg.auth_user[0] ? cfg.auth_user : cfg.cishdevice,
						cfg.server_auth_pass,
						cfg.server_ip_peer_addr[0] ? cfg.server_ip_peer_addr : "*");
				}
				/* Peer's name and password */
				if (cfg.auth_user[0] && cfg.auth_pass[0]) { 
					/* user remotename <passwd> */
					fprintf(secrets, "%s\t%s\t%s\t%s\n", 
						cfg.auth_user, 
						cfg.server_auth_user[0] ? cfg.server_auth_user : cfg.cishdevice, 
						cfg.auth_pass,
						cfg.ip_peer_addr[0] ? cfg.ip_peer_addr : "*");
				}
			}
		}
	}
	if( secrets != NULL )
		fclose(secrets);
	unlink("/etc/ppp/chap-secrets");
	symlink("/etc/ppp/pap-secrets", "/etc/ppp/chap-secrets");

#ifdef OPTION_X25
	/* IP over X.25 */
	for (serial_no=0; serial_no < RFC1356_COUNT; serial_no++)
	{
		if (rfc1356_has_config(0, serial_no))
		{
			rfc1356_get_config(0, serial_no, &rfc1356_cfg);
			if (!TUNNEL[serial_no].valid)
			{	/* fill in the proper device parameters */
				_tunnel_init(serial_no);
			}
			TUNNEL[serial_no].type = type_rfc1356;
			if (rfc1356_cfg.up) TUNNEL[serial_no].admin_up |= 0x01;
				else TUNNEL[serial_no].admin_up &= ~0x01;
			if (memcmp(&(TUNNEL[serial_no].rfc1356_cfg), &rfc1356_cfg, sizeof(struct rfc1356_config)))
			{
				memcpy(&(TUNNEL[serial_no].rfc1356_cfg), &rfc1356_cfg, sizeof(struct rfc1356_config));
				syslog(LOG_NOTICE, "reconfiguring %s%d.%d", SERIALDEV, 0, serial_no);
				_tunnel_reset(serial_no);
			}
		}
	}
#endif
#ifndef OPTION_NTPD
	/* NTP */
	if (ntp_get(&ntp_timeout, ntp_ip)<0)
	{
		TIMECMD[0] = 0;
		TIMEINTERVAL = 0;
	}
	else
	{
		strcpy (TIMECMD, "/bin/ntpclient -s -h ");
		strcat (TIMECMD, ntp_ip);
		strcat (TIMECMD, " > /dev/null");
		TIMEINTERVAL = ntp_timeout;
	}
#endif
}

int __argc;
char **__argv;
int main (int argc, char *argv[])
{
	pid_t pid;
	FILE *F;
	#ifdef LOGROTATE
	int round;
	#endif
	time_t ti;
	#ifndef OPTION_NTPD
	time_t last_ntp_sync=0;
	#endif
	time_t last_cleanup=time(NULL);

	#ifdef LOGROTATE
	round = 0;
	#endif
	__argc = argc;
	__argv = argv;
#ifndef OPTION_NTPD
	TIMECMD[0] = '\0';
	TIMEINTERVAL = 0;
#endif
	tty_init();
	#ifdef LOGROTATE
	init_logrotate();
	#endif

	pid=getpid();
	F=fopen("/var/run/systty.pid","w");
	if (F)
	{
		fprintf(F, "%d", pid);
		fclose(F);
	}
#if 0 /* Estava fudendo com get_runlevel() !!! */
	F=fopen("/var/run/utmp","w");
	if (F) fclose(F);
#endif

	signal(SIGHUP, tty_sighup);
	signal(SIGTERM, tty_exit);
	signal(SIGKILL, tty_kill);

	while (1)
	{
		#if 0
		pid = waitpid (-1, NULL, WNOHANG);
		if (pid > 0)
		{
			int i;

			for (i=0; i < TTYCOUNT; i++)
			{
				if (!TTY[i].valid) continue;
				if (TTY[i].handler == pid)
				{
					TTY[i].handler = -1;
					_tty_handle(i);
				}
			}
		}
		#endif
		tty_loop();
		#ifdef LOGROTATE
		round = (round+1) & 15;
		if (!round) check_logrotate();
		#endif
		sleep(1); /* 1s */
#ifndef OPTION_NTPD
		if (TIMEINTERVAL)
		{
			ti=time(NULL);
			if (!last_ntp_sync || ((ti - last_ntp_sync) >= TIMEINTERVAL))
			{
				system(TIMECMD);
				last_ntp_sync=ti;
				syslog(LOG_NOTICE, "ntp-sync exec");
			}
		}
#endif
		if (CLEANUPINTERVAL)
		{
			ti=time(NULL);
			if ((ti - last_cleanup) >= CLEANUPINTERVAL)
			{
				last_cleanup=ti;
				cleanup_modules();
			}
		}
	}
}

void tty_exit(int signal)
{
	int i;

	syslog(LOG_NOTICE, "received TERM signal");
	for (i=0; i < TTYCOUNT; i++)
	{
		if (TTY[i].admin_up)
		{
			if (!TTY[i].valid) continue;
			TTY[i].admin_up=0;
			_tty_reset(i);
		}
	}
#ifdef OPTION_X25
	for (i=0; i < RFC1356_COUNT; i++)
	{
		if (TUNNEL[i].admin_up)
		{
			if (!TUNNEL[i].valid) continue;
			TUNNEL[i].admin_up=0;
			_tunnel_reset(i);
		}
	}
#endif
	remove("/var/run/systty.pid");
	exit(0);
}

void tty_kill(int signal)
{
	remove("/var/run/systty.pid");
	exit(0);
}

