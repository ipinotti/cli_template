/*
 * backupd.c
 *
 *  Created on: May 21, 2010
 *      Author: tgrande
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <librouter/dev.h> /* get_dev_link */
#include <librouter/usb.h>
#include <librouter/device.h>

#include "backupd.h"

#define NUM_INTF_3G		2
#define PPPD_BIN_FILE 		"/bin/pppd"

static const char * M3G_0_CONFIG_FILE [] = {PPPD_BIN_FILE, "call", "modem-3g-0", NULL};
static const char * M3G_1_CONFIG_FILE [] = {PPPD_BIN_FILE, "call", "modem-3g-1", NULL};
static const char * M3G_2_CONFIG_FILE [] = {PPPD_BIN_FILE, "call", "modem-3g-2", NULL};

static struct bckp_conf_t *bc; /* the only global variable */

enum {
	DEFDATALEN = 56,
	MAXIPLEN = 60,
	MAXICMPLEN = 76,
	MAXPACKET = 65468,
	MAX_DUP_CHK = (8 * 128),
	MAXWAIT = 10,
	PINGINTERVAL = 1,
/* 1 second */
};

static char * backupd_intf_to_kernel_intf(char *interface)
{
	char * intf_k;

	/* adaptação da função librouter_device_to_linux_cmdline, pois a entrada da mesma
	 * se baseia em EX:"ethernet 0", e no caso do backupd, a entrada é EX:"ethernet0"
	 */
	intf_k = librouter_device_to_linux_cmdline(interface);
	strcat(intf_k, &interface[strlen((const char *) interface) - 1]);

	return intf_k;
}

static int in_cksum(unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return ans;
}

static int ping(char *ipaddr, char *device)
{
	struct sockaddr_in pingaddr;
	struct icmp *pkt;
	int pingsock, c, i, ret = 0;
	long arg;
	char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
	struct ifreq ifr;

	bkpd_dbg("Pinging %s ... \n", ipaddr);

	pingsock = socket(AF_INET, SOCK_RAW, 1); /* 1 == ICMP */
	pingaddr.sin_family = AF_INET;
	pingaddr.sin_addr.s_addr = inet_addr(ipaddr);

	/* Force source address to be of the interface we want */
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	ioctl(pingsock, SIOCGIFADDR, &ifr);

	bkpd_dbg("Ping interface %s. IP is %s\n", device,
			inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	if (bind(pingsock, (struct sockaddr*) &ifr.ifr_addr, sizeof(struct sockaddr_in)) == -1) {
		perror("bind");
		exit(2);
	}

	pkt = (struct icmp *) packet;
	memset(pkt, 0, sizeof(packet));

	pkt->icmp_type = ICMP_ECHO;
	pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));

	c = sendto(pingsock, packet, DEFDATALEN + ICMP_MINLEN, 0, (struct sockaddr *) &pingaddr,
	                sizeof(pingaddr));

	/* Set non-blocking */
	if ((arg = fcntl(pingsock, F_GETFL, NULL)) < 0) {
		fprintf(stderr, "Error fcntl(..., F_GETFL) (%s)\n", strerror(errno));
		return -1;
	}

	arg |= O_NONBLOCK;

	if (fcntl(pingsock, F_SETFL, arg) < 0) {
		fprintf(stderr, "Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
		return -1;
	}

	sleep(1);

	/* listen for replies */
	i = 30; /* Number of attempts */
	while (i--) {
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);

		c = recvfrom(pingsock, packet, sizeof(packet), 0, (struct sockaddr *) &from,
		                &fromlen);

		bkpd_dbg("recvfrom returned %d bytes\n", c);

		if (c < 0) {
			usleep(10000);
			continue;
		}

		if (c >= 76) { /* ip + icmp */
			struct iphdr *iphdr = (struct iphdr *) packet;

			pkt = (struct icmp *) (packet + (iphdr->ihl << 2)); /* skip ip hdr */
			if (pkt->icmp_type == ICMP_ECHOREPLY) {
				ret = 1;
				break;
			}
		}
	}

	close(pingsock);
	return ret;
}

static void daemonize(void)
{
	pid_t pid, sid;

	/* already a daemon */
	if (getppid() == 1)
		return;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}


	/* If we got a good PID, then we can exit the parent process. */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}


	/* At this point we are executing as the child process */

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory.  This prevents the current
	 directory from being locked; hence not being able to remove it. */
	if ((chdir("/")) < 0) {
		exit(EXIT_FAILURE);
	}


	/* FIXME --> Comentado para efetuar testes no sistema */
	/* Redirect standard files to /dev/null */
/*
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
*/



}

/**
 * Free configuration
 *
 * Traverse backup configuration structures and free them.
 *
 * @bckp_conf Pointer to linked list of configurations
 * @ret void
 */
static void clear_config(struct bckp_conf_t * bckp_conf)
{
	struct bckp_conf_t * conf = bckp_conf;

	while (conf != NULL) {
		conf = bckp_conf->next;
		free(bckp_conf);
		bckp_conf = conf;
	}

	bckp_conf = NULL;
	return;
}

/**
 * Get config from file
 *
 * The following structure is expected for each configuration
 *
 * interface=ppp0
 * shutdown=yes
 * backing_up=no
 * main_interface=
 * method=ping
 * ping-address=8.8.8.8
 *
 * @ret Pointer to linked list of configs
 */
static struct bckp_conf_t * get_config(void)
{
	FILE *fd;
	char line[128];
	enum bckp_config_field next_field = FIELD_INTF; /* For parser, begin at interface field */
	struct bckp_conf_t *conf = NULL, *bckp_conf = NULL;
	int num_configs = 0; /* Number of configurations found */
	char *p;


	if ((fd = fopen(BACKUPD_CONF_FILE, "r")) == NULL) {
		syslog(LOG_ERR, "Could not open configuration file\n");
		unlink(BACKUPD_PID_FILE);
		exit(-1);
	}

	while (fgets(line, sizeof(line), fd) != NULL) {
		switch (next_field) {
		case FIELD_INTF:
			/* Interface string */
			if (!strncmp(line, INTF_STR, INTF_STR_LEN)) {

				/* If first config, set pointer to be returned */
				if (!num_configs++)
					bckp_conf = conf = malloc(sizeof(struct bckp_conf_t));
				else
					conf = conf->next = malloc(sizeof(struct bckp_conf_t));

				memset(conf, 0, sizeof(struct bckp_conf_t));
				strcpy(conf->intf_name, line + INTF_STR_LEN);

				/* Remove any line break */
				for (p = conf->intf_name; *p != '\0'; p++) {
					if (*p == '\n')
						*p = '\0';
				}

				next_field = FIELD_SHUTD;
				conf->state = STATE_WAITING;
			}
			break;

		case FIELD_SHUTD:
			/* Shutdown field */
			if (!strncmp(line, SHUTD_STR, SHUTD_STR_LEN)) {
				if (strstr(line, "yes"))
					conf->shutdown = 1;
				next_field = FIELD_BCK_UP;
			}
			break;

		case FIELD_BCK_UP:
			/* Is backup field */
			if (!strncmp(line, BCKUP_STR, BCKUP_STR_LEN)) {
				if (strstr(line, "yes"))
					conf->is_backup = 1;
				next_field = FIELD_MAIN_INTF;
			}
			break;

		case FIELD_MAIN_INTF:
			/* Main interface field */
			if (!strncmp(line, MAIN_INTF_STR, MAIN_INTF_STR_LEN)) {
				strcpy(conf->main_intf_name, line + MAIN_INTF_STR_LEN);
				/* Remove any line break */
				for (p = conf->main_intf_name; *p != '\0'; p++) {
					if (*p == '\n')
						*p = '\0';
				}
				next_field = FIELD_METHOD;
			}
			break;

		case FIELD_METHOD:
			/* Which method */
			if (!strncmp(line, METHOD_STR, METHOD_STR_LEN)) {
				if (strstr(line, "link"))
					conf->method = BCKP_METHOD_LINK;
				else
					conf->method = BCKP_METHOD_PING;
				next_field = FIELD_PING_ADDR;
			}
			break;

		case FIELD_PING_ADDR:
			/* Is backup field */
			if (!strncmp(line, PING_ADDR_STR, PING_ADDR_STR_LEN)) {
				strcpy(conf->ping_address, line + PING_ADDR_STR_LEN);
				/* Remove any line break */
				for (p = conf->ping_address; *p != '\0'; p++) {
					if (*p == '\n')
						*p = '\0';
				}
				next_field = FIELD_INTF;
			}
			break;

		default:
			/* Should not reach this */
			syslog(LOG_ERR, "Error while parsing configuration\n");
		}
	}

	/* Something went wrong? */
	if (next_field != FIELD_INTF) {
		syslog(LOG_ERR, "Error while parsing configuration\n");
	}

	return bckp_conf; /* Return first alloc'ed config structure */
}

static void usr_handler(int sig)
{
	/* Reload configuration */
	struct bckp_conf_t *bckp_conf, *bckp_buff_bc, *bc_new;
	bkpd_dbg("do_backup... bc is %p\n", bc);

	bc_new = get_config();
	bckp_buff_bc = bc;

	for (bckp_conf = bc_new; bckp_conf != NULL; bckp_conf = bckp_conf->next) {
		bckp_conf->state = bckp_buff_bc->state;
		bckp_conf->pppd_pid = bckp_buff_bc->pppd_pid;
		bckp_buff_bc = bckp_buff_bc->next;
	}

	clear_config(bc);
	bc = bc_new;
	clear_config(bckp_conf);
	clear_config(bckp_buff_bc);

}

static void hup_handler(int sig)
{
	clear_config(bc);
	unlink(BACKUPD_PID_FILE); /* Remove PID file */
	bkpd_dbg("Exiting...\n");
	exit(0);
}

static void alarm_handler(int sig)
{
	/* TODO Think of something here */
}

static int pppd_spawn(struct bckp_conf_t *conf)
{

	struct bckp_conf_t *bckp_save_pid;
	pid_t pid;
	int m3g_index = -1;

	m3g_index = atoi(&conf->intf_name[3]); /* ppp0 -> 0 */
	bkpd_dbg("M3G INDEX = %d\n\n", m3g_index);

	switch (pid = fork()) {
	case -1:
		syslog(LOG_ERR, "Could not spawn pppd\n");
		break;

	case 0: /* Child, spawn pppd */

		switch (m3g_index) {
		case 0:
			if (execv(PPPD_BIN_FILE, (char * const *) M3G_0_CONFIG_FILE) < 0) {
				perror("Execv - The following error occurred");
				exit(EXIT_FAILURE);
			}
			break;
		case 1:
			if (execv(PPPD_BIN_FILE, (char * const *) M3G_1_CONFIG_FILE) < 0) {
				perror("Execv - The following error occurred");
				exit(EXIT_FAILURE);
			}
			break;
		case 2:
			if (execv(PPPD_BIN_FILE, (char * const *) M3G_2_CONFIG_FILE) < 0) {
				perror("Execv - The following error occurred");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			syslog(LOG_ERR, "Could not load file to spawn pppd\n");
			break;
		}

		break;

	default: /* Parent, save child pid */
		conf->pppd_pid = pid;

		bkpd_dbg("PID DO PPPD - %d\n\n", (int)pid);

		for (bckp_save_pid = bc; bckp_save_pid != NULL; bckp_save_pid = bckp_save_pid->next) {
			if (strcmp(conf->intf_name, bckp_save_pid->intf_name) == 0)
				bckp_save_pid->pppd_pid = conf->pppd_pid;
		}
		clear_config(bckp_save_pid);
		break;
	}

	return 1;
}

static void do_backup(void)
{
	struct bckp_conf_t *bckp_conf, *bckp_buff, *bckp_save_pid;
	bkpd_dbg("do_backup... bc is %p\n", bc);
	bckp_buff = bc;
	int tty_check=-1;

	for (bckp_conf = bc; bckp_conf != NULL; bckp_conf = bckp_conf->next) {

		bkpd_dbg("---------------------------\n");
		bkpd_dbg("Backup configuration\n");
		bkpd_dbg("\tInterface is %s\n", bckp_conf->intf_name);
		bkpd_dbg("\tShutdown is %s\n", bckp_conf->shutdown ? "Enabled" : "Disabled");
		bkpd_dbg("\tBackup is %s\n", bckp_conf->is_backup ? "Enabled" : "Disabled");
		bkpd_dbg("\tPid is %d\n", (int)bckp_conf->pppd_pid);
		bkpd_dbg("\tNext is %p\n", bckp_conf->next);
  		bkpd_dbg("---------------------------\n\n");

  		tty_check = librouter_usb_device_is_modem((atoi(&bckp_conf->intf_name[3])+1)); /* FIXME [dev_num+1] devido a numeração do arquivo no sistema começar em 1 e nao em 0 */
  		bkpd_dbg("tty check = %d  -- %s\n\n",tty_check, bckp_conf->intf_name);

  		if (!tty_check) /* se não apresentar modem na porta, a interface é ignorada pela maquina de estados */
  			continue;

  		/* Main state machine */
		switch (bckp_conf->state) {

		/* shutdown ON */
		case STATE_SHUTDOWN:
			bkpd_dbgb("--STATE SHUTDOWN-- %s\n\n",bckp_conf->intf_name);

			if ( (bckp_conf->shutdown) && (bckp_conf->pppd_pid != (int)NULL) ){

				kill(bckp_conf->pppd_pid,SIGTERM);
				usleep(500); /* necessario para dar tempo de retorno apos efetuar o kill */
				waitpid(bckp_conf->pppd_pid,NULL,0);

				bckp_conf->pppd_pid = (int)NULL;

				for (bckp_save_pid = bc; bckp_save_pid != NULL; bckp_save_pid = bckp_save_pid->next){
					if ( strcmp(bckp_conf->intf_name, bckp_save_pid->intf_name) == 0 )
						bckp_save_pid->pppd_pid = bckp_conf->pppd_pid;
				}
				clear_config(bckp_save_pid);
			}

			bckp_conf->state = STATE_NOBACKUP;

			break;

		/* backup disabled */
		case STATE_NOBACKUP:
			bkpd_dbgb("--STATE NOBACKUP-- %s\n\n",bckp_conf->intf_name);

			if ( (!bckp_conf->is_backup) && (!bckp_conf->shutdown) && (bckp_conf->pppd_pid == (int)NULL) )
				bckp_conf->state = STATE_CONNECT;
			else
				bckp_conf->state = STATE_WAITING;

			break;

		/* Waiting state: We must monitor the main interface status to check
		 * if the backup interface must be enabled */
		case STATE_WAITING:
			bkpd_dbgb("--STATE WAITING-- %s\n\n",bckp_conf->intf_name);


			if(!bckp_conf->shutdown){
				/* Test if back up is enabled */
				if (!bckp_conf->is_backup){
					bckp_conf->state = STATE_SHUTDOWN;
					continue;
				}
				else{
					if (bckp_conf->method == BCKP_METHOD_PING) {
						/* Test if main interface is up */
						if ( ping(bckp_conf->ping_address, backupd_intf_to_kernel_intf(bckp_conf->main_intf_name)) ) {
							if(bckp_conf->pppd_pid != (int)NULL){
								bckp_conf->state = STATE_RECONNECT;
								bkpd_dbgb("PING OK na MAIN_INTF e m3g ON com pid %d\n",bckp_conf->pppd_pid);
							}
							else
								bckp_conf->state = STATE_SHUTDOWN;

							bkpd_dbgb("PING OK -- %s\n",bckp_conf->ping_address);

						}
						else{
							bckp_conf->state = STATE_CONNECT;
							bkpd_dbgb("PING FAIL -- %s\n",bckp_conf->ping_address);
						}
					}
					else
						if (bckp_conf->method == BCKP_METHOD_LINK) {
							if ( librouter_dev_get_link(backupd_intf_to_kernel_intf(bckp_conf->main_intf_name)) ){
								if(bckp_conf->pppd_pid != (int)NULL){
									bckp_conf->state = STATE_RECONNECT;
									bkpd_dbgb("LINK OK na MAIN_INTF e m3g ON com pid %d\n",bckp_conf->pppd_pid);
								}
								else
									bckp_conf->state = STATE_SHUTDOWN;

								bkpd_dbgb("LINK OK\n");
							}
							else{
								bckp_conf->state = STATE_CONNECT;
								bkpd_dbgb("LINK Fail\n");
							}
					}
				}
			}
			else
				bckp_conf->state = STATE_SHUTDOWN;

			break;

		case STATE_RECONNECT:
			/* Must check whether the main interface link has been reestablished */
			bkpd_dbgb("--STATE RECONNECT-- %s\n\n",bckp_conf->intf_name);

			if(!bckp_conf->shutdown && bckp_conf->is_backup && bckp_conf->pppd_pid != (int)NULL){
				kill(bckp_conf->pppd_pid,SIGTERM);
				usleep(500); /* necessario para dar tempo de retorno apos efetuar o kill */
				waitpid(bckp_conf->pppd_pid,NULL,0);

				bckp_conf->pppd_pid = (int)NULL;

				for (bckp_save_pid = bc; bckp_save_pid != NULL; bckp_save_pid = bckp_save_pid->next){
					if ( strcmp(bckp_conf->intf_name, bckp_save_pid->intf_name) == 0 )
						bckp_save_pid->pppd_pid = bckp_conf->pppd_pid;
				}
				clear_config(bckp_save_pid);

			}
			bckp_conf->state = STATE_SHUTDOWN;


			break;

		case STATE_CONNECT:
			/* Power on the backup link m3G */
			bkpd_dbgb("--STATE CONNECT-- %s\n\n",bckp_conf->intf_name);

			if ( !bckp_conf->shutdown && bckp_conf->pppd_pid == (int)NULL ){
				bkpd_dbg("Before pppd spawn - %s com pid %d\n", bckp_conf->intf_name, bckp_conf->pppd_pid);
				pppd_spawn(bckp_conf);
				bkpd_dbg("After pppd spawn - %s com pid %d\n", bckp_conf->intf_name, bckp_conf->pppd_pid);
			}

			bckp_conf->state = STATE_SHUTDOWN;
			break;

		default:
			break;

		}


	}
	bckp_conf=NULL;
	bckp_save_pid=NULL;
}

int main(int argc, char **argv)
{

	pid_t mypid;
	FILE *pidfd;
	char buf[32];
	int nodaemon = 0;
	int opt;

	/* Parse opts */
	while ((opt = getopt(argc, argv, "f")) != -1) {
		switch (opt) {
		case 'f':
			nodaemon = 1;
			break;
		default: /* '?' */
			fprintf(stderr, "Usage: %s [-f]\n", argv[0]);
			exit(-1);
		}
	}

	/* Daemonize */
	if (!nodaemon)
		daemonize();

	/* Check if another instance is running */
	if ((pidfd = fopen(BACKUPD_PID_FILE, "r")) != NULL) {
		fprintf(stderr, "Another instance is already running. Exiting ...\n");
		fclose(pidfd);
		exit(-1);
	}

	/* Save pid */
	mypid = getpid();
	if ((pidfd = fopen(BACKUPD_PID_FILE, "w+")) != NULL) {
		sprintf(buf, "%d\n", (int) mypid);
		fwrite((const void *) buf, strlen(buf), 1, pidfd);
		fclose(pidfd);
	} else {
		fprintf(stderr, "Could not write to PID file\n");
		exit(-1);
	}

	/* Register signal handlers */
	signal(SIGUSR1, usr_handler);
	signal(SIGALRM, alarm_handler);
	signal(SIGHUP, hup_handler);
	signal(SIGTERM, hup_handler);
	signal(SIGINT, hup_handler);

	//alarm(1); /* Interrupt in 1 sec */
	bc = get_config();

	/* Do the job */
	while (1) {
		sleep(2);
		bkpd_dbg("Main loop ...\n");
		do_backup();
	}

	unlink(BACKUPD_PID_FILE);
	exit(0);
}
