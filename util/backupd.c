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
#include <librouter/modem3G.h>
#include <librouter/quagga.h>
#include <librouter/str.h>

#include "backupd.h"

#define PPPD_BIN_FILE 	"/bin/pppd"

static const char * M3G_0_CONFIG_FILE[] = { PPPD_BIN_FILE, "call", "modem-3g-0", NULL };
static const char * M3G_1_CONFIG_FILE[] = { PPPD_BIN_FILE, "call", "modem-3g-1", NULL };
static const char * M3G_2_CONFIG_FILE[] = { PPPD_BIN_FILE, "call", "modem-3g-2", NULL };

static struct bckp_conf_t *bc; /* global variable for config. intf.*/
static int current_sim = 0; /* global variable for store current SIM in MG30 */
static int flag_reload = 0; /* global variable for store flag for reload config from file */

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

static void wait_for_dev_goesdown(struct bckp_conf_t *bckp_conf)
{

	while (1) {
		if (librouter_dev_exists(bckp_conf->intf_name) != 1 || bckp_conf->shutdown)
			break;
		bkpd_dbgp("WAITING FOR DEVICE GOES DOWN\n");
		sleep(1); /* necessario para dar tempo de retorno apos efetuar o kill */
	}
	sleep(1);

	return;
}

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

	bkpd_dbgs("Pinging %s ... \n", ipaddr);

	if (librouter_dev_get_link_running(device) <= 0)
		return -1;

	pingsock = socket(AF_INET, SOCK_RAW, 1); /* 1 == ICMP */
	pingaddr.sin_family = AF_INET;
	pingaddr.sin_addr.s_addr = inet_addr(ipaddr);

	/* Force source address to be of the interface we want */
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	ioctl(pingsock, SIOCGIFADDR, &ifr);

	bkpd_dbgs("Ping interface %s. IP is %s\n", device,
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

		bkpd_dbgs("recvfrom returned %d bytes\n", c);

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
 * check_interface_backup_ppp		Verifica se a interface PPP monitorada é backup ou conexão direta
 * o link_running
 *
 * @param bckp_conf
 * @return 1 if it is a direct connection, 0 otherwise
 */
static int check_interface_no_backup(struct bckp_conf_t *bckp_conf)
{
	struct bckp_conf_t *bckp_conf_target;

	for (bckp_conf_target = bc; bckp_conf_target != NULL; bckp_conf_target = bckp_conf_target->next) {
		if (!strcmp(backupd_intf_to_kernel_intf(bckp_conf->main_intf_name), bckp_conf_target->intf_name)){
			if ( !bckp_conf_target->is_backup && !bckp_conf_target->shutdown )
				return 1;
		}
		return 0;
	}
	return 0;
}

/**
 * check_interface_backup_ppp		Verifica a existencia de PID da interface PPP em questao, analisando
 * o link_running
 *
 * @param bckp_conf
 * @return 1 if PPPD_PID and the link is not running, 0 otherwise
 */
static int check_interface_backup_ppp(struct bckp_conf_t *bckp_conf)
{
	struct bckp_conf_t *bckp_conf_target;

	for (bckp_conf_target = bc; bckp_conf_target != NULL; bckp_conf_target = bckp_conf_target->next) {
		if ( bckp_conf_target->is_backup && !bckp_conf_target->shutdown && (bckp_conf_target->main_intf_name != NULL && strlen(bckp_conf_target->main_intf_name) != 0)){
			if (!strcmp(backupd_intf_to_kernel_intf(bckp_conf->main_intf_name), bckp_conf_target->intf_name)){
				if( (bckp_conf_target->pppd_pid != (int) NULL) && (librouter_dev_get_link_running(bckp_conf_target->intf_name) == -1)){
					return 1;
				}
			}
			return 0;
		}
	}
	return 0;
}

/**
 * check_interface_backup_running	Verifica o link_running da main_intf_name (intf backup) da interface monitorada (backup)
 *
 * @param bckp_conf
 * @return 1 if link is running, 0 otherwise
 */
static int check_interface_backup_running(struct bckp_conf_t *bckp_conf)
{
	struct bckp_conf_t *bckp_conf_target;

	for (bckp_conf_target = bc; bckp_conf_target != NULL; bckp_conf_target = bckp_conf_target->next) {
		if(bckp_conf_target->is_backup && !bckp_conf_target->shutdown && (bckp_conf_target->main_intf_name != NULL && strlen(bckp_conf_target->main_intf_name) != 0) ){
			if (!strcmp(backupd_intf_to_kernel_intf(bckp_conf->main_intf_name), bckp_conf_target->intf_name)){
				if( (librouter_dev_get_link_running(backupd_intf_to_kernel_intf(bckp_conf_target->main_intf_name)) == IFF_RUNNING) ){
					return 1;
				}
			}
			return 0;
		}
	}
	return 0;
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

	if ((fd = fopen(BACKUPD_CONF_FILE, "r")) == NULL) {
		syslog(LOG_ERR, "Could not open configuration file\n");
		unlink(BACKUPD_PID_FILE);
		exit(-1);
	}

	bkpd_dbgp("\tREFAZENDO PARSING - GET_CONFIG\n\n");

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
				librouter_str_striplf(conf->intf_name);
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
				librouter_str_striplf(conf->main_intf_name);
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
			if (!strncmp(line, PING_ADDR_STR, PING_ADDR_STR_LEN)) {
				strcpy(conf->ping_address, line + PING_ADDR_STR_LEN);
				/* Remove any line break */
				librouter_str_striplf(conf->ping_address);
				next_field = FIELD_INSTALL_DEFAULT_ROUTE;
			}
			break;

		case FIELD_INSTALL_DEFAULT_ROUTE:
			/* Should install a default route? */
			if (!strncmp(line, DEFAULT_ROUTE_STR, DEFAULT_ROUTE_STR_LEN)) {
				if (strstr(line, "yes"))
					conf->is_default_gateway = 1;
				next_field = FIELD_ROUTE_DISTANCE;
			}
			break;

		case FIELD_ROUTE_DISTANCE:
			/* Is backup field */
			if (!strncmp(line, ROUTE_DISTANCE_STR, ROUTE_DISTANCE_STR_LEN)) {
				if (strstr(line, "yes"))
					conf->default_route_distance = 1;
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

static void reload_config(void)
{
	/* Reload configuration */
	struct bckp_conf_t *bckp_conf, *bckp_buff_bc, *bc_new;
	bkpd_dbgs("do_backup... bc is %p\n", bc);

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

static void usr_handler(int sig)
{
	flag_reload = 1;
	return;
}

static void hup_handler(int sig)
{
	clear_config(bc);
	unlink(BACKUPD_PID_FILE); /* Remove PID file */
	bkpd_dbgs("Exiting...\n");
	exit(0);
}

static void alarm_handler(int sig)
{
	/* TODO Think of something here */
}

/**
 * _install_default_route	Install a default route via quagga
 *
 * The default route will be via the ppp interface in conf
 *
 * @param conf
 * @return 0 if success, -1 if error
 */
static int _install_default_route(struct bckp_conf_t *conf)
{
	struct routes_t *r = malloc(sizeof(struct routes_t));

	if (r == NULL)
		return -1;

	memset(r, 0, sizeof(struct routes_t));

	r->network = strdup("0.0.0.0");
	r->mask = strdup("0.0.0.0");
	r->interface = strdup(conf->intf_name);
	r->metric = conf->default_route_distance; /* Make this configurable !!!! */

	librouter_quagga_add_route(r);
	librouter_quagga_free_routes(r);

	return 0;
}

/**
 * _remove_default_route	Remove a default route via quagga
 *
 * The removed route will be the one that uses ppp interface
 * referenced in conf
 *
 * @param conf
 * @return 0 if success, -1 if error
 */
static int _remove_default_route(struct bckp_conf_t *conf)
{
	struct routes_t *next, *route = librouter_quagga_get_routes();

	if (route == NULL)
		return -1;

	for (next = route; next != NULL; next = next->next) {
		if (strcmp(next->interface, conf->intf_name))
			continue;
		if (!strcmp(next->network, "0.0.0.0"))
			break;
	}

	if (next)
		librouter_quagga_del_route(next->hash);

	return 0;
}

static int pppd_spawn(struct bckp_conf_t *conf)
{
	pid_t pid;
	int m3g_index = atoi(&conf->intf_name[3]); /*  ex: ppp0 -> 0 */

	bkpd_dbgs("M3G INDEX = %d\n\n", m3g_index);

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
		bkpd_dbgp("pppd has pid %d\n\n", (int)pid);
		conf->pppd_pid = pid;
		break;
	}

	/* Check if default route should be installed */
	if (conf->is_default_gateway)
		_install_default_route(conf);

	return 1;
}

static void do_state_shutdown(struct bckp_conf_t *bckp_conf)
{
	if ((bckp_conf->shutdown) && (bckp_conf->pppd_pid != (int) NULL)) {
		/* Mata processo PPPD */
		kill(bckp_conf->pppd_pid, SIGTERM);

		wait_for_dev_goesdown(bckp_conf);

		waitpid(bckp_conf->pppd_pid, NULL, 0);
		bckp_conf->pppd_pid = (int) NULL;

		_remove_default_route(bckp_conf);
	}

	bckp_conf->state = STATE_NOBACKUP;
}

static void do_state_nobackup(struct bckp_conf_t *bckp_conf)
{

	if ((!bckp_conf->is_backup) && (!bckp_conf->shutdown)
	                && (bckp_conf->pppd_pid == (int) NULL))
		bckp_conf->state = STATE_CONNECT;
	else
		bckp_conf->state = STATE_SIMCHECK;
}

static void do_state_simcheck(struct bckp_conf_t *bckp_conf)
{
	bckp_conf->state = STATE_WAITING;

	/* Interface is administratively up? */
	if (bckp_conf->shutdown)
		return;

	/* Only Built-in modem has SIM card holders */
	if (strcmp(bckp_conf->intf_name, "ppp0"))
		return;

	/* WTF: No pppd running? */
	if (bckp_conf->pppd_pid == (int) NULL)
		return;

	/* Backup SIM is enabled ? */
	if (!librouter_modem3g_sim_order_is_enable())
		return;


	/* If interface is UP, no need for backup SIM for now */
	if (librouter_dev_exists(bckp_conf->intf_name) &&
			((librouter_dev_get_link(bckp_conf->intf_name) == IFF_UP)))
		return;

	/* Do the real work now */
	kill(bckp_conf->pppd_pid, SIGTERM);
	wait_for_dev_goesdown(bckp_conf);
	waitpid(bckp_conf->pppd_pid, NULL, 0);

	sleep(2);

	bckp_conf->pppd_pid = (int) NULL;

	/* Switch SIM */
	current_sim ^= 1;
	librouter_modem3g_sim_card_set(current_sim);
	librouter_modem3g_sim_set_all_info_inchat(current_sim, 0);

	/* Try again! */
	pppd_spawn(bckp_conf);
}

static void bckp_method_ping (struct bckp_conf_t *bckp_conf)
{
	/* Test if main interface is up */
	if (ping(bckp_conf->ping_address, backupd_intf_to_kernel_intf(bckp_conf->main_intf_name)) != -1) {
		if (bckp_conf->pppd_pid != (int) NULL) {
			bckp_conf->state = STATE_MAIN_INTF_RESTABLISHED;
			bkpd_dbgp("PING OK na MAIN_INTF e m3g ON com pid %d\n",bckp_conf->pppd_pid);
		} else
			bckp_conf->state = STATE_SHUTDOWN;

		bkpd_dbgp("PING OK -- %s\n",bckp_conf->ping_address);

	} else {
		if (librouter_dev_get_link_running (bckp_conf->intf_name) == -1){
			if (strstr(bckp_conf->main_intf_name,"m3G")){
				if (check_interface_backup_ppp(bckp_conf) || check_interface_no_backup(bckp_conf)){
					bckp_conf->state = STATE_CONNECT;
					bkpd_dbgp("PING FAIL on main INTF, and its backup_intf is DOWN\n");
				}
				else {
					bckp_conf->state = STATE_SHUTDOWN;
					bkpd_dbgp("PING FAIL on main INTF, and its backup_intf is UP\n");
				}
			}
			else
				bckp_conf->state = STATE_CONNECT;
		}
		else{
			if ( (librouter_dev_get_link_running (bckp_conf->intf_name) == IFF_RUNNING) && (strstr(bckp_conf->main_intf_name,"m3G")) ){
				if (!check_interface_backup_ppp(bckp_conf) && check_interface_backup_running(bckp_conf))
					bckp_conf->state = STATE_MAIN_INTF_RESTABLISHED;
				else
					bckp_conf->state = STATE_SHUTDOWN;
			} else
				bckp_conf->state = STATE_SHUTDOWN;

		}
		bkpd_dbgp("PING FAIL -- %s\n",bckp_conf->ping_address);
	}

}

static void bckp_method_link (struct bckp_conf_t *bckp_conf)
{
	if (librouter_dev_get_link_running(backupd_intf_to_kernel_intf(bckp_conf->main_intf_name)) == IFF_RUNNING) {
		if (bckp_conf->pppd_pid != (int) NULL) {
			bckp_conf->state = STATE_MAIN_INTF_RESTABLISHED;
			bkpd_dbgp("LINK OK na MAIN_INTF e m3g ON com pid %d\n",bckp_conf->pppd_pid);
		} else
			bckp_conf->state = STATE_SHUTDOWN;

		bkpd_dbgp("LINK OK\n");
	} else {
		if (librouter_dev_get_link_running (bckp_conf->intf_name) == -1){
			if (strstr(bckp_conf->main_intf_name,"m3G")){
				if (check_interface_backup_ppp(bckp_conf) || check_interface_no_backup(bckp_conf)){
					bckp_conf->state = STATE_CONNECT;
					bkpd_dbgp("LINK FAIL on main INTF, and its backup_intf is DOWN\n");
				}
				else {
					bckp_conf->state = STATE_SHUTDOWN;
					bkpd_dbgp("LINK FAIL on main INTF, and its backup_intf is UP\n");
				}
			}
			else
				bckp_conf->state = STATE_CONNECT;
		}
		else{
			if ( (librouter_dev_get_link_running (bckp_conf->intf_name) == IFF_RUNNING) && (strstr(bckp_conf->main_intf_name,"m3G")) ){
				if (!check_interface_backup_ppp(bckp_conf) && check_interface_backup_running(bckp_conf))
					bckp_conf->state = STATE_MAIN_INTF_RESTABLISHED;
				else
					bckp_conf->state = STATE_SHUTDOWN;
			} else
				bckp_conf->state = STATE_SHUTDOWN;
		}
		bkpd_dbgp("LINK FAIL\n");
	}
}

static void do_state_waiting(struct bckp_conf_t *bckp_conf)
{

	if (!bckp_conf->shutdown) {

		/* Test if back up is enabled */
		if (!bckp_conf->is_backup) {
			bckp_conf->state = STATE_SHUTDOWN;
			return;
		} else {
			if (bckp_conf->method == BCKP_METHOD_PING) {
				bckp_method_ping(bckp_conf);
			} else
				if (bckp_conf->method == BCKP_METHOD_LINK) {
					bckp_method_link(bckp_conf);
				}
		}
	} else
		bckp_conf->state = STATE_SHUTDOWN;

}

static void do_state_main_intf_restablished(struct bckp_conf_t *bckp_conf)
{

	if ((!bckp_conf->shutdown) && (bckp_conf->is_backup) && (bckp_conf->pppd_pid != (int) NULL)) {
		kill(bckp_conf->pppd_pid, SIGTERM);

		wait_for_dev_goesdown(bckp_conf);

		waitpid(bckp_conf->pppd_pid, NULL, 0);

		bckp_conf->pppd_pid = (int) NULL;
	}

	bckp_conf->state = STATE_SHUTDOWN;
}

static void do_state_connect(struct bckp_conf_t *bckp_conf)
{
	int ret;

	bckp_conf->state = STATE_SHUTDOWN; /*!!!*/

	if (bckp_conf->shutdown)
		return;

	if (bckp_conf->pppd_pid) {
		bkpd_dbgs("WTF, we have a PID for pppd before connecting!\n");
		return;
	}

	if (!strcmp(bckp_conf->intf_name, "ppp0")) {
		current_sim = librouter_modem3g_sim_order_get_mainsim();
		ret = librouter_modem3g_sim_card_set(librouter_modem3g_sim_order_get_mainsim());

		if (ret < 0) {
			syslog(LOG_ERR,
			                "%% Error on set SIM CARD (Built-in 3G Module) for connection");
			bckp_conf->state = STATE_SHUTDOWN;
			return;
		}
	}

	pppd_spawn(bckp_conf);
	bkpd_dbgs("After pppd spawn - %s pid %d\n", bckp_conf->intf_name, bckp_conf->pppd_pid);
}

static void do_backup(void)
{
	struct bckp_conf_t *bckp_conf;
	int tty_check = -1;

	for (bckp_conf = bc; bckp_conf != NULL; bckp_conf = bckp_conf->next) {

		tty_check = librouter_usb_device_is_modem(librouter_usb_get_realport_by_aliasport(
		                (atoi(&bckp_conf->intf_name[3]))));

		bkpd_dbgs("---------------------------\n"
				"Backup configuration\n"
				"\tInterface is %s\n"
				"\tShutdown is %s\n"
				"\tBackup is %s\n"
				"\tPid is %d\n"
				"\tNext is %p\n"
				"\ttty check = %d\n"
				"---------------------------\n\n",
				bckp_conf->intf_name,
				bckp_conf->shutdown ? "Enabled" : "Disabled",
				bckp_conf->is_backup ? "Enabled" : "Disabled",
				(int)bckp_conf->pppd_pid,
				bckp_conf->next,
				tty_check);

		if (tty_check < 0) /* se não apresentar modem na porta, a interface é ignorada pela maquina de estados */
			continue;

		bkpd_dbgp("-------------------------------------\n");
		bkpd_dbgp("DEV NAME -> %s\n",bckp_conf->intf_name);
		bkpd_dbgp("DEV EXISTS -> %d\n",librouter_dev_exists(bckp_conf->intf_name));
		bkpd_dbgp("DEV GET LINK -> %d\n",librouter_dev_get_link(bckp_conf->intf_name));
		bkpd_dbgp("DEV LINK RUNNING -> %d\n",librouter_dev_get_link_running(bckp_conf->intf_name));
		bkpd_dbgp("DEV LINK PID NUM -> %d\n",(int)bckp_conf->pppd_pid);
		bkpd_dbgp("-------------------------------------\n");
		bkpd_dbgp("DEV LINK RUNNING eth0-> %d\n",librouter_dev_get_link_running("eth0"));
		bkpd_dbgp("DEV LINK RUNNING eth1-> %d\n",librouter_dev_get_link_running("eth1"));
		bkpd_dbgp("DEV LINK RUNNING ppp0-> %d\n",librouter_dev_get_link_running("ppp0"));
		bkpd_dbgp("DEV LINK RUNNING ppp1-> %d\n",librouter_dev_get_link_running("ppp1"));
		bkpd_dbgp("DEV LINK RUNNING ppp2-> %d\n",librouter_dev_get_link_running("ppp2"));
		bkpd_dbgp("-------------------------------------\n\n");


		/* Main state machine */
		switch (bckp_conf->state) {
		/* shutdown ON */
		case STATE_SHUTDOWN:
			bkpd_dbgp("-- STATE SHUTDOWN  -- %s\n\n",bckp_conf->intf_name);
			do_state_shutdown(bckp_conf);
			break;

			/* backup disabled */
		case STATE_NOBACKUP:
			bkpd_dbgp("-- STATE NOBACKUP  -- %s\n\n",bckp_conf->intf_name);
			do_state_nobackup(bckp_conf);
			break;

			/* We must monitor the M3G0 interface status to check
			 * if the backup SIM CARD must be enabled*/
		case STATE_SIMCHECK:
			bkpd_dbgp("-- STATE SIMCHECK  -- %s\n\n",bckp_conf->intf_name);
			do_state_simcheck(bckp_conf);
			break;

			/* Waiting state: We must monitor the main interface status to check
			 * if the backup interface must be enabled */
		case STATE_WAITING:
			bkpd_dbgp("-- STATE WAITING   -- %s\n\n",bckp_conf->intf_name);
			do_state_waiting(bckp_conf);
			break;

			/* Must check whether the main interface link has been reestablished */
		case STATE_MAIN_INTF_RESTABLISHED:
			bkpd_dbgp("-- STATE RECONNECT -- %s\n\n",bckp_conf->intf_name);
			do_state_main_intf_restablished(bckp_conf);
			break;

			/* Power on the backup link m3G */
		case STATE_CONNECT:
			bkpd_dbgp("-- STATE CONNECT   -- %s\n\n",bckp_conf->intf_name);
			do_state_connect(bckp_conf);
			break;

		default:
			break;

		}

	}

	bckp_conf = NULL;

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
		sleep(1);
		bkpd_dbgs("Main loop ...\n");
		if (flag_reload) {
			flag_reload = 0;
			reload_config();
		}
		do_backup();
	}

	unlink(BACKUPD_PID_FILE);
	exit(0);
}
