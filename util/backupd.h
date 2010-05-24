/*
 * backupd.h
 *
 *  Created on: May 21, 2010
 *      Author: tgrande
 */

#ifndef BACKUPD_H_
#define BACKUPD_H_

#define DEBUG
#ifdef DEBUG
#define bkpd_dbg(x,...) \
		printf("%s : %d => ", __FUNCTION__, __LINE__); \
		printf(x, ##__VA_ARGS__)
#else
#define bkpd_dbg(x,...)
#endif


#define BACKUPD_PID_FILE	"/var/run/backupd.pid"
#define BACKUPD_CONF_FILE 	"/etc/backupd/backupd.conf"

#define INTF_STR 		"interface="
#define BCKUP_STR 		"backing_up="
#define MAIN_INTF_STR 		"main_interface="
#define METHOD_STR 		"method="
#define PING_ADDR_STR 		"ping-address="

#define INTF_STR_LEN 		strlen(INTF_STR)
#define BCKUP_STR_LEN 		strlen(BCKUP_STR)
#define MAIN_INTF_STR_LEN 	strlen(MAIN_INTF_STR)
#define METHOD_STR_LEN 		strlen(METHOD_STR)
#define PING_ADDR_STR_LEN	strlen(PING_ADDR_STR)

/*
 * Which methodology to use? For now
 * we define link and ping methods
 */
enum bckp_method {
	BCKP_METHOD_LINK,
	BCKP_METHOD_PING
};

enum bckp_config_field {
	FIELD_INTF,
	FIELD_BCK_UP,
	FIELD_MAIN_INTF,
	FIELD_METHOD,
	FIELD_PING_ADDR,
};

enum bckp_state {
	STATE_NOBACKUP,
	STATE_WAITING,
	STATE_CONNECTING,
	STATE_CONNECTED
};

struct bckp_conf_t {
	struct bckp_conf_t *next;
	char intf_name[32];
	int is_backup; /* Is backing up another interface */
	char main_intf_name[32];
	enum bckp_method method;
	char ping_address[128];
	enum bckp_state state;
};

#endif /* BACKUPD_H_ */
