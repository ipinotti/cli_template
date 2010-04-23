#include <libconfig/defines.h>

#define TTYCOUNT MAX_WAN_INTF+MAX_AUX_INTF /* 0-1:serial0-1; 2-3: aux0-1; */
#define RFC1356_COUNT 10 /* serial0.x 1-9 */

typedef short line_type;
enum {
	unassigned,
	type_ppp,
	type_rfc1356
};

typedef short run_state;
enum {
	st_down = 1,
	st_starting,
	st_running,
	st_dying,
	st_dead
};

typedef struct linestruct
{
	short		valid;
	short		admin_up;
	line_type	type;
	run_state	running;
	pid_t		handler;
	time_t		holdtime;
	short		restartcount;
	time_t		restarts[8];
	short		activate_delay;
	short		deactivate_delay;
	ppp_config	ppp;
} systty;

#ifdef OPTION_X25
typedef struct rfc1356_struct
{
	short		valid;
	short		admin_up;
	line_type	type;
	run_state	running;
	int		handler;
	time_t		holdtime;
	short		restartcount;
	time_t		restarts[8];
	struct rfc1356_config rfc1356_cfg;
} rfc1356;
#endif

void _tty_handle (int num);
void _tunnel_handle (int num);
void _tty_reset (int num);
void _tunnel_reset (int num);
void _tty_init (int num, ppp_config *cfg);
void _tunnel_init (int num);
void _tty_register_restart (int num);
void _tunnel_register_restart (int num);
pid_t tty_run_handler (int node);
pid_t tunnel_run_handler(int node);
void tty_secrets(systty *tty);
pid_t _tty_ppp_handler (int node);
void tty_init (void);
void tty_loop (void);
void tty_sighup (int sig);
void tty_loadconfig (void);
void tty_exit (int signal);
void tty_kill (int signal);

