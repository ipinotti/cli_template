/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <dirent.h>
#include <netdb.h>
#include <linux/autoconf.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <termios.h>
#include <sys/mman.h>	/*mmap*/
#include <dlfcn.h>	/*dlopen, dlsym*/

#define _XOPEN_SOURCE
#include <unistd.h>
#include <crypt.h>
#include <sys/reboot.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "commands.h"
#include "commandtree.h"
#include "cish_main.h"
#include "pprintf.h"
#include "terminal_echo.h"
#include "cish_tacplus.h" /* TAC_PLUS_PRIV_LVL */

#define DEFAULT_ETHERNET_WAN 1 /* default ethernet port for WAN*/

/* local function prototypes */

/* global variables */
struct router_config *router_cfg;
cish_command *completion_root;
cish_command *command_root;
int _cish_loggedin;
int _cish_enable;
int _cish_mask;
int _cish_booting;
int _cish_aux;
int cish_timeout = 0;
int cish_reload = 0;

static void hup_handler(int);
static void alarm_handler(int);

const char *_cish_source;

char buf[1024];
static char prompt[64];
static char prompt_printed = 0; /* debug CR flag */
extern char dynamic_ipsec_menu_name[];

void process_cish_exit(void)
{
	syslog(LOG_INFO, "session closed from %s", _cish_source);
	closelog();
	librouter_config_munmap_cfg(router_cfg);
}

static int _on_nfs(void)
{
	FILE *f;
	char cmdline[256];
	int nfs = 0;

	f = fopen("/proc/cmdline", "r");
	if (f == NULL)
		return 0;

	fread(cmdline, sizeof(cmdline), 1, f);
	if (strstr(cmdline, "nfs") != NULL)
		nfs = 1;

	fclose(f);

	return nfs;
}

static int _print_current_menu()
{
	char buf[32];
	struct menu_mapping_t {
		cish_command *cmd;
		char *menu_str;
	} menu_mapping[] = {
		{ CMD_CONFIGURE, "(config)"},
		{ CMD_KEYCHAIN, "(config-keychain)"},
		{ CMD_KEY, "(config-keychain-key)"},
		{ CMD_POLICYMAP, "(config-pmap)"},
		{ CMD_POLICYMAP_MARKRULE, "(config-pmap-markrule)"},
		{ CMD_POLICY_ROUTE, "(config-proute)"},
		{ CMD_CONFIG_ROUTER_RIP, "(config-router-rip)"},
		{ CMD_CONFIG_ROUTER_OSPF, "(config-router-ospf)"},
#ifdef OPTION_BGP
		{ CMD_CONFIG_ROUTER_BGP, "(config-router-bgp)"},
#endif
		{ CMD_CONFIG_INTERFACE_ETHERNET, "(config-if-ethernet-"},
		{ CMD_CONFIG_INTERFACE_ETHERNET_VLAN, "(config-if-ethernet-"},
#ifdef OPTION_MANAGED_SWITCH
		{ CMD_CONFIG_INTERFACE_ETHERNET_SW_PORT, "(config-if-eth-switch-port-"},
#endif
		{ CMD_CONFIG_INTERFACE_LOOPBACK, "(config-if-loopback-"},
		{ CMD_CONFIG_INTERFACE_TUNNEL, "(config-if-tunnel-"},
#ifdef OPTION_MODEM3G
		{ CMD_CONFIG_INTERFACE_M3G_USB, "(config-if-m3G-"},
		{ CMD_CONFIG_INTERFACE_M3G_BTIN, "(config-if-m3G-"},
#endif
#ifdef OPTION_PPTP
		{ CMD_CONFIG_INTERFACE_PPTP, "(config-if-pptp-"},
#endif
#ifdef OPTION_PPPOE
		{ CMD_CONFIG_INTERFACE_PPPOE, "(config-if-pppoe-"},
#endif
#ifdef OPTION_EFM
		{ CMD_CONFIG_INTERFACE_EFM, "(config-if-efm-"},
		{ CMD_CONFIG_INTERFACE_EFM_VLAN, "(config-if-efm-"},
#endif
#ifdef OPTION_IPSEC
		{ CMD_CONFIG_CRYPTO, "(config-crypto)"},
		{ CMD_IPSEC_CONNECTION_CHILDREN, "(config-crypto-conn-"},
#endif
		{ CMD_IP_DHCP_SERVER, "(config-dhcp-server)"},
		{ NULL, NULL}
	}, *map;

	for (map = menu_mapping; map->cmd != NULL; map++) {
		if (command_root == map->cmd) {
			strcat(prompt, map->menu_str);
		}
	}

	/* Add exceptions here */
#ifdef OPTION_MANAGED_SWITCH
	if (command_root == CMD_CONFIG_INTERFACE_ETHERNET_SW_PORT) {
		if (switch_port >= 0) {
			snprintf(buf, sizeof(buf), "%d)", switch_port);
			strcat(prompt, buf);
		}
	} else
#endif
	if (command_root == CMD_CONFIG_INTERFACE_ETHERNET_VLAN) {
		if (interface_minor >= 0) {
			snprintf(buf, sizeof(buf), "%d.%d)", interface_major, interface_minor);
			strcat(prompt, buf);
		}
	}
	else if (command_root == CMD_IPSEC_CONNECTION_CHILDREN) {
		if (strlen(dynamic_ipsec_menu_name) > 0) {
			strcat(prompt, dynamic_ipsec_menu_name);
			strcat(prompt, ")");
		}
	}
#ifdef OPTION_EFM
	else if (command_root == CMD_CONFIG_INTERFACE_EFM) {
		if (interface_major >= 0) {
			snprintf(buf, sizeof(buf), "%d)", interface_major - EFM_INDEX_OFFSET);
			strcat(prompt, buf);
		}
	}
	else if (command_root == CMD_CONFIG_INTERFACE_EFM_VLAN) {
		if (interface_minor >= 0) {
			snprintf(buf, sizeof(buf), "%d.%d)", interface_major - EFM_INDEX_OFFSET, interface_minor);
			strcat(prompt, buf);
		}
	}
#endif
	else {
		if (interface_major >= 0) {
			snprintf(buf, sizeof(buf), "%d)", interface_major);
			strcat(prompt, buf);
		}
	}

	return 0;
}

/* ==============================================================================
 * main
 * ============================================================================== */

int main(int argc, char *argv[])
{
	char *line;
	char *xline;
	int hadspace;
	char *bootfile;
	int retval;
	int acct_mode; /* command accounting */
	int cmd_mask;

	umask(066); /* -rw------ */

	_cish_booting = 0;
	_cish_source = "console";
	openlog("config", LOG_CONS | LOG_PID, LOG_USER);

	/* Map router configuration */
	router_cfg = librouter_config_mmap_cfg();
	if (router_cfg == NULL)
		exit(-1);

	save_termios();

	/* Begin with NORMAL mask */
	_cish_mask = MSK_NORMAL;

	set_rip_interface_cmds(librouter_quagga_ripd_is_running());
	set_ospf_interface_cmds(librouter_quagga_ospfd_is_running());
#ifdef OPTION_BGP
	set_bgp_interface_cmds(librouter_quagga_bgpd_is_running());
#endif

#if 0
	/* Enable QoS and VPN */
	set_model_qos_cmds(1);
	set_model_vpn_cmds(1);
	set_model_vlan_cmds(1);
#else
	cmd_mask = MSK_QOS | MSK_VPN | MSK_VLAN;
	set_model_cmd_mask(cmd_mask);
#endif

	/* FIXME Read HW ID or something to enable this */
#ifdef OPTION_MANAGED_SWITCH
	set_model_switch_cmds();
#endif
	set_model_ethernet_cmds(OPTION_NUM_ETHERNET_IFACES);

#ifdef OPTION_BRIDGE
	/* initialize bridging */
	librouter_br_initbr();
#endif

	/* Begin at root */
	command_root = CMD;

	if (argc == 2) {
		if (strcmp(argv[1], "-b") == 0) { /* Board is booting up */
			int size;

			librouter_nv_load_ssh_secret(SSH_KEY_FILE);
			librouter_nv_load_ntp_secret(NTP_KEY_FILE);
			librouter_snmp_load_prepare_users();
#if defined(OPTION_EFM) && defined(OPTION_MANAGED_SWITCH)
			librouter_ksz8863_set_default_config();
#endif

			size = librouter_nv_load_configuration(STARTUP_CFG_FILE);

			if (size <= 0) {
				printf("%% using default configuration\n");
				bootfile = DEFAULT_CFG_FILE;
			} else {
				bootfile = STARTUP_CFG_FILE;
			}

			setup_loopback(); /* init loopback0 */
			_cish_loggedin = 1;
			_cish_enable = 2; /* Enable special commands! */
			_cish_booting = 1;
			config_file(bootfile); /* Apply configuration */

			exit(0);
		}
	}

	if (argc > 2) {
		if (strcmp(argv[1], "-h") == 0) {
			_cish_source = argv[2];
		}
	}

	init_logwatch();
	add_logwatch("/var/log/messages");
	hadspace = 0;

	_cish_debug = 0;
	_cish_loggedin = 0;

	rl_readline_name = "cish";
	rl_attempted_completion_function = (CPPFunction *) cish_completion;
	rl_bind_key('?', cish_questionmark);
	//	rl_bind_key (26, ctrlz);
	rl_bind_key('S' & 0x1f, NULL);
	rl_bind_key('R' & 0x1f, NULL);
	rl_variable_bind("horizontal-scroll-mode", "on");
	rl_getc_function = user_getc;
	stifle_history(15);

	/* Register signals */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, hup_handler);
	signal(SIGALRM, alarm_handler);

	alarm(1);

	terminal_lines = router_cfg->terminal_lines;

	syslog(LOG_INFO, "session opened from %s", _cish_source);

	_cish_loggedin = 1;
	_cish_enable = 0;
	while (_cish_loggedin) {
		prompt[0] = 0;
		gethostname(buf, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = 0;
		strncat(prompt, buf, 24);

		_print_current_menu();

		strcat(prompt, _cish_enable ? "#" : ">");
		cish_timeout = router_cfg->terminal_timeout;
		prompt_printed = 1; /* Enable CR on debug log! */

		line = readline(prompt);

		cish_timeout = 0;

		if (!line) {
			printf("exit\n");
			line = strdup("exit");
			hadspace = 0;
		}

		if (line[0] == '!') {
			while (command_root != CMD_CONFIGURE && command_root != CMD)
				cish_execute("exit"); /* return to root! */
			hadspace = 0;
		} else {
			int i;

			for (i = 0; i < 1024 && line[i] == ' '; i++)
				;
			if (i > hadspace) {
				hadspace++; /* next level! */
			} else if (i < hadspace) {
				hadspace--; /* previous level! */
				if (command_root != CMD_CONFIGURE && command_root != CMD) {
					cish_execute("exit");
				}
			}
			xline = &line[i];

			if (strlen(xline)) {
				add_history(line);
				retval = cish_execute(xline);
				/* Command accounting */
				acct_mode = librouter_pam_get_current_acct_cmd_mode(
				                FILE_PAM_GENERIC);
				if (retval && acct_mode != AAA_ACCT_TACACS_CMD_NONE) {
					/* logs anything but exit and enable commands*/
					if (strncmp(line, "exit", strlen("exit")) && strncmp(line,
					                "enable", strlen("enable"))) {
						if ((!_cish_enable)
						                && (acct_mode
						                                == AAA_ACCT_TACACS_CMD_1
						                                || acct_mode
						                                                == AAA_ACCT_TACACS_CMD_ALL)) /* unprivileged user */
							tacacs_log((unsigned char *) line,
							                TAC_PLUS_PRIV_LVL_USR);
						else if ((_cish_enable)
						                && (acct_mode
						                                == AAA_ACCT_TACACS_CMD_15
						                                || acct_mode
						                                                == AAA_ACCT_TACACS_CMD_ALL))
							tacacs_log((unsigned char *) line,
							                TAC_PLUS_PRIV_LVL_MAX);
					}
				}
			}
		}
		free(line);
	}

	process_cish_exit();
	return 0;
}

void setup_loopback(void) /* default startup config for loopback0 */
{
}

void config_file(const char *f)
{
	int i, hadspace = 0;
	char line[1024];
	FILE *F;
	cish_command *ocmd;

	ocmd = command_root;
	command_root = CMD_CONFIGURE;

	F = fopen(f, "r");
	if (F) {
		while (!feof(F)) {
			line[0] = 0;
			fgets(line, 1023, F);
			librouter_str_striplf(line);

			if (strncmp(line, "version", 7) == 0) {
				char cfg_version[32];

				strncpy(cfg_version, line + 8, 32);
				cfg_version[31] = 0;
				librouter_str_striplf(cfg_version);
				if (strcmp(cfg_version, librouter_get_system_version())) {
					fprintf(
					                stderr,
					                "%% Configurations from version %s may not be correctly understood!\n",
					                cfg_version);
				}
				continue;
			}

			if (line[0] == '!') {
				while (command_root != CMD_CONFIGURE)
					cish_execute("exit"); /* return to configure terminal! */
				hadspace = 0;
			} else {
				strncat(line, " ", 1023); /* !!! */
				for (i = 0; i < 1024 && line[i] == ' '; i++)
					;
				if (i > hadspace) {
					hadspace++; /* next level! */
				} else if (i < hadspace) {
					hadspace--; /* previous level! */
					if (command_root != CMD_CONFIGURE) {
						cish_execute("exit");
					}
				}
#ifdef CONFIG_DEVELOPMENT
				if (_on_nfs()) {

					if (command_root == CMD_CONFIG_INTERFACE_ETHERNET
#ifdef CONFIG_DIGISTAR_3G
					                && interface_major == DEFAULT_ETHERNET_WAN
#endif
					) {
						if ((strstr(line, "ip address") != NULL) && (strstr(line, "secondary") == NULL)) {
							syslog(LOG_INFO,
							                "%% NFS Boot: skipping ethernet ip configuration\n");
							continue; /* skip ip address config when using NFS */
						}
						if (strstr(line, "shutdown") != NULL) {
							syslog(LOG_INFO,
							                "%% NFS Boot: skipping ethernet disable\n");
							continue; /* do not shutdown interface as well */
						}
					}
				}
#endif
				if (strlen(&line[i]))
					cish_execute(&line[i]);
			}
		}
		fclose(F);
	} else {
		printf("%% Could not find file: %s\n", f);
	}
	command_root = ocmd;
}

struct logwatch {
	long offset;
	const char *resource;
	int last_message_printed;
} LOGS[16];

void init_logwatch(void)
{
	int i;

	for (i = 0; i < 16; ++i) {
		LOGS[i].offset = -1;
		LOGS[i].resource = NULL;
		LOGS[i].last_message_printed = 0;
	}
}

void add_logwatch(const char *resource)
{
	int i;

	for (i = 0; i < 16 && LOGS[i].resource; i++)
		;
	if (i < 16) {
		LOGS[i].resource = resource;
	}
}

void timed_out(void)
{
	reload_termios(); // isto eh necessario porque estamos saindo a partir
	// de uma funcao chamada pela libreadline podemos estar, portanto, com
	// a configuracao de termios alterada.
	printf("\n");
	syslog(LOG_INFO, "timeout: closing session from %s", _cish_source);

	exit(0);
}

static void hup_handler(int sig)
{
	/* systtyd can reload mgetty and spot us! notify_mgetty() */
	timed_out();
}

static void alarm_handler(int sig)
{
	int l;
	FILE *logfile;
	arg_list argl = NULL;
	char *p, *crsr, _buf[256], name[16], repeat_msg[] = "last message repeated";

	if (cish_reload > 0) {
		cish_reload--;
		if (cish_reload == 10) {
			printf("\n%% Warning: %d seconds to reload!\n", cish_reload);
		} else if (cish_reload == 0) {
			printf("\n%% Reloading startup configuration...\n");
			syslog(LOG_INFO, "timeout: reload startup configuration");
			reboot(0x01234567);
		}
	}

	else if (cish_timeout > 0) {
		cish_timeout--;
		if (cish_timeout == 0)
			timed_out();
	}

	if (_cish_debug) {
		_buf[0] = 0;
		for (l = 0; l < 16 && LOGS[l].resource; l++) {
			if ((logfile = fopen(LOGS[l].resource, "r")) == NULL)
				continue;
			if (LOGS[l].offset == -1) {
				fseek(logfile, -256, SEEK_END);
				fgets(_buf, 255, logfile); /* skip to end of line! */
			} else {
				fseek(logfile, 0, SEEK_END);
				if (ftell(logfile) < LOGS[l].offset) {
					LOGS[l].offset = 0;
					rewind(logfile);
				} else
					fseek(logfile, LOGS[l].offset, SEEK_SET);
			}
			while (!feof(logfile)) {
				_buf[0] = 0;
				fgets(_buf, 255, logfile);
				_buf[255] = 0;
				if (librouter_parse_args_din(_buf, &argl) > 5) {
					crsr = strstr(_buf, argl[4]);
					if (crsr) {
						for (crsr += strlen(argl[4]); *crsr == ' '; crsr++)
							;
						if (*crsr) {
							if (strncmp(crsr, repeat_msg, strlen(
							                repeat_msg)) == 0) {
								if (LOGS[l].last_message_printed) {
									if (prompt_printed) {
										printf("\n");
										rl_on_new_line();
										prompt_printed = 0;
									}
									printf(crsr);
									LOGS[l].last_message_printed
									                = 1;
								}
							} else {
								LOGS[l].last_message_printed = 0;
								p = librouter_debug_find_token(
								                crsr, name, 0);
								if (p != NULL) {
									if (prompt_printed) {
										printf("\n");
										rl_on_new_line();
										prompt_printed = 0;
									}
									printf("%s%s", name, p);
									LOGS[l].last_message_printed
									                = 1;
								}
							}
						}
					}
				}
				librouter_destroy_args_din(&argl);
			}
			LOGS[l].offset = ftell(logfile);
			fclose(logfile);
		}
	}
	alarm(1);
}

// Funcao para ler um caracter, em substituicao `a funcao default da readline.
// A unica diferenca eh que esta trata do timeout.
int user_getc(FILE *stream)
{
	int result;
	unsigned char c;

	cish_timeout = router_cfg->terminal_timeout;

	while (1) {
		result = read(fileno(stream), &c, sizeof(unsigned char));

		if (result == sizeof(unsigned char))
			return (c);

		/* If zero characters are returned, then the file that we are
		 reading from is empty! Return EOF in that case. */
		if (result == 0)
			return (EOF);

		/* If the error that we received was SIGINT, then try again,
		 this is simply an interrupted system call to read ().
		 Otherwise, some error ocurred, also signifying EOF. */
		if (errno != EINTR)
			return (EOF);
	}
}

/* ==============================================================================
 * cish_completion
 *
 * readline function that figures out tab-completion within the current command
 * context.
 * ============================================================================== */

char **cish_completion(char *text, int start, int end)
{
	char **matches;
	char tmp[1024];
	int rightedge;
	int pos;
	cish_command *xcmd;

	completion_root = command_root;
	if (start > 0) {
		pos = 0;
		while ((rl_line_buffer[pos] == ' ') && (pos < start))
			++pos;

		while (pos < start) {
			rightedge = (strchr(rl_line_buffer + pos, ' ') - rl_line_buffer);
			if ((rightedge >= 0) && (rightedge < start)) {
				/* command is now between pos and rightedge */
				memcpy(tmp, rl_line_buffer + pos, rightedge - pos);
				tmp[rightedge - pos] = 0;

				xcmd
				                = completion_root ? expand_token(tmp,
				                                completion_root, -1) : NULL;
				if (xcmd)
					completion_root = xcmd->children;
				pos = rightedge + 1;
			} else
				pos = start;
		}
	}
	matches = (char **) NULL;

	if (!completion_root) {
		matches = (char **) malloc(2 * sizeof(char *));
		printf("\n<enter> no further known parameters\n\n");
		rl_on_new_line();
		rl_ding(); /* ding() */
		matches[0] = strdup("");
		matches[1] = NULL;
		rl_pending_input = '\b';
		return matches;
	}

	matches = (char **) rl_completion_matches(text, cish_command_generator);

	if (!(*matches[0])) {
		rl_completion_append_character = '\0';
	} else {
		rl_completion_append_character = ' ';
	}
	return (matches);
}

/* ==============================================================================
 * cish_command_generator
 *
 * finds the matchint command within the current completion_root context and
 * returns it, or NULL if there was no single choice.
 * ============================================================================== */

int _iteration;

char *cish_command_generator(const char *text, int state)
{
	cish_command *result;
	rl_completion_append_character = ' ';

	if (!state)
		_iteration = 0;

	result = expand_token(text, completion_root, _iteration);
	++_iteration;

	if (result)
		return (char *) strdup(result->name);
	if (!state) {
		rl_ding();
		return (char *) strdup("");
	}
	return NULL;
}

/* ==============================================================================
 * cish_questionmark
 *
 * figures out and prints the currently relevant help information
 * ============================================================================== */

int cish_questionmark(int count, int KEY)
{
	char tmp[1024];
	int rightedge;
	int pos;
	int start = strlen(rl_line_buffer);
	cish_command *xcmd;
	int i;
	int len;
	char incomp[1024] = "";

	completion_root = command_root;
	if (start > 0) {
		pos = 0;
		while ((rl_line_buffer[pos] == ' ') && (pos < start))
			++pos;

		while (pos < start) {
			rightedge = (strchr(rl_line_buffer + pos, ' ') - rl_line_buffer);
			if ((rightedge >= 0) && (rightedge < start)) {
				/* command is now between pos and rightedge */
				memcpy(tmp, rl_line_buffer + pos, rightedge - pos);
				tmp[rightedge - pos] = 0;
				xcmd = expand_token(tmp, completion_root, -1);
				if (!xcmd) {
					printf("\n%% Unrecognized command\n");
					rl_on_new_line();
					return 1;
				}
				if (xcmd->children)
					completion_root = xcmd->children;
				else {
					printf("\n");
					printf("<enter>  no further known parameters\n");
					printf("\n");
					rl_on_new_line();
					return 1;
				}
				pos = rightedge + 1;
			} else {
				strncpy(incomp, rl_line_buffer + pos, 1024);
				incomp[1023] = 0;
				pos = start;
			}
			while ((rl_line_buffer[pos] == ' ') && (pos < start))
				++pos;
		}
	}

	if (completion_root) {
		printf("\n");
		pos = 0;
		rightedge = 0;
		while (completion_root[pos].name) // verifica o tamanho da maior string (para formatar a saida)
		{
			len = strlen(completion_root[pos].name);
			if (len > rightedge)
				rightedge = len;
			++pos;
		}
		pos = 0;
		while (completion_root[pos].name) {
			if ((completion_root[pos].privilege <= _cish_enable)
			                && (completion_root[pos].mask & _cish_mask) && ((incomp[0]
			                == 0) || (strncmp(completion_root[pos].name, incomp,
			                strlen(incomp)) == 0))) {
				printf("%s", completion_root[pos].name);
				len = strlen(completion_root[pos].name);
				for (i = len; i < rightedge; ++i)
					putchar(' ');

				printf("  %s\n", completion_root[pos].help);
			}
			++pos;
		}
		printf("\n");
		rl_on_new_line();
	}
	return 1;
}

/* ==============================================================================
 * _config_changed
 *
 * Compares running and startup configuration and, in case they are different,
 * asks if user wants to save running config.
 * ============================================================================== */

static int _config_changed(void)
{
	FILE *f_running, *f_flash;
	struct stat run_stat, flash_stat;
	char in;
	int ret = 0;

	/* Writes running config */
	if (librouter_config_write(TMP_CFG_FILE, router_cfg) < 0)
		return -1;

	/* Load configuration fron flash */
	librouter_nv_load_configuration(STARTUP_CFG_FILE);

	/* Check size */
	stat(TMP_CFG_FILE, &run_stat);
	stat(STARTUP_CFG_FILE, &flash_stat);

	/* Why does STARTUP_CFG_FILE has one byte more then TMP_CFG_FILE???? */
	if (run_stat.st_size != flash_stat.st_size - 1) {
		ret = 1;
	} else {
		unsigned char *run_buffer, *flash_buffer;
		unsigned char run_hash[16], flash_hash[16];

		/* They have the same size, nevertheless it does not mean they are the same! */
		f_running = fopen(TMP_CFG_FILE, "r");
		f_flash = fopen(STARTUP_CFG_FILE, "r");
		if (!f_running || !f_flash)
			return -1;
		/* malloc the same ammount of memory for both */
		run_buffer = (unsigned char *) malloc(run_stat.st_size);
		flash_buffer = (unsigned char *) malloc(run_stat.st_size);

		fread(run_buffer, 1, run_stat.st_size, f_running);
		fread(flash_buffer, 1, run_stat.st_size, f_flash);

		fclose(f_running);
		fclose(f_flash);

		md5_buffer((char *) run_buffer, run_stat.st_size, run_hash);
		md5_buffer((char *) flash_buffer, run_stat.st_size, flash_hash);

		if (strncmp((char *) run_hash, (char *) flash_hash, 16))
			ret = 1;
	}

	if (ret) {
		printf("System configuration has been modified. Save? [yes/no]:");
		/* Change terminal mode to accept character without ENTER in the end */
		canon_off();
		in = getchar();
		canon_on();
		printf("\n");
		if ((in == 'y') || (in == 'Y')) {
			const char flash_save_cmd[] = "copy running-config startup-config";
			cmd_copy(flash_save_cmd);
		}
	}

	unlink(TMP_CFG_FILE);
	return 0;
}

/* ==============================================================================
 * cish_execute
 *
 * figures what to execute out a commandline and runs the relevant code
 * ============================================================================== */

int cish_execute(const char *cmd)
{
	char realcmd[2048];
	char tmp[1024];
	int rightedge;
	int pos;
	int start = strlen(cmd);
	cish_command *xcmd = NULL;
	int i;

	realcmd[0] = 0;

	pager_init();

#if 0 /* Debug */
	fprintf (stderr, "%% %s\n", cmd);
#endif

	completion_root = command_root;
	if (start > 0) {
		pos = 0;
		while ((cmd[pos] == ' ') && (pos < start))
			++pos;
		/* "    exemplo   arg1 arg2 " */
		/*      ^pos   ^rightedge     */
		while (pos < start) {
			rightedge = (strchr(cmd + pos, ' ') - cmd);
			if (rightedge < 0)
				rightedge = start;
			if ((rightedge >= 0) && (rightedge <= start)) {
				/* command is now between pos and rightedge */
				memcpy(tmp, cmd + pos, rightedge - pos);
				tmp[rightedge - pos] = 0;
				xcmd = expand_token(tmp, completion_root, -1);
				if (!xcmd) {
					int spaces;
#if 1
					if (_cish_booting)
						fprintf(stderr, "%% %s\n", cmd);
#endif
					if ((pos + strlen(prompt)) % 79) {
						printf(prompt);
						printf(cmd);
						printf("\n");
					}
					spaces = pos + strlen(prompt);
					for (i = 0; i < spaces; i++)
						printf(" ");
					printf("^\n");
					printf("%% Invalid input detected at '^' marker.\n");
					return 0;
				}
				if (xcmd->children)
					completion_root = xcmd->children;
				strncat(realcmd, xcmd->name, 1023);
				realcmd[1023] = 0;
				if ((rightedge + 1) < start) {
					strncat(realcmd, " ", 1023);
					realcmd[1023] = 0;
				}
				pos = rightedge + 1;
			} else
				pos = start;
			while ((cmd[pos] == ' ') && (pos < start))
				++pos;
		}
	}
	if (xcmd) {
		if (xcmd->func) {
#if 0 /* Debug */
			printf("Execute line: %s\n", realcmd);
#endif
			xcmd->func(realcmd);
		} else
			printf("%% incomplete command\n");
	} else {
		printf("%% command not found\n");
	}
	return 0;
}

/* ==============================================================================
 * expand_token
 *
 * parses a string into the only unique token within the current context
 * matchint it, or returns NULL.
 *
 * Obs.:
 * 1. se 'iteration' for menor que zero e houver mais de um token que acordo com 
 *    'unexpanded' retorna NULL. (exemplo: unexpanded="t", queue=CMD -> temos 
 *    duas possibilidades: 'traceroute' e 'terminal' -> retorna NULL).
 * 2. na mesma situacao anterior, mas com 'iteration' maior que zero, teremos como
 *    resposta 'traceroute' se 'iteration for 1', 'terminal' se 'iteration' for 2, etc.
 * ============================================================================== */

cish_command *expand_token(const char *unexpanded, cish_command *queue, int iteration)
{
	int idx_inqueue = 0;
	int latest_match = -1;
	int octets;
	int itcnt = 0;

	char tmp[1024];
	char *t;
	char *tt;

	while (queue[idx_inqueue].name) {
		if ((queue[idx_inqueue].privilege <= _cish_enable)
		                && (completion_root[idx_inqueue].mask & _cish_mask)) {
			/* match */
			if ((isdigit(*queue[idx_inqueue].name)) && (strchr(queue[idx_inqueue].name,
			                '-'))) {
				strncpy(tmp, queue[idx_inqueue].name, 1023);
				t = strchr(tmp, '-');
				*t = 0;
				++t;
				if ((isdigit(*tmp)) && (isdigit(*unexpanded)) && (atoi(unexpanded)
				                >= atoi(tmp)) && (atoi(unexpanded) <= atoi(t))
				                && !strchr(unexpanded, '-')) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "-23 - 23") == 0) {
				if ((atoi(unexpanded) >= -23) && (atoi(unexpanded) <= 23)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}

			} else if (strcmp(queue[idx_inqueue].name, "hh:mm:ss") == 0) {
				int d, m, a;
				strncpy(tmp, unexpanded, 1023);
				if (parse_time(tmp, &d, &m, &a) == 0) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if ((queue[idx_inqueue].name[0] != '<') && (strncmp(
			                queue[idx_inqueue].name, unexpanded, strlen(unexpanded))
			                == 0)) {
				if (iteration < 0) {
					// Caso especial: um comando que eh igual ao inicio de outro comando.
					// Ex.: 'ip' e 'ipx'.
					// Eh preciso incluir um teste a mais, pois do contrario se digitarmos
					// 'ip' sera considerado ambiguo.
					if (strncmp(queue[idx_inqueue].name, unexpanded, strlen(
					                queue[idx_inqueue].name)) == 0)
						return &(queue[idx_inqueue]);

					if (latest_match >= 0)
						return NULL;
					latest_match = idx_inqueue;
				} else {
					if (itcnt >= iteration)
						return &(queue[idx_inqueue]);
					++itcnt;
				}
			} else if (strcmp(queue[idx_inqueue].name, "<ipaddress>") == 0) {
				struct in_addr address;
				struct hostent* he;
				int address_ok;

				address_ok = 0;
				if (inet_aton(unexpanded, &address) != 0) {
					if (strcmp(unexpanded, inet_ntoa(address)) == 0)
						address_ok = 1;
				} else {
					if (((he = gethostbyname(unexpanded)) != NULL
					                && he->h_addrtype == AF_INET)) {
						memcpy(&address.s_addr, he->h_addr, he->h_length);
						address_ok = 1;
					}
				}
				if (address_ok) {
					if (iteration < 1) {
						strncpy(EXTCMD, inet_ntoa(address), 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<netmask>") == 0) {
				for (octets = 0; octets < 33; ++octets) {
					if (strncmp(masks[octets], unexpanded, strlen(unexpanded))
					                == 0) {
						if (iteration < 1) {
							strncpy(EXTCMD, masks[octets], 1023);
							EXTCMD[1023] = 0;
							CEXT.func = queue[idx_inqueue].func;
							CEXT.children = queue[idx_inqueue].children;
							return &CEXT;
						}
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<rnetmask>") == 0) {
				for (octets = 0; octets < 33; ++octets) {
					if (strncmp(rmasks[octets], unexpanded, strlen(unexpanded))
					                == 0) {
						if (iteration < 1) {
							strncpy(EXTCMD, rmasks[octets], 1023);
							EXTCMD[1023] = 0;
							CEXT.func = queue[idx_inqueue].func;
							CEXT.children = queue[idx_inqueue].children;
							return &CEXT;
						}
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<ipx network>") == 0) {
				int nibbles = 0;
				strncpy(tmp, unexpanded, 1023);
				t = tmp;
				while (*t) {
					if (isxdigit(*t)) {
						nibbles++;
					} else {
						if (!isspace(*t))
							nibbles = 0;
						break;
					}
					t++;
				}
				if ((nibbles > 0) && (nibbles <= 8)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<ipx node>") == 0) {
				int nibbles = 0;
				strncpy(tmp, unexpanded, 1023);
				t = tmp;
				while (*t) {
					if (isxdigit(*t)) {
						nibbles++;
					} else {
						if (!isspace(*t))
							nibbles = 0;
						break;
					}
					t++;
				}
				if ((nibbles > 0) && (nibbles <= 12)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<x121>") == 0) {
				int nibbles = 0, n;
				strncpy(tmp, unexpanded, 255);
				t = tmp;
				if ((tt = strchr(tmp, '/')) != NULL) {
					*tt = '\0';
					n = atoi(tt + 1);
				} else {
					n = strlen(tmp);
				}
				while (*t) {
					if (isdigit(*t)) {
						nibbles++;
					} else {
						nibbles = 0;
						break;
					}
					t++;
				}
				if ((nibbles > 0) && (nibbles <= 15) && (nibbles <= n)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<cudhexstring>") == 0) {
				int len;

				if ((len = strlen(unexpanded))) {
					int i;

					for (i = 0; unexpanded[i]; i++) {
						if (!isxdigit(unexpanded[i]))
							break;
					}
					if (i == len && len <= 32 && iteration < 1) {
						strncpy(EXTCMD, unexpanded, 32);
						EXTCMD[32] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<bandwidth>") == 0) {
				int i, factor = 0, per = 0;
				char *endptr;

				i = strtol(unexpanded, &endptr, 10);
				if (endptr == NULL)
					factor = 0;
				else {
					if (strcasecmp(endptr, "bps") == 0)
						factor = 1;
					else if (strcasecmp(endptr, "kbps") == 0)
						factor = 1000;
					else if (strcasecmp(endptr, "mbps") == 0)
						factor = 1000000;
					else if (strcasecmp(endptr, "%") == 0) {
						factor = 1;
						per = 1;
					}
				}
				if (factor && (i * factor >= (per ? 1 : QOS_MIN_BANDWIDTH)) && (i * factor <= (per ? 100 : QOS_MAX_BANDWIDTH))) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<burst>") == 0) {
				int i, factor = 0;
				char *endptr;

				i = strtol(unexpanded, &endptr, 10);
				if (endptr == NULL)
					factor = 0;
				else {
					if (strcasecmp(endptr, "bytes") == 0)
						factor = 1;
					else if (strcasecmp(endptr, "kbytes") == 0)
						factor = 1024;
				}
				if (factor && (i * factor >= 1500) && (i * factor <= 65536)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<port>") == 0) {
				int port = 0;
				struct servent *service_entry;

				service_entry = getservbyname(unexpanded, NULL); /* search in /etc/services */
				if (service_entry == NULL && isdigit(*unexpanded))
					port = atoi(unexpanded);
				if (service_entry || (port >= 1 && port <= 65535)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<ports>") == 0) {
				char *p, *local;
				int ok = 1, comm = 0;

				if ((local = malloc(strlen(unexpanded) + 1))) {
					strcpy(local, unexpanded);
					for (p = local; *p; p++) {
						if (isdigit(*p) == 0) {
							if (*p == ',') {
								comm++;
								*p = ' ';
							} else {
								ok = 0;
								break;
							}
						}
					}
					if (ok && comm <= 7) {
						int i, n;
						arg_list argl = NULL;

						if ((n = librouter_parse_args_din(local, &argl))
						                > 0) {
							free(local);
							local = NULL;
							if (comm == (n - 1)) {
								for (i = 0; i < n && ok; i++) {
									int port = 0;
									struct servent
									                *service_entry;

									service_entry
									                = getservbyname(
									                                argl[i],
									                                NULL); /* search in /etc/services */
									if (service_entry == NULL
									                && isdigit(
									                                *argl[i]))
										port
										                = atoi(
										                                argl[i]);
									if (service_entry
									                || (port
									                                >= 1
									                                && port
									                                                <= 65535))
										ok = 1;
									else
										ok = 0;
								}
								librouter_destroy_args_din(&argl);
								if (ok) {
									if (iteration < 1) {
										strncpy(
										                EXTCMD,
										                unexpanded,
										                255);
										EXTCMD[255] = 0;
										CEXT.func
										                = queue[idx_inqueue].func;
										CEXT.children
										                = queue[idx_inqueue].children;
										return &CEXT;
									}
								}
							}
						}
					}
					if (local)
						free(local);
				}
			} else if (strcmp(queue[idx_inqueue].name, "<acl>") == 0) {
				if (strlen(unexpanded) && (strchr(unexpanded, '\"') == 0)
				                && (strcmp(unexpanded, "icmp") != 0) && (strcmp(
				                unexpanded, "tcp") != 0) && (strcmp(unexpanded,
				                "udp") != 0) && (strcmp(unexpanded, "mac") != 0)
				                && (strcmp(unexpanded, "ACCEPT") != 0) && (strcmp(
				                unexpanded, "DROP") != 0) && (strcmp(unexpanded,
				                "REJECT") != 0) && (strcmp(unexpanded, "LOG") != 0)
				                && (strcmp(unexpanded, "SNAT") != 0) && (strcmp(
				                unexpanded, "DNAT") != 0) && (strcmp(unexpanded,
				                "MASQUERADE") != 0) && (strcmp(unexpanded, "DSCP")
				                != 0) && (strcmp(unexpanded, "MARK") != 0)
				                && (strcasecmp(unexpanded, "TCPMSS") != 0)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<flags>") == 0) {
				int flags_ok;

				flags_ok = 0;
				if (strlen(unexpanded)) {
					strncpy(tmp, unexpanded, 1023);
					if ((tt = strchr(tmp, '/')) != NULL) {
						t = strtok(tmp, ",/");
						while (t != NULL) {
							if (strcmp(t, "FIN") && strcmp(t, "SYN")
							                && strcmp(t, "RST")
							                && strcmp(t, "PSH")
							                && strcmp(t, "ACK")
							                && strcmp(t, "URG")
							                && strcmp(t, "ALL")) {
								flags_ok = 0;
								break;
							}
							if (t < tt)
								flags_ok |= 0x01;
							else
								flags_ok |= 0x02;
							t = strtok(NULL, ",/");
						}
						if (flags_ok == 0x03) {
							if (iteration < 1) {
								strncpy(EXTCMD, unexpanded, 255);
								EXTCMD[255] = 0;
								CEXT.func = queue[idx_inqueue].func;
								CEXT.children
								                = queue[idx_inqueue].children;
								return &CEXT;
							}
						}
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<url>") == 0) /* http://user:pass@www.pd3.com.br/filename */
			{
				if (strlen(unexpanded)) {
					strncpy(tmp, unexpanded, 1023);
					t = NULL;
					if (!strncmp(tmp, "http://", 7))
						t = tmp + 7;
					if (!strncmp(tmp, "ftp://", 6))
						t = tmp + 6;
					if (t != NULL) {
						if (iteration < 1) {
							strncpy(EXTCMD, unexpanded, 255);
							EXTCMD[255] = 0;
							CEXT.func = queue[idx_inqueue].func;
							CEXT.children = queue[idx_inqueue].children;
							return &CEXT;
						}
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<string>") == 0) {
				if (strlen(unexpanded)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<text>") == 0) {
				if (strlen(unexpanded) && (strchr(unexpanded, '\"') == 0)) {
					if (iteration < 1) {
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<mac>") == 0) {
				if (strlen(unexpanded)) {
					arg_list argl = NULL;
					if (librouter_parse_args_din((char *) unexpanded, &argl)
					                > 0) {
						if (strlen(argl[0]) == 17) {
							int i = 0;
							char *p = argl[0];
							for (; i < 6; i++, p += 3) {
								if (isxdigit(*p) == 0)
									break;
								if (isxdigit(*(p + 1)) == 0)
									break;
								if (i < 5) {
									if (*(p + 2) != ':')
										break;
								}
							}
							if (i == 6) {
								librouter_destroy_args_din(&argl);
								if (iteration < 1) {
									strncpy(EXTCMD, unexpanded,
									                1023);
									EXTCMD[1023] = 0;
									CEXT.func
									                = queue[idx_inqueue].func;
									CEXT.children
									                = queue[idx_inqueue].children;
									return &CEXT;
								}
							}
						}
						librouter_destroy_args_din(&argl);
					}
				}
			}
		}
		++idx_inqueue;
	}
	if (latest_match >= 0)
		return &(queue[latest_match]);
	return NULL;
}

void term_length(const char *cmd)
{
	arglist *args;

	args = librouter_make_args(cmd);

	terminal_lines = router_cfg->terminal_lines = atoi(args->argv[2]);

	librouter_destroy_args(args);
}

void term_timeout(const char *cmd)
{
	arglist *args;

	args = librouter_make_args(cmd);

	cish_timeout = router_cfg->terminal_timeout = atoi(args->argv[2]);

	librouter_destroy_args(args);
}

void config_clock(const char *cmd) /* clock set [hh:mm:ss] dia mes ano */
{
	arglist *args;
	int day, mon, year, hour, min, sec;
	time_t tm;
	struct tm tm_time;

	if (librouter_exec_check_daemon(NTP_DAEMON)) {
		printf("NTP service is running. Stop this service first.\n");
		return;
	}

	args = librouter_make_args(cmd);

	if ((args->argc < 3) || (parse_time(args->argv[2], &hour, &min, &sec) < 0)) {
		librouter_destroy_args(args);
		return;
	}

	time(&tm);
	localtime_r(&tm, &tm_time);

	if (args->argc > 3)
		day = atoi(args->argv[3]);
	else
		day = tm_time.tm_mday;

	if (args->argc > 4)
		mon = atoi(args->argv[4]);
	else
		mon = tm_time.tm_mon + 1;

	if (args->argc > 5)
		year = atoi(args->argv[5]);
	else
		year = tm_time.tm_year + 1900;

	if (librouter_time_set_date(day, mon, year, hour, min, sec) < 0)
		printf("%% Could not set date\n");

	librouter_destroy_args(args);
}

void config_clock_timezone(const char *cmd)
{
	arglist *args;
	char *name;
	int hours, mins;

	args = librouter_make_args(cmd);
	name = args->argv[2];
	hours = atoi(args->argv[3]);
	if (args->argc > 4)
		mins = atoi(args->argv[4]);
	else
		mins = 0;

	librouter_time_set_timezone(name, hours, mins);
	librouter_destroy_args(args);
}

void hostname(const char *cmd)
{
	arglist *args;

	args = librouter_make_args(cmd);
	sethostname(args->argv[1], strlen(args->argv[1]));
	librouter_destroy_args(args);
}

void help(const char *cmd)
{
	printf("Help may be requested at any point in a command by entering\n");
	printf("a question mark '?'.  If nothing matches, the help list will\n");
	printf("be empty and you must backup until entering a '?' shows the\n");
	printf("available options.\n");
	printf("Two styles of help are provided:\n");
	printf("1. Full help is available when you are ready to enter a\n");
	printf("   command argument (e.g. 'show ?') and describes each possible\n");
	printf("   argument.\n");
	printf("2. Partial help is provided when an abbreviated argument is entered\n");
	printf("   and you want to know what arguments match the input\n");
	printf("   (e.g. 'show pr?'.)\n\n");
}

void reload(const char *cmd)
{
	int in;
	struct termios initial_settings, new_settings;

	cish_timeout = router_cfg->terminal_timeout;
	fflush(stdout);

	/* Flushes stdin */
	new_settings.c_cc[VMIN] = 0; /* Minimum number of bytes is stdin to allow a read() */
	new_settings.c_cc[VTIME] = 0; /* Maximum time to wait for input in a read() */
	tcgetattr(0, &initial_settings);
	new_settings = initial_settings;
	new_settings.c_lflag &= ~ICANON;
	new_settings.c_cc[VMIN] = 0;
	new_settings.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &new_settings);
	while (fgetc(stdin) != EOF)
		; /* Empty stdin */
	tcsetattr(0, TCSANOW, &initial_settings);

	/* Check if configuration has changed and should be saved */
	_config_changed();

	/* Question for saving configuration? */
	printf("Proceed with reload? [confirm]");

	/* Wait for input in non-canonical mode */
	canon_off();
	in = fgetc(stdin);
	canon_on();
	cish_timeout = 0;
	printf("\n");

	if ((in == 'y') || (in == 'Y') || (in == '\n'))
		reboot(0x01234567);
}

void reload_cancel(const char *cmd)
{
	if (cish_reload) {
		cish_reload = 0; /* disable timeout! */
		printf("Reload aborted!\n");
	}
}

void reload_in(const char *cmd) /* reload in [1-60] */
{
	arglist *args;
	int timeout, in;
	struct termios initial_settings, new_settings;

	args = librouter_make_args(cmd);
	timeout = atoi(args->argv[2]);
	cish_timeout = router_cfg->terminal_timeout;
	printf("Reload scheduled in %d minutes\n", timeout);
	printf("Proceed with reload? [confirm]");
	fflush(stdout);
	tcgetattr(0, &initial_settings);
	new_settings = initial_settings;
	new_settings.c_lflag &= ~ICANON;
	new_settings.c_cc[VMIN] = 0;
	new_settings.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &new_settings);
	while (fgetc(stdin) != EOF)
		;
	tcsetattr(0, TCSANOW, &initial_settings);
	in = fgetc(stdin);
	cish_timeout = 0;
	printf("\n");

	if ((in == 'y') || (in == 'Y') || (in == '\n'))
		cish_reload = timeout * 60;

	librouter_destroy_args(args);
}

void show_reload(const char *cmd)
{
	if (cish_reload) {
		printf("Reload scheduled in %d minutes and %d seconds\n", cish_reload / 60,
		                cish_reload % 60);
	} else {
		printf("No reload is scheduled.\n");
	}
}

void stop_syslogd(void)
{
	FILE *f;
	char buf[128];
	arg_list argl = NULL;

	if ((f = fopen(FILE_SYSLOGD_PID, "r")) != NULL) {
		if (fgets(buf, 127, f) != NULL) {
			buf[127] = 0;
			if (librouter_parse_args_din(buf, &argl) > 0)
				kill(atoi(argl[0]), SIGTERM);
			librouter_destroy_args_din(&argl);
		}
		fclose(f);
	}
}

void log_remote(const char *cmd) /* logging remote <address> */
{
	arglist *args;
	char buf[16], option[24];

	librouter_kill_daemon(PROG_SYSLOGD);
	stop_syslogd();
	args = librouter_make_args(cmd);
	if (librouter_exec_get_init_option_value(PROG_SYSLOGD, "-R", buf, 16) >= 0) {
		if (strcmp(buf, args->argv[2]) == 0) {
			librouter_destroy_args(args);
			return;
		}
		sprintf(option, "-L -R %s", buf);
		librouter_exec_change_init_option(0, PROG_SYSLOGD, option);
	}
	sprintf(option, "-L -R %s", args->argv[2]);
	librouter_exec_change_init_option(1, PROG_SYSLOGD, option);
	librouter_destroy_args(args);
	librouter_exec_daemon(PROG_SYSLOGD);
}

void no_log_remote(const char *cmd)
{
	char buf[16], option[24];

	if (librouter_exec_get_init_option_value(PROG_SYSLOGD, "-R", buf, 16) >= 0) {
		librouter_kill_daemon(PROG_SYSLOGD);
		stop_syslogd();
		sprintf(option, "-L -R %s", buf);
		librouter_exec_change_init_option(0, PROG_SYSLOGD, option);
		librouter_exec_daemon(PROG_SYSLOGD);
	}
}

int ctrlz(int count, int KEY)
{
	//	printf("Ctrl+Z pressionado\n");
	return 0;
}

void firmware_download(const char *cmd) /* firmware download <url> */
{
	arglist *args;

	args = librouter_make_args(cmd);

	librouter_exec_prog(0, "/bin/wget", "-P", "/mnt/image", args->argv[2], NULL);
	librouter_destroy_args(args);
}

void firmware_save(const char *cmd)
{
	librouter_write_image(1);
}

void firmware_upload(const char *cmd)
{
	/* Enable upload service */
	if (librouter_exec_set_inetd_program(1, FTP_DAEMON) < 0) {
		printf("%% Not possible to enable FTP server\n");
		return;
	}
}

void no_firmware_upload(const char *cmd)
{
	/* Disable upload service */
	if (librouter_exec_set_inetd_program(0, FTP_DAEMON) < 0) {
		printf("%% Not possible to disable FTP server\n");
		return;
	}
}

#ifdef OPTION_IPSEC
struct runn_ipsec_itf {
	char ipsec_intf[32];
	char local_addr[32];
};

static void clear_ipsec_counters(char *conn_name)
{
	IP addr;
	int i, n;
	FILE *output;
	char *p, *t, line[1024];
	char name_buf[32];
	arg_list argl = NULL;
	unsigned int count, found;
	struct runn_ipsec_itf entry[MAX_CONN];

	if (librouter_ipsec_is_running()) { /* Wait pluto start! */
		output = popen("/lib/ipsec/whack --status", "r");
		if (!output) {
			printf("%% Not possible to clear counters\n");
			return;
		}

		/* Search for string containing the pair ipsec interface + real interface */
		for (count = 0; (count < MAX_CONN) && fgets(line, 1024, output);) {
			if ((n = librouter_parse_args_din(line, &argl)) > 3) {
				if ((strcmp(argl[1], "interface") == 0) && (strncmp(argl[2],
				                "ipsec", strlen("ipsec")) == 0)) {
					if ((p = strchr(argl[2], '/')))
						*p = 0;
					strncpy(entry[count].ipsec_intf, argl[2], 31);
					entry[count].ipsec_intf[31] = 0;
					strncpy(entry[count].local_addr, argl[3], 31);
					entry[count].local_addr[31] = 0;
					count++;
				}
			}
			librouter_destroy_args_din(&argl);
		}
		pclose(output);
		if (count == 0)
			return;

		output = popen("/lib/ipsec/whack --status", "r");
		if (!output) {
			printf("%% Not possible to clear counters\n");
			return;
		}

		/* The connection name will appear with inverted comas */
		sprintf(name_buf, "\"%s\"", conn_name);

		/* Find the right connection */
		for (found = 0; (found == 0) && fgets(line, 1024, output);) {
			if (librouter_parse_args_din(line, &argl) > 3) {
				if ((strstr(argl[1], name_buf) != NULL) && ((p = strstr(argl[2],
				                "===")) != NULL)) {

					p = p + 3; /* Start of IP address */
					t = strstr(p, "[");
					*t = '\0'; /* p now contais an IP address */

					if (inet_aton(p, &addr) != 0) {
						/* Find the right ipsec interface */
						for (i = 0; i < count; i++) {
							if (strcmp(entry[i].local_addr, p) == 0) {
								if (librouter_dev_exists(
								                entry[i].ipsec_intf))
									librouter_clear_interface_counters(
									                entry[i].ipsec_intf);
								found = 1;
							}
						}
					}
				}
			}
			librouter_destroy_args_din(&argl);
		}
		pclose(output);
	}
}
#endif

void clear_counters(const char *cmdline)
{
	arglist *args;
	char *major;
	char *minor;
	char device[32];
	char sub[16];
	char *interface;
	int clear;
	dev_family *if_edited;
	int if_major;
	int if_minor;

	args = librouter_make_args(cmdline); /* clear counters [interface] [major.minor] */
#ifdef OPTION_IPSEC
	if (strcmp(args->argv[2], "crypto") == 0) {
		int i;
		char **list = NULL, **list_ini = NULL;

		if (librouter_ipsec_list_all_names(&list_ini) < 1) {
			printf("%% Not possible to clear counters\n");
			librouter_destroy_args(args);
			return;
		}
		for (i = 0, list = list_ini; i < MAX_CONN; i++, list++) {
			if (*list) {
				if (args->argc > 3) {
					if (strcmp(*list, args->argv[3]) == 0)
						clear_ipsec_counters(*list);
				} else
					clear_ipsec_counters(*list);
				free(*list);
			}
		}
		free(list_ini);
		librouter_destroy_args(args);
		return;
	}
#endif
	strncpy(device, args->argv[2], 31);
	device[31] = 0;
	strncpy(sub, args->argv[3], 15);
	sub[15] = 0;
	if ((if_edited = librouter_device_get_family_by_name(device, str_cish))) {
		major = sub;
		minor = strchr(major, '.');
		if (minor)
			*minor++ = 0;
		if_major = atoi(major);

		if (minor)
			if_minor = atoi(minor);
		else
			if_minor = -1;

		interface = librouter_device_cli_to_linux(if_edited->cish_string, if_major, if_minor);
		if (librouter_dev_exists(interface)) {
			clear = librouter_clear_interface_counters(interface);
		} else {
			printf("%% Inactive interface %s %s\n", device, sub);
		}
		free(interface);
	} else {
		fprintf(stderr, "%% Unknown device type.\n");
	}
	librouter_destroy_args(args);
}
