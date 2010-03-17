/* ==============================================================================
 * cish - the cisco shell emulator for LRP
 *
 * (C) 2000 Mad Science Labs / Clue Consultancy
 * This program is licensed under the GNU General Public License
 * ============================================================================== */

#include <dirent.h>
#include <netdb.h>
#include <linux/config.h>
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

#include "cish_tacplus.h" /* TAC_PLUS_PRIV_LVL */

#if defined(CONFIG_BERLIN)
#include "../linux/arch/powerpc/platforms/83xx/berlin.h"
#endif

#define _XOPEN_SOURCE
#include <unistd.h>
#include <crypt.h>
#include <sys/reboot.h>

#include <libconfig/acl.h>
#include <libconfig/args.h>
#include <libconfig/bridge.h>
#include <libconfig/cish_defines.h>
#include <libconfig/debug.h>
#include <libconfig/defines.h>
#include <libconfig/dev.h>
#include <libconfig/device.h>
#include <libconfig/fr.h>
#include <libconfig/ip.h>
#include <libconfig/ipsec.h>
#include <libconfig/exec.h>
#include <libconfig/time.h>
#include <libconfig/nv.h>
#include <libconfig/process.h>
#include <libconfig/ppp.h>
#include <libconfig/ntp.h>
#include <libconfig/ssh.h>
#include <libconfig/str.h>
#include <libconfig/version.h>
#include <libconfig/wan.h>
#include <libconfig/quagga.h>
#include <libconfig/flashsave.h>
#include <libconfig/hash_sn.h>
#include <libconfig/pam.h>
#include <libconfig/system.h>
#include <libconfig/chdlc.h>
#include <libconfig/md5.h>
#ifdef CONFIG_BERLIN_SATROUTER
#include <libconfig/ipx.h>
#include <libconfig/pim.h>
#include <libconfig/qos.h>
#include <libconfig/ppcio.h>
#endif
#include <libconfig/sppp.h>
#include <libconfig/x25.h>

#include "cish_config.h"
#include "cish_main.h"
#include "commandtree.h"
#include "commands.h"
#include "debug.h"
#include "hash.h"
#include "pprintf.h"
#include "ssi.h"
#include "terminal_echo.h"
#ifdef CONFIG_BERLIN_SATROUTER
#include "nat.h"
#include "defines.h"
#include "mangle.h"
#endif

#include <readline/readline.h>
#include <readline/history.h>

/* local function prototypes */

/* global variables */
#if 0
char cish_completed_commandline[1024];
#endif
cish_command *completion_root;
cish_command *command_root;
int _cish_loggedin;
int _cish_enable;
int _cish_mask;
int _cish_booting;
int _cish_aux;
int cish_timeout=0;
int cish_reload=0;

extern int interface_major, interface_minor;

extern cish_command CMD[];
extern cish_command CMD_RAM[];
extern cish_command CMD_FIRMWARE[];
extern cish_command CMD_CONFIGURE[];
extern cish_command CMD_CONFIG_ROUTER[];
extern cish_command CMD_CONFIG_ROUTER_RIP[];
extern cish_command CMD_CONFIG_ROUTER_OSPF[];
#ifdef OPTION_BGP
extern cish_command CMD_CONFIG_ROUTER_BGP[];
#endif
extern cish_command CMD_CONFIG_INTERFACE[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET[];
extern cish_command CMD_CONFIG_INTERFACE_ETHERNET_VLAN[];
extern cish_command CMD_CONFIG_INTERFACE_BRIDGE[];
extern cish_command CMD_CONFIG_INTERFACE_LOOPBACK[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC[];
extern cish_command CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_CHDLC[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_SPPP[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_FR[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBFR[];
#ifdef OPTION_X25
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_X25[];
extern cish_command CMD_CONFIG_INTERFACE_SERIAL_SUBX25[];
#endif
extern cish_command CMD_CONFIG_INTERFACE_TUNNEL[];
extern cish_command CMD_CONFIG_CRYPTO[];
extern cish_command CMD_IPSEC_CONNECTION_CHILDREN[];
extern cish_command CMD_KEYCHAIN[];
extern cish_command CMD_KEY[];
#ifdef OPTION_NEW_QOS_CONFIG
extern cish_command CMD_POLICYMAP[];
extern cish_command CMD_POLICYMAP_MARKRULE[];
#endif

extern void write_config(FILE *f);

void hup_handler(int);
void alarm_handler(int);

const char *_cish_source;

char buf[1024];
static char prompt[64];
static char prompt_printed=0; /* debug CR flag */

#ifdef CONFIG_BERLIN_SATROUTER
  unsigned char support_key[17]="";
  #ifdef CONFIG_DMVIEW_MGNT
	unsigned int dmview_management = 0;
	unsigned int cish_on_serial_console = 0;
	pid_t modem_access_pid = 0;
  #endif
#endif

extern char dynamic_ipsec_menu_name[];

#undef BROWSE_COMMANDS

#ifdef BROWSE_COMMANDS
void print_spaces(int n)
{
	int i;
	for (i=0; i<n; i++) putchar(' ');
}

void browse_commands(cish_command *c, int pos)
{
	while (c->name)
	{
		if (strcmp(c->name, "access-list")==0) { c++; continue; }
		if (strcmp(c->name, "dhcp")==0) { c++; continue; }
		if (strcmp(c->name, "nat-rule")==0) { c++; continue; }

		printf("%s ", c->name);
		if ((c->children)&&(c->children!=c))
			browse_commands(c->children, pos+strlen(c->name)+1);
		c++;
		if (c->name) 
		{
			printf("\n");
			print_spaces(pos);
		}
	}
}

void browse(cish_command *c, char *msg)
{
	printf("\n\n\n--------------------------------------------------------------------------------\n");
	printf("%s\n", msg);
	printf("--------------------------------------------------------------------------------\n\n");
	browse_commands(c, 0);
}

#endif	

void process_cish_exit(void)
{
#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_DMVIEW_MGNT)
	if( dmview_management ) {
		int i;
		pid_t ppid = getppid();

		if( (ppid > 1) && (kill(ppid, SIGUSR1) == 0) ) {
			/* Wait some time for SIGQUIT signal */
			for( i=0; i < 60; i++ )
				sleep(1);
		}
	}
#endif
	syslog(LOG_INFO, "session closed from %s", _cish_source);
	closelog();
	munmap_cfg();

#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_DMVIEW_MGNT)
	if( modem_access_pid > 0 ) {
		kill(modem_access_pid, SIGTERM);
		waitpid(modem_access_pid, NULL, 0);
		modem_access_pid = 0;
	}
	if( release_microcom_lock() )
		set_microcom_mode(MICROCOM_MODE_LISTEN);
#endif
}

#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_DMVIEW_MGNT)
void signal_to_quit(int signal)
{
	if( dmview_management )
		dmview_management = 0;
	process_cish_exit();
	exit(0);
}
#endif

#ifdef CONFIG_BERLIN_SATROUTER

#define NO_SPECIAL_CMD						0
#define SPECIAL_CMD_GENSECRET				1
#define SPECIAL_CMD_FACTORY					2
#define SPECIAL_CMD_MOTHERBOARD_STARTMENU	3
#define SPECIAL_CMD_MOTHERBOARD_INFO		4

/*
 * VT100 escape sequences
 */

#define TERM_HOME		"\e[H"		/* moves cursor to top left */
#define TERM_CLEARLINE		"\e[2K"		/* clears current line */
#define TERM_CLEARDOWN		"\e[J"		/* clears screen from current position to bottom */
#define TERM_CLEARUP		"\e[1J"		/* clears screen from current position to home */
#define TERM_CLEAR		"\e[2J"		/* clears whole screen */
#define TERM_CURSORUP(a)	"\e["#a"A"	/* moves cursor a lines up */
#define TERM_CURSORDOWN(a)	"\e["#a"B"	/* moves cursor a lines down */
#define TERM_CURSORRIGHT(a)	"\e["#a"C"	/* moves cursor a positions to the left */
#define TERM_CURSORLEFT(a)	"\e["#a"D"	/* moves cursor a positions to the right */
#define TERM_RESETATTR		"\e[0m"
#define TERM_FONTBRIGHT		"\e[1m"
#define TERM_FONTDIM		"\e[2m"
#define TERM_FONTUNDERSCORE	"\e[4m"
#define TERM_FONTBLINK		"\e[5m"
#define TERM_FONTREVERSE	"\e[7m"
#define TERM_FONTBLACK		"\e[30m"
#define TERM_FONTRED		"\e[31m"
#define TERM_FONTWHITE		"\e[37m"

#define TERM_KEY_UP		"\e[A"
#define TERM_KEY_DOWN		"\e[B"
#define TERM_KEY_RIGHT		"\e[C"
#define TERM_KEY_LEFT		"\e[D"
#define TERM_KEY_PGUP		"\e[5~"
#define TERM_KEY_PGDOWN		"\e[6~"

#define KEY_UP			0x7f
#define KEY_DOWN		0x7e
#define KEY_RIGHT		0x7d
#define KEY_LEFT		0x7c
#define KEY_PGUP		0x7b
#define KEY_PGDOWN		0x7a

static void exclude_eth1cfg_from_file(char *filename)
{
	FILE *f;
	int n, sep=0;
	struct stat st;
	char *local, buf[128];
	arg_list argl=NULL, argld=NULL;

	if( !filename )
		return;
	if( filename[0] == 0 )
		return;
	if( stat(filename, &st) != 0 )
		return;
	if( st.st_size == 0 )
		return;
	if( !(local = malloc(st.st_size+2)) )
		return;
	local[0] = 0;
	if( !(f = fopen(filename, "r")) )
	{
		free(local);
		return;
	}
	while( !feof(f) )
	{
		if( !fgets(buf, 127, f) )
			break;
		buf[127] = 0;
		switch( (n = parse_args_din(buf, &argl)) )
		{
			case 1:
				sep = (strcmp(argl[0], "!") == 0 ? 1 : 0);
				strcat(local, buf);
				break;
			case 3:
				if( sep && !strcmp(argl[0], "interface") && !strcmp(argl[1], "ethernet") && !strcmp(argl[2], "1") )
				{
					while( !feof(f) )
					{
						fgets(buf, 127, f);
						buf[127] = 0;
						if( parse_args_din(buf, &argld) == 1 )
						{
							if( !strcmp(argld[0], "!") )
							{
								free_args_din(&argld);
								break;
							}
						}
						free_args_din(&argld);
					}
				}
				else
					strcat(local, buf);
				sep = 0;
				break;
			default:
				strcat(local, buf);
				sep = 0;
				break;
		}
		free_args_din(&argl);
	}
	fclose(f);

	if( !(f = fopen(filename, "w")) )
	{
		free(local);
		return;
	}
	fwrite(local, 1, strlen(local), f);
	fclose(f);
	free(local);
}

int is_special_invisible_cmd(char *line, unsigned int authenticated)
{
	arg_list argl=NULL;
	int n, ret_value=NO_SPECIAL_CMD;

	switch((n = parse_args_din(line, &argl)))
	{
		case 2:
			if(!strcmp(argl[0], "factory") && !strcmp(argl[1], "test"))
				ret_value = SPECIAL_CMD_FACTORY;
			else if(!strcmp(argl[0], "enterprise") && !strcmp(argl[1], "gensecret"))
				ret_value = SPECIAL_CMD_GENSECRET;
			else if(!strcmp(argl[0], "motherboard") && !strcmp(argl[1], "startmenu"))
				ret_value = SPECIAL_CMD_MOTHERBOARD_STARTMENU;
			else if(!strcmp(argl[0], "motherboard") && !strcmp(argl[1], "info"))
				ret_value = SPECIAL_CMD_MOTHERBOARD_INFO;
			break;
		default:
			break;
	}
	free_args_din(&argl);

	switch(ret_value)
	{
		case SPECIAL_CMD_GENSECRET:
		{
			int i;
			char *secret, salt[3], passwd[32], passwd_rep[32];
			static unsigned char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";   /* 0 ... 63 => ascii - 64 */

			printf("Password: ");
			fflush(stdout);
			passwd[0] = '\0';

			echo_off();
			fgets(passwd, 16, stdin);
			echo_on();
			printf("\n");
			passwd[16] = '\0';
			striplf(passwd);

			printf("Retype Password: ");
			fflush(stdout);
			passwd_rep[0] = '\0';

			echo_off();
			fgets(passwd_rep, 16, stdin);
			echo_on();
			printf("\n");
			passwd_rep[16] = '\0';
			striplf(passwd_rep);

			if(strcmp(passwd, passwd_rep))
			{
				printf("Passwords differ!\n");
				exit(1);
			}

			srandom((int) time((time_t*) 0));
			for(i=0; i < 2; i++)	salt[i] = itoa64[random() & 63];
			secret = crypt(passwd, salt);

			printf("Password encryption result: \"%s\"\n\n", secret);
			break;
		}
		case SPECIAL_CMD_FACTORY:  /* Estamos entrando no modo teste de fabrica. Precisamos de autenticacao para este modo. */
		{
			int auth_pending;
			char passwd[32], secret[32] = DATACOM_FACTORY_TEST_PASSWD_ENCRYPT; /* Senha: ioEmqFWj */

			if(authenticated)
			{
				cish_timeout = 0;	/* Neste modo nao queremos timeout */
				break;
			}
			for(auth_pending=0; auth_pending < 3; auth_pending++)
			{
				printf("Password: ");
				fflush(stdout);
				passwd[0] = 0;

				echo_off();
				cish_timeout = cish_cfg->terminal_timeout;
				fgets(passwd, 16, stdin);
				cish_timeout = 0;
				echo_on();
				printf("\n");

				passwd[16] = '\0';
				striplf(passwd);
				if(!strcmp(crypt(passwd, secret), secret))
				{
					auth_pending = 0;
					break;
				}
				syslog(LOG_WARNING, "Factory test authentication failure from %s", _cish_source);
				sleep(1);
			}
			if(auth_pending)
			{
				syslog(LOG_WARNING, "Excess failures on factory test authentication from %s", _cish_source);
				return NO_SPECIAL_CMD;
			}
			else
			{
				syslog(LOG_INFO, "Entered in factory test mode from %s", _cish_source);
				cish_timeout = 0;	/* Neste modo nao queremos timeout */
			}
			break;
		}
		case SPECIAL_CMD_MOTHERBOARD_STARTMENU:
		{
			FILE *f;
			char buf[256];

			if( (f = fopen(MOTHERBOARDINFO_TMP, "r")) )
			{
				while( !feof(f) )
				{
					fgets(buf, 255, f);
					buf[255] = 0;
					printf("%s", buf);
				}
				printf("\n");
				fclose(f);
			}
			break;
		}
		case SPECIAL_CMD_MOTHERBOARD_INFO:
		{
			FILE *f;
			char buf[256];

			if( (f = fopen(MOTHERBOARD_INFO_FILE, "r")) )
			{
				while( !feof(f) )
				{
					fgets(buf, 255, f);
					buf[255] = 0;
					printf("%s", buf);
				}
				fclose(f);
			}
			break;
		}
		case NO_SPECIAL_CMD:
			break;
	}
	return ret_value;
}

void printCenter(char *name)
{
	int i, k;

	k = (78 - strlen(name))/2;
	for(i=0; i < k; i++)
		printf(" ");
	printf("%s", name);
}

char readKey(char *options)
{
	char ch = 0, *p;
	char str[30];
	int i;
	int len;
	int fd = fileno(stdin);
	struct termios zap, original;

	fflush(stdout);

	// Desabilita o eco
	tcgetattr(fd, &original);
	zap = original;
	zap.c_lflag &= ~( ECHO | ICANON );
	// tenta ler 4 caracteres com intervalo de 100ms entre cada um deles. Importante
	// para ler teclas como setas e "page up"/"page down"
	zap.c_cc[VMIN] = 4;
	zap.c_cc[VTIME] = 1;
	tcsetattr(fd, TCSANOW, &zap);
	while(1)
	{
		len = read(fd, str, sizeof(str)-1);
		if(len == 1)
		{
			for(i=0; i<0xFF && options[i]!=0; i++)
			{
				if(str[0] == options[i])
				{
					ch = str[0];
					tcsetattr(fd, TCSANOW, &original);
 					fflush(stdout);
 					return ch;
				}
			}
		} else {
			ch = 0;				
			str[len] = '\0'; /* or else strstr won't work */
			if( (p = strstr(options, str) ) != NULL ) {
				if( str[0] == '\e' && str[1] == '[' ) {
					ch = 0;				
					if( len == 3 ) { /* arrow keys */
						switch( str[2] ) {
							case 'A': /* up */
								ch = KEY_UP;
								break;
							case 'B': /* down */
								ch = KEY_DOWN;
								break;
							case 'C': /* right */
								ch = KEY_RIGHT;
								break;
							case 'D': /* left */
								ch = KEY_LEFT;
								break;
						}
					} else if( len == 4 ) { /* pg up or pg down */
						if( str[3] == '~' ) {
							switch( str[2] ) {
								case '5': /* up */
									ch = KEY_PGUP;
									break;
								case '6': /* down */
									ch = KEY_PGDOWN;
									break;
							}
						}
					}
				}
				if( ch ) {
					tcsetattr(fd, TCSANOW, &original);
					fflush(stdout);
					return ch;
				}
			}
		}
	}
	// Retorna a configuracao original
	tcsetattr(fd, TCSANOW, &original);
	return '\0';
}

unsigned int readString(int echo_on, char *store, unsigned int max_len)
{
	char local[10];
	struct termios zap, original;
	int i, len, recv, fd=fileno(stdin);

	if(!store || !max_len)	return 0;
	*store = 0;
	fflush(stdout);
	tcgetattr(fd, &original);
	zap = original;
	zap.c_lflag &= ~(ECHO | ICANON);
	/* Desabilita echo */
	tcsetattr(fd, TCSANOW, &zap);
	for(len=0; len < (max_len-1); )
	{
		if((recv = read(fd, local, sizeof(local))) > 0)
		{
			for(i=0; i < recv; i++)
			{
				if(local[i] == '\n')
				{
					store[len] = 0;
					/* Retorna a configuracao original */
					tcsetattr(fd, TCSANOW, &original);
					return len;
				}
				if(isgraph(local[i]) == 0)
				{	/* Verificamos a possibilidade de um backspace */
					if(local[i]==0x08 && len)
					{
						if(echo_on)
						{
							tcsetattr(fd, TCSANOW, &original);
							printf(TERM_CURSORLEFT(1));
							printf(" ");
							printf(TERM_CURSORLEFT(1));
							fflush(stdout);
							tcsetattr(fd, TCSANOW, &zap);
						}
						len--;
					}
				}
				else
				{
					if(len < (max_len-1))
					{
						store[len++] = local[i];
						if(echo_on)
						{
							tcsetattr(fd, TCSANOW, &original);
							printf("%c", local[i]);
							fflush(stdout);
							tcsetattr(fd, TCSANOW, &zap);
						}
					}
					else	break;
				}
			}
		}
	}
	store[len] = 0;
	/* Retorna a configuracao original */
	tcsetattr(fd, TCSANOW, &original);
	return len;
}

char getOption(char *options)
{
	//printf(TERM_CURSORUP(3));
	printf("         Option: [ ]");
	printf(TERM_CURSORLEFT(2));
	fflush(stdout);
	return readKey(options);
}

void showMenuHead(void)
{
	unsigned int days;
	char buf[64], get[256], local[256];

	printf(TERM_CLEAR);
	printf(TERM_HOME);
	printf(" ------------------------------------------------------------------------------\r\n");
	if(get_mb_info(MBINFO_VENDOR, get, 127))
	{
#if 0
		for(p=get, local[0]=0; *p; p++)
		{
			sprintf(buf, "%c ", *p);
			strcat(local, buf);
		}
#else
		strcpy(local, get);
#endif
	}
	else
		strcpy(local, "ERROR");
	printCenter(local);
	printf("\r\n");
	if(get_mb_info(MBINFO_COMPLETEDESCR, local, 256))
		printCenter(local);
	else
		printCenter("ERROR");
	printf("\r\n");

	/* Exibe mensagem caso a placa esteja em modo trial */
	if(get_uboot_env("trialdays", buf, 9) > 0)
	{
		if(strlen(buf) == 4)
		{
			sscanf(buf, "%x", &days);
			if(days > 0)
			{
				if(days <= 364)
				{
					if(get_trialminutes_counter(buf, 19) >= 0)
					{
						int diff;
						unsigned int minutes = atoi(buf);

						diff = days - (minutes / (60 * 24)) - 1;
						if(diff > 0)
						{
							sprintf(buf, "Time left: %d days", diff);
							printCenter(buf);
							printf("\r\n");
						}
						else
						{
							if((diff = (days * 24 * 60) - minutes) > 0)
							{
								if((diff / 60) > 0)
								{
									sprintf(buf, "Time left: %d hours", diff / 60);
									printCenter(buf);
									printf("\r\n");
								}
								else
								{
									sprintf(buf, "Time left: %d minutes", diff);
									printCenter(buf);
									printf("\r\n");
								}
							}
						}
					}
				}
			}
		}
	}
	printf(" ------------------------------------------------------------------------------\r\n");
}

unsigned int make_dm_login(unsigned char needs_auth)
{
	int ret=AUTH_NOK;
	unsigned char *data, *hash_p, buf[SATR_SN_LEN+1];

	printf(TERM_CLEAR);
	printf(TERM_HOME);
	showMenuHead();
	printf("\n\n\n");
	if( discover_pam_current_mode(FILE_PAM_GENERIC) == AAA_AUTH_NONE ) {
		printf("\tType ENTER to run terminal ");
		fflush(stdout);
		readKey("\n");
		return AUTH_OK;
	}
	if( needs_auth == 0 )
		return AUTH_OK;
	if( (data = (u8 *)readline("Login: ")) == NULL )
		return AUTH_NOK;

	/* Casos especiais */
	if( strcmp((char *)data, "fabrica") == 0 ) {
		free(data);
		echo_off();
		data = (u8 *)readline("Password: ");
		echo_on();
		if( data == NULL )
			return AUTH_NOK;
		ret = (strcmp((char *)data, DATACOM_FACTORY_TEST_PASSWD) == 0) ? AUTH_FACTORY : AUTH_NOK;
		free(data);
		return ret;
	}
	else if( strcmp((char *)data, "support") == 0 ) {
		free(data);
		echo_off();
		data = (u8 *)readline("Password: ");
		echo_on();
		if( data == NULL )
			return AUTH_NOK;
		if( (get_uboot_env("serial#", (char *)buf, SATR_SN_LEN+1) > 0) && (strlen((char *)buf) == SATR_SN_LEN) && ((hash_p = hash_sn_str(buf)) != NULL) )
			ret = (strcmp((char *)hash_p, (char *)data) == 0) ? AUTH_OK : AUTH_NOK;
		free(data);
		return ret;
	}
	ret = proceed_third_authentication((char *)data, "cish");
	free(data);
	return ret;
}

struct motherboard_info
{
	char vendor[64];
	char product_name[64];
	char complete_descr[256];
	char product_code[10];
	char fw_version[10];
	char sn[MODEM_SN_LEN+1];
	char release_date[25];
	char resets[18];
};

void go_motherboard_startmenu(void)
{
	int i, pf;
	char esc=0x1B;  /* Escape */
	struct termios pts, pots;

	/* Abre canal de comunicacao com a motherboard */
	if( (pf = open(TTS_AUX0, O_RDWR | O_NDELAY)) < 0 )
		return;

	/* Modifica configuracao da porta serial */
	tcgetattr(pf, &pts);
	memcpy(&pots, &pts, sizeof(pots));
	pts.c_lflag &= ~ICANON; 
	pts.c_lflag &= ~(ECHO | ECHOCTL | ECHONL);
	pts.c_cflag |= HUPCL;
	pts.c_cc[VMIN] = 1;
	pts.c_cc[VTIME] = 0;
	pts.c_oflag &= ~ONLCR;
	pts.c_iflag &= ~ICRNL;
	pts.c_cflag &= ~CRTSCTS;
	pts.c_iflag &= ~(IXON | IXOFF | IXANY);
	cfsetospeed(&pts, B9600);
	cfsetispeed(&pts, B9600);
	tcsetattr(pf, TCSANOW, &pts);

	/* Envia caracter 'ESC' */
	for( i=0; i < 8; i++ ) {
		write(pf, &esc, 1);
		sleep(1);
	}

	tcsetattr(pf, TCSANOW, &pots);	/* Devolve configuracao original para a porta serial */
	close(pf);
}

int extract_indexed_line(unsigned char *buf, unsigned int line_number, unsigned char *store, unsigned int max_len)
{
	unsigned int i;
	unsigned char *p, *p1, *p2, *stop, key[8], line_n_str[32];

	if( (buf == NULL) || (line_number == 0) || (store == NULL) || (max_len == 0) )
		return 0;

	store[0] = 0;
	key[0] = 0x1b; /* ESC */
	key[1] = '[';
	sprintf((char *)line_n_str, "%d", line_number);
	for( i=0; line_n_str[i] != 0; i++ )
		key[i+2] = line_n_str[i];
	key[i+2] = ';';
	key[i+3] = 0;

	/* Busca sequencia */
	if( (p = (u8 *)strstr((char *)buf, (char *)key)) == NULL )
		return 0;
	p += strlen((char *)key);
	for( i=0; *p != 0; p++, i++ ) {
		if( isdigit(*p) == 0 )
			break;
	}
	if( (i == 0) || (*p != 'f') )
		return 0;
	p++;

	/* Busca proxima sequencia */
	key[2] = 0;
	p1 = (u8 *)strstr((char *)p, (char *)key);
	key[0] = 0x0a;
	key[1] = 0x0d;
	key[2] = 0;
	p2 = (u8 *)strstr((char *)p, (char *)key);

	/* Verifica a sequencia mais proxima */
	if( (p1 != NULL) && (p2 != NULL) )
		stop = ((p1 < p2) ? p1 : p2);
	else if( p1 != NULL )
		stop = p1;
	else if( p2 != NULL )
		stop = p2;
	else
		return 0;

	if( (i = (unsigned int) (stop - p)) >= max_len )
		return 0;
	memcpy(store, p, i);
	store[i] = 0;
	return i;
}

unsigned int get_modem_info(struct motherboard_info *store)
{
	FILE *file;
	fd_set ready;
	struct timeval tv;
	arg_list argl=NULL;
	int i, k, n, len, pf=0;
	struct termios pts, pots;
	char *p, *line, result[160];

	if(!store)
		return 0;
	store->vendor[0] = 0;
	store->product_name[0] = 0;
	store->complete_descr[0] = 0;
	store->product_code[0] = 0;
	store->fw_version[0] = 0;
	store->sn[0] = 0;
	store->release_date[0] = 0;
	store->resets[0] = 0;

	go_motherboard_startmenu();

	if( !(file = fopen(MOTHERBOARDINFO_TMP, "w")) )
		return 0;

	/* Abre canal de comunicacao com a motherboard */
	if( (pf = open(TTS_AUX0, O_RDWR | O_NDELAY)) < 0 ) {
		fclose(file);
		return 0;
	}

	if( !(line = malloc(1024)) ) {
		fclose(file);
		close(pf);
		return 0;
	}

	/* Modifica configuracao da porta serial */
	tcgetattr(pf, &pts);
	memcpy(&pots, &pts, sizeof(pots));
	pts.c_lflag &= ~ICANON; 
	pts.c_lflag &= ~(ECHO | ECHOCTL | ECHONL);
	pts.c_cflag |= HUPCL;
	pts.c_cc[VMIN] = 1;
	pts.c_cc[VTIME] = 0;
	pts.c_oflag &= ~ONLCR;
	pts.c_iflag &= ~ICRNL;
	pts.c_cflag &= ~CRTSCTS;
	pts.c_iflag &= ~(IXON | IXOFF | IXANY);
	cfsetospeed(&pts, B9600);
	cfsetispeed(&pts, B9600);
	tcsetattr(pf, TCSANOW, &pts);

	/* Fazemos um flush na recepcao */
	for( ; read(pf, line, 1024) > 0; )
		usleep(200000);

	/* A opcao 2 exibe as informacoes da motherboard */
	write(pf, "2", 1);
	sleep(3);
	for( i=0; i < 2; i++ ) {
		FD_ZERO(&ready);
		FD_SET(pf, &ready);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		select(pf+1, &ready, NULL, NULL, &tv);
		if( FD_ISSET(pf, &ready) ) {
			/* pf has characters for us */
			for( ; (len = read(pf, line, 1024)) > 0; )
				fwrite(line, 1, len, file);
		}
	}
	fclose(file);

	/* Devolve configuracao original para a porta serial */
	tcsetattr(pf, TCSANOW, &pots);
	close(pf);

	/* Interpretacao dos dados lidos */
	if( !(file = fopen(MOTHERBOARDINFO_TMP, "r")) ) {
		free(line);
		return 0;
	}
	strcpy(store->vendor, " ");
	for( ; !feof(file); ) {
		if( fgets(line, 1023, file) != line )
			break;
		line[1023] = 0;

		/* Busca fabricante */
		if( extract_indexed_line((u8 *)line, 2, (u8 *)result, 160) > 0 ) {
			if( (n = parse_args_din(result, &argl)) > 0 ) {
				if( n == 1 ) {
					strncpy(store->vendor, argl[0], 63);
					store->vendor[63] = 0;
				}
				else if( n > 1 ) {
					store->vendor[0] = 0;
					for( i=0; i < n; i++ ) {
						if( (strlen(store->vendor) + strlen(argl[i]) + 1) >= 64 )
							break;
						strcat(store->vendor, argl[i]);
						strcat(store->vendor, " ");
					}
					if( (i = strlen(store->vendor)) > 0 )
						store->vendor[i-1] = 0;
				}
			}
			free_args_din(&argl);
		}

		/* Busca nome do equipamento com a descricao completa */
		if( extract_indexed_line((u8 *)line, 3, (u8 *)result, 160) > 0 ) {
			if( (n = parse_args_din(result, &argl)) > 0 ) {
				/* Nome do produto */
				store->product_name[0] = 0;
				for( i=0; i < n; i++ ) {
					if( strcmp(argl[i], "-") == 0 )
						break;
					if( (strlen(store->product_name) + strlen(argl[i]) + 1) >= 64 )
						break;
					strcat(store->product_name, argl[i]);
					strcat(store->product_name, " ");
				}
				if( (i = strlen(store->product_name)) > 0 )
					store->product_name[i-1] = 0;
				/* Descricao completa */
				store->complete_descr[0] = 0;
				for( i=0; i < n; i++ ) {
					if( (strlen(store->complete_descr) + strlen(argl[i]) + 1) >= 256 )
						break;
					strcat(store->complete_descr, argl[i]);
					strcat(store->complete_descr, " ");
				}
				if( (i = strlen(store->complete_descr)) > 0 )
					store->complete_descr[i-1] = 0;
			}
			free_args_din(&argl);
		}

		/* Busca codigo do produto */
		if( extract_indexed_line((u8 *)line, 7, (u8 *)result, 160) > 0 ) {
			if( (n = parse_args_din(result, &argl)) >= 2 ) {
				if( (strcasecmp(argl[0], "Product") == 0) && (strcasecmp(argl[1], "code") == 0) ) {
					free_args_din(&argl);
					if( (p = strstr(line, result)) != NULL ) {
						p += strlen(result);
						if( extract_indexed_line((u8 *)p, 7, (u8 *)result, 160) > 0 ) {
							if( (n = parse_args_din(result, &argl)) > 0 ) {
								for( i=0; i < n; i++ ) {
									if( strcmp(argl[i], ":[") == 0 ) {
										if( ++i < n ) {
											for( k=0; k < strlen(argl[i]); k++ ) {
												if( isdigit(argl[i][k]) == 0 )
													break;
											}
											if( k >= strlen(argl[i]) ) {
												strncpy(store->product_code, argl[i], 9);
												store->product_code[9] = 0;
											}
										}
										break;
									}
								}
							}
							free_args_din(&argl);
						}
					}
				}
			}
			free_args_din(&argl);
		}

		/* Busca versao de firmware */
		if( extract_indexed_line((u8 *)line, 8, (u8 *)result, 160) > 0 ) {
			if( (n = parse_args_din(result, &argl)) >= 2 ) {
				if( (strcasecmp(argl[0], "Firmware") == 0) && (strcasecmp(argl[1], "version") == 0) ) {
					free_args_din(&argl);
					if( (p = strstr(line, result)) != NULL ) {
						p += strlen(result);
						if( extract_indexed_line((u8 *)p, 8, (u8 *)result, 160) > 0 ) {
							if( (n = parse_args_din(result, &argl)) > 0 ) {
								for( i=0; i < n; i++ ) {
									if( strcmp(argl[i], ":[") == 0 ) {
										if( ++i < n ) {
											strncpy(store->fw_version, argl[i], 9);
											store->fw_version[9] = 0;
										}
										break;
									}
								}
							}
							free_args_din(&argl);
						}
					}
				}
			}
			free_args_din(&argl);
		}

		/* Busca numero de serie */
		if( extract_indexed_line((u8 *)line, 11, (u8 *)result, 160) > 0 ) {
			if( (n = parse_args_din(result, &argl)) >= 2 ) {
				if( (strcasecmp(argl[0], "Serial") == 0) && (strcasecmp(argl[1], "number") == 0) ) {
					free_args_din(&argl);
					if( (p = strstr(line, result)) != NULL ) {
						p += strlen(result);
						if( extract_indexed_line((u8 *)p, 11, (u8 *)result, 160) > 0 ) {
							if( (n = parse_args_din(result, &argl)) > 0 ) {
								for( i=0; i < n; i++ ) {
									if( strcmp(argl[i], ":[") == 0 ) {
										if( ++i < n ) {
											for( k=0; k < strlen(argl[i]); k++ ) {
												if( isdigit(argl[i][k]) == 0 )
													break;
											}
											if( k >= strlen(argl[i]) ) {
												strncpy(store->sn, argl[i], MODEM_SN_LEN);
												store->sn[MODEM_SN_LEN] = 0;
											}
										}
										break;
									}
								}
							}
							free_args_din(&argl);
						}
					}
				}
			}
			free_args_din(&argl);
		}

		/* Busca data da versao */
		if( extract_indexed_line((u8 *)line, 12, (u8 *)result, 160) > 0 ) {
			if( (n = parse_args_din(result, &argl)) >= 2 ) {
				if( (strcasecmp(argl[0], "Release") == 0) && (strcasecmp(argl[1], "date") == 0) ) {
					free_args_din(&argl);
					if( (p = strstr(line, result)) != NULL ) {
						p += strlen(result);
						if( extract_indexed_line((u8 *)p, 12, (u8 *)result, 160) > 0 ) {
							if( (n = parse_args_din(result, &argl)) > 0 ) {
								for( i=0; i < n; i++ ) {
									if( strcmp(argl[i], ":[") == 0 ) {
										store->release_date[0] = 0;
										for( i++; i < n; i++ ) {
											if( strcmp(argl[i], "]") == 0 )
												break;
											if( (strlen(store->release_date) + strlen(argl[i]) + 1) >= 25 )
												break;
											strcat(store->release_date, argl[i]);
											strcat(store->release_date, " ");
										}
										if( (i = strlen(store->release_date)) > 0 )
											store->release_date[i-1] = 0;
										break;
									}
								}
							}
							free_args_din(&argl);
						}
					}
				}
			}
			free_args_din(&argl);
		}

		/* Busca numero de resets */
		if( extract_indexed_line((u8 *)line, 14, (u8 *)result, 160) > 0 ) {
			if( (n = parse_args_din(result, &argl)) >= 5 ) {
				if( (strcasecmp(argl[0], "Number") == 0)
					&& (strcasecmp(argl[1], "of") == 0)
					&& (strcasecmp(argl[2], "after") == 0)
					&& (strcasecmp(argl[3], "factory") == 0)
					&& (strcasecmp(argl[4], "resets") == 0) ) {
					free_args_din(&argl);
					if( (p = strstr(line, result)) != NULL ) {
						p += strlen(result);
						if( extract_indexed_line((u8 *)p, 14, (u8 *)result, 160) > 0 ) {
							if( (n = parse_args_din(result, &argl)) > 0 ) {
								for( i=0; i < n; i++ ) {
									if( strcmp(argl[i], ":[") == 0 ) {
										if( ++i < n ) {
											for( k=0; k < strlen(argl[i]); k++ ) {
												if( isdigit(argl[i][k]) == 0 )
													break;
											}
											if( k >= strlen(argl[i]) ) {
												strncpy(store->resets, argl[i], 17);
												store->resets[17] = 0;
											}
										}
										break;
									}
								}
							}
							free_args_din(&argl);
						}
					}
				}
			}
			free_args_din(&argl);
		}
	}
	fclose(file);
	free(line);

	/* Testa todos os campos */
	if(	(store->vendor[0] != 0)
		&& (store->product_name[0] != 0)
		&& (store->complete_descr[0] != 0)
		&& (store->product_code[0] != 0)
		&& (store->fw_version[0] != 0)
		&& (store->sn[0] != 0)
		&& (store->release_date[0] != 0)
		&& (store->resets[0] != 0) ) {
		/* OK */
		return 1;
	}
	return 0;
}

void change_modem_to_transparent(void)
{
	int pf;
	struct termios pts, pots;
	/* Comando de rede GET_ID: 00 07 00 80 01 00 00 */
	unsigned char cmd[18] = {0x01, 0x15, 0x02, 0x20, 0xff, 0x71, 0x00, 0x00, 0x07, 0x00, 0x80, 0x01, 0x00, 0x00, 0x03, 0x0C, 0x1B, 0x02};

	/* Abre canal de comunicacao com a motherboard */
	if( (pf = open(TTS_AUX0, O_RDWR | O_NDELAY)) < 0 )
		return;

	/* Modifica configuracao da porta serial */
	tcgetattr(pf, &pts);
	memcpy(&pots, &pts, sizeof(pots));
	pts.c_lflag &= ~ICANON; 
	pts.c_lflag &= ~(ECHO | ECHOCTL | ECHONL);
	pts.c_cflag |= HUPCL;
	pts.c_cc[VMIN] = 1;
	pts.c_cc[VTIME] = 0;
	pts.c_oflag &= ~ONLCR;
	pts.c_iflag &= ~ICRNL;
	pts.c_cflag &= ~CRTSCTS;
	pts.c_iflag &= ~(IXON | IXOFF | IXANY);
	cfsetospeed(&pts, B9600);
	cfsetispeed(&pts, B9600);
	tcsetattr(pf, TCSANOW, &pts);

	/* Envia dados */
	if( write(pf, cmd, 18) != 18 )
		printf("Not possible to send telebras command to modem!\n");

	/* Devolve configuracao original para a porta serial */
	tcsetattr(pf, TCSANOW, &pots);
	close(pf);
}

void change_modem_to_telebras(void)
{
	int i, pf;
	char ch = 0x1B; /* Escape */
	struct termios pts, pots;

	/* Abre canal de comunicacao com a motherboard */
	if( (pf = open(TTS_AUX0, O_RDWR | O_NDELAY)) < 0 )
		return;

	/* Modifica configuracao da porta serial */
	tcgetattr(pf, &pts);
	memcpy(&pots, &pts, sizeof(pots));
	pts.c_lflag &= ~ICANON; 
	pts.c_lflag &= ~(ECHO | ECHOCTL | ECHONL);
	pts.c_cflag |= HUPCL;
	pts.c_cc[VMIN] = 1;
	pts.c_cc[VTIME] = 0;
	pts.c_oflag &= ~ONLCR;
	pts.c_iflag &= ~ICRNL;
	pts.c_cflag &= ~CRTSCTS;
	pts.c_iflag &= ~(IXON | IXOFF | IXANY);
	cfsetospeed(&pts, B9600);
	cfsetispeed(&pts, B9600);
	tcsetattr(pf, TCSANOW, &pts);

	/* Envia caracter 'ESC' */
	for( i=0; i < 8; i++ ) {
		write(pf, &ch, 1);
		sleep(1);
	}
	/* Envia caracter 'e' */
	ch = 'e';
	write(pf, &ch, 1);

	/* Devolve configuracao original para a porta serial */
	tcsetattr(pf, TCSANOW, &pots);
	close(pf);
}

unsigned int discover_modem_mgnt_state(void)
{
	fd_set ready;
	struct stat st;
	char esc = 0x1B; /* Escape */
	struct timeval tv;
	struct termios pts, pots;
	int i, j, fd, len, pf = 0, mode;
	char *local, buf[1024], filename[strlen(VAR_RUN_FILE_TMP)+1];

	/* Abre canal de comunicacao com a motherboard */
	if( (pf = open(TTS_AUX0, O_RDWR | O_NDELAY)) < 0 ) {
		syslog(LOG_ERR, "Unable to open device %s!", TTS_AUX0);
		return 0;
	}
	/* Modifica configuracao da porta serial */
	tcgetattr(pf, &pts);
	memcpy(&pots, &pts, sizeof(pots));
	pts.c_lflag &= ~ICANON; 
	pts.c_lflag &= ~(ECHO | ECHOCTL | ECHONL);
	pts.c_cflag |= HUPCL;
	pts.c_cc[VMIN] = 1;
	pts.c_cc[VTIME] = 0;
	pts.c_oflag &= ~ONLCR;
	pts.c_iflag &= ~ICRNL;
	pts.c_cflag &= ~CRTSCTS;
	pts.c_iflag &= ~(IXON | IXOFF | IXANY);
	cfsetospeed(&pts, B9600);
	cfsetispeed(&pts, B9600);
	tcsetattr(pf, TCSANOW, &pts);
	/* Fazemos um flush na recepcao */
	for( ; read(pf, buf, 1024) > 0; )
		usleep(200000);

	for( mode=0, i=0; (mode == 0) && (i < 2); i++ ) {
		strcpy(filename, VAR_RUN_FILE_TMP);
		if( (fd = mkstemp(filename)) == -1 ) {
			syslog(LOG_ERR, "Unable to create temporary file at %s!", VAR_RUN_FILE_TMP);
			goto err;
		}
		write(pf, &esc, 1); /* Envia caracter 'ESC' */
		sleep(1);
		for( j=0; j < 2; j++ ) {
			FD_ZERO(&ready);
			FD_SET(pf, &ready);
			tv.tv_sec = 0;
			tv.tv_usec = 250000;
			select(pf+1, &ready, NULL, NULL, &tv);
			if( FD_ISSET(pf, &ready) ) {
				for( ; (len = read(pf, buf, 1024)) > 0; )
					write(fd, buf, len);
			}
		}
		lseek(fd, 0, SEEK_SET);
		if( fstat(fd, &st) < 0 ) {
			close(fd);
			goto err;
		}
		if( st.st_size > 0 ) {
			if( (local = malloc(st.st_size + 1)) != NULL ) {
				read(fd, local, st.st_size);
				*(local + st.st_size) = 0;
				mode = MODEM_MGNT_TELEBRAS;
				if( strstr(local, "--------------------") ) {
					if( strstr(local, " - ") )
						mode = MODEM_MGNT_TRANSPARENT;
					else {
						char *p_open = strchr(local, '[');
						char *p_close = strchr(local, ']');
						if( p_open && p_close && (p_close > p_open) ) {
							char *p_open_int = strchr(p_open+1, '[');
							if( p_open_int ) {
								if( p_open_int > p_close )
									mode = MODEM_MGNT_TRANSPARENT;
							}
							else
								mode = MODEM_MGNT_TRANSPARENT;
						}
					}
				}
				free(local);
			}
		}
		close(fd);
		remove(filename);
	}

	/* Devolve configuracao original para a porta serial */
	tcsetattr(pf, TCSANOW, &pots);
	close(pf);
	return mode;

err:
	/* Devolve configuracao original para a porta serial */
	tcsetattr(pf, TCSANOW, &pots);
	close(pf);
	return 0;
}

void choose_terminal(void)
{
	char buf[64];

	for( ; ; ) {
		showMenuHead();
		printf("\n");
		printf("     1 - Configure TDM\n");
		printf("     2 - Configure Router\n");
		printf("\n");
		printf("     E - Exit\n");
		printf("     R - Exit and reset\n");
		printf("\n\n\n");
		switch( getOption("12eErR\e\n \0") ) {
			case '1':
#ifdef CONFIG_DMVIEW_MGNT
				/* Desabilita echo ateh conseguirmos exibir a primeira tela do modem */
				echo_off();
new_access:
				if( get_microcom_lock() ) {
					int i, mode = 0;

					set_microcom_mode(MICROCOM_MODE_MODEM);
					echo_on();
					printf(TERM_CLEAR);
					fflush(stdout);
					echo_off();

					/* Ajuste do modo de gerencia do modem */
					for( i=0; (i < 3) && ((mode = discover_modem_mgnt_state()) != MODEM_MGNT_TRANSPARENT); i++ )
						change_modem_to_transparent();
					if( mode != MODEM_MGNT_TRANSPARENT ) {
						/* Retorna ao modo normal */
						set_microcom_mode(MICROCOM_MODE_LISTEN);
						release_microcom_lock();
						echo_on();
						break;
					}

					/* Acessa terminal do modem */
					modem_access_pid = fork();
					if( modem_access_pid == -1 ) { /* Error */
						modem_access_pid = 0;
						syslog(LOG_ERR, "Fork failed!");
						/* Retorna ao modo normal */
						set_microcom_mode(MICROCOM_MODE_LISTEN);
						release_microcom_lock();
						echo_on();
						break;
					}
					else if( modem_access_pid == 0 ) { /* Child */
						char *xargv[3];

						echo_on();
						sprintf(buf, "-D%s", TTS_AUX0);
						xargv[0] = "/bin/microcom";
						xargv[1] = buf;
						xargv[2] = NULL;
						execv(xargv[0], xargv);
					}
					else {
						/* Espera ateh que daemon termine */
						echo_on();
						while( 1 ) {
							if( waitpid(modem_access_pid, NULL, 0) == -1 ) {
								if( errno != EINTR )
									break;
							}
							else
								break;
						}
						modem_access_pid = 0;
					}

					/* Retorna ao modo normal */
					set_microcom_mode(MICROCOM_MODE_LISTEN);
					release_microcom_lock();
				}
				else { /* Alguem possui o lock para o microcom */
					if( cish_on_serial_console && (is_microcom_lock_from_remote() || (get_vcli_pid() > 1)) ) {
						echo_on();
						printf(TERM_CLEAR);
						fflush(stdout);
						echo_off();

						/* Derruba sumariamente o processo que estah com o lock ao microcom */
						if( transfer_microcom_lock_to_us() >= 0 )
							goto new_access;
					}
					echo_on();
				}
#else
				printf(TERM_CLEAR);
				fflush(stdout);

				/* Acessa terminal do modem */
				sprintf(buf, "/bin/microcom -D%s", TTS_AUX0);
				system(buf);
#endif
				break;
			case '2':
#ifdef CONFIG_DMVIEW_MGNT
				if( get_microcom_lock() )
					set_microcom_mode(MICROCOM_MODE_LOCAL);
#endif
				printf(TERM_CLEAR);
				fflush(stdout);
				return;
			case 'e':
			case 'E':
			case '\e':
				printf(TERM_CLEAR);
				fflush(stdout);
				process_cish_exit();
				exit(0);
			case 'r':
			case 'R':
				printf(TERM_CLEAR);
				fflush(stdout);
				//process_cish_exit();
				sleep(1);
				reboot(0x01234567);
		}
		printf(TERM_CLEAR);
		fflush(stdout);
	}
}

static int valid_file(const struct dirent *file)
{
	return (file->d_name[0]=='.' ? 0 : 1);
}

/* Verifica a compatibilidade entre a placa satelite e a motherboard */
static int check_boards_compat(int mothercode, int satcode)
{
#ifdef CONFIG_DEVELOPMENT
	return 0;
#endif

	switch( mothercode ) {
#ifdef CONFIG_BERLIN_SATROUTER_LIMITED_CRCS
		case SUPP_MOTHERBOARD_CODE_DM991CR:
		case SUPP_MOTHERBOARD_CODE_DM991CS:
		case SUPP_MOTHERBOARD_CODE_DM706CR:
		case SUPP_MOTHERBOARD_CODE_DM706CS:
#else
		case SUPP_MOTHERBOARD_CODE_DM706E:
		case SUPP_MOTHERBOARD_CODE_DM706M1:
		case SUPP_MOTHERBOARD_CODE_DM706M2:
		case SUPP_MOTHERBOARD_CODE_DM706M4:
		case SUPP_MOTHERBOARD_CODE_DM706XM:
		case SUPP_MOTHERBOARD_CODE_DM706XM1:
		case SUPP_MOTHERBOARD_CODE_DM706XM2:
		case SUPP_MOTHERBOARD_CODE_DM706XD:
		case SUPP_MOTHERBOARD_CODE_DM706XD1:
		case SUPP_MOTHERBOARD_CODE_DM706XD2:
#endif
			/* OK, sem restricoes */
			break;
		default:
			printf("** This firmware is invalid for the product! **\n");
			return -1;
	}
	switch( mothercode ) {
		case SUPP_MOTHERBOARD_CODE_DM991CR:
		case SUPP_MOTHERBOARD_CODE_DM991CS:
		case SUPP_MOTHERBOARD_CODE_DM706XD:
		case SUPP_MOTHERBOARD_CODE_DM706XD1:
		case SUPP_MOTHERBOARD_CODE_DM706XD2:
			switch( satcode ) {
				case BOARD_HW_ID_0:
				case BOARD_HW_ID_2:
				case BOARD_HW_ID_4:
					break;
				case BOARD_HW_ID_1:
				case BOARD_HW_ID_3:
				default:
					return -1;
			}
			break;
		case SUPP_MOTHERBOARD_CODE_DM706CR:
		case SUPP_MOTHERBOARD_CODE_DM706CS:
			switch( satcode ) {
				case BOARD_HW_ID_1:
				case BOARD_HW_ID_3:
					break;
				case BOARD_HW_ID_0:
				case BOARD_HW_ID_2:
				case BOARD_HW_ID_4:
				default:
					return -1;
			}
			break;
		case SUPP_MOTHERBOARD_CODE_DM706E:
		case SUPP_MOTHERBOARD_CODE_DM706M1:
		case SUPP_MOTHERBOARD_CODE_DM706M2:
		case SUPP_MOTHERBOARD_CODE_DM706M4:
		case SUPP_MOTHERBOARD_CODE_DM706XM:
		case SUPP_MOTHERBOARD_CODE_DM706XM1:
		case SUPP_MOTHERBOARD_CODE_DM706XM2:
			switch( satcode ) {
				case BOARD_HW_ID_1:
					break;
				case BOARD_HW_ID_0:
				case BOARD_HW_ID_2:
				case BOARD_HW_ID_3:
				case BOARD_HW_ID_4:
				default:
					return -1;
			}
			break;
		default:
			return -1;
	}
	return 0;
}

void wakeup_motherboard(void)
{
	char chr;
	int i, pf;
	struct termios pts, pots;

	/* Abre canal de comunicacao com a motherboard */
	if( (pf = open(TTS_AUX0, O_RDWR | O_NDELAY)) < 0 )
		return;

	/* Modifica configuracao da porta serial */
	tcgetattr(pf, &pts);
	memcpy(&pots, &pts, sizeof(pots));
	pts.c_lflag &= ~ICANON; 
	pts.c_lflag &= ~(ECHO | ECHOCTL | ECHONL);
	pts.c_cflag |= HUPCL;
	pts.c_cc[VMIN] = 1;
	pts.c_cc[VTIME] = 0;
	pts.c_oflag &= ~ONLCR;
	pts.c_iflag &= ~ICRNL;
	pts.c_cflag &= ~CRTSCTS;
	pts.c_iflag &= ~(IXON | IXOFF | IXANY);
	cfsetospeed(&pts, B9600);
	cfsetispeed(&pts, B9600);
	tcsetattr(pf, TCSANOW, &pts);

	/* Envia caracteres 'ENTER' */
	for( i=0, chr=0x0A; i < 3; i++ )
	{
		write(pf, &chr, 1);
		sleep(1);
	}

	tcsetattr(pf, TCSANOW, &pots);	/* Devolve configuracao original para a porta serial */
	close(pf);
}

void wait_for_menu(int fd)
{
	fd_set ready;
	char buf[32];
	struct timeval tv;

	FD_ZERO(&ready);
	FD_SET(fd, &ready);
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	select(fd+1, &ready, NULL, NULL, &tv);
	if( FD_ISSET(fd, &ready) )
	{
		for( ; read(fd, buf, 32) > 0; )
			usleep(200000);
		FD_ZERO(&ready);
		FD_SET(fd, &ready);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		select(fd+1, &ready, NULL, NULL, &tv);
		if( FD_ISSET(fd, &ready) )
		{
			for( ; read(fd, buf, 32) > 0; )
				usleep(200000);
		}
	}
}

unsigned int discover_motherboard(void)
{
	FILE *f;
	struct motherboard_info motherboard;

	remove(MOTHERBOARD_INFO_FILE);

	/* Busca informacoes da motherboard */
	if( get_modem_info(&motherboard) ) {
		if( (f = fopen(MOTHERBOARD_INFO_FILE, "w")) ) {
			fwrite("vendor=", 1, strlen("vendor="), f);
			if(strlen(motherboard.vendor))
				fwrite(motherboard.vendor, 1, strlen(motherboard.vendor), f);
			fwrite("\n", 1, 1, f);

			fwrite("product_name=", 1, strlen("product_name="), f);
			if(strlen(motherboard.product_name))
				fwrite(motherboard.product_name, 1, strlen(motherboard.product_name), f);
			fwrite("\n", 1, 1, f);

			fwrite("complete_descr=", 1, strlen("complete_descr="), f);
			if(strlen(motherboard.complete_descr))
				fwrite(motherboard.complete_descr, 1, strlen(motherboard.complete_descr), f);
			fwrite("\n", 1, 1, f);

			fwrite("product_code=", 1, strlen("product_code="), f);
			if(strlen(motherboard.product_code))
				fwrite(motherboard.product_code, 1, strlen(motherboard.product_code), f);
			fwrite("\n", 1, 1, f);

			fwrite("fw_version=", 1, strlen("fw_version="), f);
			if(strlen(motherboard.fw_version))
				fwrite(motherboard.fw_version, 1, strlen(motherboard.fw_version), f);
			fwrite("\n", 1, 1, f);

			fwrite("sn=", 1, strlen("sn="), f);
			if(strlen(motherboard.sn))
				fwrite(motherboard.sn, 1, strlen(motherboard.sn), f);
			fwrite("\n", 1, 1, f);

			fwrite("release_date=", 1, strlen("release_date="), f);
			if(strlen(motherboard.release_date))
				fwrite(motherboard.release_date, 1, strlen(motherboard.release_date), f);
			fwrite("\n", 1, 1, f);

			fwrite("resets=", 1, strlen("resets="), f);
			if(strlen(motherboard.resets))
				fwrite(motherboard.resets, 1, strlen(motherboard.resets), f);
			fwrite("\n", 1, 1, f);

			fclose(f);
			return 1;
		}
	}
	return 0;
}

#ifdef CONFIG_DM
#define	LED_MASK_SYS	0x00000001
#define	LED_MASK_WAN	0x00000002
#define	LED_MASK_ETH0	0x00000004
#define	LED_MASK_ETH1	0x00000008

static void stop_ledd(pid_t pid, u32 led_mask)
{
	u8 cmd[24];
	int i, ret;

	for( i=0; i <= 20; i++ ) {
		kill(pid, SIGINT);
		ret = waitpid(pid, NULL, WNOHANG);
		switch( ret ) {
			case -1: /* error */
			case 0: /* no change on process state */
				usleep(500000);
				break;
			default:
				if( ret == pid )
					goto go_out;
				break;
		}
	}
	sprintf((char *)cmd, "kill -9 %d", pid);
	system((char *)cmd);
	usleep(500000);
	usleep(500000);
	waitpid(pid, NULL, WNOHANG);

go_out:
	if( led_mask & LED_MASK_SYS )
		system("/bin/gpio led_sys on");
	if( led_mask & LED_MASK_WAN )
		system("/bin/gpio wan_status on");
	if( led_mask & LED_MASK_ETH0 )
		dev_set_link_up("ethernet0");
	switch( get_board_hw_id() ) {
		case BOARD_HW_ID_1:
			break;
		case BOARD_HW_ID_0:
		case BOARD_HW_ID_2:
		case BOARD_HW_ID_3:
		case BOARD_HW_ID_4:
			if( led_mask & LED_MASK_ETH1 )
				dev_set_link_up("ethernet1");
			break;
	}
}
#endif

unsigned int process_factory_cmd(char *line)
{
	/*  Teste de fabrica da DataCom.
	 *  Recebe-se comandos no formato "funcname(r0, r1, r2, ...)"
	 */
#ifdef CONFIG_DM
	static u32 led_mask = 0;
	static pid_t led_test_pid = 0;
	u32 exflag = 0;
	arg_list argl = NULL;
	int i, n, count, print_result = 0;
	char *p, *local = NULL, *xargv[2], result[50], command[128] = "";

	if( line == NULL )
		goto exec_err;
	if( (local = malloc(strlen(line) + 1)) == NULL )
		goto exec_err;
	if( (n = parse_args_din(line, &argl)) == 0 )
		goto exec_err;
	local[0] = '\0';
	for( i=0; i < n; i++ )
		strcat(local, argl[i]);
	free_args_din(&argl);

	for( count=0, p=local; (p = strchr(p, '(')); count++, p++ );
	if( count != 1 )
		goto exec_err;

	for( count=0, p=local; (p = strchr(p, ')')); count++, p++ );
	if( count != 1 )
		goto exec_err;

	if( strchr(local, '(') > strchr(local, ')') )
		goto exec_err;
	for( p=local; *p; p++ ) {
		if( (*p == '(') || (*p == ',') || (*p == ')'))
			*p = ' ';
	}

	if( (n = parse_args_din(local, &argl)) == 0 )
		goto exec_err;
	free(local);
	local = NULL;

	strncpy(command, argl[0], 127);
	command[127] = '\0';

	if( strcmp(argl[0], "tdm") == 0 ) {
		/* TESTA INTERFACE TDM. Exemplo: "tdm()" */
		int k;
		u32 rx, tx;
		cisco_proto cisco;
		struct net_device_stats *st;

		/* Configura o intervalo entre envio de pacotes de keepalive para 1 segundo */
		chdlc_get_config(0, &cisco);
		cisco.interval = 1;
		chdlc_set_config(0, &cisco);

		/* Zera estatisticas da interface */
		clear_interface_counters("serial0");
		for( k=0; k < 5; k++ )
			sleep(1);
		rx = tx = 0;
		if( get_if_list() >= 0 ) {
			for( k=0; k < link_table_index; k++ ) {
				if( strcmp(link_table[k].ifname, "serial0") == 0 ) {
					st = &link_table[k].stats;
					rx = st->rx_packets;
					tx = st->tx_packets;
					break;
				}
			}
		}
		if( (tx == 0) || (tx > 10) || (rx < tx) )
			goto exec_err;
	}
	else if( strcmp(argl[0], "enableEth") == 0 ) {
		/* ATIVA INTERFACE ETHERNET E DESABILITA AS DEMAIS. Exemplo: "enableEth(0)" */
		if( n != 2 )
			goto exec_err;
		switch( atoi(argl[1]) ) {
			case 0:
				switch( get_board_hw_id() ) {
					case BOARD_HW_ID_1:
						break;
					case BOARD_HW_ID_0:
					case BOARD_HW_ID_2:
					case BOARD_HW_ID_3:
					case BOARD_HW_ID_4:
						dev_set_link_down("ethernet1");
						break;
				}
				dev_set_link_up("ethernet0");
				break;
			case 1:
				dev_set_link_down("ethernet0");
				switch( get_board_hw_id() ) {
					case BOARD_HW_ID_1:
						goto exec_err;
					case BOARD_HW_ID_0:
					case BOARD_HW_ID_2:
					case BOARD_HW_ID_3:
					case BOARD_HW_ID_4:
						dev_set_link_up("ethernet1");
						break;
				}
				break;
			default:
				goto exec_err;
		}
	}
	else if( strcmp(argl[0], "ethernet") == 0 ) {
		/* TESTA INTERFACES ETHERNET. Exemplo: "ethernet()" */
		#define	LOCAL_FILE	"/etc/factory_test_file"
		#define REMOTE_FILE	"/var/run/ftp/factory_test_file"
		#define	DIFF_FILE	"/var/run/factory_test.diff"

		FILE *f;
		int n, fd_local;
		struct stat st_local;
		struct dirent **namelist;
		char buf[strlen(LOCAL_FILE) + strlen(REMOTE_FILE) + strlen(DIFF_FILE) + 43];

		if( (f = fopen(LOCAL_FILE, "r")) )
			fclose(f);
		else
			symlink("/etc/services", LOCAL_FILE);
		if( (f = fopen(REMOTE_FILE, "r")) )
			fclose(f);
		else {
			if( (n = scandir("/var/run/ftp", &namelist, valid_file, alphasort)) < 0 )
				goto exec_err;
			if( n == 0 ) {
				free(namelist);
				goto exec_err;
			}
			sprintf(buf, "/bin/ln -s /var/run/ftp/%s %s", namelist[0]->d_name, REMOTE_FILE);
			system(buf);
			for( i=0; i < n; i++ )
				free(namelist[i]);
			free(namelist);
		}

		sprintf(buf, "/bin/diff %s %s > %s", LOCAL_FILE, REMOTE_FILE, DIFF_FILE);
		system(buf);
		if( (fd_local = open(DIFF_FILE, O_RDONLY)) < 0 ) {
			system("/bin/rm -f /var/run/ftp/*");
			goto exec_err;
		}
		if( fstat(fd_local, &st_local) < 0 ) {
			close(fd_local);
			system("/bin/rm -f /var/run/ftp/*");
			goto exec_err;
		}
		close(fd_local);
		if( st_local.st_size > 0 ) {
			/*
			if( (f = fopen(DIFF_FILE, "r")) ) {
				char buf[100];
				while( fgets(buf, 100, f) )
					printf("* %s *\n", buf);
				fclose(f);
			}
			*/
			system("/bin/rm -f /var/run/ftp/*");
			goto exec_err;
		}
		system("/bin/rm -f /var/run/ftp/*");
	}
	else if( strcmp(argl[0], "mac") == 0 ) {
		/* CONFIGURA NUMERO MAC. Exemplo: "mac(0x00,0x11,0x22,0x33,0x44,0x55)" */
		int ret = 0;

		if( n < 7 )
			goto exec_err;
		result[0] = '\0';
		for( i=1; i < 7; i++ ) {
			if( strlen(argl[i]) == 4 ) {
				p = argl[i]+2;
				if( (isxdigit(*p) == 0) || (isxdigit(*(p+1)) == 0) ) {
					ret = -1;
					break;
				}
				strcat(result, p);
				if( i < 6 )
					strcat(result, ":");
			}
			else {
				ret = -1;
				break;
			}
		}
		if( (ret < 0) || (change_uboot_env("ethaddr", result) < 0) )
			goto exec_err;
	}
	else if( strcmp(argl[0], "get_mac") == 0 ) {
		/* LEITURA DO NUMERO MAC. Exemplo: "get_mac()" */
		arg_list arglmac = NULL;

		if( get_uboot_env("ethaddr", result, 20) <= 0 )
			goto exec_err;
		for( p=result; *p; p++ ) {
			if( *p == ':' )
				*p = ' ';
		}
		if( parse_args_din(result, &arglmac) != 6 ) {
			free_args_din(&arglmac);
			goto exec_err;
		}
		sprintf(result, "%s%s%s%s%s%s\n", arglmac[0], arglmac[1], arglmac[2], arglmac[3], arglmac[4], arglmac[5]);
		free_args_din(&arglmac);
		print_result++;
	}
	else if( strcmp(argl[0], "serial_number") == 0 ) {
		/* CONFIGURA NUMERO DE SERIE. Exemplo: "serial_number(1234567890)" */
		int k, l;
		char serial[SATR_SN_LEN+1];

		if( (n < 2) || (strlen(argl[1]) > SATR_SN_LEN) )
			goto exec_err;
		for( p=argl[1]; *p; p++ ) {
			if( isdigit(*p) == 0 )
				goto exec_err;
		}
		if( strlen(argl[1]) < SATR_SN_LEN ) {
			for( k=0, l=0; k < (SATR_SN_LEN - strlen(argl[1])); k++ )
				serial[l++] = '0';
			for( k=0; k < strlen(argl[1]); k++ )
				serial[l++] = argl[1][k];
			serial[l] = 0;
		}
		else
			strcpy(serial, argl[1]);
		if(change_uboot_env("serial#", serial) < 0)
			goto exec_err;
	}
	else if( strcmp(argl[0], "get_serial_number") == 0 ) {
		/* LEITURA DO NUMERO SERIE. Exemplo: "get_serial_number()" */
		char buf[SATR_SN_LEN+1];

		if( get_uboot_env("serial#", buf, SATR_SN_LEN+1) <= 0 )
			goto exec_err;
		sprintf(result, "%010x\n", atoi(buf));
		print_result++;
	}
	else if( strcmp(argl[0], "manuf") == 0 ) {
		/* CONFIGURACAO DO FABRICANTE. Exemplo: "manuf(0x00)" */
		if( (n < 2) || (strlen(argl[1]) != 4) )
			goto exec_err;
		if( change_uboot_env("manuf", argl[1]+2) < 0 )
			goto exec_err;
	}
	else if( strcmp(argl[0], "get_manuf") == 0 ) {
		/* LEITURA DO FABRICANTE. Exemplo: "get_manuf()" */
		char tmp[20];

		if( get_uboot_env("manuf", tmp, 20) <= 0 )
			goto exec_err;
		sprintf(result, "0x%s\n", tmp);
		print_result++;
	}
	else if( strcmp(argl[0], "get_product_code") == 0 ) {
		/* LEITURA DO CODIGO DO PRODUTO. Exemplo: "get_product_code()" */
		char boardcode[10];

		if( get_mb_info(MBINFO_PRODUCTCODE, boardcode, 10) > 0 ) {
			sprintf(result, "%s\n", boardcode);
			print_result++;
		}
		else {
			wakeup_motherboard();
			if( (discover_motherboard() > 0) && (get_mb_info(MBINFO_PRODUCTCODE, boardcode, 10) > 0) ) {
				sprintf(result, "%s\n", boardcode);
				print_result++;
			}
			else
				goto exec_err;
		}
	}
	else if( strcmp(argl[0], "check_product_codes") == 0 ) {
		/* VERIFICA CONSISTENCIA DO CONJUNTO MODEM+ROUTER. Exemplo: "check_product_codes()" */
		char boardcode[10];

		if( get_mb_info(MBINFO_PRODUCTCODE, boardcode, 10) <= 0 ) {
			wakeup_motherboard();
			if( (discover_motherboard() <= 0) || (get_mb_info(MBINFO_PRODUCTCODE, boardcode, 10) <= 0) )
				goto exec_err;
		}
		if( check_boards_compat(atoi(boardcode), get_board_hw_id()) < 0 )
			goto exec_err;
	}
	else if( strcmp(argl[0], "ledOn") == 0 ) {
		/* ATIVA SEQUENCIA DE TESTE DOS LEDS. Exemplo: "ledOn()" */
		if( led_test_pid == 0 ) {
			led_mask |= (get_led_state("led_sys") == 1 ? LED_MASK_SYS : 0);
			led_mask |= (get_led_state("wan_status") == 1 ? LED_MASK_WAN : 0);
			led_mask |= (dev_get_link("ethernet0") == 1 ? LED_MASK_ETH0 : 0);
			switch( get_board_hw_id() ) {
				case BOARD_HW_ID_1:
					break;
				case BOARD_HW_ID_0:
				case BOARD_HW_ID_2:
				case BOARD_HW_ID_3:
				case BOARD_HW_ID_4:
					led_mask |= (dev_get_link("ethernet1") == 1 ? LED_MASK_ETH1 : 0);
					break;
			}
			switch( (led_test_pid = fork()) ) {
				case -1: /* Error */
					led_test_pid = 0;
					goto exec_err;
				case 0:
					xargv[0] = "/bin/ledd";
					xargv[1] = NULL;
					execv(xargv[0], xargv);
					/* Not reached */
					exit(1);
				default:
					break;
			}
		}
	}
	else if( strcmp(argl[0], "ledOff") == 0 ) {
		/* DESATIVA SEQUENCIA DE TESTE DOS LEDS. Exemplo: "ledOff()" */
		if( led_test_pid == 0 )
			goto exec_err;
		stop_ledd(led_test_pid, led_mask);
		led_test_pid = 0;
		led_mask = 0;
	}
	else if( strcmp(argl[0], "open_tdm") == 0 ) {
		/* CONECTA TERMINAL DO MODEM. Exemplo: "open_tdm()" */
		pid_t pid;
		char *xargv[3];
		unsigned int k, mode;

		echo_off();
		if( get_microcom_lock() == 0 ) { /* Alguem possui o lock para o microcom */
			echo_on();
			goto exec_err;
		}
		set_microcom_mode(MICROCOM_MODE_MODEM);
		echo_on();
		printf(TERM_CLEAR);
		fflush(stdout);
		echo_off();

		/* Ajuste do modo de gerencia do modem */
		for( k=0, mode=0; (k < 3) && ((mode = discover_modem_mgnt_state()) != MODEM_MGNT_TRANSPARENT); k++ )
			change_modem_to_transparent();
		if( mode != MODEM_MGNT_TRANSPARENT ) {
			/* Retorna ao modo normal */
			set_microcom_mode(MICROCOM_MODE_LISTEN);
			release_microcom_lock();
			echo_on();
			goto exec_err;
		}

		/* Acessa terminal do modem */
		switch( (pid = fork()) ) {
			case -1: /* Erro */
				syslog(LOG_ERR, "Fork failed!");

				/* Retorna ao modo normal */
				set_microcom_mode(MICROCOM_MODE_LISTEN);
				release_microcom_lock();
				echo_on();
				goto exec_err;
			case 0: /* Processo filho */
				echo_on();
				sprintf(buf, "-D%s", TTS_AUX0);
				xargv[0] = "/bin/microcom";
				xargv[1] = buf;
				xargv[2] = NULL;
				execv(xargv[0], xargv);
				break;
			default:
				/* Espera ateh que daemon termine */
				echo_on();
				while( 1 ) {
					if( waitpid(pid, NULL, 0) == -1 ) {
						if( errno != EINTR )
							break;
					}
					else
						break;
				}
				printf(TERM_CLEAR);
				fflush(stdout);
				break;
		}

		/* Retorna ao modo normal */
		set_microcom_mode(MICROCOM_MODE_LISTEN);
		release_microcom_lock();
	}
	else if( strcmp(argl[0], "exit") == 0 ) {
		if( led_test_pid != 0 ) {
			stop_ledd(led_test_pid, led_mask);
			led_test_pid = 0;
			led_mask = 0;
		}
		exflag = 1;
		print_result++;
	}
	else if( strcmp(argl[0], "reboot") == 0 ) {
		/* REBOOT */
		reboot(0x01234567);
	}
	else
		goto exec_err;

	free_args_din(&argl);
	if( exflag )
		return exflag;
	printf("RESPOSTA(%s):%s\n", command, print_result ? result : "55");
	fflush(stdout);
	return 0;

exec_err:
	if( local )
		free(local);
	free_args_din(&argl);
	printf("RESPOSTA(%s):0A\n", command);
	fflush(stdout);
	return 0;
#endif
}

unsigned int notify_modem_about_us(void)
{
	FILE *file;
	fd_set ready;
	struct timeval tv;
	arg_list argl=NULL;
	struct termios pts, pots;
	char *line, chr, result[160], esc=0x1b; /* Escape */
	int i, n, pf, len, ret=0, board_hw_id=get_board_hw_id();

	if( board_hw_id == BOARD_HW_ID_0 )
		/* Notificacao do modo nao se aplica caso seja a placa com dois PHYs Kendin */
		return 1;

	go_motherboard_startmenu();

	if( !(file = fopen(MOTHERBOARDINFO_TMP, "w")) )
		return 0;

	/* Abre canal de comunicacao com a motherboard */
	if( (pf = open(TTS_AUX0, O_RDWR | O_NDELAY)) < 0 )
	{
		fclose(file);
		return 0;
	}

	if( !(line = malloc(1024)) )
	{
		fclose(file);
		close(pf);
		return 0;
	}

	/* Modifica configuracao da porta serial */
	tcgetattr(pf, &pts);
	memcpy(&pots, &pts, sizeof(pots));
	pts.c_lflag &= ~ICANON; 
	pts.c_lflag &= ~(ECHO | ECHOCTL | ECHONL);
	pts.c_cflag |= HUPCL;
	pts.c_cc[VMIN] = 1;
	pts.c_cc[VTIME] = 0;
	pts.c_oflag &= ~ONLCR;
	pts.c_iflag &= ~ICRNL;
	pts.c_cflag &= ~CRTSCTS;
	pts.c_iflag &= ~(IXON | IXOFF | IXANY);
	cfsetospeed(&pts, B9600);
	cfsetispeed(&pts, B9600);
	tcsetattr(pf, TCSANOW, &pts);

	/* A opcao 2 exibe as informacoes da motherboard */
	write(pf, "2", 1);
	wait_for_menu(pf);

	/* O caractere 230 farah com que a motherboard pule para a tela de troca de ID */
	chr = 230;
	write(pf, &chr, 1);
	wait_for_menu(pf);

	switch( board_hw_id )
	{
		case BOARD_HW_ID_1:
		case BOARD_HW_ID_2:
			chr = 'R';
			break;
		case BOARD_HW_ID_3:
		case BOARD_HW_ID_4:
			chr = 'S';
			break;
	}
	write(pf, &chr, 1);	/* Envia o caracter que vai definir o modo */
	wait_for_menu(pf);

	/* Fazemos um flush na recepcao */
	for( ; read(pf, line, 1024) > 0; )
		usleep(100000);

	/* Envia Escape para que a motherboard grave o novo ID */
	write(pf, &esc, 1);
	sleep(3);
	for(i=0; i < 2; i++)
	{
		FD_ZERO(&ready);
		FD_SET(pf, &ready);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		select(pf+1, &ready, NULL, NULL, &tv);
		if(FD_ISSET(pf, &ready))
		{	/* pf has characters for us */
			for( ; (len = read(pf, line, 1024)) > 0; )
				fwrite(line, 1, len, file);
		}
	}
	fclose(file);

	/* Interpretacao dos dados lidos */
	if( (file = fopen(MOTHERBOARDINFO_TMP, "r")) != NULL ) {
		for( ; !feof(file) && (ret == 0); ) {
			if( fgets(line, 1023, file) != line )
				break;
			line[1023] = 0;

			/* Busca nome do equipamento */
			if( extract_indexed_line((u8 *)line, 3, (u8 *)result, 160) > 0 ) {
				if( (n = parse_args_din(result, &argl)) > 0 ) {
					sprintf(line, "C%c", chr);
					for( i=0; i < n; i++ ) {
						if( strcmp(argl[i], "-") == 0 ) {
							if( i > 0 ) {
								if( strncasecmp(line, (argl[i-1] + strlen(argl[i-1]) - 2), 2) == 0 )
									ret = 1;
							}
							break;
						}
					}
				}
				free_args_din(&argl);
			}
		}
		fclose(file);
	}

	free(line);
	tcsetattr(pf, TCSANOW, &pots);	/* Devolve configuracao original para a porta serial */
	close(pf);
	return ret;
}

#endif

/* ==============================================================================
 * main
 * ============================================================================== */

int main(int argc, char *argv[])
{
	char *line;
	char *xline;
	int  hadspace;
	char *bootfile;
#ifndef I2C_HC08_ID_ADDR
	char mac[6];
#endif
#ifdef CONFIG_BERLIN_SATROUTER
	bd_t bpb;
	char product_ident[24];
	unsigned int board_tf_executed = 1, factory_test_login = 0;
#else
	int retval;
	int acct_mode; /* command accounting */
#endif

	umask(066); /* -rw------ */
#ifdef CONFIG_BERLIN_SATROUTER
	/* Verifica se a placa ainda nao passou pelo teste de fabrica (TF) */
	if( (get_uboot_env("ethaddr", product_ident, 20) > 0) && (strcmp(product_ident, "40:00:00:00:00:01") == 0) )
		board_tf_executed = 0;

#ifdef CONFIG_DMVIEW_MGNT
	/* Gerencia Datacom */
	if( (argc == 2) && (strcmp(argv[1], "dmview_management") == 0) )
		dmview_management = 1;

	/* cish estah sendo executado a partir do terminal serial? */
	if( argc == 1 ) {
		char local_buf[256];

		if( (get_process_fd_device(getpid(), STDIN_FILENO, local_buf, 255) >= 0) && (strcmp(local_buf, TTS_AUX1) == 0) )
			cish_on_serial_console = 1;
	}
#endif /* CONFIG_DMVIEW_MGNT */

	/* Gera senha do usuario universal 'support' baseado no numero de serie da placa */
	{
		unsigned char *hash_p, buf[SATR_SN_LEN+1];

		if( get_uboot_env("serial#", (char *)buf, SATR_SN_LEN+1) > 0 ) {
			if( strlen((char *)buf) == SATR_SN_LEN ) {
				if( (hash_p = hash_sn_str(buf)) )
					memcpy(support_key, hash_p, 17);
			}
		}
	}

	if( (argc > 1) && (strcmp(argv[1], "--inc") == 0) ) {
		char boardcode[10];
#ifdef CONFIG_DMVIEW_MGNT
		unsigned int k, discover_counter = 0;
#endif

#ifdef CONFIG_DEVELOPMENT
		#warning *********************** VERSAO DESENVOLVIMENTO ***********************
		system("echo expert::0:0:expert:/:/bin/sh >> /etc/passwd");
		init_program(0, "/bin/mgetty /dev/tts/aux1");
		init_program(1, "agetty");
#endif

		/* Gera usuario 'support' no sistema com senha baseada no numero de serie da placa */
		if( strlen((char *)support_key) > 1 ) {
			char local_buf[70];

			system("/bin/deluser support >/dev/null 2>/dev/null");
			sprintf(local_buf, "/bin/adduser support -p %s >/dev/null 2>/dev/null", support_key);
			system(local_buf);
		}
#ifdef CONFIG_DEVELOPMENT
		#warning ******* ESTA VERSAO NAO REALIZA NENHUMA CONSISTENCIA COM O MODEM *******
		return (inc_starts_counter()<0 ? 1 : 0);
#endif

		/* Se o TF ainda nao foi executado entao nao precisamos buscar as informacoes do modem neste momento. */
		if( board_tf_executed == 0 )
			return (inc_starts_counter()<0 ? 1 : 0);

#ifdef CONFIG_DMVIEW_MGNT
		for( k=0; k < 5; k++ ) {
			if( discover_modem_mgnt_state() == MODEM_MGNT_TRANSPARENT )
				break;
			change_modem_to_transparent();
		}
#endif

		/* Busca informacoes da motherboard */
		for( ; ; ) {
			wakeup_motherboard();
			if( discover_motherboard() > 0 )
				break;
			/* Sem uma identificacao correta da motherboard nao podemos continuar */
			printf("Please wait, trying to get motherboard info...\n");
#ifdef CONFIG_DMVIEW_MGNT
			if( ++discover_counter >= 4 ) {
				/* Envia comando de chaveamento para o modem */
				change_modem_to_transparent();
				discover_counter = 0;
			}
#endif
		}
		if( get_mb_info(MBINFO_PRODUCTCODE, boardcode, 10) == 0 ) {
			printf("** Motherboard identification failed **\n");
			goto proceed_reboot;
		}
		switch( atoi(boardcode) ) { /* Verificacao do codigo da motherboard */
			case SUPP_MOTHERBOARD_CODE_DM991CR:
			case SUPP_MOTHERBOARD_CODE_DM991CS:
			case SUPP_MOTHERBOARD_CODE_DM706CR:
			case SUPP_MOTHERBOARD_CODE_DM706CS:
			case SUPP_MOTHERBOARD_CODE_DM706E:
			case SUPP_MOTHERBOARD_CODE_DM706M1:
			case SUPP_MOTHERBOARD_CODE_DM706M2:
			case SUPP_MOTHERBOARD_CODE_DM706M4:
			case SUPP_MOTHERBOARD_CODE_DM706XM:
			case SUPP_MOTHERBOARD_CODE_DM706XM1:
			case SUPP_MOTHERBOARD_CODE_DM706XM2:
			case SUPP_MOTHERBOARD_CODE_DM706XD:
			case SUPP_MOTHERBOARD_CODE_DM706XD1:
			case SUPP_MOTHERBOARD_CODE_DM706XD2:
				/* Incrementa em flash o contador "starts" */
				return (inc_starts_counter()<0 ? 1 : 0);
			default:
				printf("** Invalid motherboard **\n");
				break;
		}

		/* Nao deveriamos chegar aqui!!! */
proceed_reboot:
		printf("Rebooting in 5 seconds...\n");
		sleep(5);
		reboot(0x01234567);
	}

	get_mb_info(MBINFO_PRODUCTNAME, product_ident, sizeof(product_ident));
	
#else
	hardkey();
#endif

#ifdef BROWSE_COMMANDS	
	browse(CMD, "CMD");
	browse(CMD_CONFIGURE, "CMD_CONFIGURE");
	browse(CMD_CONFIG_INTERFACE_ETHERNET, "CMD_CONFIG_INTERFACE_ETHERNET");
	browse(CMD_CONFIG_INTERFACE_ETHERNET_VLAN, "CMD_CONFIG_INTERFACE_ETHERNET_VLAN");	
	browse(CMD_CONFIG_INTERFACE_SERIAL_CHDLC, "CMD_CONFIG_INTERFACE_SERIAL_CHDLC");
	browse(CMD_CONFIG_INTERFACE_SERIAL_FR, "CMD_CONFIG_INTERFACE_SERIAL_FR");
	browse(CMD_CONFIG_INTERFACE_SERIAL_SUBFR, "CMD_CONFIG_INTERFACE_SERIAL_SUBFR");
	browse(CMD_CONFIG_INTERFACE_SERIAL_PPP, "CMD_CONFIG_INTERFACE_SERIAL_PPP");
	browse(CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC, "CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC");
	browse(CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC, "CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC");
	browse(CMD_CONFIG_ROUTER_RIP, "CMD_CONFIG_ROUTER_RIP");
	browse(CMD_CONFIG_ROUTER_OSPF, "CMD_CONFIG_ROUTER_OSPF");
	exit(0);
#endif
	_cish_booting = 0;
	_cish_source = "console";
	openlog("config", LOG_CONS|LOG_PID, LOG_USER);

	br_initbr();
	/* Map CISH configuration */
	mmap_cfg();
	save_termios();

	/* Begin with NORMAL mask */
	_cish_mask = MSK_NORMAL;
#ifdef OPTION_FEATURE
	load_ftures();
#endif
	set_rip_interface_cmds(get_ripd());
	set_ospf_interface_cmds(get_ospfd());
#ifdef OPTION_BGP
	set_bgp_interface_cmds(get_bgpd());
#endif
#ifdef CONFIG_BERLIN_SATROUTER
	read_bpb(&bpb);
	set_model_aux_cmds(0);
	set_model_qos_cmds(1);
	switch( get_board_hw_id() )
	{
		case BOARD_HW_ID_1:
			set_model_ethernet_cmds("0-0");
			break;
		case BOARD_HW_ID_0:
		case BOARD_HW_ID_2:
		case BOARD_HW_ID_3:
		case BOARD_HW_ID_4:
			set_model_ethernet_cmds("0-1");
			break;
	}
	set_model_serial_cmds("0-1");
	crypto_on_off(1); /* Enable crypto by default */
#else /* AR3000 / AR4000 */
	set_model_aux_cmds(1);
	set_model_qos_cmds(1);
	crypto_on_off(1); /* Enable crypto by default */
#ifdef CONFIG_BERLIN_AR4000
	set_model_serial_cmds("0-1");
	set_model_ethernet_cmds("0-1");
#endif
#endif

	command_root=CMD;
	if (get_runlevel() == '4') /* firmware upload */
	{
		CMD_FIRMWARE[0].privilege=1; /* enable download */
		CMD_FIRMWARE[1].privilege=1; /* enable save */
		CMD_FIRMWARE[2].privilege=1000; /* disable upload */
	}

#ifdef CONFIG_BERLIN_SATROUTER
	disable_exc_cmds();
#endif

	/* thttpd/config.h CGI_PATTERN "config|exec|interface|router|ssi|keychain|key|crypto|ipsec" */
	if (strcmp(argv[0], "exec") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
	else if (strcmp(argv[0], "config") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_CONFIGURE;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}	
	else if (strcmp(argv[0], "interface") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_CONFIG_INTERFACE;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
	else if (strcmp(argv[0], "router") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_CONFIG_ROUTER;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
	else if (strcmp(argv[0], "ssi") == 0)
	{
#if 0
		ssi_main();
#endif
		munmap_cfg();
		return 0;
	}
	else if (strcmp(argv[0], "keychain") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_KEYCHAIN;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
	else if (strcmp(argv[0], "key") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_KEY;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
#ifdef OPTION_NEW_QOS_CONFIG
	else if (strcmp(argv[0], "policy-map") == 0) 
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_POLICYMAP;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	} 
	else if (strcmp(argv[0], "policy-mark") == 0) 
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_POLICYMAP_MARKRULE;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
#endif
#ifdef OPTION_IPSEC
	else if (strcmp(argv[0], "crypto") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_CONFIG_CRYPTO;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
	else if (strcmp(argv[0], "ipsec") == 0)
	{
		_cish_loggedin = 1;
		_cish_enable = 1;
		terminal_lines = 0;
		command_root = CMD_IPSEC_CONNECTION_CHILDREN;
#ifdef OPTION_CGI
		cgi_main(argv[0]);
#endif
		munmap_cfg();
		return 0;
	}
#endif

	if (argc == 2)
	{
		if (strcmp (argv[1], "-b") == 0)
		{
			int size;

#ifdef CONFIG_BERLIN_SATROUTER
			char boardcode[10];
			int satcode, mothercode;

#ifdef CONFIG_DEVELOPMENT
			goto cont_boot;
#endif
			/* Se o TF ainda nao foi executado entao nao precisamos fazer os testes de consistencia neste momento. */
			if( board_tf_executed == 0 )
				goto cont_boot;

			if( get_mb_info(MBINFO_PRODUCTCODE, boardcode, 10) ) {
				switch( atoi(boardcode) ) {
					case SUPP_MOTHERBOARD_CODE_DM991CR:
					case SUPP_MOTHERBOARD_CODE_DM991CS:
					case SUPP_MOTHERBOARD_CODE_DM706CR:
					case SUPP_MOTHERBOARD_CODE_DM706CS:
						/* Notifica modem a respeito do modo no qual ele deve operar (CR ou CS) */
						if( notify_modem_about_us() != 1 )
						{
							printf("** Error during product initialization **\n");
							printf("Rebooting in 5 seconds...\n");
							sleep(5);
							reboot(0x01234567);
						}
						/* Busca novamente informacoes da motherboard */
						if( !discover_motherboard() )
						{
							/* Sem uma identificacao correta da motherboard nao podemos continuar */
							printf("** Motherboard detection failed, after ID setting **\n");
							printf("Rebooting in 5 seconds...\n");
							sleep(5);
							reboot(0x01234567);
						}
						break;

					case SUPP_MOTHERBOARD_CODE_DM706E:
					case SUPP_MOTHERBOARD_CODE_DM706M1:
					case SUPP_MOTHERBOARD_CODE_DM706M2:
					case SUPP_MOTHERBOARD_CODE_DM706M4:
					case SUPP_MOTHERBOARD_CODE_DM706XM:
					case SUPP_MOTHERBOARD_CODE_DM706XM1:
					case SUPP_MOTHERBOARD_CODE_DM706XM2:
					case SUPP_MOTHERBOARD_CODE_DM706XD:
					case SUPP_MOTHERBOARD_CODE_DM706XD1:
					case SUPP_MOTHERBOARD_CODE_DM706XD2:
						break;

					default:
						printf("** Invalid product after ID setting **\n");
						goto proceed_reboot;
						break;
				}
			}
			else {
				printf("** Invalid product after ID setting **\n");
				goto proceed_reboot;
			}

			/* Teste da motherboard */
			if( get_mb_info(MBINFO_PRODUCTCODE, boardcode, 10) )
			{
				mothercode = atoi(boardcode);
				satcode = get_board_hw_id();

				/* Verificamos a compatibilidade entre as placas */
				if( check_boards_compat(mothercode, satcode) < 0 ) {
					printf("** Invalid product after ID setting **\n");
					goto proceed_reboot;
				}
			}
			else {
				printf("** Invalid product after ID setting **\n");
				goto proceed_reboot;
			}

			go_motherboard_startmenu();
#endif

			hardkey();
#if 0
			load_ssh_secret(SSH_KEY_FILE);
#endif
#ifdef OPTION_NTPD
			load_ntp_secret(NTP_KEY_FILE);
#endif
#ifdef CONFIG_BERLIN_SATROUTER
			/*  Testes de TRIAL.
			 *  Verificamos se o equipamento estah em modo trial e se sim, se ainda pode executar.
			 */
			{
				unsigned int days;
				char buf[20], trial_out=0;
				char message_timeout[] = "No left time.\nContact vendor for more informations.\n\n";
				
				if(get_uboot_env("trialdays", buf, 9) > 0)
				{
					if(strlen(buf) == 4)
					{
						sscanf(buf, "%x", &days);
						if(days > 0)
						{
							exec_daemon(TRIAL_DAEMON);
							if(days <= 364)
							{
								if(get_trialminutes_counter(buf, 19) >= 0)
								{
									int diff;
									int minutes = atoi(buf);
							
									if(minutes >= 0)
									{
										diff = days - (minutes / (60 * 24)) - 1;
										if(diff > 0)	printf("Time left: %d days\n\n", diff);
										else
										{
											if((diff = (days * 24 * 60) - minutes) > 0)
											{
												if((diff / 60) > 0)
													printf("Time left: %d hours\n\n", diff / 60);
												else	printf("Time left: %d minutes\n\n", diff);
											}
										}
										if(minutes >= (days * 24 * 60))	trial_out++;
									}
								}
							}
						}
					}
				}
				if(trial_out)
				{
					FILE *f;
					int k, n;
					char buf[256];
					fd_set test_fds;
					arg_list argl=NULL;
					
					/* Configura o nome default do sistema */
					if((f = fopen(DEFAULT_CFG_FILE, "r")))
					{
						while(!feof(f))
						{
							fgets(buf, 255, f);
							buf[255] = '\0';
							if((n = parse_args_din(buf, &argl)) > 0)
							{
								if(!strcmp(argl[0], "hostname"))
								{
									for(k=1, buf[0]=0; k < n; k++)
									{
										if((strlen(buf) + strlen(argl[k])) >= 256)	break;
										if(k > 1)	strcat(buf, " ");
										strcat(buf, argl[k]);
									}
									if(buf[0])	sethostname(buf, strlen(buf));
									free_args_din(&argl);
									break;
								}
								free_args_din(&argl);
							}
						}
						fclose(f);
					}
					conf_pam_mode(NULL, AAA_AUTH_LOCAL, 1, FILE_PAM_GENERIC);
					set_ethernet_ip_addr("ethernet0", "192.168.0.25", "255.255.255.0");
					dev_set_link_up("ethernet0");
					switch( get_board_hw_id() )
					{
						case BOARD_HW_ID_1:
							break;
						case BOARD_HW_ID_0:
						case BOARD_HW_ID_2:
						case BOARD_HW_ID_3:
						case BOARD_HW_ID_4:
							set_ethernet_ip_addr("ethernet1", "192.168.0.25", "255.255.255.0");
							dev_set_link_up("ethernet1");
							break;
					}
					set_inetd_program(1, TELNET_DAEMON);
					if(load_ssh_secret(SSH_KEY_FILE) < 0)	ssh_create_rsakey(768);
					system("/bin/sshd -D &");
					start_default_snmp();
					system("/bin/snmpd -f -C -c /etc/snmpd.conf >/dev/null 2>/dev/null &");
					system("/bin/gpio led_sys on");
					printf(message_timeout);
			
					/* Permanecemos eternamente neste loop.
					* Caso a placa saia do estado de trial vencido, ela serah reinicializada.
					*/
					for(;;)
					{
						FD_ZERO(&test_fds);
						FD_SET(fileno(stdin), &test_fds);
						if(select(FD_SETSIZE, &test_fds, (fd_set *) NULL, (fd_set *) NULL, (struct timeval *) NULL) > 0)
						{
							if(FD_ISSET(fileno(stdin), &test_fds))
							{
								if(read(fileno(stdin), buf, sizeof(buf)))       printf(message_timeout);
							}
						}
					}
				}
			}
			
cont_boot:
			/* Definimos o encapsulamento default */
			wan_set_protocol(0, IF_PROTO_CISCO);
			wan_set_protocol(1, IF_PROTO_CISCO);
#ifdef CONFIG_SPPP_NETLINK
			/* Definimos a autenticacao default para o SPPP */
			conf_pam_mode(NULL, AAA_AUTH_LOCAL, 1, FILE_PAM_SPPP);
#endif
#endif
			size=load_configuration(STARTUP_CFG_FILE);
			if (size <= 0)
			{
				printf("%% using default configuration\n");
				bootfile=DEFAULT_CFG_FILE;
#ifdef CONFIG_BERLIN_SATROUTER
				switch( get_board_hw_id() )
				{
					case BOARD_HW_ID_0:
					case BOARD_HW_ID_2:
					case BOARD_HW_ID_3:
					case BOARD_HW_ID_4:
						break;
					case BOARD_HW_ID_1:
						exclude_eth1cfg_from_file(bootfile);
						break;
				}
#endif
			}
			else
			{
				bootfile=STARTUP_CFG_FILE;
			}
#if 0 /* Dont necessary anymore! linux/drivers/char/m41t11.c */
			set_system_date_with_rtc();
#endif
			setup_loopback(); /* init loopback0 */
			_cish_loggedin = 1;
			_cish_enable = 2; /* Enable special commands! */
			_cish_booting = 1;
			config_file(bootfile); /* reload config */
#if 0
			notify_systtyd(); /* systtyd isnt running yet! */
			cleanup_modules(); /* !!! hang cish -b if ethernet link down !!! */
#endif
#ifdef CONFIG_BERLIN_SATROUTER
#ifdef CONFIG_DMVIEW_MGNT
			if( discover_modem_mgnt_state() != MODEM_MGNT_TELEBRAS )
				change_modem_to_telebras();
			if( !dmview_management )
				set_microcom_mode(MICROCOM_MODE_LISTEN); /* Ativamos o microcom */
#else
			set_microcom_mode(MICROCOM_MODE_NONE); /* Desativamos o microcom */
#endif
#endif
			exit(0);
		}
	}
	if (argc > 2)
	{
#ifdef CONFIG_BERLIN_SATROUTER
		{
			unsigned int k;
			
			for(k=1; k < argc; k++)
			{
				if(!strcmp(argv[k], "-h"))
				{
					if((k+1) < argc)
					{
						_cish_source = argv[k+1];
						break;
					}
				}
			}
		}
#else
		if (strcmp(argv[1], "-h") == 0)
		{
			_cish_source=argv[2];
		}
#endif
	}

	init_logwatch();
	add_logwatch("/var/log/messages");
	hadspace = 0;

	_cish_debug = 0;
	_cish_loggedin = 0;

	signal(SIGPIPE, SIG_IGN);

	rl_readline_name = "cish";
	rl_attempted_completion_function = (CPPFunction *) cish_completion;
	rl_bind_key ('?',cish_questionmark);
//	rl_bind_key (26, ctrlz);
	rl_bind_key ('S'&0x1f, NULL);
	rl_bind_key ('R'&0x1f, NULL);
	rl_variable_bind ("horizontal-scroll-mode", "on");
	rl_getc_function = user_getc;
	stifle_history(15);

#if 0
	bcount=0;
	F = fopen ("/etc/router/customize/banner.conf","r");
	if (F)
	{
		while ((bcount<4) && (!feof (F)))
		{
			tmp[0] = 0;
			fgets (tmp, 79, F);
			tmp[79] = 0;
			striplf(tmp);
			if (strlen (tmp)) printf ("%s\n", tmp);
		}
		fclose (F);
		printf ("\n");
	}
#endif
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, hup_handler);
	signal(SIGALRM, alarm_handler);
#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_DMVIEW_MGNT)
	signal(SIGQUIT, signal_to_quit);
#endif
	alarm(1);

	terminal_lines = cish_cfg->terminal_lines;

#ifndef I2C_HC08_ID_ADDR
	memset(mac, 0, 6);
	get_mac("ethernet0", mac);
#endif

#ifdef CONFIG_BERLIN_SATROUTER
#ifdef CONFIG_DMVIEW_MGNT
	if( board_tf_executed && !dmview_management )
#else
	if( board_tf_executed )
#endif
	{
		unsigned int k;
		unsigned char needs_auth=1;
		
		if(argc > 1)
		{
			for(k=1; k < argc; k++)
			{
				if(!strcmp(argv[k], "--authenticated"))
				{
					needs_auth = 0;
					break;
				}
			}
		}
		switch(make_dm_login(needs_auth))
		{
			case AUTH_NOK:
				printf(TERM_CLEAR);
				fflush(stdout);
				process_cish_exit();
				exit(0);
	
			case AUTH_OK:
				break;
	
			case AUTH_FACTORY:
				factory_test_login = 1;
				break;
		}
	}

	if( board_tf_executed == 1 )
	{  /* Teste de TRIAL */
		unsigned int days;
		char buf[20], trial_out=0;
		char message_timeout[] = "No left time.\nContact vendor for more informations.\n\n";
		
		if(get_uboot_env("trialdays", buf, 9) > 0)
		{
			if(strlen(buf) == 4)
			{
				sscanf(buf, "%x", &days);
				if(days > 0)
				{
					exec_daemon(TRIAL_DAEMON);
					if(days <= 364)
					{
						if(get_trialminutes_counter(buf, 19) >= 0)
						{
							int diff;
							int minutes = atoi(buf);
					
							if(minutes >= 0)
							{
								diff = days - (minutes / (60 * 24)) - 1;
								if(diff > 0)	printf("Time left: %d days\n\n", diff);
								else
								{
									if((diff = (days * 24 * 60) - minutes) > 0)
									{
										if((diff / 60) > 0)
											printf("Time left: %d hours\n\n", diff / 60);
										else	printf("Time left: %d minutes\n\n", diff);
									}
								}
								if(minutes >= (days * 24 * 60))	trial_out++;
							}
						}
					}
				}
			}
		}
		if(trial_out)
		{
			char buf[256];
			fd_set test_fds;
			
			printf(message_timeout);
	
			/* Permanecemos eternamente neste loop.
			 * Caso a placa saia do estado de trial vencido, ela serah reinicializada.
			 */
			for(;;)
			{
				FD_ZERO(&test_fds);
				FD_SET(fileno(stdin), &test_fds);
				if(select(FD_SETSIZE, &test_fds, (fd_set *) NULL, (fd_set *) NULL, (struct timeval *) NULL) > 0)
				{
					if(FD_ISSET(fileno(stdin), &test_fds))
					{
						if(read(fileno(stdin), buf, sizeof(buf)))       printf(message_timeout);
					}
				}
			}
		}
	}

ret_main_terminal:
#ifdef CONFIG_DMVIEW_MGNT
	if( !factory_test_login && !dmview_management && board_tf_executed )
#else
	if( !factory_test_login && board_tf_executed )
#endif
		choose_terminal();
	printf(TERM_CLEAR);
	printf(TERM_HOME);
	fflush(stdout);
#endif /* CONFIG_BERLIN_SATROUTER */

	syslog(LOG_INFO, "session opened from %s", _cish_source);

	_cish_loggedin = 1;
	_cish_enable = 0;
	while (_cish_loggedin)
	{
		prompt[0] = 0;
#ifdef CONFIG_BERLIN_SATROUTER
		generate_init_prompt(product_ident, prompt, 64);
#else
		gethostname(buf, sizeof(buf)-1); buf[sizeof(buf)-1]=0;
		strncat (prompt, buf, 24);
#endif

		if (command_root==CMD_CONFIGURE)
		{
			strcat(prompt, "(config)");
		}
		else if (command_root==CMD_KEYCHAIN)
		{
			strcat(prompt, "(config-keychain)");
		}
		else if (command_root==CMD_KEY)
		{
			strcat(prompt, "(config-keychain-key)");
		}
#ifdef OPTION_NEW_QOS_CONFIG
		else if (command_root == CMD_POLICYMAP)
		{
			strcat(prompt, "(config-pmap)");
		}
		else if (command_root == CMD_POLICYMAP_MARKRULE)
		{
			strcat(prompt, "(config-pmap-markrule)");
		}
#endif
		else if (command_root==CMD_CONFIG_ROUTER_RIP)
		{
			strcat(prompt, "(config-router-rip)");
		}
		else if (command_root==CMD_CONFIG_ROUTER_OSPF)
		{
			strcat(prompt, "(config-router-ospf)");
		}
#ifdef OPTION_BGP
		else if (command_root == CMD_CONFIG_ROUTER_BGP)
		{
			strcat(prompt, "(config-router-bgp)");
		}
#endif
		else if (command_root==CMD_CONFIG_INTERFACE_ETHERNET)
		{
			sprintf(prompt+strlen(prompt), "(config-if-ethernet%d)", interface_major);
		}
		else if (command_root==CMD_CONFIG_INTERFACE_ETHERNET_VLAN)
		{
			sprintf(prompt+strlen(prompt), "(config-if-ethernet%d.%d)", interface_major, interface_minor);
		}
		else if ((command_root==CMD_CONFIG_INTERFACE_SERIAL_PPP)||
			(command_root==CMD_CONFIG_INTERFACE_SERIAL_PPP_ASYNC)||
			(command_root==CMD_CONFIG_INTERFACE_SERIAL_FR)||
			(command_root==CMD_CONFIG_INTERFACE_SERIAL_CHDLC)||
			(command_root == CMD_CONFIG_INTERFACE_SERIAL_SPPP)||
#ifdef OPTION_X25
			(command_root==CMD_CONFIG_INTERFACE_SERIAL_X25)||
#endif
			(command_root==CMD_CONFIG_INTERFACE_SERIAL))
		{
			sprintf(prompt+strlen(prompt), "(config-if-serial%d)", interface_major);
		}
		else if (command_root==CMD_CONFIG_INTERFACE_SERIAL_SUBFR)
		{
			sprintf(prompt+strlen(prompt), "(config-if-serial%d.%d)", interface_major, interface_minor);
		}
#ifdef OPTION_X25
		else if (command_root==CMD_CONFIG_INTERFACE_SERIAL_SUBX25)
		{
			sprintf(prompt+strlen(prompt), "(config-if-serial%d.%d)", interface_major, interface_minor);
		}
#endif
		else if (command_root==CMD_CONFIG_INTERFACE_AUX_PPP_ASYNC)
		{
			sprintf(prompt+strlen(prompt), "(config-if-aux%d)", interface_major-MAX_WAN_INTF); /* Offset! */
		}
		else if (command_root==CMD_CONFIG_INTERFACE_LOOPBACK)
		{
			sprintf(prompt+strlen(prompt), "(config-if-loopback%d)", interface_major);
		}
		else if (command_root==CMD_CONFIG_INTERFACE_TUNNEL)
		{
			sprintf(prompt+strlen(prompt), "(config-if-tunnel%d)", interface_major);
		}
		#ifdef OPTION_IPSEC
		else if (command_root == CMD_CONFIG_CRYPTO)
		{
			strcat(prompt, "(config-crypto)");
		}
		else if (command_root == CMD_IPSEC_CONNECTION_CHILDREN) /* ipsec connection names dynamic menus */
		{
			if (strlen(dynamic_ipsec_menu_name) > 0)
			{
				strcat(prompt, "(config-crypto-conn-");
				strcat(prompt, dynamic_ipsec_menu_name);
				strcat(prompt, ")");
			}
		}
		#endif

		strcat(prompt, _cish_enable ? "#" : ">");
		cish_timeout = cish_cfg->terminal_timeout;
		prompt_printed = 1; /* Enable CR on debug log! */
#ifdef CONFIG_BERLIN_SATROUTER
		if( board_tf_executed ) {
			if( factory_test_login ) {
				if( (line = malloc(strlen("factory test")+1)) )
					strcpy(line, "factory test");
				else
					line = readline(prompt);
			}
			else
				line = readline(prompt);
		}
		else {
			if( (line = malloc(strlen("factory test")+1)) )
				strcpy(line, "factory test");
			else
				line = readline(prompt);
		}
#else
		line = readline(prompt);
#endif
		cish_timeout = 0;
		if (!line)
		{
			printf("exit\n");
			line=strdup("exit");
			hadspace=0;
		}

		if (line[0] == '!') {
			while (command_root != CMD_CONFIGURE && command_root != CMD)
				cish_execute("exit"); /* return to root! */
			hadspace=0;
		} else {
			int i;

			for (i=0; i < 1024 && line[i] == ' '; i++);
			if (i > hadspace) {
				hadspace++; /* next level! */
			} else if (i < hadspace) {
				hadspace--; /* previous level! */
				if (command_root != CMD_CONFIGURE && command_root != CMD) {
					cish_execute("exit");
				}
			}
			xline=&line[i];

			if (strlen(xline))
			{
#ifdef CONFIG_BERLIN_SATROUTER
				int special_auth = (board_tf_executed == 0) ? 1 : ((factory_test_login > 0) ? 1 : 0);

				switch(is_special_invisible_cmd(xline, special_auth)) {
					case NO_SPECIAL_CMD:
						if( board_tf_executed == 1 ) {
							add_history(line);
							cish_execute(xline);
						}
						else {
							/* Caso especial: TF ainda nao foi executado, somente aceitamos o comando "enable" */
							arg_list argx = NULL;

							if( parse_args_din(xline, &argx) == 1 ) {
								if( strcmp(argx[0], "enable") == 0 ) {
									add_history(line);
									cish_execute(xline);
								}
							}
							free_args_din(&argx);
						}
						break;
					
					case SPECIAL_CMD_FACTORY:
					{	/* Estamos no modo teste de fabrica. */
						FILE *f;
						unsigned int exflag;
						char *s, *bck_cfg=NULL, ch;
						int bck_timeout = cish_cfg->terminal_timeout;

						free(line);

						/* Nao ha timeout para o CLI caso estejamos em modo teste de fabrica */
						cish_timeout = cish_cfg->terminal_timeout = 0;

						/* Alteramos o prompt de forma que o usuario saiba quando estah no modo teste de fabrica */
						s = prompt + strlen(prompt) - 1;
						ch = *s;
						sprintf(s, "-FT%c", ch);

						/* Salva configuracao atual */
						if((f = fopen(FT_TMP_CFG_FILE, "wt"))) {
							write_config(f);
							fclose(f);
							bck_cfg = FT_TMP_CFG_FILE;
						}

						/* Configura interface serial0 a partir do arquivo /etc/factory_cfg_serial */
						tc_remove_all("serial0");
						tc_remove_all("serial1");
						dev_set_link_down("serial0");
						dev_set_link_down("serial1");
						//_cish_loggedin = 1;
						_cish_enable = 2; /* Enable special commands! */
						//_cish_booting = 1;
						config_file("/etc/factory_cfg_serial");

						set_ethernet_ip_addr("ethernet0", "192.168.0.16", "255.255.255.0");
						switch( get_board_hw_id() ) {
							case BOARD_HW_ID_1:
								break;
							case BOARD_HW_ID_0:
							case BOARD_HW_ID_2:
							case BOARD_HW_ID_3:
							case BOARD_HW_ID_4:
								set_ethernet_ip_addr("ethernet1", "192.168.0.17", "255.255.255.0");
								break;
						}
						set_inetd_program(1, FTP_DAEMON); /* enable upload service */

						/* Desativa as interfaces ethernet.
						 * Motivo: teste de fabrica devera ativar uma a uma atraves de comando especifico para
						 * garantir que o teste estah sendo realizado na interface correta.
						 */
						dev_set_link_down("ethernet0");
						switch( get_board_hw_id() ) {
							case BOARD_HW_ID_1:
								break;
							case BOARD_HW_ID_0:
							case BOARD_HW_ID_2:
							case BOARD_HW_ID_3:
							case BOARD_HW_ID_4:
								dev_set_link_down("ethernet1");
								break;
						}
						clear_history();

#ifdef CONFIG_DMVIEW_MGNT
						if( !dmview_management ) {
							/* Desativa qualquer microcom em execucao */
							pid_t pid;

							set_microcom_mode(MICROCOM_MODE_NONE);
							if( (pid = get_pid(PROG_MICROCOM)) > 0 )
								kill(pid, SIGTERM);
						}
#endif

						for( exflag=0; exflag == 0; ) { /* Loop de comandos */
							if((line = readline(prompt))) {
								if(strlen((s = stripwhite(line)))) {
									if(*s != '\n') {
										add_history(line);
										exflag = process_factory_cmd(s);
									}
								}
								free(line);
								rl_on_new_line();
							}
						}

#ifdef CONFIG_DMVIEW_MGNT
						if( !dmview_management ) {
							/* Microcom retoma modo normal de funcionamento */
							set_microcom_mode(MICROCOM_MODE_LISTEN);
						}
#endif

						/* Voltamos a ter timeout */
						cish_cfg->terminal_timeout = bck_timeout;

						/* Restaura configuracao */
						if(bck_cfg) {
							_cish_loggedin = 1;
							_cish_enable = 2; /* Enable special commands! */
							_cish_booting = 1;
							config_file(bck_cfg);
							remove(bck_cfg);
						}

						/* Depois do teste de fabrica ter terminado, fechamos
						 * o cish nao importando de onde ele foi chamado.
						 */
						process_cish_exit();
						exit(0);
					}
					
					case SPECIAL_CMD_GENSECRET:
					case SPECIAL_CMD_MOTHERBOARD_STARTMENU:
					case SPECIAL_CMD_MOTHERBOARD_INFO:
					default:
						break;
				}
#else /* CONFIG_BERLIN_SATROUTER */
				add_history(line);
				retval = cish_execute(xline);
				/* Command accounting */
				acct_mode = discover_pam_current_acct_command_mode(FILE_PAM_GENERIC);
				if (retval && acct_mode!=AAA_ACCT_TACACS_CMD_NONE) 
				{
					/* logs anything but exit and enable commands*/
					if ( strncmp(line,"exit", strlen("exit")) && 
						strncmp(line,"enable", strlen("enable")) )
					{	
						if ( (!_cish_enable) && 
							(acct_mode == AAA_ACCT_TACACS_CMD_1 || 
							acct_mode == AAA_ACCT_TACACS_CMD_ALL) ) /* unprivileged user */
							tacacs_log((unsigned char *)line,TAC_PLUS_PRIV_LVL_USR);
						else if ((_cish_enable) && 
							  (acct_mode == AAA_ACCT_TACACS_CMD_15 || 
							   acct_mode == AAA_ACCT_TACACS_CMD_ALL) )
								tacacs_log((unsigned char *)line,TAC_PLUS_PRIV_LVL_MAX);
					}
				}
#endif
			}
		}
		free(line);
	}
#ifdef CONFIG_BERLIN_SATROUTER
#ifdef CONFIG_DMVIEW_MGNT
	if( release_microcom_lock() )
		set_microcom_mode(MICROCOM_MODE_LISTEN);
	if( !dmview_management )
		goto ret_main_terminal;
#else
	goto ret_main_terminal;
#endif
#endif
	process_cish_exit();
	return 0;
}

void setup_loopback(void) /* default startup config for loopback0 */
{
#if 0 /* loopback configured by startup-config(default-config) */
	dev_set_link_up("loopback0");
	ip_addr_add("loopback0", "127.0.0.1", NULL, "255.0.0.0");
	add_route_dev("127.0.0.0", "255.0.0.0", "loopback0");
#endif
}

void config_file(const char *f)
{
	int i, hadspace=0;
	char line[1024];
	FILE *F;
	cish_command *ocmd;

	ocmd=command_root;
	command_root=CMD_CONFIGURE;

	F=fopen(f, "r");
	if (F)
	{
		while (!feof(F))
		{
			line[0]=0;
			fgets(line, 1023, F);
			striplf(line);

			if (strncmp(line, "version", 7) == 0)
			{
				char cfg_version[32];

				strncpy(cfg_version, line+8, 32);
				cfg_version[31]=0;
				striplf(cfg_version);
				if (strcmp(cfg_version, get_system_version()))
				{
					fprintf(stderr, "%% Configurations from version %s may not be correctly understood!\n", cfg_version);
				}
				continue;
			}
			if (line[0] == '!') {
				while (command_root != CMD_CONFIGURE)
					cish_execute("exit"); /* return to configure terminal! */
				hadspace=0;
			} else {
				strncat(line, " ", 1023); /* !!! */
				for (i=0; i < 1024 && line[i] == ' '; i++);
				if (i > hadspace) {
					hadspace++; /* next level! */
				} else if (i < hadspace) {
					hadspace--; /* previous level! */
					if (command_root != CMD_CONFIGURE) {
						cish_execute("exit");
					}
				}
				if (strlen(&line[i]))
					cish_execute(&line[i]);
			}
		}
		fclose(F);
	}
	else
	{
		printf ("%% Could not find file: %s\n", f);
	}
	command_root=ocmd;
}

struct logwatch {
	long offset;
	const char *resource;
	int last_message_printed;
} LOGS[16];

void init_logwatch (void)
{
	int i;
	
	for (i=0; i < 16; ++i)
	{
		LOGS[i].offset = -1;
		LOGS[i].resource = NULL;
		LOGS[i].last_message_printed = 0;
	}
}

void add_logwatch (const char *resource)
{
	int i;

	for (i=0; i < 16 && LOGS[i].resource; i++);
	if (i < 16)
	{
		LOGS[i].resource = resource;
	}
}

void timed_out(void)
{
	reload_termios(); // isto eh necessario porque estamos saindo a partir
	// de uma funcao chamada pela libreadline podemos estar, portanto, com
	// a configuracao de termios alterada.
	printf("\n");
	syslog (LOG_INFO, "timeout: closing session from %s", _cish_source);
#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_DMVIEW_MGNT)
	process_cish_exit();
#endif
	exit(0);
}

void hup_handler(int sig)
{
	/* systtyd can reload mgetty and spot us! notify_mgetty() */
	timed_out();
}

void alarm_handler(int sig)
{
	int l;
	FILE *logfile;
	arg_list argl = NULL;
	char *p, *crsr, _buf[256], name[16], repeat_msg[] = "last message repeated";

	if (cish_reload > 0) {
		cish_reload--;
		if (cish_reload == 10) {
			printf("\n%% Warning: %d seconds to reload!\n", cish_reload);
		}
		else if (cish_reload == 0) {
			printf("\n%% Reloading startup configuration...\n");
			syslog(LOG_INFO, "timeout: reload startup configuration");
#if 0 /* warm-boot */
			config_memory(NULL); /* reload start-up configuration! */
#else /* cold-boot */
#if 0 /* Quando invocado por telnet esta derrubando o shell remoto e o reboot nao ocorre! */
			system("/bin/clean");
#endif
			reboot(0x01234567);
#endif
		}
	}
	else if (cish_timeout > 0) {
		cish_timeout--;
		if (cish_timeout == 0)
			timed_out();
	}

	if (_cish_debug) {
		_buf[0] = 0;
		for (l=0; l < 16 && LOGS[l].resource; l++) {
			if ((logfile = fopen(LOGS[l].resource, "r")) == NULL)
				continue;
			if (LOGS[l].offset == -1) {
				fseek(logfile, -256, SEEK_END);
				fgets(_buf, 255, logfile); /* skip to end of line! */
			}
			else {
				fseek(logfile, 0, SEEK_END);
				if (ftell(logfile) < LOGS[l].offset) {
					LOGS[l].offset = 0;
					rewind(logfile);
				}
				else
					fseek(logfile, LOGS[l].offset, SEEK_SET);
			}
			while (!feof(logfile)) {
				_buf[0] = 0;
				fgets(_buf, 255, logfile);
				_buf[255] = 0;
				if (parse_args_din(_buf, &argl) > 5) {
					crsr = strstr(_buf, argl[4]);
					if (crsr) {
						for (crsr+=strlen(argl[4]); *crsr == ' '; crsr++);
						if (*crsr) {
							if (strncmp(crsr, repeat_msg, strlen(repeat_msg)) == 0) {
								if (LOGS[l].last_message_printed) {
									if (prompt_printed) {
										printf("\n");
										rl_on_new_line();
										prompt_printed = 0;
									}
									printf(crsr);
									LOGS[l].last_message_printed = 1;
								}
							}
							else {
								LOGS[l].last_message_printed = 0;
								p = find_debug_token(crsr, name, 0);
								if (p != NULL) {
									if (prompt_printed) {
										printf("\n");
										rl_on_new_line();
										prompt_printed = 0;
									}
									printf("%s%s", name, p);
									LOGS[l].last_message_printed = 1;
								}
							}
						}
					}
				}
				free_args_din(&argl);
			}
			LOGS[l].offset = ftell(logfile);
			fclose(logfile);
		}
	}
	alarm(1);
}

// Funcao para ler um caracter, em substituicao `a funcao default da readline.
// A unica diferenca eh que esta trata do timeout.
int user_getc (FILE *stream)
{
	int result;
	unsigned char c;
	
	cish_timeout = cish_cfg->terminal_timeout;
	
	while (1)
	{
		result = read (fileno (stream), &c, sizeof (unsigned char));

		if (result == sizeof (unsigned char))
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

char **cish_completion (char *text, int start, int end)
{
	char **matches;
	char tmp[1024];
	int rightedge;
	int pos;
	cish_command *xcmd;
	
	completion_root = command_root;
	if (start>0)
	{
		pos = 0;
		while ((rl_line_buffer[pos] == ' ') && (pos < start)) ++pos;
		
		while (pos < start)
		{
			rightedge = (strchr (rl_line_buffer+pos, ' ') - rl_line_buffer);
			if ((rightedge>=0) && (rightedge < start))
			{
				/* command is now between pos and rightedge */
				memcpy (tmp, rl_line_buffer+pos, rightedge-pos);
				tmp[rightedge-pos] = 0;
								
				xcmd = completion_root ? expand_token (tmp, completion_root, -1) : NULL;
				if (xcmd) completion_root = xcmd->children;
				pos = rightedge+1;
			}
			else pos=start;
		}
	}
	matches = (char **) NULL;
	
	if (!completion_root) 
	{
		matches = (char **) malloc (2 * sizeof(char *));
		printf ("\n<enter> no further known parameters\n\n");
		rl_on_new_line();
		rl_ding(); /* ding() */
		matches[0] = strdup ("");
		matches[1] = NULL;
		rl_pending_input = '\b';
		return matches;
	}
	
	matches = (char **)rl_completion_matches (text, cish_command_generator);
	
	if (! (*matches[0]))
	{
		rl_completion_append_character = '\0';
	}
	else
	{
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

char *cish_command_generator (const char *text, int state)
{
	cish_command *result;
	rl_completion_append_character = ' ';
	
	if (!state) _iteration = 0;
	
	result = expand_token (text, completion_root, _iteration);
	++_iteration;
	
	if (result) return (char *) strdup(result->name);
	if (!state)
	{
		rl_ding();
		return (char *) strdup ("");
	}
	return NULL;
}

/* ==============================================================================
 * cish_questionmark
 *
 * figures out and prints the currently relevant help information
 * ============================================================================== */

int cish_questionmark (int count, int KEY)
{
	char tmp[1024];
	int rightedge;
	int pos;
	int start = strlen(rl_line_buffer);
	cish_command *xcmd;
	int i;
	int len;
	char incomp[1024]="";
	
	completion_root = command_root;
	if (start>0)
	{
		pos = 0;
		while ((rl_line_buffer[pos] == ' ') && (pos < start)) ++pos;
		
		while (pos < start)
		{
			rightedge = (strchr (rl_line_buffer+pos, ' ') - rl_line_buffer);
			if ((rightedge>=0) && (rightedge < start))
			{
				/* command is now between pos and rightedge */
				memcpy(tmp, rl_line_buffer+pos, rightedge-pos);
				tmp[rightedge-pos] = 0;
				xcmd=expand_token(tmp, completion_root,-1);
				if (!xcmd)
				{
					printf("\n%% Unrecognized command\n");
					rl_on_new_line();
					return 1;
				}
				if (xcmd->children) completion_root = xcmd->children;
				else
				{
					printf ("\n");
					printf ("<enter>  no further known parameters\n");
					printf ("\n");
					rl_on_new_line();
					return 1;
				}
				pos = rightedge+1;
			}
			else 
			{
				strncpy(incomp, rl_line_buffer+pos, 1024); incomp[1023]=0;
				pos=start;
			}
			while ((rl_line_buffer[pos] == ' ') && (pos < start)) ++pos;
		}
	}

	if (completion_root)
	{
		printf ("\n");
		pos = 0;
		rightedge=0;
		while (completion_root[pos].name) // verifica o tamanho da maior string (para formatar a saida)
		{
			len = strlen (completion_root[pos].name);
			if (len > rightedge) rightedge = len;
			++pos;
		}
		pos = 0;
		while (completion_root[pos].name)
		{
			if ((completion_root[pos].privilege <= _cish_enable) && 
			    (completion_root[pos].mask & _cish_mask) &&
			    ((incomp[0]==0)||(strncmp(completion_root[pos].name, incomp, strlen(incomp))==0)))
			{
				printf ("%s", completion_root[pos].name);
				len = strlen (completion_root[pos].name);
				for (i=len;i<rightedge;++i) putchar (' ');

				printf ("  %s\n", completion_root[pos].help);
			}
			++pos;
		}
		printf ("\n");
		rl_on_new_line();
	}
	return 1;
}

#ifdef OPTION_CGI
// Retorna 1 se o comando esta completo (ou se nao reconheceu o comando)

int cish_completion_http (char *cmdline, char *base_url)
{
	char tmp[1024];
	int rightedge;
	int pos;
	int start=strlen(cmdline);
	cish_command *xcmd;
	char incomp[1024]="";
	
	// caso particular: comando 'configure', 'interface ...', etc
	if (strcmp(cmdline, "configure ")==0)
	{
		printf("<a href=/config>http</a><dd>Configure from http<dt>\n");
		return 0;		
	}
	
	completion_root = command_root;
	if (start>0)
	{
		pos = 0;
		while ((cmdline[pos] == ' ') && (pos < start)) ++pos;
		
		while (pos < start)
		{
			rightedge = (strchr (cmdline+pos, ' ') - cmdline);
			if ((rightedge>=0) && (rightedge < start))
			{
				/* command is now between pos and rightedge */
				memcpy (tmp, cmdline+pos, rightedge-pos);
				tmp[rightedge-pos] = 0;
				xcmd = expand_token (tmp, completion_root,-1);
				if (!xcmd)
					return 1;
				if (xcmd->children) completion_root = xcmd->children;
				else return 1;
				pos = rightedge+1;
			}
			else 
			{
				strncpy(incomp, cmdline+pos, 1024); incomp[1023]=0;
				pos=start;
			}
			while ((cmdline[pos] == ' ') && (pos < start)) ++pos;
		}
	}
	
	if (completion_root)
	{
		const char *name, *help;
		
		pos = 0;
		while (completion_root[pos].name)
		{
			if ((completion_root[pos].privilege <= _cish_enable) && 
			    (completion_root[pos].mask & _cish_mask) &&
			    ((incomp[0]==0)||(strncmp(completion_root[pos].name, incomp, strlen(incomp))==0)))
			{
				cmdline2url(cmdline, buf);
				name = completion_root[pos].name;
				help = completion_root[pos].help;
				
				if (strcmp(name, "<enter>")==0)
				{
					strcat(buf, "CR");
					printf("<a href=%s%s>CR</a><dd>%s<dt>\n",
						base_url, buf, help);
				}
				else if (strcmp(name, "hh:mm:ss")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=HH:MM:SS> <input type=text name=arg size=8></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if ((isdigit(*name)) && (strchr (name, '-')))
				{
					int size1, size2, size;
					
					size1 = strchr(name, '-')-name;
					size2 = strlen(name)-size1-1;
					if (size1>size2) size=size1; else size=size2;
					if (size<1) size=1;
					
					if (strncmp(cmdline, "interface", 9)==0)
					{
					}
					
					printf("<form method=post action=%s%sARG><input type=submit value=Number> %s <input type=text name=arg size=%d></form><dd>%s<dt>",
						base_url, buf, name, size, help);
				}
				else if (strcmp(name, "-23 - 23")==0)
				{
					int size=3;
					
					printf("<form method=post action=%s%sARG><input type=submit value=Number> %s <input type=text name=arg size=%d></form><dd>%s<dt>",
						base_url, buf, name, size, help);
				}
				else if (strcmp(name, "<ipaddress>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=IP_Address> <input type=text name=arg size=15></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<netmask>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=IP_Mask> <input type=text name=arg size=15></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<rnetmask>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Wildcard_bits> <input type=text name=arg size=15></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<ipx network>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=IPX_Network> <input type=text name=arg size=8></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<ipx node>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=IPX_Network> <input type=text name=arg size=12></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<x121>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=X121> <input type=text name=arg size=18></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<cudhexstring>") == 0) 
				{
					printf("<form method=post action=%s%sARG><input type=submit value=CUD> <input type=text name=arg size=32></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<bandwidth>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Bandwidth> <input type=text name=arg size=13></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<burst>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Burst> <input type=text name=arg size=13></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<port>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Port> <input type=text name=arg size=15></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<acl>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=ACL> <input type=text name=arg size=60></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<flags>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Flags> <input type=text name=arg size=60></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<url>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Url> <input type=text name=arg size=128></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<string>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Hash> <input type=text name=arg size=60></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<text>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Word> <input type=text name=arg size=60></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else if (strcmp(name, "<mac>")==0)
				{
					printf("<form method=post action=%s%sARG><input type=submit value=Mac> <input type=text name=arg size=20></form><dd>%s<dt>",
						base_url, buf, help);
				}
				else
				{
					strcat(buf, name);
					printf("<a href=%s%s>%s</a><dd>%s<dt>\n",
						base_url, buf, name, help);
				}
			}
			++pos;
		}
		printf ("\n");
	}
	return 0;
}
#endif

/* ==============================================================================
 * cish_config_changed
 *
 * Compares running and startup configuration and, in case they are different,
 * asks if user wants to save running config.
 * ============================================================================== */

int cish_config_changed(void)
{
	FILE *f_running, *f_flash;
	struct stat run_stat, flash_stat;
	char in;
	int ret=0;
		
	/* Writes running config */
	f_running = fopen(TMP_CFG_FILE, "wt");
	if (!f_running) return -1;
	write_config (f_running);
	fclose(f_running);

	/* Load configuration fron flash */
	load_configuration(STARTUP_CFG_FILE);
	
	/* Check size */
	stat(TMP_CFG_FILE,&run_stat);
	stat(STARTUP_CFG_FILE,&flash_stat);
#if 0 /* debug */
	printf("flash file size = %d\n", flash_stat.st_size);
	printf("run file size = %d\n", run_stat.st_size);
#endif

	/* Why does STARTUP_CFG_FILE has one byte more then TMP_CFG_FILE???? */
	if (run_stat.st_size != flash_stat.st_size-1) {
		ret=1;
	} else {
		unsigned char *run_buffer, *flash_buffer;
		unsigned char run_hash[16], flash_hash[16];

		/* They have the same size, nevertheless it does not mean they are the same! */
		f_running = fopen(TMP_CFG_FILE, "r");
		f_flash = fopen(STARTUP_CFG_FILE, "r");
		if (!f_running || !f_flash) return -1;
		/* malloc the same ammount of memory for both */
		run_buffer = (unsigned char *) malloc(run_stat.st_size);
		flash_buffer = (unsigned char *) malloc(run_stat.st_size);
		
		fread (run_buffer, 1, run_stat.st_size, f_running);
		fread (flash_buffer, 1, run_stat.st_size, f_flash);

		fclose(f_running);
		fclose(f_flash);
	
		md5_buffer((char *)run_buffer, run_stat.st_size, run_hash);
		md5_buffer((char *)flash_buffer, run_stat.st_size, flash_hash);
#if 0
		printf("run hash = %s\n", run_hash);
		printf("flash hash = %s\n", flash_hash);
#endif
		if (strncmp((char *)run_hash, (char *)flash_hash, 16)) ret=1;
	}

	if (ret) {
		printf("System configuration has been modified. Save? [yes/no]:");
		/* Change terminal mode to accept character without ENTER in the end */
		canon_off();
		in=getchar();
		canon_on();
		printf("\n");
		if ((in=='y')||(in=='Y')) {
			const char flash_save_cmd[]="copy running-config startup-config";
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

int cish_execute (const char *cmd)
{
	char realcmd[2048];
	char tmp[1024];
	int rightedge;
	int pos;
	int start=strlen(cmd);
	cish_command *xcmd = NULL;
	int i;

	realcmd[0]=0;

	pager_init();

	#if 0
	fprintf (stderr, "%% %s\n", cmd);
	#endif

	completion_root=command_root;
	if (start > 0)
	{
		pos=0;
		while ((cmd[pos] == ' ') && (pos < start)) ++pos;	/* "    exemplo   arg1 arg2 " */
															/*      ^pos   ^rightedge     */
		while (pos < start)
		{
			rightedge=(strchr(cmd+pos, ' ') - cmd);
			if (rightedge < 0) rightedge=start;
			if ((rightedge >= 0) && (rightedge <= start))
			{
				/* command is now between pos and rightedge */
				memcpy(tmp, cmd+pos, rightedge-pos);
				tmp[rightedge-pos]=0;
				xcmd=expand_token(tmp, completion_root, -1);
				if (!xcmd)
				{
					int spaces;
					#if 1
					if (_cish_booting) fprintf (stderr, "%% %s\n", cmd);
					#endif
					if ((pos+strlen(prompt)) % 79)
					{
						printf(prompt);
						printf(cmd);
						printf("\n");
					}
					spaces=pos+strlen(prompt);
					for(i=0; i < spaces; i++) printf(" ");
					printf("^\n");
					printf("%% Invalid input detected at '^' marker.\n");
					return 0;
				}
				if (xcmd->children) completion_root=xcmd->children;
				strncat(realcmd, xcmd->name, 1023);
				realcmd[1023]=0;
				if ((rightedge+1) < start)
				{
					strncat(realcmd, " ", 1023); realcmd[1023]=0;
				}
				pos=rightedge+1;
			}
				else pos=start;
			while ((cmd[pos] == ' ') && (pos < start)) ++pos;
		}
	}
	if (xcmd)
	{
		if (xcmd->func)
		{
			#if 0
			printf("Execute line: %s\n", realcmd);
			#endif
			xcmd->func(realcmd);
		}
		else printf ("%% incomplete command\n");
	}
	else
	{
		printf ("%% command not found\n");
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

cish_command *expand_token (const char *unexpanded, cish_command *queue, int iteration)
{
	int idx_inqueue = 0;
	int latest_match = -1;
	int octets;
	int itcnt = 0;
	
	char tmp[1024];
	char *t;
	char *tt;
	
	while (queue[idx_inqueue].name)
	{
		if ((queue[idx_inqueue].privilege <= _cish_enable) && 
		    (completion_root[idx_inqueue].mask & _cish_mask) )
		{
			/* match */
			if ((isdigit(*queue[idx_inqueue].name)) && (strchr(queue[idx_inqueue].name, '-')))
			{
				strncpy (tmp, queue[idx_inqueue].name, 1023);
				t = strchr (tmp, '-');
				*t = 0;
				++t;
				if ((isdigit (*tmp)) && (isdigit (*unexpanded)) &&
					(atoi(unexpanded) >= atoi(tmp)) &&
					(atoi(unexpanded) <= atoi(t)) && !strchr(unexpanded, '-'))
				{
					if (iteration < 1)
					{
						strncpy (EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "-23 - 23") == 0)
			{
				if ((atoi(unexpanded) >= -23) && (atoi(unexpanded) <= 23))
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			
			}
			else if (strcmp (queue[idx_inqueue].name, "hh:mm:ss") == 0)
			{
				int d, m, a;
				strncpy (tmp, unexpanded, 1023);
				if (parse_time(tmp, &d, &m, &a)==0)
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if ((queue[idx_inqueue].name[0]!='<') &&
				(strncmp (queue[idx_inqueue].name, unexpanded, strlen(unexpanded)) == 0))
			{
				if (iteration<0)
				{
					// Caso especial: um comando que eh igual ao inicio de outro comando.
					// Ex.: 'ip' e 'ipx'.
					// Eh preciso incluir um teste a mais, pois do contrario se digitarmos
					// 'ip' sera considerado ambiguo.
					if (strncmp (queue[idx_inqueue].name, unexpanded, strlen(queue[idx_inqueue].name)) == 0)
						return &(queue[idx_inqueue]);
					
					if (latest_match >=0) return NULL;
					latest_match = idx_inqueue;
				}
				else
				{
					if (itcnt >= iteration) return &(queue[idx_inqueue]);
					++itcnt;
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<ipaddress>") == 0)
			{
#if 0
				strncpy(tmp, unexpanded, 1023);
				t=tmp;
				octets=0;
				while ((octets < 4) && (t != NULL))
				{
					tt=strchr(t, '.');
					if (tt != NULL) *tt=0;
					if (isdigit(*t) && (atoi(t) < 256))
					{
						if (tt != NULL) *tt = '.';
						octets++;
						t = tt != NULL ? tt+1 : tt;
					}
						else t=NULL;
				}
				if (octets == 4)
#else
				struct in_addr address;
				struct hostent* he;
				int address_ok;

				address_ok=0;
				if (inet_aton(unexpanded, &address) != 0)
				{
					if (strcmp(unexpanded, inet_ntoa(address)) == 0) address_ok=1;
				}
				else
				{
					if (((he=gethostbyname(unexpanded)) != NULL && he->h_addrtype == AF_INET))
					{
						memcpy(&address.s_addr, he->h_addr, he->h_length);
						address_ok=1;
					}
				}
				if (address_ok)
#endif
				{
					if (iteration < 1)
					{
#if 0
						strncpy(EXTCMD, unexpanded, 1023);
#else
						strncpy(EXTCMD, inet_ntoa(address), 1023);
#endif
						EXTCMD[1023]=0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<netmask>") == 0)
			{
				for (octets=0; octets < 33; ++octets)
				{
					if (strncmp (masks[octets], unexpanded, strlen(unexpanded)) == 0)
					{
						if (iteration<1)
						{
							strncpy (EXTCMD, masks[octets], 1023);
							EXTCMD[1023] = 0;
							CEXT.func = queue[idx_inqueue].func;
							CEXT.children = queue[idx_inqueue].children;
							return &CEXT;
						}
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<rnetmask>") == 0)
			{
				for (octets=0; octets < 33; ++octets)
				{
					if (strncmp (rmasks[octets],unexpanded,strlen(unexpanded)) == 0)
					{
						if (iteration<1)
						{
							strncpy (EXTCMD, rmasks[octets], 1023);
							EXTCMD[1023] = 0;
							CEXT.func = queue[idx_inqueue].func;
							CEXT.children = queue[idx_inqueue].children;
							return &CEXT;
						}
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<ipx network>") == 0)
			{
				int nibbles = 0;
				strncpy(tmp, unexpanded, 1023);
				t = tmp;
				while (*t)
				{
					if (isxdigit(*t)) 
					{
						nibbles++;
					}
					else 
					{
						if (!isspace(*t)) nibbles = 0; 
						break; 
					}
					t++;
				}
				if ((nibbles>0)&&(nibbles<=8))
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<ipx node>") == 0)
			{
				int nibbles = 0;
				strncpy (tmp, unexpanded, 1023);
				t = tmp;
				while (*t)
				{
					if (isxdigit(*t)) 
					{
						nibbles++;
					}
					else 
					{
						if (!isspace(*t)) nibbles = 0; 
						break; 
					}
					t++;
				}
				if ((nibbles>0)&&(nibbles<=12))
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<x121>") == 0) {
				int nibbles=0, n;
				strncpy (tmp, unexpanded, 255);
				t = tmp;
				if ((tt = strchr(tmp, '/')) != NULL) {
					*tt = '\0';
					n = atoi(tt + 1);
				} else {
					n = strlen(tmp);
				}
				while (*t)
				{
					if (isdigit(*t))
					{
						nibbles++;
					}
					else
					{
						nibbles=0;
						break;
					}
					t++;
				}
				if ((nibbles>0)&&(nibbles<=15)&&(nibbles<=n))
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 1023);
						EXTCMD[1023] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp(queue[idx_inqueue].name, "<cudhexstring>") == 0) {
				int len;

				if ((len=strlen(unexpanded))) {
					int i;

					for (i=0; unexpanded[i]; i++) {
						if (!isxdigit(unexpanded[i]))
							break;
					}
					if (i == len && len <= 32 && iteration < 1) {
						strncpy(EXTCMD, unexpanded, 32);
						EXTCMD[32]=0;
						CEXT.func=queue[idx_inqueue].func;
						CEXT.children=queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			} else if (strcmp (queue[idx_inqueue].name, "<bandwidth>") == 0)
			{
				int i, factor=0, per=0;
				char *endptr;

				i=strtol(unexpanded, &endptr, 10);
				if (endptr==NULL) factor=0;
				else
				{
					if (strcasecmp(endptr,"bps")==0) factor=1;
					else if (strcasecmp(endptr,"kbps")==0) factor=1024;
					else if (strcasecmp(endptr,"mbps")==0) factor=1048576;
					else if (strcasecmp(endptr,"%")==0) { factor=1; per=1; }
				}
				if (factor && (i*factor >= (per ? 1 : 1000)) && (i*factor <= (per ? 100 : 5056000)))
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<burst>") == 0)
			{
				int i, factor=0;
				char *endptr;

				i=strtol(unexpanded, &endptr, 10);
				if (endptr==NULL) factor=0;
				else
				{
					if (strcasecmp(endptr,"bytes")==0) factor=1;
					else if (strcasecmp(endptr,"kbytes")==0) factor=1024;
				}
				if (factor && (i*factor >= 1500) && (i*factor <= 65536))
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<port>") == 0)
			{
				int port=0;
				struct servent *service_entry;

				service_entry=getservbyname(unexpanded, NULL); /* search in /etc/services */
				if (service_entry == NULL && isdigit(*unexpanded)) port=atoi(unexpanded);
				if (service_entry || (port >= 1 && port <= 65535))
				{
					if (iteration<1)
					{
						strncpy (EXTCMD, unexpanded, 255);
						EXTCMD[255] = 0;
						CEXT.func = queue[idx_inqueue].func;
						CEXT.children = queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<ports>") == 0)
			{
				char *p, *local;
				int ok=1, comm=0;

				if( (local = malloc( strlen(unexpanded) + 1 )) )
				{
					strcpy(local, unexpanded);
					for( p=local; *p; p++ )
					{
						if( isdigit(*p) == 0 )
						{
							if( *p == ',' )
							{
								comm++;
								*p = ' ';
							}
							else
							{
								ok = 0;
								break;
							}
						}
					}
					if( ok && comm<=7 )
					{
						int i, n;
						arg_list argl=NULL;

						if( (n = parse_args_din(local, &argl)) > 0 )
						{
							free(local);
							local = NULL;
							if( comm == (n-1) )
							{
								for( i=0; i<n && ok; i++ )
								{
									int port=0;
									struct servent *service_entry;

									service_entry=getservbyname(argl[i], NULL); /* search in /etc/services */
									if (service_entry == NULL && isdigit(*argl[i]))
										port=atoi(argl[i]);
									if (service_entry || (port >= 1 && port <= 65535))
										ok = 1;
									else
										ok = 0;
								}
								free_args_din(&argl);
								if( ok )
								{
									if (iteration<1)
									{
										strncpy (EXTCMD, unexpanded, 255);
										EXTCMD[255] = 0;
										CEXT.func = queue[idx_inqueue].func;
										CEXT.children = queue[idx_inqueue].children;
										return &CEXT;
									}
								}
							}
						}
					}
					if(local)
						free(local);
				}
			}
			else if (strcmp (queue[idx_inqueue].name, "<acl>") == 0)
			{
				if (strlen(unexpanded)&&(strchr(unexpanded,'\"')==0)&&
					(strcmp(unexpanded, "icmp")!=0)&&(strcmp(unexpanded, "tcp")!=0)&&(strcmp(unexpanded, "udp")!=0)&&(strcmp(unexpanded, "mac")!=0)&&
					(strcmp(unexpanded, "ACCEPT")!=0)&&(strcmp(unexpanded, "DROP")!=0)&&(strcmp(unexpanded, "REJECT")!=0)&&(strcmp(unexpanded, "LOG")!=0)&&
					(strcmp(unexpanded, "SNAT")!=0)&&(strcmp(unexpanded, "DNAT")!=0)&&(strcmp(unexpanded, "MASQUERADE")!=0)&&
					(strcmp(unexpanded, "DSCP")!=0)&&(strcmp(unexpanded, "MARK")!=0)&&(strcasecmp(unexpanded, "TCPMSS")!=0))
				{
					if (iteration < 1)
					{
						strncpy(EXTCMD, unexpanded, 255);
						EXTCMD[255]=0;
						CEXT.func=queue[idx_inqueue].func;
						CEXT.children=queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp(queue[idx_inqueue].name, "<flags>") == 0)
			{
				int flags_ok;

				flags_ok=0;
				if (strlen(unexpanded))
				{
					strncpy(tmp, unexpanded, 1023);
					if ((tt=strchr(tmp, '/')) != NULL)
					{
						t=strtok(tmp, ",/");
						while (t != NULL)
						{
							if (strcmp(t, "FIN") && strcmp(t, "SYN") && strcmp(t, "RST") && strcmp(t, "PSH") && 
								strcmp(t, "ACK") && strcmp(t, "URG") && strcmp(t, "ALL")) { flags_ok=0; break; }
							if (t < tt) flags_ok |= 0x01; else flags_ok |= 0x02;
							t=strtok(NULL, ",/");
						}
						if (flags_ok == 0x03)
						{
							if (iteration < 1)
							{
								strncpy(EXTCMD, unexpanded, 255);
								EXTCMD[255]=0;
								CEXT.func=queue[idx_inqueue].func;
								CEXT.children=queue[idx_inqueue].children;
								return &CEXT;
							}
						}
					}
				}
			}
			else if (strcmp(queue[idx_inqueue].name, "<url>") == 0) /* http://user:pass@www.pd3.com.br/filename */
			{
				if (strlen(unexpanded))
				{
					strncpy(tmp, unexpanded, 1023);
					t=NULL;
					if (!strncmp(tmp, "http://", 7)) t=tmp+7;
					if (!strncmp(tmp, "ftp://", 6)) t=tmp+6;
					if (t != NULL)
					{
						if (iteration < 1)
						{
							strncpy(EXTCMD, unexpanded, 255);
							EXTCMD[255]=0;
							CEXT.func=queue[idx_inqueue].func;
							CEXT.children=queue[idx_inqueue].children;
							return &CEXT;
						}
					}
				}
			}
			else if (strcmp(queue[idx_inqueue].name, "<string>") == 0)
			{
				if (strlen(unexpanded))
				{
					if (iteration < 1)
					{
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023]=0;
						CEXT.func=queue[idx_inqueue].func;
						CEXT.children=queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp(queue[idx_inqueue].name, "<text>") == 0)
			{
				if (strlen(unexpanded) && (strchr(unexpanded,'\"') == 0))
				{
					if (iteration < 1)
					{
						strncpy(EXTCMD, unexpanded, 1023);
						EXTCMD[1023]=0;
						CEXT.func=queue[idx_inqueue].func;
						CEXT.children=queue[idx_inqueue].children;
						return &CEXT;
					}
				}
			}
			else if (strcmp(queue[idx_inqueue].name, "<mac>") == 0)
			{
				if (strlen(unexpanded))
				{
					arg_list argl=NULL;
					if(parse_args_din((char *) unexpanded, &argl) > 0)
					{
						if(strlen(argl[0]) == 17)
						{
							int i=0;
							char *p=argl[0];
							for(; i < 6; i++,p+=3)
							{
								if(isxdigit(*p) == 0)		break;
								if(isxdigit(*(p+1)) == 0)	break;
								if(i < 5)
								{
									if(*(p+2) != ':')	break;
								}
							}
							if(i == 6)
							{
								free_args_din(&argl);
								if(iteration < 1)
								{
									strncpy(EXTCMD, unexpanded, 1023);
									EXTCMD[1023]=0;
									CEXT.func=queue[idx_inqueue].func;
									CEXT.children=queue[idx_inqueue].children;
									return &CEXT;
								}
							}
						}
						free_args_din(&argl);
					}
				}
			}
		}
		++idx_inqueue;
	}
	if (latest_match>=0) return &(queue[latest_match]);
	return NULL;
}

void term_length (const char *cmd)
{
	arglist *args;
	
	args = make_args (cmd);
	
	terminal_lines = cish_cfg->terminal_lines = atoi (args->argv[2]);
	
	destroy_args (args);
}

void term_timeout (const char *cmd)
{
	arglist *args;
	
	args = make_args (cmd);
	
	cish_timeout = cish_cfg->terminal_timeout = atoi (args->argv[2]);
	
	destroy_args (args);
}

void config_clock(const char *cmd) /* clock set [hh:mm:ss] dia mes ano */
{
	arglist *args;
	int day, mon, year, hour, min, sec;
	time_t tm;
	struct tm tm_time;

	if( is_daemon_running(NTP_DAEMON) ) {
		printf("NTP service is running. Stop this service first.\n");
		return;
	}
	args=make_args(cmd);
	if ((args->argc < 3) ||
		(parse_time(args->argv[2], &hour, &min, &sec) < 0)) {
		destroy_args(args);
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
	set_date(day, mon, year, hour, min, sec); /* !!! Test result! */
	destroy_args(args);
}

void config_clock_timezone (const char *cmd)
{
	arglist *args;
	char *name;
	int hours, mins;
	
	args = make_args (cmd);
	name = args->argv[2];
	hours = atoi(args->argv[3]);
	if (args->argc>4)
		mins = atoi(args->argv[4]);
	else
		mins = 0;
		
	set_timezone(name, hours, mins);	
	destroy_args (args);
}

void dump_terminal (FILE *O)
{
	pfprintf(O, "terminal length %d\n", cish_cfg->terminal_lines);
	pfprintf(O, "terminal timeout %d\n", cish_cfg->terminal_timeout);
	pfprintf(O, "!\n");
}

void hostname (const char *cmd)
{
	arglist *args;
	
	args = make_args (cmd);
	sethostname(args->argv[1], strlen(args->argv[1]));
	destroy_args (args);
}

void help (const char *cmd)
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

#if 0

void reload(const char *cmd)
{
	int in;
	struct termios initial_settings, new_settings;

	cish_timeout=cish_cfg->terminal_timeout;
	/* Question for saving configuration? */
	printf("Proceed with reload? [confirm]");
	fflush(stdout);
	tcgetattr(0, &initial_settings);
	new_settings = initial_settings;
	new_settings.c_lflag &= ~ICANON;
	new_settings.c_cc[VMIN] = 0;
	new_settings.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &new_settings);
	while(fgetc(stdin) != EOF);
	tcsetattr(0, TCSANOW, &initial_settings);
	in=fgetc(stdin);
	cish_timeout=0;
	printf("\n");
	if ((in=='y')||(in=='Y')||(in=='\n')) {
#if 0 /* Quando invocado por telnet esta derrubando o shell remoto e o reboot nao ocorre! */
		system("/bin/clean");
#endif
		reboot(0x01234567);
	}
}

#else

void reload(const char *cmd)
{
	int in;
	struct termios initial_settings, new_settings;

#if defined(CONFIG_BERLIN_SATROUTER) && defined(CONFIG_DMVIEW_MGNT)
	if( dmview_management )
		reboot(0x01234567);
#endif
	cish_timeout=cish_cfg->terminal_timeout;
	fflush(stdout);
	/* Flushes stdin */
	new_settings.c_cc[VMIN] = 0;	/* Minimum number of bytes is stdin to allow a read() */
	new_settings.c_cc[VTIME] = 0;	/* Maximum time to wait for input in a read() */
	tcgetattr(0, &initial_settings);
	new_settings = initial_settings;
	new_settings.c_lflag &= ~ICANON;
	new_settings.c_cc[VMIN] = 0;
	new_settings.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &new_settings);
	while(fgetc(stdin) != EOF);		/* Empty stdin */
	tcsetattr(0, TCSANOW, &initial_settings);

	/* Check if configuration has changed and should be saved */
	cish_config_changed();
	
	/* Question for saving configuration? */
	printf("Proceed with reload? [confirm]");
	
	/* Wait for input in non-canonical mode */
	canon_off();
	in=fgetc(stdin);
	canon_on();
	cish_timeout=0;
	printf("\n");
	if ((in=='y')||(in=='Y')||(in=='\n')) {
#if 0 /* Quando invocado por telnet esta derrubando o shell remoto e o reboot nao ocorre! */
		system("/bin/clean");
#endif
		reboot(0x01234567);
	}
}

#endif

void reload_cancel(const char *cmd)
{
	if (cish_reload)
	{
		cish_reload=0; /* disable timeout! */
		printf("Reload aborted!\n");
	}
}

void reload_in(const char *cmd) /* reload in [1-60] */
{
	arglist *args;
	int timeout, in;
	struct termios initial_settings, new_settings;

	args=make_args(cmd);
	timeout=atoi(args->argv[2]);
	cish_timeout=cish_cfg->terminal_timeout;
	printf("Reload scheduled in %d minutes\n", timeout);
	printf("Proceed with reload? [confirm]");
	fflush(stdout);
	tcgetattr(0, &initial_settings);
	new_settings = initial_settings;
	new_settings.c_lflag &= ~ICANON;
	new_settings.c_cc[VMIN] = 0;
	new_settings.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &new_settings);
	while(fgetc(stdin) != EOF);
	tcsetattr(0, TCSANOW, &initial_settings);
	in=fgetc(stdin);
	cish_timeout=0;
	printf("\n");
	if ((in=='y')||(in=='Y')||(in=='\n')) {
		cish_reload=timeout*60;
	}
	destroy_args(args);
}

void show_reload(const char *cmd)
{
	if (cish_reload)
	{
		printf("Reload scheduled in %d minutes and %d seconds\n", cish_reload/60, cish_reload%60);
	}
	else
	{
		printf("No reload is scheduled.\n");
	}
}

void stop_syslogd(void)
{
	FILE *f;
	char buf[128];
	arg_list argl = NULL;

	if( (f = fopen(FILE_SYSLOGD_PID, "r")) != NULL ) {
		if( fgets(buf, 127, f) != NULL ) {
			buf[127] = 0;
			if( parse_args_din(buf, &argl) > 0 )
				kill(atoi(argl[0]), SIGTERM);
			free_args_din(&argl);
		}
		fclose(f);
	}
}

void log_remote(const char *cmd) /* logging remote <address> */
{
	arglist *args;
	char buf[16], option[24];

	kill_daemon(PROG_SYSLOGD);
	stop_syslogd();
	args = make_args(cmd);
	if( init_program_get_option_value(PROG_SYSLOGD, "-R", buf, 16) >= 0 ) {
		if( strcmp(buf, args->argv[2]) == 0 ) {
			destroy_args(args);
			return;
		}
		sprintf(option, "-L -R %s", buf);
		init_program_change_option(0, PROG_SYSLOGD, option);
	}
	sprintf(option, "-L -R %s", args->argv[2]);
	init_program_change_option(1, PROG_SYSLOGD, option);
	destroy_args(args);
	exec_daemon(PROG_SYSLOGD);
}

void no_log_remote(const char *cmd)
{
	char buf[16], option[24];

	if( init_program_get_option_value(PROG_SYSLOGD, "-R", buf, 16) >= 0 ) {
		kill_daemon(PROG_SYSLOGD);
		stop_syslogd();
		sprintf(option, "-L -R %s", buf);
		init_program_change_option(0, PROG_SYSLOGD, option);
		exec_daemon(PROG_SYSLOGD);
	}
}

void dump_log(FILE *out, int cform)
{
	char buf[16];

	if( init_program_get_option_value(PROG_SYSLOGD, "-R", buf, 16) >= 0 )
		pfprintf(out, "logging remote %s\n!\n", buf);
}

int ctrlz (int count, int KEY)
{
//	printf("Ctrl+Z pressionado\n");
	return 0;
}

void firmware_download(const char *cmd) /* firmware download <url> */
{
	arglist *args;

	args=make_args(cmd);

	exec_prog(0, "/bin/wget", "-P", "/mnt/image", args->argv[2], NULL);
	destroy_args(args);
}

void firmware_save(const char *cmd)
{
	write_image(1);
}

void firmware_upload(const char *cmd)
{
	/* Enable upload service */
	if( set_inetd_program(1, FTP_DAEMON) < 0 ) {
		printf("%% Not possible to enable FTP server\n");
		return;
	}
}

void no_firmware_upload(const char *cmd)
{
	/* Disable upload service */
	if( set_inetd_program(0, FTP_DAEMON) < 0 ) {
		printf("%% Not possible to disable FTP server\n");
		return;
	}
}

#ifdef I2C_HC08_ID_ADDR
int test_expert_passwd(char *passwd)
{
	char *id;

	if ((id=get_system_ID(0)) == NULL) return 0;
	if (!strcmp(passwd, hash_str((unsigned char *)id, 0xff))) return 1;
	return 0;
}
#endif

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

	if( get_ipsec() ) { /* Wait pluto start! */
		output = popen("/lib/ipsec/whack --status", "r");
		if( !output ) {
			printf("%% Not possible to clear counters\n");
			return;
		}

		/* Search for string containing the pair ipsec interface + real interface */
		for( count=0; (count < MAX_CONN) && fgets(line, 1024, output); ) {
			if( (n = parse_args_din(line, &argl)) > 3 ) {
				if( (strcmp(argl[1], "interface") == 0) && (strncmp(argl[2], "ipsec", strlen("ipsec")) == 0) ) {
					if( (p = strchr(argl[2], '/')) )
						*p = 0;
					strncpy(entry[count].ipsec_intf, argl[2], 31);
					entry[count].ipsec_intf[31] = 0;
					strncpy(entry[count].local_addr, argl[3], 31);
					entry[count].local_addr[31] = 0;
					count++;
				}
			}
			free_args_din(&argl);
		}
		pclose(output);
		if( count == 0 )
			return;

		output = popen("/lib/ipsec/whack --status", "r");
		if( !output ) {
			printf("%% Not possible to clear counters\n");
			return;
		}

		/* The connection name will appear with inverted comas */
		sprintf(name_buf, "\"%s\"", conn_name);
		
		/* Find the right connection */
		for( found=0; (found == 0) && fgets(line, 1024, output); ) {
			if( parse_args_din(line, &argl) > 3 ) {
				if( (strstr(argl[1], name_buf) != NULL) && ((p = strstr(argl[2], "===")) != NULL) ) {

					p = p + 3; /* Start of IP address */
					t = strstr(p,"[");
					*t = '\0'; /* p now contais an IP address */

					if( inet_aton(p, &addr) != 0 ) {
						/* Find the right ipsec interface */
						for( i=0; i < count; i++ ) {
							if( strcmp(entry[i].local_addr, p) == 0 ) {
								if( dev_exists(entry[i].ipsec_intf) )
									clear_interface_counters(entry[i].ipsec_intf);
								found = 1;
							}
						}
					}
				}
			}
			free_args_din(&argl);
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
	device_family *if_edited;
	int if_major;
	int if_minor;

	args=make_args(cmdline); /* clear counters [interface] [major.minor] */
#ifdef OPTION_IPSEC
	if( strcmp(args->argv[2], "crypto") == 0 ) {
		int i;
		char **list=NULL, **list_ini=NULL;

		if( list_all_ipsec_names(&list_ini) < 1 ) {
			printf("%% Not possible to clear counters\n");
			destroy_args(args);
			return;
		}
		for( i=0, list=list_ini; i < MAX_CONN; i++, list++ ) {
			if( *list ) {
				if( args->argc > 3 ) {
					if( strcmp(*list, args->argv[3]) == 0 )
						clear_ipsec_counters(*list);
				}
				else
					clear_ipsec_counters(*list);
				free(*list);
			}
		}
		free(list_ini);
		destroy_args(args);
		return;
	}
#endif
	strncpy(device, args->argv[2], 31); device[31]=0;
	strncpy(sub, args->argv[3], 15); sub[15]=0;
	if ((if_edited=getfamily(device)))
	{
		major=sub;
		minor=strchr(major, '.');
		if (minor) *minor++ = 0;
		if_major=atoi(major);
		if (minor) if_minor=atoi(minor);
			else if_minor=-1;
		if (strcasecmp(if_edited->cish_string, "serial") == 0)
		{
			switch(wan_get_protocol(if_major))
			{
				case IF_PROTO_FR:
					if (minor && !fr_dlci_exists(if_major, if_minor))
					{
						fprintf(stderr, "%% Invalid interface number.\n");
						destroy_args(args);
						return;
					}
					break;
#ifdef OPTION_X25
				case IF_PROTO_X25:
					if (minor && !x25_svc_exists(if_major, if_minor))
					{
						fprintf(stderr, "%% Invalid interface number.\n");
						destroy_args(args);
						return;
					}
					break;
#endif
				case SCC_PROTO_MLPPP:
					sprintf(device, "%s%d", SERIALDEV_PPP, if_major); /* 'sx0' */
					clear=clear_interface_counters(device); /* clear scc_hdlc.c sx0 interface! */
					break;
			}
		}
		interface=convert_device(if_edited->cish_string, if_major, if_minor);
		if (dev_exists(interface)) {
			clear=clear_interface_counters(interface);
		} else {
			printf("%% Inactive interface %s %s\n", device, sub);
		}
		free(interface);
	}
	else
	{
		fprintf(stderr, "%% Unknown device type.\n");
	}
	destroy_args(args);
}

#ifdef CONFIG_IPHC
void clear_iphc(const char *cmdline) /* clear ip header-compression [interface] [major.minor] */
{
	arglist *args;
	long protocol;
	int if_major, if_minor;
	device_family *if_edited;
	char *major, *minor, *interface, sub[16], device[32];

	args = make_args(cmdline);
	strncpy(device, args->argv[3], 31);
	device[31] = 0;
	strncpy(sub, args->argv[4], 15);
	sub[15] = 0;
	if( (if_edited = getfamily(device)) ) {
		major = sub;
		minor = strchr(major, '.');
		if( minor )
			*minor++ = 0;
		if_major = atoi(major);
		if( minor )
			if_minor = atoi(minor);
		else
			if_minor = -1;
		if( strcasecmp(if_edited->cish_string, "serial") == 0 ) {
			protocol = wan_get_protocol(if_major);
			switch( protocol ) {
				case IF_PROTO_FR:
					if( minor == NULL ) { /* Se nao for subinterface, retorna imediatamente */
						destroy_args(args);
						return;
					}
					if( fr_dlci_exists(if_major, if_minor) == 0 ) {
						fprintf(stderr, "%% Invalid interface number.\n");
						destroy_args(args);
						return;
					}
					break;
				default:
					break;
			}
			interface = convert_device(if_edited->cish_string, if_major, if_minor);
			if( dev_exists(interface) ) {
				switch( protocol ) {
#ifdef CONFIG_FR_IPHC
					case IF_PROTO_FR:
						fr_pvc_clear_iphc_counters(interface);
						break;
#endif
#ifdef CONFIG_SPPP_IPHC
					case IF_PROTO_PPP:
						sppp_clear_iphc_counters(interface);
						break;
#endif
				}
			}
			else
				printf("%% Inactive interface %s %s\n", device, sub);
			free(interface);
		}
	}
	else
		fprintf(stderr, "%% Unknown device type.\n");
	destroy_args(args);
}
#endif

