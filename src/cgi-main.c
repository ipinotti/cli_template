#include <stdio.h>
#include <unistd.h>

#include <libconfig/cgi-lib.h>
#include <libconfig/html-lib.h>
#include <libconfig/args.h>

#include "cgi-main.h"
#include "commandtree.h"
#include "commands.h"
#include "cish_main.h"
#include "options.h"

/* need to declare a pointer variable of type LIST to keep track of our list */
LIST *head;
extern cish_command CMD_CONFIGURE[];
extern cish_command CMD_KEYCHAIN[];
extern cish_command CMD_KEY[];
extern cish_command CMD_CONFIG_ROUTER[];
extern cish_command CMD_CONFIG_INTERFACE[];
extern cish_command CMD_CONFIG_CRYPTO[];
extern cish_command CMD_IPSEC_CONNECTION_CHILDREN[];

void cmdline2url(char *cmdline, char *url)
{
	char *p;

	p=cmdline;
	while (*p==' ') p++;
	strcpy(url, "/");
	strcat(url, p);
	p=url;
	while (*p)
	{
		if (*p==' ') *p='/';
		p++;
	}
}

int url2cmdline(char *cmdline, char *url)
{
	char *p;
	int len, cr=0;

	if (url == NULL)
	{
		*cmdline=0;
		return 0;
	}
	p=url;
	while (*p=='/') p++;
	strcpy(cmdline, p);
	len = strlen(cmdline);
	if ((len>3)&&(strcasecmp(cmdline+len-3, "/cr")==0)) 
	{
		cmdline[len-3]=0;
		len -= 3;
		cr=1;
	}
	if ((len>4)&&(strcasecmp(cmdline+len-4, "/arg")==0))
	{
		cmdline[len-4] = ' ';
		strcpy(cmdline+len-3, find_val(head, "arg"));
		len = strlen(cmdline);
	}
	p=cmdline;
	while (*p)
	{
		if (*p=='/') *p=' ';
		p++;
	}
	return cr;
}

void cgi_main(char *progname)
{
	char hostname[256];
	char cmd_line[512], url[512], *p;
	char base_url[128];
	int cr=0, text_box=0;

	gethostname(hostname, 256);
	hostname[255]=0;

	/* need to call this function at the beginning to initiate and setup out list */
	head = cgi_input_parse();

	url[0]=0;
	if (PATH_INFO)
	{
		strncpy(url, PATH_INFO, 500);
		url[499]=0;
	}

	// verifica se um comando foi digitado no text box
	p = find_val(head, "base_url");
	if (p)
	{
		// ex.: comando digitado no text box: "show arp"
		//      p = "show arp"
		strncpy(base_url, p, 128);
		base_url[127]=0;
		p = find_val(head, "command");
		if (!p) return;
		strncpy(cmd_line, p, 512);
		cmd_line[511]=0;
		text_box=1;
	}

	// verifica se a url eh do tipo "/interface/ethernet/0/..."
	if (command_root == CMD_CONFIG_INTERFACE) // progname = 'interface'
	{
		// ex.: url = "/ethernet/0/ip/addr/10.0.0.1/255.0.0.0"
		//      p = "ethernet 0"
		//      p2 = "ip/addr/10.0.0.1/225.0.0.0"
		//      cmd_line = "ip addr 10.0.0.1 255.0.0.0"
		//      cmd = "interface ethernet 0"
		//      base_url = "/ethernet/0"
		char *p, *p2;
		char cmd[128];
		char tmp[512];

		strcpy(tmp, url);
		p=tmp;
		while (*p=='/') p++;
		p2=strchr(p, '/');
		if (!p2) return;
		*p2++ = ' ';
		p2=strchr(p2, '/');
		if (p2)
		{
			*p2++ = 0;
			if (!text_box) cr = url2cmdline(cmd_line, p2);
		}
		else
		{
			cr=0;
			if (!text_box) *cmd_line = 0;
		}
		snprintf(cmd, 128, "interface %s", p);
		cmd[127]=0;
		config_interface(cmd);
		cmdline2url(p, cmd);
		if (!text_box) snprintf(base_url, 128, "/interface%s", cmd);
	}
	else if (command_root == CMD_KEYCHAIN) // progname = 'keychain'
	{
		// ex.: url = "/temp/key"
		char *p, *p2;
		char cmd[128];
		char tmp[512];

		strcpy(tmp, url);
		p=tmp;
		while (*p=='/') p++;
		p2=strchr(p, '/');
		if (p2)
		{
			*p2++ = 0;
			if (!text_box) cr = url2cmdline(cmd_line, p2);
		}
		else
		{
			cr=0;
			if (!text_box) *cmd_line = 0;
		}
		snprintf(cmd, 128, "key chain %s", p);
		cmd[127]=0;
		config_keychain(cmd);
		cmdline2url(p, cmd);
		if (!text_box) snprintf(base_url, 128, "/keychain%s", cmd);
	}
	else if (command_root == CMD_KEY) // progname = 'key'
	{
		char *p, *p2, *p3;
		char cmd[128];
		char tmp[512];

//		syslog(LOG_NOTICE, "CMD_KEY: %s", url);
		strcpy(tmp, url);
		p=tmp;
		while (*p=='/') p++;
		p2=strchr(p, '/');
		if (p2)
		{
			*p2++ = 0;
			p3=strchr(p2, '/');
			if (p3)
			{
				*p3++ = 0;
				if (!text_box) cr = url2cmdline(cmd_line, p3);
			}
			else
			{
				cr = 0;
				if (!text_box) *cmd_line = 0;
			}
		}
		snprintf(cmd, 128, "key chain %s", p);
		cmd[127]=0;
		config_keychain(cmd);
		snprintf(cmd, 128, "key %s", p2);
		cmd[127]=0;
		config_key(cmd);
		if (!text_box) snprintf(base_url, 128, "/key/%s/%s", p, p2);
	}
	else if (command_root == CMD_CONFIG_ROUTER) // progname = 'router'
	{
		// ex.: url = "/rip/network"
		//      p = "rip network"
		//      p2 = "network/?/?"
		//      cmd_line = "network ? ?"
		//      cmd = "router rip network"
		//      base_url = "/rip/network"
		char *p, *p2;
		char cmd[128];
		char tmp[512];

		strcpy(tmp, url);
		p=tmp;
		while (*p=='/') p++;
		p2=strchr(p, '/');
		if (p2)
		{
			*p2++ = 0;
			if (!text_box) cr=url2cmdline(cmd_line, p2);
		}
		else
		{
			cr=0;
			if (!text_box) *cmd_line=0;
		}
		snprintf(cmd, 128, "router %s", p);
		cmd[127]=0;
		config_router(cmd);
		cmdline2url(p, cmd);
		if (!text_box) snprintf(base_url, 128, "/router%s", cmd);
	}
#ifdef OPTION_IPSEC
	else if (command_root == CMD_CONFIG_CRYPTO) // progname = 'crypto'
	{
		cd_crypto_dir(NULL);
		if (!text_box)
		{
			cr = url2cmdline(cmd_line, url);
			sprintf(base_url, "/crypto");
		}
	}
	else if (command_root == CMD_IPSEC_CONNECTION_CHILDREN) // progname = 'ipsec'
	{
		char *p, *p2;
		char cmd[128];
		char tmp[512];

		strcpy(tmp, url);
		p=tmp;
		while (*p=='/') p++;
		p2=strchr(p, '/');
		if (p2)
		{
			*p2++ = ' ';
			p2=strchr(p2, '/');
			if (p2)
			{
				*p2++ = 0;
				if (!text_box) cr=url2cmdline(cmd_line, p2);
			}
		}
		if (!p2)
		{
			cr=0;
			if (!text_box) *cmd_line=0;
		}
		snprintf(cmd, 128, "ipsec %s", p);
		cd_connection_dir(cmd);
		cmdline2url(p, cmd);
		if (!text_box) snprintf(base_url, 128, "/ipsec%s", cmd);
	}
#endif
	else // ultimo caso: a url eh do tipo "/exec/..." (command_root=CMD)
	     // ou do tipo "/config/..." (command_root=CMD_CONFIGURE)
	{
		// ex.: url = "/show/arp"
		//      cmd_line = "show arp"
		if (!text_box) 
		{
			cr = url2cmdline(cmd_line, url);
			snprintf(base_url, 128, "/%s", progname);
		}
	}
	
	strcat(cmd_line, " ");
	
	// caso particular: se temos uma url do tipo "/config/interface/..."
	// temos que redirecionar para uma url do tipo "/interface/..."
	if ((command_root==CMD_CONFIGURE)&&(strncmp(cmd_line, "interface", 9)==0))
	{
		arglist *args;

		args=make_args(cmd_line);
		if (args->argc == 3)
		{
			cish_execute(cmd_line);
			mime_header("text/html");
			printf("<html><head><meta http-equiv=\"refresh\" content=\"0; url=/%s/%s/%s\"></head></html>\n",
				args->argv[0], args->argv[1], args->argv[2]);
			destroy_args(args);
			return;
		}
		destroy_args(args);
	}
	// caso particular: se temos uma url do tipo "/config/key/chain/<keychain_name>"
	// temos que redirecionar para uma url do tipo "/keychain/<keychain_name>"
	if ((command_root==CMD_CONFIGURE)&&(strncmp(cmd_line, "key chain", 9)==0))
	{
		arglist *args;

		args=make_args(cmd_line);
		if (args->argc == 3)
		{
			cish_execute(cmd_line);
			mime_header("text/html");
			printf("<html><head><meta http-equiv=\"refresh\" content=\"0; url=/%s%s/%s\"></head></html>\n",
				args->argv[0], args->argv[1], args->argv[2]);
			destroy_args(args);
			return;
		}
		destroy_args(args);
	}
	// caso particular: se temos uma url do tipo "/keychain/<keychain_name>/key/<key_num>"
	// temos que redirecionar para uma url do tipo "/key/<keychain_name>/<key_num>"
	if ((command_root==CMD_KEYCHAIN)&&(strncmp(cmd_line, "key", 3)==0))
	{
		arglist *args;

		args=make_args(cmd_line);
		if (args->argc == 2)
		{
			char *p, *p2;
			char tmp[512];

			strcpy(tmp, url);
			p=tmp;
			while (*p=='/') p++;
			p2=strchr(p, '/');
			if (p2)
			{
				*p2++ = 0;
			}
			cish_execute(cmd_line);
			mime_header("text/html");
			printf("<html><head><meta http-equiv=\"refresh\" content=\"0; url=/%s/%s/%s\"></head></html>\n",
				args->argv[0], p, args->argv[1]);
			destroy_args(args);
			return;
		}
		destroy_args(args);
	}
	// caso particular: se temos uma url do tipo "/config/router/..."
	// temos que redirecionar para uma url do tipo "/router/..."
	if ((command_root==CMD_CONFIGURE)&&(strncmp(cmd_line, "router", 6)==0))
	{
		arglist *args;

		args=make_args(cmd_line);
		if (args->argc == 2)
		{
			cish_execute(cmd_line);
			mime_header("text/html");
			printf("<html><head><meta http-equiv=\"refresh\" content=\"0; url=/%s/%s\"></head></html>\n",
				args->argv[0], args->argv[1]);
			destroy_args(args);
			return;
		}
		destroy_args(args);
	}
#ifdef OPTION_IPSEC
	// caso particular: se temos uma url do tipo "/config/crypto/..."
	// temos que redirecionar para uma url do tipo "/crypto/..."
	if ((command_root==CMD_CONFIGURE)&&(strncmp(cmd_line, "crypto", 6) == 0))
	{
		arglist *args;

		args=make_args(cmd_line); /* crypto */
		if (args->argc == 1)
		{
			cish_execute(cmd_line);
			mime_header("text/html");
			printf("<html><head><meta http-equiv=\"refresh\" content=\"0; url=/%s\"></head></html>\n",
				args->argv[0]);
			destroy_args(args);
			return;
		}
		destroy_args(args);
	}
	if ((command_root==CMD_CONFIG_CRYPTO)&&(strncmp(cmd_line, "ipsec", 5) == 0))
	{
		arglist *args;

		args=make_args(cmd_line);
		if (args->argc == 3 && strcmp(args->argv[2], "add")) /* ipsec/connection/[conname] */
		{
			cish_execute(cmd_line);
			mime_header("text/html");
			printf("<html><head><meta http-equiv=\"refresh\" content=\"0; url=/%s/%s/%s\"></head></html>\n",
				args->argv[0], args->argv[1], args->argv[2]);
			destroy_args(args);
			return;
		}
		destroy_args(args);
	}
#endif

	// E, finalmente, vamos montar a pagina
	
	/* send the mime header to the server using our function in html-lib */
	mime_header("text/html");

	/* send the top of our html page to the server */
	html_begin(hostname, "bgcolor=#ffffff");

	/* send the text enclosed in the heading tags */
	h1(hostname);
	
	printf("<hr><pre>\n");

	// text box
	printf("<form method=post action=\"/%s%s\">\n", progname, url);
	printf("Command <input type=text name=command size=60 value=\"\">\n");
	printf("<input type=hidden name=base_url value=\"%s\"></form>\n", base_url);
	
	printf("<br><hr>\n");
	
	printf("%s\n\n", cmd_line);
	
	fflush(stdout);
	
	if (text_box||cr||cish_completion_http(cmd_line, base_url))
	{
		fflush(stdout);
		cish_execute(cmd_line);
	}
	
	printf("<br><hr>\n");
	printf("command completed<hr></pre>\n");

	/* send the html closing tags */
	html_end();

	return;
}

