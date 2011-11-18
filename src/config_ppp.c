
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "commands.h"
#include "commandtree.h"
#include "pprintf.h"
#include <librouter/options.h>

#ifdef OPTION_PPP
void ppp_shutdown(const char *cmd)
{
	int i;
	char *dev;
	ppp_config cfg;
	char master[IFNAMSIZ];


	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.up) {
		cfg.up = 0;
		dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
		                interface_minor);
#ifdef OPTION_QOS
		librouter_qos_tc_remove_all(dev);
#endif
		free(dev);
		librouter_ppp_set_config(interface_major, &cfg);
		for (i = 0; i < 15; i++) {
			if (librouter_ppp_is_pppd_running(interface_major) == 0)
				break;
			sleep(1);
		}

		if (interface_major < MAX_WAN_INTF) {
			sprintf(master, "%s%d", SERIALDEV_PPP, interface_major); /* sx */
			librouter_dev_set_link_down(master); /* ~UP */
		}
	}
}

void ppp_noshutdown(const char *cmd)
{
	char *dev;
	ppp_config cfg;
	char master[IFNAMSIZ];

	librouter_ppp_get_config(interface_major, &cfg);
	if (!cfg.up) {
		if (interface_major < MAX_WAN_INTF) {
			sprintf(master, "%s%d", SERIALDEV_PPP, interface_major); /* sx */
			librouter_dev_set_link_up(master); /* UP */
		}

		cfg.up = 1;
		librouter_ppp_set_config(interface_major, &cfg);
		dev = librouter_device_cli_to_linux(interface_edited->cish_string, interface_major,
		                interface_minor);
#ifdef OPTION_QOS
		librouter_qos_tc_insert_all(dev);
#endif
		free(dev);
	}
}

void ppp_speed(const char *cmd)
{
	arglist *args;
	ppp_config cfg;
	int speed;

	args = librouter_make_args(cmd);
	speed = atoi(args->argv[1]);
	librouter_destroy_args(args);

	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.speed != speed) {
		cfg.speed = speed;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_nospeed(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.speed) {
		cfg.speed = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_ipaddr(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strncpy(cfg.ip_addr, args->argv[2], 16);
	cfg.ip_addr[15] = 0;
	strncpy(cfg.ip_mask, args->argv[3], 16);
	cfg.ip_mask[15] = 0;
	cfg.ip_unnumbered = -1; /* Desativando a flag do IP UNNUMBERED */
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_noipaddr(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.ip_addr[0] = cfg.ip_mask[0] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_peeraddr(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strncpy(cfg.ip_peer_addr, args->argv[2], 16);
	cfg.ip_peer_addr[15] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_nopeeraddr(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.ip_peer_addr[0] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_mtu(const char *cmd)
{
	arglist *args;
	int mtu;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	mtu = atoi(args->argv[1]);
	librouter_destroy_args(args);

	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.mtu != mtu) {
		cfg.mtu = mtu;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_nomtu(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.mtu) {
		cfg.mtu = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_chat(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);

	if (!librouter_ppp_chat_exists(args->argv[1])) {
		printf("%% Chat script %s does not exist\n", args->argv[1]);
		return;
	}

	librouter_ppp_get_config(interface_major, &cfg);
	strncpy(cfg.chat_script, args->argv[1], MAX_CHAT_SCRIPT);
	cfg.chat_script[MAX_CHAT_SCRIPT - 1] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_nochat(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.chat_script[0] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_dial_on_demand(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);

	if (cfg.chat_script[0] == 0) {
		printf("%% Dial-on-demand requires a chat script\n");
		return;
	}

	if (!cfg.dial_on_demand) {
		cfg.dial_on_demand = 1;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_no_dial_on_demand(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.dial_on_demand) {
		cfg.dial_on_demand = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_idle(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.chat_script[0] == 0) {
		printf("%% idle requires a chat script\n");
		return;
	}
	cfg.idle = atoi(args->argv[1]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_no_idle(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.idle) {
		cfg.idle = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_holdoff(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.chat_script[0] == 0) {
		printf("%% holdoff requires a chat script\n");
		return;
	}
	cfg.holdoff = atoi(args->argv[1]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_no_holdoff(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.holdoff) {
		cfg.holdoff = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_auth_user(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strncpy(cfg.auth_user, args->argv[2], MAX_PPP_USER);
	cfg.auth_user[MAX_PPP_USER - 1] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_auth_pass(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strncpy(cfg.auth_pass, args->argv[2], MAX_PPP_PASS);
	cfg.auth_pass[MAX_PPP_PASS - 1] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_noauth(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.auth_user[0] = cfg.auth_pass[0] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_defaultroute(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (!cfg.default_route) {
		cfg.default_route = 1;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_no_defaultroute(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.default_route) {
		cfg.default_route = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_vj(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.novj) {
		cfg.novj = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_no_vj(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (!cfg.novj) {
		cfg.novj = 1;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_flow_rtscts(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.flow_control != FLOW_CONTROL_RTSCTS) {
		cfg.flow_control = FLOW_CONTROL_RTSCTS;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_flow_xonxoff(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.flow_control != FLOW_CONTROL_XONXOFF) {
		cfg.flow_control = FLOW_CONTROL_XONXOFF;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_no_flow(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.flow_control != FLOW_CONTROL_NONE) {
		cfg.flow_control = FLOW_CONTROL_NONE;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_chatscript(const char *cmd)
{
	char *s, *chat_name, *old_chat;

	s = (char *) cmd;
	while (*s == ' ')
		++s;

	s = strchr(s, ' ');
	if (!s)
		return;
	while (*s == ' ')
		++s;
	chat_name = s;

	s = strchr(s, ' ');
	if (!s)
		return;
	*s++ = 0;
	while (*s == ' ')
		++s;

	old_chat = librouter_ppp_get_chat(chat_name);
	if (old_chat) {
		printf("%% Chat script %s already defined as %s\n", chat_name, old_chat);
		free(old_chat);
		return;
	}

	if (librouter_ppp_add_chat(chat_name, s) == -1) {
		printf("%% Chat script %s save error!\n", chat_name);
	}
}

void ppp_nochatscript(const char *cmd) /* no chatscript <name> */
{
	arglist *args;

	args = librouter_make_args(cmd);
	if (librouter_ppp_del_chat(args->argv[2]) == -1) {
		printf("%% Chat script %s not defined!\n", args->argv[2]);
	}
	librouter_destroy_args(args);
}

void ppp_ipxnet(const char *cmd)
{
	arglist *args;
	u32 net;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	net = strtoul(args->argv[2], NULL, 16);
	librouter_destroy_args(args);

	librouter_ppp_get_config(interface_major, &cfg);
	if ((cfg.ipx_network != net) || (cfg.ipx_enabled == 0)) {
		cfg.ipx_network = net;
		librouter_ip_get_mac("ethernet0", cfg.ipx_node);
		cfg.ipx_enabled = 1;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_no_ipxnet(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.ipx_enabled) {
		cfg.ipx_enabled = 0;
		cfg.ipx_network = 0;
		memset(&cfg.ipx_node, 0, 6);
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_unnumbered(const char *cmd) /* ip unnumbered ethernet 0-x */
{
	arglist *args;
	char addr[32], mask[32];
	ppp_config cfg;
	char *dev;

	args = librouter_make_args(cmd);
	dev = librouter_device_cli_to_linux(args->argv[2], atoi(args->argv[3]), -1);
	librouter_ip_ethernet_ip_addr(dev, addr, mask); // Captura o endere�o e mascara da interface Ethernet
	librouter_ppp_get_config(interface_major, &cfg); // Armazena em cfg a configuracao da serial
	strncpy(cfg.ip_addr, addr, 16); //Atualiza cfg com os dados da ethernet
	cfg.ip_addr[15] = 0;
	strncpy(cfg.ip_mask, mask, 16);
	cfg.ip_mask[15] = 0;
	cfg.ip_unnumbered = atoi(args->argv[3]); //Atualiza a flag do unnumbered no cfg
	librouter_ppp_set_config(interface_major, &cfg); //Atualiza as configuracoes da serial
	free(dev);
	librouter_destroy_args(args);
}

void ppp_no_unnumbered(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg); //Armazena em cfg a configuracao da serial
	cfg.ip_addr[0] = cfg.ip_mask[0] = 0; //Zera IP e MASK
	cfg.ip_unnumbered = -1; //Atualiza a flag do unnumbered no cfg
	librouter_ppp_set_config(interface_major, &cfg); //Atualiza as configuracoes da serial
}

void ppp_server_ipaddr(const char *cmd) /* server ip address */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strncpy(cfg.server_ip_addr, args->argv[3], 16);
	cfg.server_ip_addr[15] = 0;
	strncpy(cfg.server_ip_mask, args->argv[4], 16);
	cfg.server_ip_mask[15] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_noipaddr(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.server_ip_addr[0] = cfg.server_ip_mask[0] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_server_peeraddr(const char *cmd) /* server ip peer-address */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strncpy(cfg.server_ip_peer_addr, args->argv[3], 16);
	cfg.server_ip_peer_addr[15] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_nopeeraddr(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.server_ip_peer_addr[0] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_server_auth_local_algo(const char *cmd) /* ppp authentication algorithm <chap/pap> */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.server_flags &= ~(SERVER_FLAGS_PAP | SERVER_FLAGS_CHAP);
	if (!strcmp("chap", args->argv[3]))
		cfg.server_flags |= SERVER_FLAGS_CHAP;
	else if (!strcmp("pap", args->argv[3]))
		cfg.server_flags |= SERVER_FLAGS_PAP;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_local_user(const char *cmd) /* ppp authentication hostname <name> */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	if (!strcmp(args->argv[0], "no"))
		cfg.server_auth_user[0] = 0;
	else
		strncpy(cfg.server_auth_user, args->argv[3], MAX_PPP_USER);
	cfg.server_auth_user[MAX_PPP_USER - 1] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_local_pass(const char *cmd) /* ppp authentication password <passwd> */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	if (!strcmp(args->argv[0], "no"))
		cfg.server_auth_pass[0] = 0;
	else
		strncpy(cfg.server_auth_pass, args->argv[3], MAX_PPP_PASS);
	cfg.server_auth_pass[MAX_PPP_PASS - 1] = 0;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_noauth_local(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.server_auth_user[0] = cfg.server_auth_pass[0] = 0;
	cfg.server_flags &= ~(SERVER_FLAGS_PAP | SERVER_FLAGS_CHAP);
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_server_noauth(const char *cmd)
{
	ppp_server_noauth_local(NULL);
	ppp_server_noauth_radius(NULL);
	ppp_server_noauth_tacacs(NULL);
}

void ppp_server_auth_radius_authkey(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strcpy(cfg.radius_authkey, args->argv[4]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_radius_retries(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.radius_retries = atoi(args->argv[4]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_radius_servers(const char *cmd)
{
	int i;
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.radius_servers[0] = '\0';
	for (i = 4; args->argv[i]; i++) {
		if ((strlen(cfg.radius_servers) + strlen(args->argv[i]) + 1) < MAX_RADIUS_SERVERS)
			strcat(cfg.radius_servers, args->argv[i]);
		else
			break;
	}
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_radius_timeout(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.radius_timeout = atoi(args->argv[4]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_radius_sameserver(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.radius_sameserver = 1;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_server_auth_radius_trynextonreset(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.radius_trynextonreject = 1;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_server_auth_tacacs_authkey(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	strcpy(cfg.tacacs_authkey, args->argv[4]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_tacacs_servers(const char *cmd)
{
	int i;
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.tacacs_servers[0] = '\0';
	for (i = 4; args->argv[i]; i++) {
		if ((strlen(cfg.tacacs_servers) + strlen(args->argv[i]) + 1) < MAX_RADIUS_SERVERS)
			strcat(cfg.tacacs_servers, args->argv[i]);
		else
			break;
	}
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_server_auth_tacacs_sameserver(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.tacacs_sameserver = 1;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_server_auth_tacacs_trynextonreset(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.tacacs_trynextonreject = 1;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_server_noauth_radius(const char *cmd)
{
	ppp_server_noauth_radius_authkey(NULL);
	ppp_server_noauth_radius_retries(NULL);
	ppp_server_noauth_radius_sameserver(NULL);
	ppp_server_noauth_radius_servers(NULL);
	ppp_server_noauth_radius_timeout(NULL);
	ppp_server_noauth_radius_trynextonreject(NULL);
}

void ppp_server_noauth_tacacs(const char *cmd)
{
	ppp_server_noauth_tacacs_authkey(NULL);
	ppp_server_noauth_tacacs_sameserver(NULL);
	ppp_server_noauth_tacacs_servers(NULL);
	ppp_server_noauth_tacacs_trynextonreject(NULL);
}

void ppp_server_noauth_radius_authkey(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (strlen(cfg.radius_authkey) > 0) {
		cfg.radius_authkey[0] = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_radius_retries(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.radius_retries > 0) {
		cfg.radius_retries = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_radius_sameserver(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.radius_sameserver > 0) {
		cfg.radius_sameserver = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_radius_servers(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (strlen(cfg.radius_servers) > 0) {
		cfg.radius_servers[0] = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_radius_timeout(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.radius_timeout > 0) {
		cfg.radius_timeout = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_radius_trynextonreject(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.radius_trynextonreject > 0) {
		cfg.radius_trynextonreject = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_tacacs_authkey(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (strlen(cfg.tacacs_authkey) > 0) {
		cfg.tacacs_authkey[0] = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_tacacs_sameserver(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.tacacs_sameserver > 0) {
		cfg.tacacs_sameserver = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_tacacs_servers(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (strlen(cfg.tacacs_servers) > 0) {
		cfg.tacacs_servers[0] = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server_noauth_tacacs_trynextonreject(const char *cmd)
{
	ppp_config cfg;
	librouter_ppp_get_config(interface_major, &cfg);
	if (cfg.tacacs_trynextonreject > 0) {
		cfg.tacacs_trynextonreject = 0;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_server(const char *cmd) /* no server shutdown */
{
	ppp_config cfg, cfg_aux0, cfg_aux1;

	librouter_ppp_get_config(MAX_WAN_INTF, &cfg_aux0);
	librouter_ppp_get_config(MAX_WAN_INTF + 1, &cfg_aux1);
	if (interface_major == MAX_WAN_INTF) /* aux0 */
	{
		if (cfg_aux1.server_flags & SERVER_FLAGS_ENABLE) {
			printf("%% shuting down ppp server on aux 1\n");
			cfg_aux1.server_flags &= ~SERVER_FLAGS_ENABLE;
			librouter_ppp_set_config(MAX_WAN_INTF + 1, &cfg_aux1);
		}
		cfg_aux0.server_flags |= SERVER_FLAGS_ENABLE;
		librouter_ppp_set_config(MAX_WAN_INTF, &cfg_aux0);
	} else if (interface_major == MAX_WAN_INTF + 1) /* aux1 */
	{
		if (cfg_aux0.server_flags & SERVER_FLAGS_ENABLE) {
			printf("%% shuting down ppp server on aux 0\n");
			cfg_aux0.server_flags &= ~SERVER_FLAGS_ENABLE;
			librouter_ppp_set_config(MAX_WAN_INTF, &cfg_aux0);
		}
		cfg_aux1.server_flags |= SERVER_FLAGS_ENABLE;
		librouter_ppp_set_config(MAX_WAN_INTF + 1, &cfg_aux1);
	} else {
		librouter_ppp_get_config(interface_major, &cfg);
		cfg.server_flags |= SERVER_FLAGS_ENABLE;
		librouter_ppp_set_config(interface_major, &cfg);
	}
}

void ppp_no_server(const char *cmd) /* server shutdown */
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.server_flags &= ~SERVER_FLAGS_ENABLE;
	librouter_ppp_set_config(interface_major, &cfg);
}

#ifndef OPTION_NTPD
void ntp_sync(const char *cmd) /* ntp-sync [300-86400] <ipaddress> */
{
	arglist *args;

	args=librouter_make_args(cmd);
	if (args->argc == 3) librouter_ntp_set(atoi(args->argv[1]), args->argv[2]);
	librouter_destroy_args(args);
}

void no_ntp_sync(const char *cmd)
{
	librouter_ntp_set(0, NULL);
}
#endif

void serial_backup(const char *cmd) /* backup <aux?> activate_delay deactivate_delay */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	if (args->argv[1][3] == '0')
		cfg.backup = 1;
	else if (args->argv[1][3] == '1')
		cfg.backup = 2;
	cfg.activate_delay = atoi(args->argv[2]);
	cfg.deactivate_delay = atoi(args->argv[3]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void serial_no_backup(const char *cmd)
{
	ppp_config cfg;

	librouter_ppp_get_config(interface_major, &cfg);
	cfg.backup = 0;
	librouter_ppp_set_config(interface_major, &cfg);
}

void ppp_keepalive_interval(const char *cmd) /* keepalive interval [seconds] */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.echo_interval = atoi(args->argv[2]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_keepalive_timeout(const char *cmd) /* keepalive timeout [seconds] */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	cfg.echo_failure = atoi(args->argv[2]);
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_debug(const char *cmd) /* [no] ppp debug */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	if (args->argc == 3)
		cfg.debug = 0;
	else
		cfg.debug = 1;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

/* Sem suporte a LFI:
 *   [no] ppp multilink
 *
 * Com suporte a LFI:
 *   ppp multilink
 *   ppp multilink fragment <value>
 *   ppp multilink interleave priority-mark <value>
 *   no ppp multilink
 *   no ppp multilink fragment
 *   no ppp multilink interleave priority-mark
 *   no ppp multilink interleave priority-mark <value>
 */
void ppp_multilink(const char *cmd)
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
#ifdef CONFIG_HDLC_SPPP_LFI
	{
		int i, free, marknum;

		if( strcmp(args->argv[0], "no") != 0 ) {
			switch( args->argc ) {
				case 2:
				case 4:
				case 5:
				break;
				default:
				librouter_destroy_args(args);
				return;
			}
			switch( args->argc ) {
				case 2: /* ppp multilink */
				cfg.multilink = 1;
				break;

				case 4: /* ppp multilink fragment <value> */
				cfg.multilink = 1;
				cfg.fragment_size = atoi(args->argv[3]);
				break;

				case 5: /* ppp multilink interleave priority-mark <value> */
				cfg.multilink = 1;
				for(i=0, free=-1, marknum=atoi(args->argv[4]); i < CONFIG_MAX_LFI_PRIORITY_MARKS; i++) {
					if( cfg.priomarks[i] == marknum ) {
						printf("%% Mark %d already used as priority\n", marknum);
						librouter_destroy_args(args);
						return;
					}
					else {
						if( cfg.priomarks[i] == 0 ) {
							free = i;
							break;
						}
					}
				}
				if( free == -1 ) {
					printf("%% Not possible to configure priority. Max number of priority marks exceeded.\n");
					librouter_destroy_args(args);
					return;
				}
				cfg.priomarks[free] = marknum;
				break;
			}
		}
		else {
			switch( args->argc ) {
				case 3: /* no ppp multilink */
				cfg.multilink = 0;
				cfg.fragment_size = 0;
				for(i=0; (i < CONFIG_MAX_LFI_PRIORITY_MARKS) && (cfg.priomarks[i] != 0); i++)
				cfg.priomarks[i] = 0;
				break;

				case 4: /* no ppp multilink fragment */
				cfg.fragment_size = 0;
				break;

				case 5: /* no ppp multilink interleave priority-mark */
				for(i=0; (i < CONFIG_MAX_LFI_PRIORITY_MARKS) && (cfg.priomarks[i] != 0); i++)
				cfg.priomarks[i] = 0;
				break;

				case 6: /* no ppp multilink interleave priority-mark <value> */
				for(i=0, marknum=atoi(args->argv[5]); i < CONFIG_MAX_LFI_PRIORITY_MARKS; i++) {
					if( cfg.priomarks[i] == marknum ) {
						for(; i < (CONFIG_MAX_LFI_PRIORITY_MARKS-1); i++)
						cfg.priomarks[i] = cfg.priomarks[i+1];
						cfg.priomarks[i] = 0;
						break;
					}
				}
				break;

				default:
				librouter_destroy_args(args);
				return;
			}
		}
	}
#else
	if (args->argc == 3)
		cfg.multilink = 0;
	else
		cfg.multilink = 1;
#endif
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}

void ppp_usepeerdns(const char *cmd) /* [no] ppp usepeerdns */
{
	arglist *args;
	ppp_config cfg;

	args = librouter_make_args(cmd);
	librouter_ppp_get_config(interface_major, &cfg);
	if (args->argc == 3)
		cfg.usepeerdns = 0;
	else
		cfg.usepeerdns = 1;
	librouter_ppp_set_config(interface_major, &cfg);
	librouter_destroy_args(args);
}
#endif /* OPTION_PPP */

