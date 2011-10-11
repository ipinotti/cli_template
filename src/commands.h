#ifndef _COMMANDS_H
#define _COMMANDS_H 1

#include <stdio.h>
#include <linux/autoconf.h>

/* Libconfig includes */
#include <librouter/options.h>
#include <librouter/acl.h>
#include <librouter/args.h>
#include <librouter/bridge.h>
#include <librouter/config_mapper.h>
#include <librouter/config_fetcher.h>
#include <librouter/device.h>
#include <librouter/typedefs.h>
#include <librouter/ip.h>
#include <librouter/ipv6.h>
#include <librouter/dev.h>
#include <librouter/dhcp.h>
#include <librouter/dns.h>
#include <librouter/lan.h>
#include <librouter/ppp.h>
#include <librouter/str.h>
#include <librouter/libtime.h>
#include <librouter/flashsave.h>
#include <librouter/mangle.h>
#include <librouter/nat.h>
#include <librouter/ntp.h>
#include <librouter/nv.h>
#include <librouter/pam.h>
#include <librouter/pim.h>
#include <librouter/defines.h>
#include <librouter/version.h>
#include <librouter/debug.h>
#include <librouter/qos.h>
#include <librouter/ipsec.h>
#include <librouter/exec.h>
#include <librouter/process.h>
#include <librouter/quagga.h>
#include <librouter/snmp.h>
#include <librouter/ppcio.h>
#include <librouter/md5.h>
#include <librouter/ps.h>
#include <librouter/pptp.h>
#include <librouter/pppoe.h>

#ifdef OPTION_MODEM3G
#include <librouter/modem3G.h>
#endif
#ifdef OPTION_SMCROUTE
#include <librouter/smcroute.h>
#endif
#include <librouter/tunnel.h>
#ifdef OPTION_VRRP
#include <librouter/vrrp.h>
#endif
#include <librouter/ssh.h>
#include <librouter/vlan.h>

#ifdef OPTION_MANAGED_SWITCH
#if defined(OPTION_SWITCH_MICREL_KSZ8863)
#include <librouter/ksz8863.h>
#elif defined(OPTION_SWITCH_MICREL_KSZ8895)
#include <librouter/ksz8895.h>
#elif defined(OPTION_SWITCH_BROADCOM)
#include <librouter/bcm53115s.h>
#endif
#endif /* OPTION_MANAGED_SWITCH */

#ifdef OPTION_EFM
#include <librouter/efm.h>
#endif

//#define CISH_DEBUG
#ifdef CISH_DEBUG
#define cish_dbg(x,...) \
		syslog(LOG_INFO, "%s : %d => "x , __FUNCTION__, __LINE__, ##__VA_ARGS__);
#else
#define cish_dbg(x,...)
#endif

void show_cpu(const char *);
void show_interfaces(const char *);
void show_mroute(const char *);
void show_processes(const char *);
void show_motherboard_info(const char *cmdline);
void show_satrouter_info(const char *cmdline);
void show_release_date(const char *cmdline);
void show_arp(const char *);
void show_ip_dns(const char *);
void show_memory(const char *);
void show_uptime(const char *);
void show_routingtables(const char *);
void show_running_config(const char *);
void show_level_running_config(const char *);
void show_startup_config(const char *);
void show_previous_config(const char *);
void show_slot_config(const char *);
void show_techsupport(const char *);
void show_privilege(const char *);
void show_credits(const char *);
void show_accesslists(const char *);
void show_manglerules(const char *);
void show_natrules(const char *);
void show_version(const char *);
void show_performance(const char *);
void show_qos(const char *cmdline);
void show_crypto(const char *cmdline);
void show_l2tp(const char *cmdline);
void show_dumpleases(const char *cmdline);
void show_ntpkeys(const char *cmdline);
void show_ntpassociations(const char *cmdline);
void show_recycle(const char *);
void show_kmalloc(const char *);
void show_softnet(const char *);
void clear_ssh_hosts(const char *cmd);
void clear_counters(const char *cmd);

void show_clock(const char *);
void show_logging(const char *);
void clear_logging(const char *);

#ifdef OPTION_ROUTER
void ip_param(const char *);
void no_ip_param(const char *);
#endif

void config_term(const char *);
void config_term_done(const char *);
void config_keychain(const char *);
void config_keychain_done(const char *);
void config_key(const char *);
void config_key_done(const char *);
void config_key_string(const char *);

void set_rip_interface_cmds(int enable);
void set_ospf_interface_cmds(int enable);
void set_bgp_interface_cmds(int enable);
void set_model_aux_cmds(int enable);
void set_model_qos_cmds(int enable);
void set_model_vpn_cmds(int enable);
void set_model_ipv6_cmds(int enable);

void set_model_cmd_mask(int mask);
void del_model_cmd_mask(int mask);

void set_model_auth_cmds(void);

void set_model_switch_cmds(void);
void set_model_serial_cmds(const char *);
void disable_exc_cmds(void);

#ifdef OPTION_ROUTER
void config_router(const char *);
void config_no_router(const char *);
void config_router_done(const char *);
void ospf_execute_root_cmd(const char *);
void ospf_execute_router_cmd(const char *);
void ospf_execute_interface_cmd(const char *);
void bgp_execute_root_cmd(const char *);
void bgp_execute_router_cmd(const char *);
void bgp_execute_interface_cmd(const char *);
int bgp_start_router_cmd(int temp_asn);
void rip_execute_root_cmd(const char *);
void rip_execute_keychain_cmd(const char *);
void rip_execute_key_cmd(const char *);
void rip_execute_router_cmd(const char *);
void rip_execute_interface_cmd(const char *);
void show_ip_ospf(const char *cmdline);
void show_ip_rip(const char *cmdline);
void show_ip_bgp(const char *cmdline);
#endif /* OPTION_ROUTER */

void zebra_execute_cmd(const char *);
void zebra_execute_interface_cmd(const char *);
//void librouter_quagga_zebra_dump_static_routes(FILE *out);
void zebra_dump_routes(FILE *out);


void config_interface(const char *);

void ping(const char *);
void traceroute(const char *);
void exit_cish(const char *);
void ssh(const char *);
void telnet(const char *);
void tcpdump(const char *);

void ipx_routing(const char *cmd);
void no_ipx_routing(const char *cmd);
void dump_ipx(FILE *out, int);
void ipx_route(const char *cmd);
void no_ipx_route(const char *cmd);
void dump_ipx_routes(FILE *out, int conf_format);
void show_ipx_routingtables(const char *cmdline);

void enable(const char *);
void disable(const char *);

void cmd_copy(const char *);
void config_memory(const char *);
void config_write(const char *);
void erase_cfg(const char *);
void setsecret(const char *);
void set_nosecret(const char *);
void clear_enable_secret(const char *);
void no_enable_tacrad(const char *cmdline);
void set_enable_tacrad(const char *cmdline);

void dump_ip(FILE *, int);
void dump_ip_servers(FILE *, int);
void dump_terminal(FILE *);
void dump_log(FILE *, int);
void dump_bridge(FILE *);
void dump_version(FILE *);
void http_server(const char *cmd);
void no_http_server(const char *cmd);
void https_server(const char *cmd);
void no_https_server(const char *cmd);
void telnet_server(const char *cmd);
void no_telnet_server(const char *cmd);
void firmware_download(const char *cmd);
void firmware_save(const char *cmd);
void firmware_upload(const char *cmd);
void no_firmware_upload(const char *cmd);


/* DHCP Server */
void dhcp_server_enable(const char *cmd);
void dhcp_server_disable(const char *cmd);
void dhcp_server_network(const char *cmd);
void dhcp_server_pool(const char *cmd);

void dhcp_server_dns(const char *cmd);
void dhcp_server_leasetime(const char *cmd);
void dhcp_server_domainname(const char *cmd);
void dhcp_server_nbns(const char *cmd);
void dhcp_server_nbdd(const char *cmd);
void dhcp_server_nbnt(const char *cmd);
void dhcp_server_default_router(const char *cmd);

void dhcp_server(const char *cmd);
void dhcp_server_exit(const char *cmd);

void dhcp_relay(const char *cmd);
void no_dhcp_relay(const char *cmd);
void ip_dnsrelay(const char *cmd);
void ip_domainlookup(const char *cmd);
void ip_nameserver(const char *cmd);

void ip_nat_ftp(const char *);
void ip_nat_irc(const char *);
void ip_nat_tftp(const char *);
void dump_nat_helper(FILE *);

void ssh_server(const char *cmd);
void no_ssh_server(const char *cmd);
void ssh_generate_rsa_key(const char *cmd);

void pim_dense_server(const char *cmd);
void no_pim_dense_server(const char *cmd);
void pim_sparse_server(const char *cmd);
void no_pim_sparse_server(const char *cmd);
void pim_sparse_mode(const char *cmd);
void pim_sparse_mode_intf(const char *cmd);
void pim_dense_mode(const char *cmd);
void pim_bsr_candidate(const char *cmd);
void pim_rp_address(const char *cmd);
void pim_rp_candidate(const char *cmd);

void arp_entry(const char *cmd);

#ifdef OPTION_PPP
void ppp_ipaddr(const char *);
void ppp_noipaddr(const char *);
void ppp_peeraddr(const char *);
void ppp_nopeeraddr(const char *);
void ppp_defaultroute(const char *);
void ppp_no_defaultroute(const char *);
void ppp_vj(const char *cmd);
void ppp_no_vj(const char *cmd);
void ppp_shutdown(const char *);
void ppp_noshutdown(const char *);
void ppp_chat(const char *);
void ppp_nochat(const char *);
void ppp_dial_on_demand(const char *);
void ppp_no_dial_on_demand(const char *);
void ppp_idle(const char *);
void ppp_no_idle(const char *);
void ppp_holdoff(const char *);
void ppp_no_holdoff(const char *);
void ppp_auth_user(const char *);
void ppp_auth_pass(const char *);
void ppp_noauth(const char *);
void ppp_flow_rtscts(const char *);
void ppp_flow_xonxoff(const char *);
void ppp_no_flow(const char *);
void ppp_mtu(const char *);
void ppp_nomtu(const char *);
void ppp_speed(const char *);
void ppp_nospeed(const char *);
void ppp_ipxnet(const char *);
void ppp_no_ipxnet(const char *);
void ppp_unnumbered(const char *);
void ppp_no_unnumbered(const char *);

void ppp_server_ipaddr(const char *);
void ppp_server_noipaddr(const char *);
void ppp_server_peeraddr(const char *);
void ppp_server_nopeeraddr(const char *);
void ppp_server_auth_local_algo(const char *);
void ppp_server_auth_local_user(const char *);
void ppp_server_auth_local_pass(const char *);
void ppp_server_noauth_local(const char *);
void ppp_server_auth_radius_authkey(const char *);
void ppp_server_auth_radius_retries(const char *);
void ppp_server_auth_radius_servers(const char *);
void ppp_server_auth_radius_timeout(const char *);
void ppp_server_auth_radius_sameserver(const char *);
void ppp_server_auth_radius_trynextonreset(const char *);
void ppp_server_auth_tacacs_authkey(const char *);
void ppp_server_auth_tacacs_servers(const char *);
void ppp_server_auth_tacacs_sameserver(const char *);
void ppp_server_auth_tacacs_trynextonreset(const char *);
void ppp_server_noauth_radius(const char *);
void ppp_server_noauth_tacacs(const char *);
void ppp_server_noauth_radius_authkey(const char *);
void ppp_server_noauth_radius_retries(const char *);
void ppp_server_noauth_radius_sameserver(const char *);
void ppp_server_noauth_radius_servers(const char *);
void ppp_server_noauth_radius_timeout(const char *);
void ppp_server_noauth_radius_trynextonreject(const char *);
void ppp_server_noauth_tacacs_authkey(const char *);
void ppp_server_noauth_tacacs_sameserver(const char *);
void ppp_server_noauth_tacacs_servers(const char *);
void ppp_server_noauth_tacacs_trynextonreject(const char *);
void ppp_server_noauth(const char *);
void ppp_server(const char *);
void ppp_no_server(const char *);
void ppp_keepalive_interval(const char *);
void ppp_keepalive_timeout(const char *);
void ppp_debug(const char *);
void ppp_multilink(const char *);
void ppp_usepeerdns(const char *);
void ppp_chatscript(const char *);
void ppp_nochatscript(const char *);
#endif

#ifdef OPTION_IPSEC
void l2tp_peer(const char *);
void l2tp_ppp_auth_pass(const char *);
void l2tp_ppp_auth_user(const char *);
void l2tp_ppp_noauth(const char *);
void l2tp_ppp_ipaddr(const char *);
void l2tp_ppp_noipaddr(const char *);
void l2tp_ppp_defaultroute(const char *);
void l2tp_ppp_no_defaultroute(const char *);
void l2tp_ppp_peeraddr(const char *);
void l2tp_ppp_nopeeraddr(const char *);
void l2tp_ppp_unnumbered(const char *);
void l2tp_ppp_no_unnumbered(const char *);
void l2tp_ppp_vj(const char *);
void l2tp_ppp_no_vj(const char *);
void l2tp_ppp_keepalive_interval(const char *);
void l2tp_ppp_keepalive_timeout(const char *);
void l2tp_ppp_mtu(const char *);
void l2tp_ppp_nomtu(const char *);
#endif

void vlan_add(const char *cmd);
void vlan_del(const char *cmd);
void vlan_change_cos(const char *cmd);

void hostname(const char *);
void help(const char *);
void reload(const char *);
void reload_cancel(const char *);
void reload_in(const char *);
void show_reload(const char *);

void log_remote(const char *);
void no_log_remote(const char *);

void ntp_sync(const char *);
void no_ntp_sync(const char *);

void dump_snmp(FILE *, int);
void snmp_enable(const char *);
void snmp_community(const char *);
void snmp_text(const char *);
void snmp_no_community(const char *);
void snmp_no_server(const char *);
void snmp_trapsink(const char *);
void snmp_no_trapsink(const char *);
void snmp_user(const char *cmd);
void show_snmp_users(const char *cmd);
void snmp_version(const char *cmd);

#ifdef OPTION_BRIDGE
void bridge_setaging(const char *cmd);
void bridge_setfd(const char *cmd);
void bridge_sethello(const char *cmd);
void bridge_setmaxage(const char *cmd);
void bridge_setprio(const char *cmd);
void bridge_nostp(const char *cmd);
void bridge_stp(const char *cmd);
void bridge_setproto(const char *cmd);
void bridge_no(const char *cmd);
void dump_bridge(FILE *F);
void bridge_show(const char *cmd);
#endif

void term_length(const char *);
void term_timeout(const char *);

void config_clock(const char *cmd);
void config_clock_timezone(const char *cmd);

#ifdef CONFIG_IPHC
void clear_iphc(const char *cmdline);
#endif

void cmd_aaa(const char *cmd);
void cmd_aaa_authen(const char *cmd);
void cmd_aaa_acct(const char *cmd);
void cmd_aaa_author(const char *cmd);
void add_user(const char *cmd);
void del_user(const char *cmd);
void add_radiusserver(const char *cmd);
void del_radiusserver(const char *cmd);
void add_tacacsserver(const char *cmd);
void del_tacacsserver(const char *cmd);
int authorize_cli_command(char *cmd);
void account_cli_command(char *cmd);
void dump_aaa(FILE *out);

#define FEATURE_VPN 0 /* struct features index */
int is_feature_on(int);
void feature(const char *);
void no_feature(const char *);
void show_features(const char *);
void load_ftures(void);
void crypto_on_off(int);

void add_ipsec_conn(const char *);
void generate_rsa_key(const char *);
void del_ipsec_conn(const char *);
void ipsec_autoreload(const char *);
void ipsec_nat_traversal(const char *);
void ipsec_overridemtu(const char *);
void cd_connection_dir(const char *);
void cd_crypto_dir(const char *);
void config_crypto_done(const char *cmd);
void config_connection_done(const char *cmd);
int remove_conn_files(char *name);
void ipsec_set_secret_key(const char *cmd);
void ipsec_authby_rsa(const char *cmd);
void ipsec_authproto_esp(const char *cmd);
void set_esp_hash(const char *cmd);
void set_ipsec_id(const char *cmd);
void clear_ipsec_id(const char *cmd);
void set_ipsec_addr(const char *cmd);
void set_ipsec_nexthop(const char *cmd);
void clear_ipsec_nexthop(const char *cmd);
void set_ipsec_remote_rsakey(const char *cmd);
void clear_ipsec_remote_rsakey(const char *cmd);
void set_ipsec_subnet(const char *cmd);
void clear_ipsec_subnet(const char *cmd);
void ipsec_link_up(const char *cmd);
void ipsec_link_down(const char *cmd);
void set_ipsec_l2tp_protoport(const char *cmd);
void ipsec_pfs(const char *cmd);
void l2tp_dhcp_server(const char *cmd);
void l2tp_server(const char *cmd);
void check_initial_conn(void);
void dump_crypto(FILE *out);

void giga_script(const char *);
void giga_scriptplus(const char *);
void giga_terminal(const char *);

void ntp_authenticate(const char *cmd);
void ntp_generate_keys(const char *cmd);
void ntp_restrict(const char *cmd);
void ntp_server(const char *cmd);
void ntp_trust_on_key(const char *cmd);
void ntp_set_key_value(const char *cmd);
void no_ntp_authenticate(const char *cmd);
void no_ntp_restrict(const char *cmd);
void no_ntp_server(const char *cmd);
void ntp_enable(const char *cmd);
void no_ntp_trustedkeys(const char *cmd);
void ntp_update_calendar(const char *cmd);

void rmon_agent(const char *cmd);
void rmon_event(const char *cmd);
void rmon_alarm(const char *cmd);
void no_rmon_agent(const char *cmd);
void no_rmon_event(const char *cmd);
void no_rmon_alarm(const char *cmd);
void rmon_snmp_version(const char *cmd);
void show_rmon_events(const char *cmd);
void show_rmon_alarms(const char *cmd);
void show_rmon_agent(const char *cmd);
void show_rmon_mibs(const char *cmd);
void show_rmon_mibtree(const char *cmd);
void dump_rmon(FILE *out);
void clear_rmon_events(const char *cmd);

void ip_mroute(const char *);
void show_vrrp(const char *);
void show_fr_pvc(const char *);

#ifdef CONFIG_IPHC
void show_iphc_stats(const char *cmdline);
#endif

#endif

/* Previously declared on configterm.c */
void interface_no_shutdown(const char *);
void interface_ethernet_ipaddr_dhcp(const char *);
void interface_ethernet_ipaddr(const char *);
void interface_ethernet_ipaddr_secondary(const char *);
void interface_ethernet_no_ipaddr(const char *);
void interface_ethernet_no_ipaddr_secondary(const char *);
void interface_fr_ipaddr(const char *);
void interface_subfr_ipaddr(const char *);
void interface_subfr_fragment(const char *);
void interface_subfr_bridgegroup(const char *);
void interface_subfr_no_bridgegroup(const char *);
void interface_ethernet_bridgegroup(const char *);
void interface_ethernet_no_bridgegroup(const char *);
void interface_chdlc_ipaddr(const char *);
void interface_chdlc_bridgegroup(const char *);
void interface_chdlc_no_bridgegroup(const char *);
void interface_sppp_ipaddr(const char *);
void interface_ipxnet(const char *);
void interface_no_ipxnet(const char *);
void interface_ethernet_ipxnet(const char *);
void interface_ethernet_no_ipxnet(const char *);
void interface_shutdown(const char *);
void interface_txqueue(const char *);

/* IPv6 */
void show_routingtables_ipv6(const char *);
void interface_ethernet_ipaddr_v6(const char *cmdline);
void interface_ethernet_no_ipaddr_v6(const char *cmdline);
void interface_ethernet_flush_ipaddr_v6(const char *cmdline);
void zebra_execute_cmd_ipv6(const char *cmdline);
void dump_routing_ipv6(FILE *out, int conf_format);
void zebra_dump_routes_ipv6(FILE *out);
void interface_no_ipaddr_v6(const char *cmdline);
void interface_flush_ipaddr_v6(const char *cmdline);
void interface_ipaddr_v6(const char *cmdline);
void ipv6_param(const char *);
void no_ipv6_param(const char *);

#ifdef OPTION_MANAGED_SWITCH
#if defined(OPTION_SWITCH_MICREL)
void sw_vlan_default(const char *);
void sw_ingress_rate_limit(const char *);
void sw_egress_traffic_shape(const char *);
void sw_replace_null_vid(const char *);
void sw_multicast_storm_protect(const char *);
void sw_broadcast_storm_protect(const char *);
void sw_broadcast_storm_protect_rate(const char *);
void sw_enable_wfq(const char *);
void sw_vlan_entry(const char *);
void sw_8021q(const char *);
void sw_8021p(const char *);
void sw_8021p_prio(const char *);
void sw_dscp(const char *);
void sw_dscp_prio(const char *);
void sw_txqueue_split(const char *);
#elif defined(OPTION_SWITCH_BROADCOM)
void sw_vlan_default(const char *);
void sw_replace_null_vid(const char *);
void sw_multicast_storm_protect(const char *);
void sw_broadcast_storm_protect(const char *);
void sw_broadcast_storm_protect_rate(const char *);
void sw_drop_untagged(const char *);
void sw_enable_wrr(const char *);
void sw_vlan_entry(const char *);
void sw_8021q(const char *);
void sw_8021p(const char *);
void sw_8021p_prio(const char *);
void sw_dscp(const char *);
void sw_dscp_prio(const char *);
#endif
#endif /* OPTION_MANAGED_SWITCH */

/* TODO config_interface.c -> create config_interface.h */
void config_interface_done(const char *);
void config_interface_switch_port(const char *);
void config_interface_switch_port_done(const char *);

/* TODO config_interface.c -> perhaps create a file for each interface */
void interface_efm_set_mode(const char *);

#ifdef OPTION_QOS
void do_bandwidth(const char *);
void do_max_reserved_bw(const char *);
void do_service_policy(const char *);
void no_service_policy(const char *);
#endif

void interface_mtu(const char *);
void interface_description(const char *);
void interface_no_description(const char *);
void interface_rxring(const char *);
void interface_txring(const char *);
void interface_weight(const char *);
void interface_x25_lapb_mode(const char *);
void interface_x25_lapb_n2(const char *);
void interface_x25_lapb_t1(const char *);
void interface_x25_lapb_t2(const char *);
void interface_x25_lapb_window(const char *);
void interface_x25_route_add(const char *);
void interface_x25_route_del(const char *);
void interface_x25_svc_add(const char *);
void interface_x25_svc_del(const char *);
void interface_subx25_ipaddr(const char *);
void interface_subx25_address(const char *);
void interface_subx25_ips(const char *);
void interface_subx25_map_ip(const char *);
void interface_subx25_ops(const char *);
void interface_subx25_win(const char *);
void interface_subx25_wout(const char *);
void interface_policy_no(const char *);
void interface_policy(const char *);
void interface_sppp_ipaddr(const char *cmdline);
void interface_traffic_rate_no(const char *);
void interface_traffic_rate(const char *);
void interface_subfr_fragment(const char *cmdline);
void interface_snmptrap(const char *);
void interface_no_snmptrap(const char *);
void interface_ipaddr(const char *);
void interface_ipaddr_secondary(const char *);
void interface_no_ipaddr(const char *);
void interface_no_ipaddr_secondary(const char *);
void tunnel_destination(const char *);
void tunnel_key(const char *);
void tunnel_mode(const char *);
void tunnel_source_interface(const char *);
void tunnel_source(const char *);
void tunnel_checksum(const char *);
void tunnel_pmtu(const char *);
void tunnel_sequence(const char *);
void tunnel_keepalive(const char *);
void tunnel_ttl(const char *);
void interface_fec_autonegotiation(const char *cmdline);
void interface_fec_cfg(const char *cmdline);

/* Mangle */
void do_mangle(const char *);
void no_mangle_rule(const char *);
void interface_mangle(const char *);
void interface_no_mangle(const char *);

void dump_mangle(char *xmangle, FILE *F, int conf_format);
int mangle_exists(char *mangle);
int matched_mangle_exists(char *mangle, char *iface_in, char *iface_out, char *chain);
int get_iface_mangle_rules(char *iface, char *in_mangle, char *out_mangle);
int get_mangle_refcount(char *mangle);
int clean_iface_mangle_rules(char *iface);

#ifdef OPTION_FIREWALL
/* Access Lists */
void do_accesslist(const char *);
void do_accesslist_mac(const char *);
void do_accesslist_policy(const char *);
void no_accesslist(const char *);
void interface_acl(const char *);
void interface_no_acl(const char *);
#endif

#ifdef OPTION_NAT
/* NAT */
void do_nat_rule(const char *);
void no_nat_rule(const char *);
void interface_nat(const char *);
void interface_no_nat(const char *);
#endif


int nat_rule_exists(char *acl);
int matched_nat_rule_exists(char *acl, char *iface_in, char *iface_out, char *chain);
int get_iface_nat_rules(char *iface, char *in_acl, char *out_acl);
int get_nat_rule_refcount(char *acl);
int clean_iface_nat_rules(char *iface);

/* Debug */
void debug_all(const char *);
void debug_one(const char *);
void show_debug(const char *cmd);
void debug_console(const char *cmd);

/* Policy Map */
void do_policy_description(const char *cmdline);
void do_policy_mark(const char *cmdline);
void config_policy_bw(const char *cmdline);
void config_policy_ceil(const char *cmdline);
void config_policy_queue(const char *cmdline);
void config_policy_realtime(const char *cmdline);
void do_policymap(const char *cmdline);
void quit_mark_config(const char *cmdline);
void policymap_done(const char *cmdline);

/* Service Policy*/
void no_service_policy(const char *cmdline);
void do_service_policy(const char *cmdline);

/* PPTP */
void pptp_set_info(const char *cmd);
void pptp_set_no_info(const char *cmd);
void pptp_set_mppe(const char *cmd);
void pptp_set_clientmode(const char *cmd);

/* PPPOE */
void pppoe_set_info(const char *cmd);
void pppoe_set_no_info(const char *cmd);
void pppoe_set_clientmode(const char *cmd);

/* Policy Route - PBR */
void policyroute_rule_set_info(const char *cmdline);
void policyroute_route_set_info(const char *cmdline);
void policyroute_route_flush_table(const char *cmdline);
void policyroute_done(const char *cmdline);
void cd_policyroute_dir(const char *cmdline);
void show_policyroute_rules(const char *cmdline);
void show_policyroute_routes(const char *cmdline);


/* 3G Device */
#ifdef OPTION_MODEM3G
void interface_modem3g_set_apn(const char *cmdline);
void interface_modem3g_set_username(const char *cmdline);
void interface_modem3g_set_password(const char *cmdline);
void show_modem3g_apn(const char *cmdline);
void show_modem3g_username(const char *cmdline);
void show_modem3g_password(const char *cmdline);
void backup_interface_shutdown(const char *cmdline);
void backup_interface(const char *cmdline);
void backup_method_set_ping (const char *cmdline);
void backup_method_set_link (const char *cmdline);
void interface_modem3g_sim_card_select(const char *cmdline);
void interface_modem3g_btin_set_info(const char *cmdline);
void interface_modem3g_default_gateway(const char *cmdline);
#endif

void config_banner_login(const char *cmdline);
void config_banner_system(const char *cmdline);
void show_banner(const char *cmdline);
