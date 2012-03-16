#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "commands.h"
#include "commandtree.h"

#ifdef OPTION_IPSEC
#if 0 /* Auto-reload doesn't exist on openswan */
cish_command CMD_CONFIG_CRYPTO_AUTORELOAD[] = {
	{"60-3600", "Set interval of auto-reload connections (dns)", NULL, ipsec_autoreload, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_IPSEC_CONNECTION_AUTHBY_SECRET[] = {
	{"<text>", "pre-shared key", NULL, ipsec_set_secret_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_AUTHBY[] = {
#ifdef IPSEC_SUPPORT_RSA_RAW
	{"rsa", "Use RSA pair keys", NULL, ipsec_authby_rsa, 1, MSK_NORMAL},
#endif
	{"secret", "Use pre-shared key", CMD_IPSEC_CONNECTION_AUTHBY_SECRET, NULL, 1, MSK_NORMAL},
#ifdef OPTION_PKI
	{"X.509", "Use X.509 ceritificates", NULL, ipsec_authby_x509, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_AUTHPROTO[] = {
#ifdef IPSEC_SUPPORT_TRANSPORT_MODE
	{"transport", "Transport mode", NULL, ipsec_authproto_ah, 1, MSK_NORMAL},
#endif
	{"tunnel", "Tunnel mode", NULL, ipsec_authproto_esp, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ESP_HASH[] = {
	{"md5", "MD5 hash", NULL, set_esp_hash, 1, MSK_NORMAL},
	{"sha1", "SHA1 hash", NULL, set_esp_hash, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ESP[] = {
	{"3des", "3DES cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
	{"aes", "AES cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
	{"des", "DES cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
	{"null", "NULL cypher", CMD_IPSEC_CONNECTION_ESP_HASH, set_esp_hash, 1, MSK_NORMAL},
	{"<enter>", "cypher do not care", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_ADDR_IP[] = {
	{"<ipaddress>", "IP address", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_ADDR_FQDN[] = {
	{"<text>", "FQDN address", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef IPSEC_SUPPORT_LOCAL_ADDRESS_INTERFACE
cish_command CMD_IPSEC_CONNECTION_INTERFACE_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_EFM
cish_command CMD_IPSEC_CONNECTION_INTERFACE_EFM[] = {
	{CLI_STRING_EFM_IFACES, "EFM interface number", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_MODEM3G
cish_command CMD_IPSEC_CONNECTION_INTERFACE_M3G[] = {
	{CLI_STRING_USB_PORTS, "Modem 3G interface number", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

#ifdef OPTION_TUNNEL
cish_command CMD_IPSEC_CONNECTION_INTERFACE_TUNNEL[] = {
	{CLI_STRING_TUN_IFACES, "Tunnel interface number", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_IPSEC_CONNECTION_INTERFACE[] = {
#ifdef OPTION_MODEM3G
	{"m3G", "Modem 3G interface", CMD_IPSEC_CONNECTION_INTERFACE_M3G, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_EFM
	{"efm", "EFM interface", CMD_IPSEC_CONNECTION_INTERFACE_EFM, NULL, 1, MSK_NORMAL},
#endif
	{"ethernet", "Ethernet interface", CMD_IPSEC_CONNECTION_INTERFACE_ETHERNET, NULL, 1, MSK_NORMAL},
#ifdef OPTION_TUNNEL
	{"tunnel", "Tunnel interface", CMD_IPSEC_CONNECTION_INTERFACE_TUNNEL, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};
#endif /* IPSEC_SUPPORT_LOCAL_ADDRESS_INTERFACE */

cish_command CMD_IPSEC_CONNECTION_L_ADDR[] = {
	{"default-route", "Use default route as address", NULL, set_ipsec_addr, 1, MSK_NORMAL},
#if IPSEC_SUPPORT_LOCAL_ADDRESS_FQDN
	{"fqdn", "Address in the name format", CMD_IPSEC_CONNECTION_LR_ADDR_FQDN, NULL, 1, MSK_NORMAL},
#endif
	{"ip", "Address in the dotted representation", CMD_IPSEC_CONNECTION_LR_ADDR_IP, NULL, 1, MSK_NORMAL},
#ifdef IPSEC_SUPPORT_LOCAL_ADDRESS_INTERFACE
	{"interface", "Interface to be used", CMD_IPSEC_CONNECTION_INTERFACE, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_R_ADDR[] = {
	{"any", "Any address (roadwarrior)", NULL, set_ipsec_addr, 1, MSK_NORMAL},
	{"fqdn", "Address in the name format", CMD_IPSEC_CONNECTION_LR_ADDR_FQDN, NULL, 1, MSK_NORMAL},
	{"ip", "Address in the dotted representation", CMD_IPSEC_CONNECTION_LR_ADDR_IP, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_ID[] = {
	{"<text>", "ID string (@)", NULL, set_ipsec_id, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_NEXTHOP[] = {
	{"<ipaddress>", "Address of the next hop", NULL, set_ipsec_nexthop, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef IPSEC_SUPPORT_RSA_RAW
cish_command CMD_IPSEC_CONNECTION_R_RSAKEY[] = {
	{"<text>", "The public key", NULL, set_ipsec_remote_rsakey, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif /* IPSEC_SUPPORT_RSA_RAW */

cish_command CMD_IPSEC_CONNECTION_LR_SUBNET_MASK[] = {
	{"<netmask>", "subnet mask", NULL, set_ipsec_subnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LR_SUBNET[] = {
	{"<ipaddress>", "Address of subnet", CMD_IPSEC_CONNECTION_LR_SUBNET_MASK, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_LOCAL[] = {
	{"address", "The local address type entered by the user", CMD_IPSEC_CONNECTION_L_ADDR, NULL, 1, MSK_NORMAL},
	{"id", "Local identification of the tunnel", CMD_IPSEC_CONNECTION_LR_ID, NULL, 1, MSK_NORMAL},
	{"nexthop", "Equipment that gives access to the network", CMD_IPSEC_CONNECTION_LR_NEXTHOP, NULL, 1, MSK_NORMAL},
	{"subnet", "The local subnet (network & mask)", CMD_IPSEC_CONNECTION_LR_SUBNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_REMOTE[] = {
	{"address", "The remote address type entered by the user", CMD_IPSEC_CONNECTION_R_ADDR, NULL, 1, MSK_NORMAL},
	{"id", "Remote identification of the tunnel", CMD_IPSEC_CONNECTION_LR_ID, NULL, 1, MSK_NORMAL},
	{"nexthop", "Equipment that gives access to the network", CMD_IPSEC_CONNECTION_LR_NEXTHOP, NULL, 1, MSK_NORMAL},
#ifdef IPSEC_SUPPORT_RSA_RAW
	{"rsakey", "The RSA public key of the remote", CMD_IPSEC_CONNECTION_R_RSAKEY, NULL, 1, MSK_NORMAL},
#endif
	{"subnet", "The remote subnet (network & mask)", CMD_IPSEC_CONNECTION_LR_SUBNET, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PEER1[] = {
	{"<netmask>", "Remote address mask", NULL, l2tp_peer, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PEER[] = {
	{"<ipaddress>", "Remote address", CMD_IPSEC_CONNECTION_L2TP_PEER1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_PASS[] = {
	{"<text>","Password", NULL, l2tp_ppp_auth_pass, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_USER[] = {
	{"<text>","Username", NULL, l2tp_ppp_auth_user, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH[] = {
	{"pass","Set authentication password", CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_PASS, NULL, 1, MSK_NORMAL},
	{"user","Set authentication username", CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH_USER, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_ADDRESS[] = {
	{"<ipaddress>", "Local address (on internal interface)", NULL, l2tp_ppp_ipaddr, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_ETHERNET[] = {
	{CLI_STRING_ETH_IFACES, "Ethernet interface number", NULL, l2tp_ppp_unnumbered, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_M3G[] = {
	{"0-2", "Modem 3G interface number", NULL, l2tp_ppp_unnumbered, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_LOOPBACK[] = {
	{"0-0", "Loopback interface number", NULL, l2tp_ppp_unnumbered, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED[] = {
	{"ethernet", "Ethernet interface", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_ETHERNET, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_LOOPBACK, NULL, 1, MSK_NORMAL},
#ifdef NOT_YET_IMPLEMENTED
#ifdef OPTION_MODEM3G
	{"m3G", "Modem 3G interface", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED_M3G, NULL, 1, MSK_NORMAL},
#endif
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_PEER[] = {
        {"pool", "Remote address from pool", NULL, l2tp_ppp_peeraddr, 1, MSK_NORMAL},
        {"<ipaddress>", "Remote address (on internal interface)", NULL, l2tp_ppp_peeraddr, 1, MSK_NORMAL},
        {NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_IP[] = {
	{"address", "Set local address", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_ADDRESS, NULL, 1, MSK_NORMAL},
	{"default-route", "Use default-route on this interface", NULL, l2tp_ppp_defaultroute, 1, MSK_NORMAL},
	{"peer-address", "Set peer address", CMD_CONFIG_INTERFACE_SERIAL_PPP_IP_PEER, NULL, 1, MSK_NORMAL},
	{"unnumbered", "Enable IP processing without an explicit address", CMD_IPSEC_CONNECTION_L2TP_PPP_IP_UNNUMBERED, NULL, 1, MSK_NORMAL},
	{"vj", "Enable Van Jacobson style TCP/IP header compression", NULL, l2tp_ppp_vj, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_INTERVAL[] = {
	{"1-100", "seconds", NULL, l2tp_ppp_keepalive_interval, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_TIMEOUT[] = {
	{"1-100", "seconds", NULL, l2tp_ppp_keepalive_timeout, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE[] = {
	{"interval", "Set interval between two keepalive commands", CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_INTERVAL, NULL, 1, MSK_NORMAL},
	{"timeout", "Set keepalive failure timeout", CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE_TIMEOUT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP_MTU[] = {
	{"128-16384", "Max Transfer Unit", NULL, l2tp_ppp_mtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PPP[] = {
	{"authentication", "Authentication settings", CMD_IPSEC_CONNECTION_L2TP_PPP_AUTH, NULL, 1, MSK_NORMAL},
	{"ip", "Set IP parameters", CMD_IPSEC_CONNECTION_L2TP_PPP_IP, NULL, 1, MSK_NORMAL},
	{"keepalive", "Set keepalive parameters", CMD_IPSEC_CONNECTION_L2TP_PPP_KEEPALIVE, NULL, 1, MSK_NORMAL},
	{"mtu", "Set interface mtu", CMD_IPSEC_CONNECTION_L2TP_PPP_MTU, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP_PROTOPORT[] = {
	{"SP1", "Windows XP SP1 protoport", NULL, set_ipsec_l2tp_protoport, 1, MSK_NORMAL},
	{"SP2", "Windows XP SP2 protoport", NULL, set_ipsec_l2tp_protoport, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_L2TP[] = {
	{"peer", "Set remote peer address/mask", CMD_IPSEC_CONNECTION_L2TP_PEER, NULL, 1, MSK_NORMAL},
	{"ppp", "Set PPP options", CMD_IPSEC_CONNECTION_L2TP_PPP, NULL, 1, MSK_NORMAL},
	{"protoport", "Set protoport", CMD_IPSEC_CONNECTION_L2TP_PROTOPORT, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_LOCAL[] = {
	{"id", "Clear local identification of the tunnel", NULL, clear_ipsec_id, 1, MSK_NORMAL},
	{"nexthop", "Clear local nexthop", NULL, clear_ipsec_nexthop, 1, MSK_NORMAL},
	{"subnet", "Clear local subnet", NULL, clear_ipsec_subnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_REMOTE[] = {
	{"id", "Clear remote identification of the tunnel", NULL, clear_ipsec_id, 1, MSK_NORMAL},
	{"nexthop", "Clear remote nexthop", NULL, clear_ipsec_nexthop, 1, MSK_NORMAL},
#ifdef IPSEC_SUPPORT_RSA_RAW
	{"rsakey", "Clear the RSA public key of the remote", NULL, clear_ipsec_remote_rsakey, 1, MSK_NORMAL},
#endif
	{"subnet", "Clear remote subnet", NULL, clear_ipsec_subnet, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_L2TP_PPP_IP[] = {
	{"address", "Unset local address", NULL, l2tp_ppp_noipaddr, 1, MSK_NORMAL},
	{"default-route", "Don't use default-route on this interface", NULL, l2tp_ppp_no_defaultroute, 1, MSK_NORMAL},
	{"peer-address", "Unset peer address", NULL, l2tp_ppp_nopeeraddr, 1, MSK_NORMAL},
	{"unnumbered", "Disable IP processing without an explicit address", NULL, l2tp_ppp_no_unnumbered, 1, MSK_NORMAL},
	{"vj", "Disable Van Jacobson style TCP/IP header compression", NULL, l2tp_ppp_no_vj, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_L2TP_PPP[] = {
	{"authentication", "Turn off authentication", NULL, l2tp_ppp_noauth, 1, MSK_NORMAL},
	{"ip", "Unset IP parameters", CMD_IPSEC_CONNECTION_NO_L2TP_PPP_IP, NULL, 1, MSK_NORMAL},
	{"mtu", "Default interface mtu", NULL, l2tp_ppp_nomtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO_L2TP[] = {
	{"peer", "Clear remote peer", NULL, l2tp_peer, 1, MSK_NORMAL},
	{"ppp", "Unset PPP options", CMD_IPSEC_CONNECTION_NO_L2TP_PPP, NULL, 1, MSK_NORMAL},
	{"protoport", "Clear protoport", NULL, set_ipsec_l2tp_protoport, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_NO[] = {
	{"local", "Local settings of the tunnel", CMD_IPSEC_CONNECTION_NO_LOCAL, NULL, 1, MSK_NORMAL},
	{"pfs", "Disable PFS", NULL, ipsec_pfs, 1, MSK_NORMAL},
	{"remote", "Remote settings of the tunnel", CMD_IPSEC_CONNECTION_NO_REMOTE, NULL, 1, MSK_NORMAL},
	{"l2tp", "L2TP settings of the tunnel", CMD_IPSEC_CONNECTION_NO_L2TP, NULL, 1, MSK_NORMAL},
	{"shutdown", "Bring the connection up", NULL, ipsec_link_up, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_CHILDREN[] = {
	{"authby", "Key type", CMD_IPSEC_CONNECTION_AUTHBY, NULL, 1, MSK_NORMAL},
	{"authproto", "Authentication protocol", CMD_IPSEC_CONNECTION_AUTHPROTO, NULL, 1, MSK_NORMAL},
	{"esp", "ESP crypto configuration", CMD_IPSEC_CONNECTION_ESP, set_esp_hash, 1, MSK_NORMAL},
	{"exit", "Exit from connection configuration mode", NULL, config_connection_done, 1, MSK_NORMAL},
	{"local", "Local settings of the tunnel", CMD_IPSEC_CONNECTION_LOCAL, NULL, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_IPSEC_CONNECTION_NO, NULL, 1, MSK_NORMAL},
	{"pfs", "Enable PFS", NULL, ipsec_pfs, 1, MSK_NORMAL},
	{"remote", "Remote settings of the tunnel", CMD_IPSEC_CONNECTION_REMOTE, NULL, 1, MSK_NORMAL},
	{"l2tp", "L2TP settings of the tunnel", CMD_IPSEC_CONNECTION_L2TP, NULL, 1, MSK_NORMAL},
	{"shutdown", "Shutdown connection", NULL, ipsec_link_down, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ADD_NAME[] = {
	{"<text>", "Connection name", NULL, add_ipsec_conn, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_IPSEC_CONNECTION_ADD[] = {
	{"add", "Add a new connection", CMD_IPSEC_CONNECTION_ADD_NAME, NULL, 1, MSK_NORMAL},
#if CMDS_BEF_LIST != 1	/* number of nodes before static list. BE CAREFUL */
  #error *** Review the code! Only one node before static list.
#endif
#if IPSEC_MAX_CONN <= 50
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
#else
  #error *** This firmware supports a maximum of 50 tunnels. For another number review the code!
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_IPSEC_CONNECTION[] = {
	{"connection", "Manage connections", CMD_IPSEC_CONNECTION_ADD, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef IPSEC_SUPPORT_RSA_RAW
cish_command CMD_CRYPTO_KEY_RSA_LEN[] = {
	{"512-2048", "Length in bits (multiple of 16)", NULL, generate_rsa_key, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_KEY_RSA[] = {
	{"rsa", "RSA pair keys", CMD_CRYPTO_KEY_RSA_LEN, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_KEY_GENERATE[] = {
	{"generate", "Generate new keys", CMD_CRYPTO_KEY_RSA, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif /* IPSEC_SUPPORT_RSA_RAW */

cish_command CMD_CRYPTO_IPSEC_NO_CONN[] = {
#if IPSEC_MAX_CONN <= 50
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/* static allocation */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
	{NULL,NULL,NULL,NULL, 0, MSK_NORMAL},	/*        "          */
#else
  #error *** This firmware supports a maximum of 50 tunnels. For another number review the code!
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_IPSEC_NO[] = {
	{"connection", "Delete a connection", CMD_CRYPTO_IPSEC_NO_CONN, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

extern cish_command CMD_CRYPTO_L2TP_POOL3[]; /* Loop! */

cish_command CMD_CRYPTO_L2TP_POOL11[] = {
	{"<netmask>", "Network mask", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL10[] = {
	{"<text>", "Domain name for the client", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL9[] = {
	{"<ipaddress>", "IP address of a DNS server", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL83[] = {
	{"0-59", "seconds", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL82[] = {
	{"0-59", "minutes", CMD_CRYPTO_L2TP_POOL83, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL81[] = {
	{"0-23", "hours", CMD_CRYPTO_L2TP_POOL82, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL8[] = {
	{"0-20000", "days", CMD_CRYPTO_L2TP_POOL81, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL7[] = {
	{"<ipaddress>", "IP address of a NetBIOS name server WINS (NBNS)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL6[] = {
	{"<ipaddress>", "IP address of a NetBIOS datagram distribution server (NBDD)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL5[] = {
	{"B", "NetBIOS B-node (Broadcast - no WINS)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{"P", "NetBIOS P-node (Peer - WINS only)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{"M", "NetBIOS M-node (Mixed - broadcast, then WINS)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{"H", "NetBIOS H-node (Hybrid - WINS, then broadcast)", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL4[] = {
	{"<ipaddress>", "IP address of the default router", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL3[] = {
	{"default-lease-time", "Specify default lease time", CMD_CRYPTO_L2TP_POOL8, NULL, 1, MSK_NORMAL},
	{"domain-name", "Specify the domain name for the client", CMD_CRYPTO_L2TP_POOL10, NULL, 1, MSK_NORMAL},
	{"dns-server", "Specify the IP address of a DNS server", CMD_CRYPTO_L2TP_POOL9, NULL, 1, MSK_NORMAL},
	{"mask", "Specify network mask", CMD_CRYPTO_L2TP_POOL11, NULL, 1, MSK_NORMAL},
	{"max-lease-time", "Specify maximum lease time", CMD_CRYPTO_L2TP_POOL8, NULL, 1, MSK_NORMAL},
	{"netbios-name-server", "Specify the IP address of the NetBIOS name server WINS (NBNS)", CMD_CRYPTO_L2TP_POOL7, NULL, 1, MSK_NORMAL},
	{"netbios-dd-server", "Specify the IP address of the NetBIOS datagram distribution server (NBDD)", CMD_CRYPTO_L2TP_POOL6, NULL, 1, MSK_NORMAL},
	{"netbios-node-type", "Specify the NetBIOS node type of the client", CMD_CRYPTO_L2TP_POOL5, NULL, 1, MSK_NORMAL},
	{"router", "Specify the IP address of the default router", CMD_CRYPTO_L2TP_POOL4, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL2[] = {
	{"<ipaddress>", "Pool end", CMD_CRYPTO_L2TP_POOL3, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL1[] = {
	{"<ipaddress>", "Pool begin", CMD_CRYPTO_L2TP_POOL2, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL_ETHERNET[] = {
	{"0-0", "DHCP address pool on ethernet", NULL, l2tp_dhcp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP_POOL[] = {
	{"ethernet", "DHCP address pool on ethernet", CMD_CRYPTO_L2TP_POOL_ETHERNET, NULL, 1, MSK_NORMAL},
	{"local", "Local DHCP address pool", CMD_CRYPTO_L2TP_POOL1, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_L2TP[] = {
	{"pool", "L2TP IP pool server", CMD_CRYPTO_L2TP_POOL, NULL, 1, MSK_NORMAL},
	{"server", "Enable L2TP server", NULL, l2tp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_NO_L2TP[] = {
	{"server", "Disable L2TP server", NULL, l2tp_server, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_PKI
cish_command CMD_CRYPTO_PKI_NO_CA[] = {
	{"<string>", "CA identification", NULL, pki_no, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI_NO[] = {
	{"ca", "Delete X.509 Certificate Authority", CMD_CRYPTO_PKI_NO_CA, NULL, 1, MSK_NORMAL},
	{"cert", "Delete X.509 Certificate", NULL, pki_no, 1, MSK_NORMAL},
	{"csr", "Delete X.509 Certificate Signing Request", NULL, pki_no, 1, MSK_NORMAL},
	{"privkey", "Delete Private RSA Key", NULL, pki_no, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI_GENERATE[] = {
	{"generate", "Trigger generation", NULL, pki_generate, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI_KEYLEN[] = {
	{"768-2048", "key length", CMD_CRYPTO_PKI_GENERATE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI_CA_NAME[] = {
	{"<string>", "CA identification", NULL, pki_cacert_add, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI_CA[] = {
	{"add", "Add CA", CMD_CRYPTO_PKI_CA_NAME, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI_CERT[] = {
	{"add", "Add host certificate signed by CA", NULL, pki_cert_add, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef IPSEC_SUPPORT_SCEP
cish_command CMD_CRYPTO_PKI_SCEP_CA[] = {
	{"<text>", "CA used to generate PKCS#7 message", NULL, pki_csr_enroll, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI_SCEP[] = {
	{"<url>", "SCEP Server URL", CMD_CRYPTO_PKI_SCEP_CA, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CRYPTO_PKI_CSR[] = {
#ifdef IPSEC_SUPPORT_SCEP
	{"scep", "Simple Certificate Enrollment Protocol Options",  CMD_CRYPTO_PKI_SCEP, NULL, 1, MSK_NORMAL},
#endif
	{"generate", "Generate PKCS#10 to offline enrollment", NULL, pki_generate, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CRYPTO_PKI[] = {
	{"ca", "X.509 Certificate Authorities Options", CMD_CRYPTO_PKI_CA, NULL, 1, MSK_NORMAL},
	{"cert", "X.509 Certificate Options", CMD_CRYPTO_PKI_CERT, NULL, 1, MSK_NORMAL},
	{"csr", "X.509 Certificate Signing Request Options", CMD_CRYPTO_PKI_CSR, NULL, 1, MSK_NORMAL},
	{"privkey", "Private RSA Key Options", CMD_CRYPTO_PKI_KEYLEN, NULL, 1, MSK_NORMAL},
	{"save", "Save PKI keys and certificates in non-volatile memory", NULL, pki_save, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#endif /* OPTION_PKI */

cish_command CMD_CRYPTO_NO[] = {
#if 0
	{"auto-reload", "Disable auto-reload interval", NULL, ipsec_autoreload, 1, MSK_NORMAL},
#endif
	{"ipsec", "Manage IPSEC tunnels", CMD_CRYPTO_IPSEC_NO, NULL, 1, MSK_NORMAL},
	{"l2tp", "Manage L2TP server", CMD_CRYPTO_NO_L2TP, NULL, 1, MSK_NORMAL},
	{"nat-traversal", "Disable NAT-Traversal", NULL, ipsec_nat_traversal, 1, MSK_NORMAL},
	{"overridemtu", "Disable override interface crypto MTU setting", NULL, ipsec_overridemtu, 1, MSK_NORMAL},
#ifdef OPTION_PKI
	{"pki", "Public-Key Infrastructure Settings", CMD_CRYPTO_PKI_NO, NULL, 1, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CRYPTO_OVERRIDEMTU[] = {
	{"64-1460", "Override interface crypto MTU setting", NULL, ipsec_overridemtu, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CONFIG_CRYPTO[] = {
#if 0
	{"auto-reload", "Configure auto-reload interval (seconds)", CMD_CONFIG_CRYPTO_AUTORELOAD, NULL, 1, MSK_NORMAL},
#endif
	{"exit", "Exit from crypto configuration mode", NULL, config_crypto_done, 1, MSK_NORMAL},
	{"ipsec", "Manage IPSEC tunnels", CMD_CRYPTO_IPSEC_CONNECTION, NULL, 1, MSK_NORMAL},
#ifdef IPSEC_SUPPORT_RSA_RAW
	{"key", "Manage keys", CMD_CRYPTO_KEY_GENERATE, NULL, 1, MSK_NORMAL},
#endif
	{"l2tp", "Manage L2TP server", CMD_CRYPTO_L2TP, NULL, 1, MSK_NORMAL},
	{"nat-traversal", "Manage NAT-Traversal", NULL, ipsec_nat_traversal, 1, MSK_NORMAL},
	{"no", "Reverse settings", CMD_CRYPTO_NO, NULL, 1, MSK_NORMAL},
	{"overridemtu", "Override interface crypto MTU setting", CMD_CONFIG_CRYPTO_OVERRIDEMTU, NULL, 1, MSK_NORMAL},
#ifdef OPTION_PKI
	{"pki", "Public-Key Infrastructure Settings", CMD_CRYPTO_PKI, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_SHOWLEVEL
	{"show", "Show level configuration", CMD_SHOW_LEVEL, NULL, 0, MSK_NORMAL},
#endif
	{NULL,NULL,NULL,NULL, 0}
};
#endif /* OPTION_IPSEC */
