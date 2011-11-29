#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#include "commands.h"
#include "commandtree.h"

cish_command CMD_CONFIG[] = {
	{"memory","Configure from NV memory", NULL, config_memory, 1, MSK_NORMAL},
	{"terminal","Configure through terminal", NULL, config_term, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TRACEROUTE[] = {
	{"<ipaddress>", "Destination host", NULL, traceroute, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TRACEROUTE6[] = {
	{"<ipv6address>", "Destination host", NULL, traceroute, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING7[] = {
	{"1-1000000", "count", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING6[] = {
	{"count", "Repeat count", CMD_PING7, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING5[] = {
	{"0-65468", "bytes", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING4[] = {
	{"size", "Datagram size", CMD_PING5, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING3B[] = {
	{"0-65468", "bytes", CMD_PING6, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING3A[] = {
	{"1-1000000", "count", CMD_PING4, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING2[] = {
	{"count", "Repeat count", CMD_PING3A, NULL, 0, MSK_NORMAL},
	{"size", "Datagram size", CMD_PING3B, NULL, 0, MSK_NORMAL},
	{"<enter>", "", NULL, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_PING[] = {
	{"<ipaddress>", "Destination host", CMD_PING2, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_IPV6
cish_command CMD_PING_IPV6[] = {
	{"<ipv6address>", "Destination host", CMD_PING2, ping, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_SSH3[] = {
	{"1-65535", "Port number", NULL, ssh, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SSH2[] = {
	{"<text>", "Username", CMD_SSH3, ssh, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_SSH[] = {
	{"<ipaddress>", "IP address of a remote system", CMD_SSH2, ssh, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TELNET2[] = {
	{"1-65535", "Port number", NULL, telnet, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TELNET[] = {
	{"<ipaddress>", "IP address of a remote system", CMD_TELNET2, telnet, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_TCPDUMP[] = {
	{"<text>", "tcpdump options", NULL, tcpdump, 0, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_COPY_TFTP3[] = {
	{"<text>", "Name of configuration file", NULL, cmd_copy, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_TFTP2[] = {
	{"<ipaddress>", "IP address of remote host", CMD_COPY_TFTP3, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_FROM_TFTP[] = {
	{"running-config", "Update (merge with) current system configuration", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{"startup-config", "Copy to startup configuration", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_FROM_START[] = {
	{"running-config", "Update (merge with) current system configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"tftp", "Copy to a TFTP server", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY_FROM_RUN[] = {
#ifdef CONFIG_DEVELOPMENT
	{"slot0-config", "Copy to slot0 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot1-config", "Copy to slot1 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot2-config", "Copy to slot2 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot3-config", "Copy to slot3 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"slot4-config", "Copy to slot4 configuration", NULL, cmd_copy, 1, MSK_NORMAL},
#endif
	{"startup-config", "Copy to startup configuration", NULL, cmd_copy, 1, MSK_NORMAL},
	{"tftp", "Copy to a TFTP server", CMD_COPY_TFTP2, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_COPY[] = {
	{"previous-config", "Copy from previous configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"running-config", "Copy from current system configuration", CMD_COPY_FROM_RUN, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_DEVELOPMENT
	{"slot0-config", "Copy from slot0 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot1-config", "Copy from slot1 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot2-config", "Copy from slot2 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot3-config", "Copy from slot3 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"slot4-config", "Copy from slot4 configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
#endif
	{"startup-config", "Copy from startup configuration", CMD_COPY_FROM_START, NULL, 1, MSK_NORMAL},
	{"tftp", "Copy from a TFTP server", CMD_COPY_FROM_TFTP, NULL, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_ERASE[] = {
	{"startup-config", "Erase contents of configuration memory", NULL, erase_cfg, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_FIRMWARE_DOWNLOAD[] = {
#ifdef CONFIG_DM
	{"<url>", "Remote site url (http://user:pass@www.enterprise.com.br/filename)", NULL, firmware_download, 1, MSK_NORMAL},
#else
	{"<url>", "Remote site url (http://user:pass@www.pd3.com.br/filename)", NULL, firmware_download, 1, MSK_NORMAL},
#endif
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_NO_FIRMWARE[] = {
	{"upload", "Disable upload firmware mode (FTP server)", NULL, no_firmware_upload, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_FIRMWARE[] = {
	{"download", "Download new firmware", CMD_FIRMWARE_DOWNLOAD, NULL, 1, MSK_NORMAL},
	{"save", "Save uploaded firmware to flash", NULL, firmware_save, 1, MSK_NORMAL},
	{"upload", "Enable upload firmware mode (FTP server)", NULL, firmware_upload, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_NO[] = {
	{"debug", "Disable Debugging parameters", CMD_DEBUG, NULL, 1, MSK_NORMAL},
	{"firmware", "Firmware update", CMD_NO_FIRMWARE, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#if 0
cish_command CMD_FIRMWARE_RAM[] = {
	{"save", "Save uploaded firmware to flash", NULL, firmware_save, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};

cish_command CMD_RAM[] = {
	{"exit","Exit session", NULL, exit_cish, 0, MSK_NORMAL},
	{"firmware","Firmware update", CMD_FIRMWARE_RAM, NULL, 0, MSK_NORMAL},
	{"reload", "Halt and perform a cold restart", NULL, reload, 0, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};
#endif


#ifdef OPTION_RMON
cish_command CMD_CLEAR_RMON[] = {
	{"events", "Clear RMON events", NULL, clear_rmon_events, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CLEAR_SSH[] = {
	{"hosts", "Clear known SSH hosts identification", NULL, clear_ssh_hosts, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef OPTION_CLEAR_INTERFACE_COUNTERS
cish_command CMD_CLEAR_INTERFACE_LOOPBACK_[] = {
	{"0-0", "Loopback interface number", NULL, clear_counters, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_INTERFACE_EFM_[] = {
	{"0-0", "EFM interface number", NULL, clear_counters, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_INTERFACE_ETHERNET_[] = {
	{"0-0", "Ethernet interface number", NULL, clear_counters, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD_CLEAR_INTERFACE[] = {
#ifdef OPTION_EFM
	{"efm", "Aux interface", CMD_CLEAR_INTERFACE_EFM_, NULL, 1, MSK_NORMAL},
#endif
	{"ethernet", "Ethernet interface", CMD_CLEAR_INTERFACE_ETHERNET_, NULL, 1, MSK_NORMAL},
	{"loopback", "Loopback interface", CMD_CLEAR_INTERFACE_LOOPBACK_, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_CLEAR[] = {
	{"logging", "Clear the contents of logging buffers", NULL, clear_logging, 1, MSK_NORMAL},
#ifdef OPTION_CLEAR_INTERFACE_COUNTERS
	{"counters", "Clear counters on interface", CMD_CLEAR_INTERFACE, NULL, 1, MSK_NORMAL},
#endif
#ifdef OPTION_RMON
	{"rmon", "Clear the RMON counters", CMD_CLEAR_RMON, NULL, 1, MSK_NORMAL},
#endif
	{"ssh", "Clear SSH informations", CMD_CLEAR_SSH, NULL, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

#ifdef CONFIG_GIGA
cish_command CMD_GIGA[] = {
	{"script", "Auto configure", NULL, giga_script, 0, MSK_NORMAL},
	{"scriptplus", "Auto configure", NULL, giga_scriptplus, 0, MSK_NORMAL},
	{"terminal", "Terminal access", NULL, giga_terminal, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};
#endif

cish_command CMD_RELOAD_TIMEOUT[] = {
	{"1-60", "Delay before reload in minutes", NULL, reload_in, 1, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};


cish_command CMD_RELOAD[] = {
	{"cancel", "Abort scheduled reload", NULL, reload_cancel, 1, MSK_NORMAL},
	{"in", "Schedule reload timeout", CMD_RELOAD_TIMEOUT, NULL, 1, MSK_NORMAL},
	{"<enter>", "", NULL, NULL, 0, MSK_NORMAL},
	{NULL,NULL,NULL,NULL, 0}
};

cish_command CMD[] = {
	{"clear", "Reset functions", CMD_CLEAR, NULL, 1, MSK_NORMAL},
	{"clock", "Manage the system clock", CMD_CONFIG_CLOCK, NULL, 1, MSK_NORMAL},
	{"configure", "Configure parameters", CMD_CONFIG, NULL, 1, MSK_NORMAL},
	{"copy", "Copy configuration or image data", CMD_COPY, NULL, 1, MSK_NORMAL},
	{"debug", "Debugging parameters", CMD_DEBUG, NULL, 1, MSK_NORMAL},
	{"disable", "Leave administrator mode", NULL, disable, 1, MSK_NORMAL},
	{"enable", "Enter administrator mode", NULL, enable, 0, MSK_ENABLE}, /* enable(); disable(); */
	{"erase", "Erase configuration memory", CMD_ERASE, NULL, 1, MSK_NORMAL},
	{"exit", "Exit session", NULL, exit_cish, 0, MSK_NORMAL},
	{"firmware", "Firmware update", CMD_FIRMWARE, NULL, 1, MSK_NORMAL},
#ifdef CONFIG_GIGA
	{"giga", "Test commands", CMD_GIGA, NULL, 1, MSK_NORMAL},
#endif
	{"help", "Description of the interactive help system", NULL, help, 0, MSK_NORMAL},
	{"no", "Override parameters", CMD_NO, NULL, 1, MSK_NORMAL},
	{"ping", "Send IPv4 echo messages", CMD_PING, NULL, 0, MSK_NORMAL},
#ifdef OPTION_IPV6
	{"ping6", "Send IPv6 echo messages", CMD_PING_IPV6, NULL, 0, MSK_NORMAL},
#endif
	{"reload", "Halt and perform a cold restart", CMD_RELOAD, reload, 1, MSK_NORMAL},
	{"show", "Show running system information", CMD_SHOW, NULL, 0, MSK_NORMAL},
	{"ssh", "Open a SSH connection", CMD_SSH, NULL, 1, MSK_NORMAL},
	{"tcpdump", "Start packet sniffer", CMD_TCPDUMP, tcpdump, 1, MSK_NORMAL},
	{"telnet", "Open a telnet connection", CMD_TELNET, NULL, 1, MSK_NORMAL},
	{"terminal", "Set terminal line parameters", CMD_TERMINAL, NULL, 0, MSK_NORMAL},
	{"traceroute", "Traceroute to an IPv4 destination", CMD_TRACEROUTE, NULL, 0, MSK_NORMAL},
#ifdef OPTION_IPV6
	{"traceroute6", "Traceroute to an IPv6 destination", CMD_TRACEROUTE6, NULL, 0, MSK_NORMAL},
#endif
	{"write", "Save current configuration in non-volatile memory", NULL, config_write, 1, MSK_NORMAL},
	{NULL, NULL, NULL, NULL}
};
