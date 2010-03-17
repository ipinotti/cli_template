
OBJS 		= cish_main.o \
		  cish_tacplus.o \
		  commands_aaa.o \
		  commands_vlan.o \
		  commands_icmptools.o \
		  commands_telnet.o \
		  commands_tcpdump.o \
		  commands_ip.o \
		  commands_ipx.o \
		  commands_show.o \
		  commands_fr.o \
		  commands_chdlc.o \
		  commands_ppp.o \
		  commands_bridge.o \
		  commands_feature.o \
		  commandtree.o \
		  commands_crypto.o \
		  command_exit.o \
		  commands_ntp.o \
		  commands_rmon.o \
		  commands_sppp.o \
		  commands_vrrp.o \
		  commands_x25.o \
		  debug.o \
		  terminal_echo.o \
		  command_route.o \
		  enable.o \
		  configterm.o \
		  config_policymap.o \
		  acl.o \
		  mangle.o \
		  nat.o \
		  sys_exec.o \
		  interface_snmp.o \
		  pprintf.o \
		  config_router.o \
		  match.o \
		  hash.o \
		  cish_config.o \
		  hardkey.o \
		  crc.o
		  #cgi-main.o
		  #ssi.o
		  #ssi_cmds.o

all: cish utils

install: cish utils
	cp -f cish /tftpboot/10.1.0.2/bin
	cp -f cish /tftpboot/10.1.0.2/web/exec
	cp -f cish /tftpboot/10.1.0.2/web/ssi
	cp -f cish /tftpboot/10.1.0.2/web/config
	cp -f cish /tftpboot/10.1.0.2/web/interface
	make -C util install

clean:
	rm -f $(OBJS) cish
	make -C util clean

cish: $(OBJS)
	$(CC) -o cish $(OBJS) $(LDFLAGS) $(LIBS)

utils:
	make -C util

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<
