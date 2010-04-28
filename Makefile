
OBJS 		= cish_main.o \
		  cish_tacplus.o \
		  commands_aaa.o \
		  commands_vlan.o \
		  commands_icmptools.o \
		  commands_telnet.o \
		  commands_tcpdump.o \
		  commands_ip.o \
		  commands_show.o \
		  commands_ppp.o \
		  commandtree.o \
		  commands_crypto.o \
		  command_exit.o \
		  commands_ntp.o \
		  commands_rmon.o \
		  debug.o \
		  terminal_echo.o \
		  command_route.o \
		  enable.o \
		  configterm.o \
		  config_policymap.o \
		  commands_acl.o \
		  commands_mangle.o \
		  commands_nat.o \
		  sys_exec.o \
		  interface_snmp.o \
		  pprintf.o \
		  config_router.o \
		  match.o \
		  hash.o \
		  cish_config.o \
		  crc.o
		 
all: cish utils

install: cish utils
	cp -f cish /tftpboot/10.1.0.2/bin
	cp -f cish /tftpboot/10.1.0.2/web/exec
	cp -f cish /tftpboot/10.1.0.2/web/ssi
	cp -f cish /tftpboot/10.1.0.2/web/config
	cp -f cish /tftpboot/10.1.0.2/web/interface
	$(MAKE) -C util install

clean:
	rm -f $(OBJS) cish
	$(MAKE) -C util clean

cish: $(OBJS)
	$(CC) -o cish -Wl,--rpath,$(ROOTDIR)/$(FSDIR)/lib $(OBJS) $(LDFLAGS) $(LIBS)

utils:
	$(MAKE) -C util

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<
