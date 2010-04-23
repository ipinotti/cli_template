SUBDIRS = \
	cmds

bin_PROGRAMS = \
	cish

cish_SOURCES = \
	cish_main.c \
	cish_config.c \
	cish_tacplus.c \
	commandtree.c \
	config_policymap.c \
	config_router.c \
	configterm.c \
	debug.c \
	enable.c \
	hash.c \
	interface_snmp.c \
	match.c \
	pprintf.c \
	ssi.c \
	ssi_cmds.c \
	sys_exec.c \
	terminal_echo.c \
	crc.S

cish_LIBADD = \
	$(top_builddir)/src/cmds/libcmds.la
