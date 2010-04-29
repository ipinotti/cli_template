SUBDIRS = \
	cmds

bin_PROGRAMS = \
	cish

cish_SOURCES = \
	cish_main.c \
	cish_config.c \
	cish_tacplus.c \
	match.c \
	pprintf.c \
	terminal_echo.c \
	commandtree.c \
	config_policymap.c \
	config_router.c \
	config_terminal.c \
	config_interface.c \
	config_snmp.c \
	config_debug.c \
	config_enable.c


cish_LDADD = \
	$(top_builddir)/src/cmds/libcmds.la
