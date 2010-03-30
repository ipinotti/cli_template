include ../../../common.mk

CFLAGS		= -O0 -g -Wall
INCLUDES	= -I. -I$(ROOTDIR)/include
LIBS		= -lconfig
HASHLIBS	=
LDFLAGS 	= -L$(ROOTDIR)/lib

all: cishinit ifstat bwmon #rfc1356

install: cishinit ifstat bwmon
clean:
	rm -f *.o cishinit ifstat bwmon rfc1356 core

cishinit: cishinit.o
	$(CC) $(LDFLAGS) -o cishinit cishinit.o

ifstat: ifstat.o
	$(CC) $(LDFLAGS) -o ifstat ifstat.o

systtyd: systtyd.o
	$(CC) $(LDFLAGS) -o systtyd systtyd.o $(LIBS)

bwmon: bwmon.o
	$(CC) $(LDFLAGS) -o bwmon bwmon.o $(LIBS)

rfc1356: rfc1356.o
	$(CC) -o rfc1356 rfc1356.o

rfc1356.o: rfc1356.c $(TOPDIR)/include/linux/sk_tunnel.h
	$(CC) -I $(TOPDIR)/include -c -o $@ $(@:.o=.c)

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<
