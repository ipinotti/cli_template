include ../../common.mk

all:
	CFLAGS='-O2 -Wall' \
	INCLUDES='-I. -I$(ROOTDIR)/include -I$(ROOTDIR)/include/ncurses' \
	LDFLAGS='-L$(ROOTDIR)/$(FSDIR)/lib' \
	LIBS='-lncurses -lcrypt -lreadline -lconfig -lconfigsnmp' \
	$(MAKE);

install: all
	cp -avf cish $(ROOTDIR)/$(FSDIR)/bin
	cp -avf util/bwmon $(ROOTDIR)/$(FSDIR)/bin

clean:
	rm -f cish
	rm -f util/bwmon
	rm -f util/systtyd
	rm -f util/rfc1356
	rm -f util/cishinit
	rm -f util/ifstat
	find -iname "*.o" -exec rm {} \;

distclean: clean
	find -iname "*~" -exec rm {} \;
