include ../../common.mk

CFLAGS= -O2 -Wall -I. -I$(ROOTDIR)/include -I$(ROOTDIR)/include/ncurses \
	  -I$(ROOTDIR)/$(FSDIR)/include
LDFLAGS= -L$(ROOTDIR)/$(FSDIR)/lib

all: config
	$(MAKE) all

config: configure
	if [ ! -f Makefile ]; then \
		export CFLAGS="$(CFLAGS)"; \
		export LDFLAGS="$(LDFLAGS)"; \
		./configure --prefix='$(ROOTDIR)/fs' \
		--host='powerpc-hardhat-linux' \
		--build='i386'; \
	fi

configure:
	autoreconf -i

install:
	$(MAKE) install
clean:
	$(MAKE) clean
distclean:
	$(MAKE) distclean
