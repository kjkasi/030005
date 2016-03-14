PREFIX=/usr
LIBUPNP_PREFIX=/usr
#LIBIPTC_PREFIX=/usr

#CC=gcc
#INCLUDES= -I$(LIBUPNP_PREFIX)/include -I../include
LIBS= -lpthread -lupnp -lixml -lthreadutil -L$(LIBUPNP_PREFIX)/lib -L../libs
FILES= main.o gatedevice.o pmlist.o util.o config.o

CFLAGS += -Wall -g -O2 -static

ifdef HAVE_LIBIPTC
ifdef LIBIPTC_PREFIX
LIBS += -L$(LIBIPTC_PREFIX)/lib
#INCLUDES += -I$(LIBIPTC_PREFIX)/include
endif

LIBS += -liptc
INCLUDES += -DHAVE_LIBIPTC
FILES += iptc.o
endif

all: upnpd

upnpd: $(FILES)
	$(CC) $(CFLAGS) $(FILES) $(LIBS) -o $@
	@echo "make $@ finished on `date`"

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o upnpd

install: upnpd
	install -d $(DESTDIR)/etc/linuxigd
	install -d $(DESTDIR)/sbin
	install etc/gatedesc.xml $(DESTDIR)/etc/linuxigd
	install etc/gateconnSCPD.xml  $(DESTDIR)/etc/linuxigd
	install etc/gateicfgSCPD.xml $(DESTDIR)/etc/linuxigd
	install etc/dummy.xml $(DESTDIR)/etc/linuxigd
	install upnpd $(DESTDIR)/sbin
	install etc/upnpd.conf $(DESTDIR)/etc
