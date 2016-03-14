
# brcm begin
KERNEL_HEADERS=-I$(KERNEL_DIR)/include

#AR=ar
#RANLIB=ranlib

#CC=gcc
#CFLAGS = -Wall -g $(KERNEL_HEADERS)
CFLAGS = -Wall -Os $(KERNEL_HEADERS)
ifeq ($(FEATURE_BRIDGELAN2WAN),y)
CFLAGS += -fPIC
endif
# brcm end

prefix=/usr/local
exec_prefix=${prefix}
includedir=${prefix}/include
libdir=${exec_prefix}/lib

libbridge_SOURCES= \
	libbridge_devif.c \
	libbridge_if.c \
	libbridge_init.c \
	libbridge_misc.c 

libbridge_OBJECTS=$(libbridge_SOURCES:.c=.o)

ifeq ($(FEATURE_BRIDGELAN2WAN),y)
all:	libbridge.so
else
all:	libbridge.a
endif

install: libbridge.a
	mkdir -p $(DESTDIR)$(includedir)
	install -m 644 libbridge.h $(DESTDIR)$(includedir)
	mkdir -p $(DESTDIR)$(libdir)
	install -m 644 libbridge.a $(DESTDIR)$(libdir)

clean:
	rm -f *.o libbridge.a libbridge.so

libbridge.a:	$(libbridge_OBJECTS)
	$(AR) rcs $@ $(libbridge_OBJECTS)
	$(RANLIB) $@

ifeq ($(FEATURE_BRIDGELAN2WAN),y)
libbridge.so:	$(libbridge_OBJECTS)
	$(CC) -shared -o $@ $(libbridge_OBJECTS)
endif

%.o: %.c libbridge.h libbridge_private.h
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

libbridge_compat.o:	libbridge_compat.c if_index.c
	$(CC) $(CFLAGS) -c libbridge_compat.c

