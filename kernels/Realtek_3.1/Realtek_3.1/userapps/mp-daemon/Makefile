all:	UDPserver

#CC	= mips-uclibc-gcc
#STRIP	= mips-uclibc-strip

WSTL_LIBS_DIR   := $(WESTELL_APP_DIR)/libs
CFLAGS	=
IFLAGS	=
LDFLAGS =

ifeq ($(SLINK),1)
CFLAGS  += -ffunction-sections -fdata-sections
LDFLAGS += --static -Wl,--gc-sections
endif

CFLAGS += -I$(WSTL_CFG_DIR)/include
CFLAGS += -I$(WSTL_LIBS_DIR)/include
DEBUG	= -Wall -Os

OBJ_DEPEND = $(WSTL_CFG_DIR)/lib/libcfg.so

UDPserver: Makefile UDPserver.o $(OBJ_DEPEND)
	$(CC) -o $@ $(DEBUG) $(CFLAGS) $(IFLAGS) $(LDFLAGS) UDPserver.o -L$(LIBUTIL_DIR) -L$(WSTL_CFG_DIR)/lib -lcfg -lpthread -lwstlUtil
	$(STRIP) $@
romfs:
	$(ROMFSINST) /bin/UDPserver

clean:
	rm -f UDPserver *.o 

UDPserver.o: UDPserver.c
	$(CC) -c -o $@ $(DEBUG) $(CFLAGS) $(IFLAGS) $<
