# makefile for Lua core library

LUA= ..

include $(LUA)/config

ifneq ($(strip $(LUA_MINIMAL)),y)

# Normal build (with parser)
#
OBJS=	\
	lapi.o \
	lcode.o \
	ldebug.o \
	ldo.o \
	ldump.o \
	lfunc.o \
	lgc.o \
	llex.o \
	lmem.o \
	lobject.o \
	lopcodes.o \
	lparser.o \
	lstate.o \
	lstring.o \
	ltable.o \
	ltests.o \
	ltm.o \
	lundump.o \
	lvm.o \
	lzio.o

SRCS=	\
	lapi.c \
	lcode.c \
	ldebug.c \
	ldo.c \
	ldump.c \
	lfunc.c \
	lgc.c \
	llex.c \
	lmem.c \
	lobject.c \
	lopcodes.c \
	lparser.c \
	lstate.c \
	lstring.c \
	ltable.c \
	ltests.c \
	ltm.c \
	lundump.c \
	lvm.c \
	lzio.c \
	lapi.h \
	lcode.h \
	ldebug.h \
	ldo.h \
	lfunc.h \
	lgc.h \
	llex.h \
	llimits.h \
	lmem.h \
	lobject.h \
	lopcodes.h \
	lparser.h \
	lstate.h \
	lstring.h \
	ltable.h \
	ltm.h \
	lundump.h \
	lvm.h \
	lzio.h

else

# We don't want the parsing modules
#
OBJS=	\
	lapi.o \
	ldebug.o \
	ldo.o \
	ldump.o \
	lfunc.o \
	lgc.o \
	lmem.o \
	lobject.o \
	lopcodes.o \
	lstate.o \
	lstring.o \
	ltable.o \
	ltests.o \
	ltm.o \
	lundump.o \
	lvm.o \
	lzio.o \
	stubs.o

SRCS=	\
	lapi.c \
	ldebug.c \
	ldo.c \
	ldump.c \
	lfunc.c \
	lgc.c \
	lmem.c \
	lobject.c \
	lopcodes.c \
	lstate.c \
	lstring.c \
	ltable.c \
	ltests.c \
	ltm.c \
	lundump.c \
	lvm.c \
	lzio.c \
	stubs.c \
	lapi.h \
	lcode.h \
	ldebug.h \
	ldo.h \
	lfunc.h \
	lgc.h \
	llex.h \
	llimits.h \
	lmem.h \
	lobject.h \
	lopcodes.h \
	lparser.h \
	lstate.h \
	lstring.h \
	ltable.h \
	ltm.h \
	lundump.h \
	lvm.h \
	lzio.h

endif

TD= $(BIN)/liblua.$(DL_EXT)
TS= $(LIB)/liblua.a

all:	$(TD) $(TS)

$(TD):	$(OBJS)
	$(CC) $(MYLDFLAGS) -shared -o $@ $(OBJS)

$(TS):	$(OBJS)
	$(AR) $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f $(OBJS) $(TD) $(TS)

co:
	co -q -f -M $(SRCS)

klean:	clean
	rm -f $(SRCS)
