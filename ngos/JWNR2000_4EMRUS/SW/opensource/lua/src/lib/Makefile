# makefile for Lua standard library

LUA= ../..

include $(LUA)/config

EXTRA_DEFS= $(POPEN) $(TMPNAM) $(DEGREES) $(LOADLIB)

ifneq ($(strip $(LUA_MINIMAL)),y)

# Normal build (with parser)
#
OBJS= lbaselib.o ldblib.o liolib.o lmathlib.o ltablib.o lstrlib.o loadlib.o lauxlib.o 
SRCS= lbaselib.c ldblib.c liolib.c lmathlib.c ltablib.c lstrlib.c loadlib.c lauxlib.c 

else

# Minimal build (without parser)
#
OBJS= lbaselib.o ldblib.o liolib.o ltablib.o lstrlib.o loadlib.o lauxlib.o 
SRCS= lbaselib.c ldblib.c liolib.c ltablib.c lstrlib.c loadlib.c lauxlib.c 

endif

TD= $(BIN)/liblualib.$(DL_EXT)
TS= $(LIB)/liblualib.a

all:	$(TD) $(TS)

$(TD):	$(OBJS) $(BIN)/liblua.$(DL_EXT)
	$(CC) $(MYLDFLAGS) -shared -o $@ $(OBJS) -L$(BIN) -llua

## EDW - this was the original link commad - which
##  was hardcoding the link to the lua library.
#	$(CC) -shared -o $@ $(OBJS) $(BIN)/liblua.$(DL_EXT)

$(TS):	$(OBJS)
	$(AR) $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f $(OBJS) $(TD) $(TS)

co:
	co -q -f -M $(SRCS)

klean:	clean
	rm -f $(SRCS)
