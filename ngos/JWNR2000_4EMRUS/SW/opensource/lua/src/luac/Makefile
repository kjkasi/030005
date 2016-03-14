# makefile for Lua compiler

LUA= ../..

include $(LUA)/config

INCS= -I$(INC) -I.. $(EXTRA_INCS)
OBJS= luac.o print.o lopcodes.o
SRCS= luac.c print.c

T= $(BIN)/luac$(EXE_EXT)

all:	$T

ifeq ($(LIB_TYPE),dynamic)
$T:	$(OBJS) $(BIN)/liblua.$(DL_EXT) $(BIN)/liblualib.$(DL_EXT)
	$(CC) -o $@ $(MYLDFLAGS) $(OBJS) -L$(BIN) -llua -llualib $(EXTRA_LIBS) $(DLLIB)
else
$T:	$(OBJS) $(LIB)/liblua.a $(LIB)/liblualib.a
	$(CC) -o $@ $(MYLDFLAGS) $(OBJS) -L$(LIB) -llua -llualib $(EXTRA_LIBS) $(DLLIB)
endif

# print.c needs opcode names from lopcodes.c
lopcodes.o:	../lopcodes.c ../lopcodes.h
	$(CC) -o $@ -c $(CFLAGS) -DLUA_OPNAMES ../lopcodes.c

$(LIB)/liblua.a:
	cd ..; $(MAKE)

$(LIB)/liblualib.a:
	cd ../lib; $(MAKE)

$(LIB)/liblua.$(DL_EXT):
	cd ..; $(MAKE)

$(LIB)/liblualib.$(DL_EXT):
	cd ../lib; $(MAKE)

clean:
	rm -f $(OBJS) $(T)

co:
	co -q -f -M $(SRCS)

klean:	clean
	rm -f $(SRCS)
