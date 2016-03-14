.EXPORT_ALL_VARIABLES:

LTOP=$(shell pwd)
CFLAGS += -I$(KERNEL_DIR)/include -I$(INC_KERNEL_PATH) 

LDFLAGS += -L$(FLEX_DIR)     

HOST=$(ARCH)-unknown-linux

all: Makefile
	$(MAKE)

Makefile:
	@echo "LTOP = $(LTOP)"
	echo "CFLAGS = $(CFLAGS)"
	@echo "HOST = $(HOST)"
	$(SHELL) ./configure --host=$(HOST)

clean:
	test ! -f Makefile || $(MAKE) distclean
