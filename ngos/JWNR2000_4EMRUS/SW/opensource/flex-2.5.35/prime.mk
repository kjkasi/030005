.EXPORT_ALL_VARIABLES:

LTOP=$(shell pwd)
CFLAGS += -I$(KERNEL_DIR)/include -I$(INC_KERNEL_PATH) 

all: Makefile
	$(MAKE)

Makefile:
	@echo "LTOP = $(LTOP)"
	echo "CFLAGS = $(CFLAGS)"
	cp -f prime.config config.cache
	$(SHELL) ./configure --host=mips-unknown-linux --cache-file=config.cache

clean:
	test ! -f Makefile || $(MAKE) distclean
