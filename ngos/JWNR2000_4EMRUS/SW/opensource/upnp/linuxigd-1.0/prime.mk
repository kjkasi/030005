
.EXPORT_ALL_VARIABLES:

# CC = /opt/toolchains/westell_msw2/bin/mips-linux-uclibc-gcc
BTOP=$(PWD)# actually returns PWD of where top make was exec
LTOP=$(shell pwd)
# -I$(BTOP)/linux/linux-2.6.8.1/include/linux/
WSTL_CFLAGS = -I$(LIBUPNP_DIR)/install/usr/local/include/ -L$(LIBUPNP_DIR)/install/usr/local/lib/
CFLAGS += $(WSTL_CFLAGS) -I$(INC_KERNEL_PATH) -I$(INC_KERNEL_PATH1) -I$(KERNEL_DIR)/include

all: Makefile
	$(MAKE) DESTDIR=$(LTOP)/install install
	@echo WESTELL POST install

Makefile:
	@echo "BTOP = $(BTOP)"
	@echo "LTOP = $(LTOP)"
	@echo "CFLAGS = $(CFLAGS)"
	case "$(CC)" in *mips*) ;; *) false;; esac;
	mkdir -p install

clean:
	test ! -f Makefile || $(MAKE) DESTDIR=$(LTOP)/install clean
	-rm -rf install

