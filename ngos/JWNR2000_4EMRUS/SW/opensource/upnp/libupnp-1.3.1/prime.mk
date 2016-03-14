
.EXPORT_ALL_VARIABLES:

BTOP=$(PWD)# actually returns PWD of where top make was exec
LTOP=$(shell pwd)
CFLAGS += -I$(INC_KERNEL_PATH) -I$(INC_KERNEL_PATH1) -I$(KERNEL_DIR)/include

all: Makefile
	$(MAKE) DESTDIR=$(LTOP)/install install
	@echo WESTELL POST install

Makefile:
	@echo "BTOP = $(BTOP)"
	@echo "LTOP = $(LTOP)"
	@echo "CFLAGS = $(CFLAGS)"
	case "$(CC)" in *mips*) ;; *) false;; esac;
	$(SHELL) ./configure --host=mips-broadcom-linux
	mkdir -p install

clean:
	test ! -f Makefile || $(MAKE) DESTDIR=$(LTOP)/install distclean
	-rm -rf install 

