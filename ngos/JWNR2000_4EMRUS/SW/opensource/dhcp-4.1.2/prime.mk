.EXPORT_ALL_VARIABLES:

LTOP=$(shell pwd)
HOST=$(ARCH)-unknown-linux

# Westell added for ATT reqm no. 656
ifeq ($(DHCPV6_SUPPORT_INFORMATION_REQUEST),y)
CFLAGS += -DDHCPV6_SUPPORT_INFORMATION_REQUEST
endif

ifeq ($(DHCPV6_SUPPORT_IA_NA),y)
CFLAGS += -DDHCPV6_SUPPORT_IA_NA
endif

CFLAGS += -DIFT_PPP

all: Makefile
	$(MAKE)
	
Makefile:
	@echo "LTOP = $(LTOP)"
	@echo "CFLAGS = $(CFLAGS)"
	@touch config.cache
	@echo "ac_cv_file__dev_random=yes" > config.cache
	$(SHELL) ./configure --host=$(HOST) --enable-shared=no --cache-file=config.cache --enable-failover=no --enable-tracing=no --enable-execute=no

clean:
	test ! -f Makefile || $(MAKE) distclean
