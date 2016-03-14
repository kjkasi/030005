# File: drivers/char/wstl/flshmgmt/Makefile
#
# Makefile for the board level driver
#

wstlflmt-objs := flshmgmt.oo datarecords.oo

obj-$(CONFIG_WSTL_FLASHMGMT) += wstlflmt.oo

EXTRA_CFLAGS += -I. -fno-exceptions

EXTRA_CFLAGS += -I$(WSTLDRIVERS_DIR)/include

ifeq ($(CONFIG_WSTL_AMAZONSE),y)
EXTRA_CFLAGS += -DCONFIG_WSTL_AMAZONSE
endif
ifeq ($(BUILD_RTL8196C),y)
EXTRA_CFLAGS += -DBUILD_RTL8196C
endif

-include $(TOPDIR)/Rules.make

clean:
	rm -f core *.o *.a *.s
