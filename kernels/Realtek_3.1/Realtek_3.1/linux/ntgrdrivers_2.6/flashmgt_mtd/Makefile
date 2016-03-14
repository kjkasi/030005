# File: drivers/char/wstl/flshmgmt/Makefile
#
# Makefile for the board level driver
#

wstlflmt-objs := flshmgmt.oo datarecords.oo flTools.oo flash_layer.oo crc.oo flash.oo FlashHdrUtil.oo

obj-$(CONFIG_WSTL_FLASHMGMT_MTD) += wstlflmt.oo

EXTRA_CFLAGS += -I. -fno-exceptions

EXTRA_CFLAGS += -I$(WSTLDRIVERS_DIR)/include -DCONFIG_WSTL_FLASHMGMT_MTD

ifeq ($(CONFIG_WSTL_AMAZONSE),y)
EXTRA_CFLAGS += -DCONFIG_WSTL_AMAZONSE
endif
ifeq ($(BUILD_RTL8196C),y)
EXTRA_CFLAGS += -DBUILD_RTL8196C
endif

ifeq ($(CONFIG_WSTL_FFS),y)
EXTRA_CFLAGS += -DCONFIG_WSTL_FFS
endif

-include $(TOPDIR)/Rules.make

clean:
	rm -f core *.o *.a *.s
