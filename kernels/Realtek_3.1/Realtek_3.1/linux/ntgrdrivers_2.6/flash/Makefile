# File: drivers/char/wstl/wflash/Makefile
#
# Makefile for the flash driver
#
obj-$(CONFIG_WSTL_FLASH) += flash.oo flTools.oo FlashHdrUtil.oo crc.oo

ifeq ($(strip $(BRCM_CHIP)),6328)
EXTRA_CFLAGS += -DUSE_SERIAL_FLASH -I$(INC_KERNEL_PATH4)
endif

ifeq ($(strip $(BRCM_CHIP)),6362)
EXTRA_CFLAGS += -DUSE_SERIAL_FLASH -I$(INC_KERNEL_PATH4)
endif
ifeq ($(strip $(BUILD_RTL8196C)),y)
EXTRA_CFLAGS += -fno-exceptions -DUSE_REALTEK_SERIAL_FLASH -DNUMBER_OF_FLASH_BANKS=1
endif
EXTRA_CFLAGS += -I$(WSTLDRIVERS_DIR)/include

-include $(TOPDIR)/Rules.make

clean:
	rm -f core *.o *.a *.s
