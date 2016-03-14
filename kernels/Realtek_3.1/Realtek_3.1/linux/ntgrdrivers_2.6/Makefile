# File: wstldrivers/Makefile
#
# Makefile for Westell's Linux kernel modules.
#

-include $(KERNEL_OBJ)/.config

obj-$(CONFIG_WSTL_FLASH) += flash/
obj-$(CONFIG_WSTL_FLASHMGMT) += wstlflmt/
obj-$(CONFIG_WSTL_FLASHMGMT_MTD) += flashmgt_mtd/
obj-$(CONFIG_WSTL_FFS)   += wstlffs/
obj-$(CONFIG_WSTL_GPIODRV)  += realtekgpio/
clean:
	find . \( -name "*.o" -o -name "*.cmd" -o -name "*.bin" -o -name "*.ko" -o -name "*.mod.c" -o -name "*.a" \) -exec rm -f "{}" \;
