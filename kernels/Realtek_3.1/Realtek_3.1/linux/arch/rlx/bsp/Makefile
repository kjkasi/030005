# Realtek Semiconductor Corp.
#
# Tony Wu (tonywu@realtek.com)
# Oct. 18, 2008
#

#
# RTL8198
#
# Netgear Commneted the following line
#include $(DIR_LINUX)/.config

core-y   += arch/rlx/bsp/
#Netgear Modified below line
cflags-y += -Iinclude/asm-rlx -Iarch/rlx/bsp/ -Iarch/rlx/

# Netgear change
#load-y   += 0x80000000
load-y   += 0x80008000

extra-y  += vmlinux.lds

obj-y := prom.o setup.o irq.o timer.o serial.o
obj-$(CONFIG_PCI) += pci.o

EXTRA_AFLAGS := $(CFLAGS)
EXTRA_CFLAGS += -I$(DIR_LINUX)/drivers/net/rtl819x/AsicDriver
EXTRA_CFLAGS += -I$(DIR_LINUX)/drivers/net/rtl819x/common

#Netgear Add Start
ifdef CONFIG_WSTL_FLASH
EXTRA_CFLAGS += -DCONFIG_WSTL_FLASH
endif

ifdef CONFIG_WSTL_FLASHMGMT_MTD
EXTRA_CFLAGS += -DCONFIG_WSTL_FLASH
endif

ifdef CONFIG_WSTL_CMDLINE
obj-y        += wstl_cmdline.o
EXTRA_CFLAGS += -DCONFIG_WSTL_CMDLINE
endif

ifdef CONFIG_WSTL_WDOG
obj-y        += wstl_wdog.o
EXTRA_CFLAGS += -DCONFIG_WSTL_WDOG
endif
#Netgear Add End
ifdef CONFIG_RTL_819X_SWCORE
EXTRA_CFLAGS += -DCONFIG_RTL_819X_SWCORE
endif
