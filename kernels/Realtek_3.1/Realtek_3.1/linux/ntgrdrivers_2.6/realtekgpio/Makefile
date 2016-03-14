# File: drivers/char/wstl/wstlgpio/Makefile
#
# Makefile for the GPIO driver
#
wstlgpio-objs := gpiodrvr.oo 

obj-$(CONFIG_WSTL_GPIODRV) += wstlgpio.oo

ifeq ($(BUILD_LANTIQ_UGW_5_1),y)
EXTRA_CFLAGS += -DLANTIQ_UGW_5_1
endif

ifdef CONFIG_WSTL_AMAZONSE
wstlgpio-objs += infineon_io.oo
EXTRA_CFLAGS += -I. -DCONFIG_WSTL_AMAZONSE \
	-I$(WSTLDRIVERS_DIR)/include 
endif

ifdef BUILD_RTL8196C
wstlgpio-objs += realtek_gpio.oo
EXTRA_CFLAGS += -I. -DBUILD_RTL8196C \
	-I$(WSTLDRIVERS_DIR)/include 
else
wstlgpio-objs += bcm_io.oo
EXTRA_CFLAGS += -I. -DBRCM_CHIP=$(BRCM_CHIP)\
	-I$(WSTLDRIVERS_DIR)/include \
	-I$(INC_BRCMDRIVER_PUB_PATH) \
	-I$(INC_BRCMDRIVER_PRIV_PATH) \
	-I$(INC_BRCMSHARED_PUB_PATH) \
	-I$(INC_BRCMSHARED_PRIV_PATH) \
	-I$(INC_BRCMDRIVER_PUB_PATH)/bcm963xx \
	-I$(INC_BRCMDRIVER_PRIV_PATH)/bcm963xx \
	-I$(INC_BRCMSHARED_PUB_PATH)/bcm963xx \
	-I$(INC_BRCMSHARED_PRIV_PATH)/bcm963xx
endif
