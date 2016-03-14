# The number of variables we're exporting is insane
# This exports all variables to sub-makefiles

.EXPORT_ALL_VARIABLES:

#IVON=$(shell ksh print "\033[7m")
#IVOFF=$(shell ksh print "\033[m")

# include build variables that may be target specific
include include.mk
###########################################
#
# Define Basic Variables
#
###########################################

KERNEL_PATH             = ../../../kernels/Realtek_3.1
VENDOR_DIR		:= $(KERNEL_PATH)/Realtek_3.1
KERNEL_DIR		:= $(BUILD_DIR)/$(VENDOR_DIR)/linux
DIR_LINUX		:= $(KERNEL_DIR)
LINUXDIR		:= $(KERNEL_DIR)
HOSTTOOLS_DIR		:= $(BUILD_DIR)/$(VENDOR_DIR)/hostTools
WSTLDRIVERS_DIR		:= $(KERNEL_DIR)/ntgrdrivers_2.6

DEFAULTCFG_DIR		:= $(TARGETS_DIR)/defaultcfg
FSSRC_DIR		:= $(TARGETS_DIR)/fs.src

CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
	else if [ -x /bin/bash ]; then echo /bin/bash; \
	else echo sh; fi ; fi)

GENDEFCONFIG_CMD = $(HOSTTOOLS_DIR)/scripts/gendefconfig
DEPMOD_BUILD	= $(HOSTTOOLS_DIR)/depmod.pl
###########################################
#
# Build Number
# the build number is in a config file 
# also used by FLASH_BUILD
#
###########################################

include $(TARGETS_DIR)/build_number.cfg
BUILD_NUMBER = $(optional)
ifneq ($(strip $(WSTL_USE_PHY)),)
ifneq ($(strip $(WSTL_USE_PHY)),CBT)
$(error WSTL_USE_PHY defined to unknown value: $(WSTL_USE_PHY))
endif
endif

###########################################
#
# Import Build Profiles
#
###########################################

ifeq ($(PROFILE),)
$(error PROFILE must be specified)
else
PROFILE_DIR=$(TARGETS_DIR)/$(PROFILE)
include $(PROFILE_DIR)/$(PROFILE)
endif

include $(PROFILE_DIR)/releasetag.cfg
RELEASE_ID =$(relname)

# some apps (net_mgr, etc) need info on the kernel build
ifeq ($(BUILD_WESTELL_FTMAPP),y)
	include ../JWNR/config.linux_JNR
else
	include config.linux
endif

###########################################
#
# Define Toolchain
#
###########################################

# If the user has specified a toolchain, use it
ifeq ($(TOOLCHAIN),)
$(error TOOLCHAIN must be specified)
endif

CROSS_COMPILE	= $(TOOL_PREFIX)

AR		= $(CROSS_COMPILE)ar
AS		= $(CROSS_COMPILE)as
LD		= $(CROSS_COMPILE)ld
CC		= $(CROSS_COMPILE)gcc
CXX		= $(CROSS_COMPILE)g++
CPP		= $(CROSS_COMPILE)cpp
NM		= $(CROSS_COMPILE)nm
STRIP		= true ||
REAL_STRIP	= $(CROSS_COMPILE)strip
#SSTRIP		= $(CROSS_COMPILE)sstrip
SSTRIP		= $(HOSTTOOLS_DIR)/sstrip
OBJCOPY		= $(CROSS_COMPILE)objcopy
OBJDUMP		= $(CROSS_COMPILE)objdump
RANLIB		= $(CROSS_COMPILE)ranlib

LIBDIR = $(TOOLCHAIN_TOP)/lib
USRLIBDIR = $(TOOLCHAIN_TOP)/usr/lib
EXTRALIBDIR = $(TOOLCHAIN_TOP)/usr/mips-linux-uclibc/lib
LIB_PATH        = $(TOOLCHAIN_TOP)/lib
LIBCDIR         = $(TOOLCHAIN_TOP)/lib

MAKEDEPPROG = gcc

PATH := $(TOOLCHAIN)/bin-ccache:$(TOOLCHAIN)/bin:$(HOSTTOOLS_DIR):$(PATH)
###########################################
#
# Netgear Debug options
#
###########################################

# Build debugging symbols (these are stripped, so doesn't hurt to do).
CFLAGS 		+= -g
ifneq ($(strip $(BUILD_DEBUG_AGENT)),)
# Optimize for size (may not want this when debugging)
CFLAGS 		+= -Os
endif

ifneq ($(strip $(BUILD_DEBUG_EFENCE)),)
	EFENCE_LIB= -I$(EFENCE_DIR) 
	EFENCE_INC= -I$(EFENCE_DIR)  -libefence.so.0.0
endif

ifneq ($(strip $(BUILD_DEBUG_DMALLOC)),)
	DMALLOC_INC= -I$(DMALLOC_DIR) 
	DMALLOC_LIB= -L$(DMALLOC_DIR) -ldmalloc -ldmallocth
endif

ifneq ($(strip $(BUILD_DEBUG_MPATROL)),)
	MPATROL_INC= -I$(MPATROL_DIR)/src 
	MPATROL_LIB= -L$(INSTALL_DIR)/lib -lmpatrol -lbfd -lintl -liberty
endif

###########################################
#
# Westell build options
#
###########################################

WSTL_BUILD_OPTS = -DGLOBAL_DEBUGGING_ENABLED=$(GLOBAL_DEBUGGING_ENABLED) \
	          -DWSTL_DEBUG_OUTPUT=$(WSTL_DEBUG_OUTPUT) \
	          -DWSTL_RELEASE_BUILD=$(WSTL_RELEASE_BUILD) \
                  -DWSTL_NUM_SWITCH_PORTS=5  -DSTATSD_NO_DSL

CFLAGS		+= $(WSTL_BUILD_OPTS)

#Infineon adds
CFLAGS		+= -Os -march=4181 -mtune=4181

# busybox uses a smaller set of tools for RELEASE
ifeq ($(WSTL_RELEASE_BUILD),1)
	WSTLCFG=wstl_release.config_ipv6
else
	WSTLCFG=wstl.config_ipv6
endif

###########################################
#
# Kernel Build Related Paths
#
###########################################

INC_KERNEL_BASE = $(BUILD_DIR)/$(VENDOR_DIR)/kernel
KERNEL_OBJ = $(KERNEL_DIR)
KERNEL_MOD = $(TARGET_DIR)/modules

KERNEL_CFG = $(KERNEL_OBJ)/.config

VMLINUX = $(KERNEL_OBJ)/vmlinux

INSTALL_MOD_PATH = $(KERNEL_MOD)

###########################################
#
# Application-specific settings
#
###########################################


INC_KERNEL_PATH		= $(PROFILE_DIR)/objects/include
INC_KERNEL_PATH1	= $(PROFILE_DIR)/objects/include2
INC_KERNEL_PATH2	= .
INC_KERNEL_PATH3	= .
INC_CFM_DIR		=  

# Next line needed for Realtek USB builds
DIR_BOARD		= $(TARGET_DIR)

###########################################
#
# Checks for building with Cygwin
# Needed for using the hostTools
#
###########################################
ifneq ($(shell uname -o),Cygwin)
BUILD_HOST_TYPE = linux
HOST_EXE_EXT =
else
BUILD_HOST_TYPE = cygwin
HOST_EXE_EXT = .exe
endif

###########################################
#
# buildimage related values
#
###########################################

HOSTTOOLS_BIN	= $(HOSTTOOLS_DIR)/$(BUILD_HOST_TYPE)
FLASH_BUILD	= $(HOSTTOOLS_DIR)/FlashImageBuild$(HOST_EXE_EXT)

KERNEL_PKG = vmlinux.pkg

FLSH_BUILD = FlashImageBuild

ROOTFS     = rootfs
STRIPFS    = rootfs.stripped
ROOTFS_IMG = rootfs.img
ifeq ($(BUILD_LANGUPG_FEATURE),y)
LANGFS     = lang
LANGFS_IMG = langfs.img
endif

APP_CFG	   = rootfs.cfg
APP_UPG    = App.upg
ROOT_UPG   = RootFs.upg

###########################################
#
# Setup for INSTALL_DIR for userapps
#
###########################################
INSTALL_DIR = $(TARGET_DIR)/$(ROOTFS)

###########################################
#
# For production builds
#
###########################################
BUILD_SAVE_DIR = $(BUILD_DIR)/../../Build/current

###########################################
#
# FLASH layout stuff
#
###########################################

# because we EXPORT_ALL_VARIABLES, all variables get expanded when make spawns a
# shell, so we add a char that illegal to shell variable names but legal to make
# variable name (. or -) to prevents the expansion during the "spawn" (which if
# if it does, produces an awk error message because $(1) is undefined)
math.exp = $(shell gawk 'BEGIN{printf "0x%X\n",$(1)}')
FLASH_LEN = $(CONFIG_MTD_PHYSMAP_LEN)
FLASH_FFS = $(CONFIG_MTD_PHYSMAP_FFS)
FLASH_BOOT = $(CONFIG_MTD_PHYSMAP_BOOT)
FLASH_SYS_HDR_END_ADRS = $(CONFIG_MTD_PHYSMAP_FFS)
FLASH_FILE_SYSTEM_OFST = $(call math.exp,$(CONFIG_MTD_PHYSMAP_FFS)-$(CONFIG_MTD_PHYSMAP_BOOT))
FLASH_MAIN_APP_VECTOR_OFST = $(call math.exp,$(CONFIG_MTD_PHYSMAP_LEN)-4)
FLASH_SAFEBOOT_OFST = 0x0
FLASH_BOOTMODE_OFST = 0xBD03FD80
###########################################
#
# Complete list of applications
#
#  Add your directory here - so that it
#  is cleaned when "make clean" is performed
#
###########################################

USERAPPS_DIR		= $(BUILD_DIR)/$(VENDOR_DIR)/userapps
OPENSOURCE_DIR		= $(BUILD_DIR)/opensource
WESTELL_APP_DIR		= $(BUILD_DIR)/Westell/userapps
LIBC_OPTIMIZATION 	= $(HOSTTOOLS_DIR)/libcreduction

BFTPD_DIR	= $(OPENSOURCE_DIR)/bftpd
BUSYBOX_DIR	= $(OPENSOURCE_DIR)/busybox
DEBUGTOOLS_DIR	= $(OPENSOURCE_DIR)/debug
ifeq ($(strip $(BUILD_DNSMASQ_VERSION)),2.56)
DNSMASQ_DIR     = $(OPENSOURCE_DIR)/dnsmasq-2.56
else
DNSMASQ_DIR     = $(OPENSOURCE_DIR)/dnsmasq-2.40
endif
EBTABLES_DIR	= $(OPENSOURCE_DIR)/ebtables
#ETHTOOL_DIR	= $(OPENSOURCE_DIR)/ethtool-1.6
INADYN_DIR	= $(OPENSOURCE_DIR)/inadyn.v1.96
PHDDNS_DIR	= $(OPENSOURCE_DIR)/phddns-2.0.2.16556
IPROUTE2_DIR	= $(OPENSOURCE_DIR)/iproute2
#IPROUTE2_DIR	= $(OPENSOURCE_DIR)/iproute2-2.6.9
IPTABLES_DIR	= $(OPENSOURCE_DIR)/iptables-1.4.6
#IPTABLES_DIR	= $(OPENSOURCE_DIR)/iptables-1.3.8
LIBGMP_DIR	= $(OPENSOURCE_DIR)/libgmp-4.2.1
LIBOPENSSL_DIR	= $(OPENSOURCE_DIR)/openssl
LIBOSIP2_DIR	= $(OPENSOURCE_DIR)/libosip2-2.0.9
LUA_DIR		= $(OPENSOURCE_DIR)/lua
NETTOOLS_DIR	= $(OPENSOURCE_DIR)/net-tools-1.60
NTPCLIENT_DIR	= $(OPENSOURCE_DIR)/ntpclient
PPP_DIR		= $(OPENSOURCE_DIR)/ppp
#Added for upnp
IGD_DIR         = $(OPENSOURCE_DIR)/upnp/linuxigd-1.0
LIBUPNP_DIR     = $(OPENSOURCE_DIR)/upnp/libupnp-1.3.1
#Added for Print Server
P910_DIR	= $(OPENSOURCE_DIR)/p910nd-0.93
CIFS_SRC_DIR	= $(WESTELL_APP_DIR)/cifs

PPP_PATCH_H	= $(PPP_DIR)/pppd/patchlevel.h
PPPPLUGINS_DIR	= $(INSTALL_DIR)/lib/pppd/$(PPPVERSION)
PPPVERSION	= $(shell awk -F '"' '/VERSION/ { print $$2; }' $(PPP_PATCH_H))
#RP_PPPOE_DIR	= $(OPENSOURCE_DIR)/rp-pppoe-3.5
RP_PPPOE_DIR	= $(OPENSOURCE_DIR)/rp-pppoe-3.10
SIPROXD_DIR	= $(OPENSOURCE_DIR)/siproxd-0.5.13
SAMBA_DIR	= $(OPENSOURCE_DIR)/samba-2.2.12/source
SSHD_DIR	= $(OPENSOURCE_DIR)/sshd
STRONGSWAN_DIR	= $(OPENSOURCE_DIR)/strongswan-4.1.11
OPENL2TP_DIR	= $(OPENSOURCE_DIR)/openl2tp-1.8	
PPTP_DIR	= $(OPENSOURCE_DIR)/pptp-1.7.1	
VCONFIG_DIR	= $(OPENSOURCE_DIR)/vlan
ZEBRA_DIR	= $(OPENSOURCE_DIR)/zebra
NAIL_DIR	= $(OPENSOURCE_DIR)/nail
WIRELESS_TOOLS_DIR	= $(OPENSOURCE_DIR)/wireless/wireless_tools.29
HOSTAPD_DIR	= $(OPENSOURCE_DIR)/wireless/hostapd-0.4.8
WPA2_DIR =  $(OPENSOURCE_DIR)/wireless/wpa2
MACCHANGER_DIR =  $(OPENSOURCE_DIR)/macchanger-1.5.0
#Added for IPv6
FLEX_DIR	= $(OPENSOURCE_DIR)/flex-2.5.35
RADVD_DIR	= $(OPENSOURCE_DIR)/radvd-1.6
IPUTILS_DIR	= $(OPENSOURCE_DIR)/iputils-s20100418
DHCPV6_DIR      = $(OPENSOURCE_DIR)/dhcp-4.1.2
IGMP_DIR	= $(OPENSOURCE_DIR)/igmp

LIBNFNETLINK_DIR	= $(OPENSOURCE_DIR)/conntrack-tools/libnfnetlink-1.0.0
LIBNETFILTER_CONNTRACK_DIR	= $(OPENSOURCE_DIR)/conntrack-tools/libnetfilter_conntrack-0.9.1
CONNTRACK_TOOLS_DIR	= $(OPENSOURCE_DIR)/conntrack-tools/conntrack-tools-1.0.0
LIBNFNETLINK_CFLAGS = -I$(CONNTRACK_TOOLS_DIR)/build/ -I$(LIBNFNETLINK_DIR)/include/ -I$(CONNTRACK_TOOLS_DIR)/build/lib
LIBNFNETLINK_LIBS = "$(CONNTRACK_TOOLS_DIR)/build/lib/libnfnetlink.a"
LIBNETFILTER_CONNTRACK_CFLAGS = -I$(CONNTRACK_TOOLS_DIR)/build/ -I$(LIBNETFILTER_CONNTRACK_DIR)/include/ -I$(CONNTRACK_TOOLS_DIR)/build/lib
LIBNETFILTER_CONNTRACK_LIBS = "$(CONNTRACK_TOOLS_DIR)/build/lib/libnetfilter_conntrack.la"
LDFLAGS = -L$(CONNTRACK_TOOLS_DIR)/build/lib 

BCMSWCH_DIR	= $(WESTELL_APP_DIR)/bcmSwitch
CLIUTILS_DIR	= $(WESTELL_APP_DIR)/cli_utils
DDNS_DIR        = $(WESTELL_APP_DIR)/ipupdate-1.1.1
IGMPPROXY_DIR	= $(WESTELL_APP_DIR)/igmpproxy
RTIGMPPROXY_DIR	= $(WESTELL_APP_DIR)/igmp/realtek_igmp
LIBFTMSHM_DIR   = $(WESTELL_APP_DIR)/libs/westellFTM
LIBHTTP_DIR	= $(WESTELL_APP_DIR)/libs/westellHTTP
LIBINIPARSER_DIR = $(WESTELL_APP_DIR)/libs/IniParser
LIBDEBUGPRINT_DIR = $(WESTELL_APP_DIR)/libs/DebugPrint
TIMEUTILS_DIR = $(WESTELL_APP_DIR)/libs/TimeUtils
COMMONROUTINES_DIR =$(WESTELL_APP_DIR)/libs/CommonRoutines
LOGREAD_DIR =$(WESTELL_APP_DIR)/libs/logRead
LIBUPGRADE_DIR	= $(WESTELL_APP_DIR)/libs/upgrade
LIBXML_DIR	= $(WESTELL_APP_DIR)/libs/westellXML
NET_MGR_DIR	= $(WESTELL_APP_DIR)/network
VOIP_DIR	= $(WESTELL_APP_DIR)/voip
VOIP_LIB_DIR    = $(WESTELL_APP_DIR)/libvoip
ifneq ($(strip $(BUILD_WSTL_CFG)),)
WSTL_CFG_DIR	= $(WESTELL_APP_DIR)/config
else
ifneq ($(BUILD_WSTL_CFG_C_BASED),)
WSTL_CFG_DIR    = $(WESTELL_APP_DIR)/configC
endif
endif
WSTL_ERTUPGRADE_DIR        = $(WESTELL_APP_DIR)/ERTUpgrade
WSTL_CWMPD_DIR	= $(WESTELL_APP_DIR)/cwmpd
WSTL_RECFG_DIR	= $(WESTELL_APP_DIR)/RemoteCfg
WSTL_FIREBALL_DIR = $(WESTELL_APP_DIR)/fireball
WSTL_UPNP_DIR   = $(WESTELL_APP_DIR)/upnp_app 
WSTL_DIAG_DIR   = $(WESTELL_APP_DIR)/diag
WSTL_STATS_DIR	= $(WESTELL_APP_DIR)/statsd
#RV_MTF          = $(WESTELL_APP_DIR)/rvMTF2.5
WSTL_WIRELESS_DIR=$(WESTELL_APP_DIR)/wireless/realtek
LIBUTIL_DIR = $(WESTELL_APP_DIR)/libs/westellUTIL
AUTHSRC_DIR = $(BUILD_DIR)/$(VENDOR_DIR)/userapps/auth/src
WSCDSRC_DIR = $(BUILD_DIR)/$(VENDOR_DIR)/userapps/wsc
MINIUPNP_DIR = $(BUILD_DIR)/$(VENDOR_DIR)/userapps/mini_upnp
MPTOOL_DIR = $(BUILD_DIR)/$(VENDOR_DIR)/userapps/mp-daemon
WRUA_DIR	= $(WINDRIVER_APP_DIR)/usermode-agent/3.1/src

#Added for IPv6
FLEX_DIR	= $(OPENSOURCE_DIR)/flex-2.5.35
RADVD_DIR	= $(OPENSOURCE_DIR)/radvd-1.6
IPUTILS_DIR	= $(OPENSOURCE_DIR)/iputils-s20100418
DHCPV6_DIR      = $(OPENSOURCE_DIR)/dhcp-4.1.2
IGMP_DIR	= $(OPENSOURCE_DIR)/igmp

# if PROFILE already hasn't defined a specific web content dir/type, do so here
ifndef WEB_CONTENT_DIRECTORY
WEB_CONTENT_DIRECTORY = $(WESTELL_APP_DIR)/WebServer/Content/netGear
endif

SUBDIRS_OPENSOURCE =	\
			$(BUSYBOX_DIR) \
			$(OPENSOURCE_DIR)/bridge-utils/brctl \
			$(LIBOSIP2_DIR) \
			$(LIBOPENSSL_DIR) \
			$(SIPROXD_DIR) \
			$(LIBNETFILTER_CONNTRACK_DIR) \
			$(CONNTRACK_TOOLS_DIR) \
			$(VCONFIG_DIR) \
			$(NETTOOLS_DIR) \
			$(IPTABLES_DIR) \
			$(DNSMASQ_DIR) \
			$(WIRELESS_TOOLS_DIR) \
			$(LUA_DIR) \
			$(PPP_DIR) \
			$(EBTABLES_DIR) \
            $(FLEX_DIR) \
			$(RADVD_DIR) \
			$(IPUTILS_DIR) \
			$(DHCPV6_DIR) \
			$(NAIL_DIR) \
			$(PHDDNS_DIR) \
			$(INADYN_DIR) \

SUBDIRS_WESTELL =	\
			$(WSTL_CFG_DIR)/data \
			$(WESTELL_APP_DIR)/WebServer/LINUX \
			$(WESTELL_APP_DIR)/WebServer/Util \
			$(WESTELL_APP_DIR)/ManagementUtility \
			$(CLIUTILS_DIR) \
			$(COMMONROUTINES_DIR) \
			$(LOGREAD_DIR) \
			$(WSTL_CFG_DIR) \
			$(WESTELL_APP_DIR)/adslDiag \
			$(WSTL_STATS_DIR) \
			$(WSTL_RECFG_DIR) \
			$(WESTELL_APP_DIR)/wchk \
			$(WESTELL_APP_DIR)/ModemMgmt \
			$(WESTELL_APP_DIR)/Led \
			$(WESTELL_APP_DIR)/MMReboot \
			$(WESTELL_APP_DIR)/dconfig \
			$(NET_MGR_DIR) \
			$(TIMEUTILS_DIR) \
			$(LIBUPGRADE_DIR) \
			$(LIBFTMSHM_DIR) \
			$(LIBHTTP_DIR) \
			$(LIBXML_DIR) \
			$(LIBINIPARSER_DIR) \
			$(LIBDEBUGPRINT_DIR) \
			$(WSTL_CWMPD_DIR) \
			$(WESTELL_APP_DIR)/upnp \
			$(WESTELL_APP_DIR)/fireball \
			$(WSTL_UPNP_DIR) \
			$(BCMSWCH_DIR) \
			$(WESTELL_APP_DIR)/FTM \
			$(RTIGMPPROXY_DIR) \
			$(WESTELL_APP_DIR)/mem_profiler \
			$(DDNS_DIR) \
			$(WSTL_WIRELESS_DIR) \
			$(LIBUTIL_DIR) \
			$(CIFS_SRC_DIR) \
			$(WESTELL_APP_DIR)/pcapp \
			$(WSTL_ERTUPGRADE_DIR) \
			$(WESTELL_APP_DIR)/bannersrv \
			$(WESTELL_APP_DIR)/potapp

SUBDIRS_REALTEK =	\
			$(AUTHSRC_DIR) \
			$(AUTHSRC_DIR)/dlisten \
			$(WSCDSRC_DIR) \
			$(MINIUPNP_DIR) \
			$(MPTOOL_DIR) \

APP_SUBDIRS = $(SUBDIRS_OPENSOURCE) $(SUBDIRS_WESTELL) $(SUBDIRS_REALTEK)

# Lists of applications which may be built.  Each should have a
# variable set in the target file which controls whether it is built.

OPENSOURCE_APPS = \
		busybox \
		brctl \
		lua \
		ppp \
		ebtables \
		dnsmasq \
		vconfig \
		net-tools-1.60 \
		ntpclient \
		openssl \
		iptables \
		libosip2 \
		siproxd \
		flex \
    	radvd \
		iputils \
		dhcpv6 \
		iproute2 \
		upnp \
		conntrack-tools \
		wireless_tools \
		openl2tp \
		pptp \
		inadyn \
		phddns \
		nail
	    
WESTELL_APPS = \
		CommonRoutines \
		westellUTIL \
		wstlcfg \
		upgrade \
		ftmshm \
		westellHTTP \
		westellXML \
		TimeUtils \
		logRead \
		wstlstats \
		IniParser \
		DebugPrint \
		cifs_server \
		websvr \
		ipupdate-1.1.1 \
		RemoteCfg \
		mgmtutil \
		led \
		net_mgr \
		modemmgmt \
		mmreboot \
		dconfig \
		fireball \
		cli \
        FTM \
		mem_profiler \
		rt_igmpproxy \
		wireless\
		langUtil \
		upnp_app \
		diag \
		pcapp \
		bannersrv \
		ERTUpgrade \
		potapp \
        rssi_dump \
		cwmpd

REALTEK_APPS = \
                auth \
		miniupnp \
		wscd \
		mptool-daemon

###########################################
#
# Make Targets
#
###########################################

all: sanity_check kernelbuild modbuild kernelbuildlite appbuild tool oopsinfo buildimage

sanity_check:
	@if [ "$(PROFILE)" = "" ]; then \
	  echo You need to specify build profile name from $(TARGETS_DIR) using 'make PROFILE=<profile name>...'; exit 1; \
	fi
	@if [ -f $(PROFILE_CHECK) ]; then \
		if [ "X$(PROFILE)" != "X$(OLDPROFILE)" ]; then \
			echo; \
			echo "PROFILE mismatch! Old PROFILE=$(OLDPROFILE). New PROFILE=$(PROFILE). Automatically cleaning source tree..."; \
			echo; \
			echo $(MAKE) -C $(BUILD_DIR) PROFILE=$(OLDPROFILE) clean ; \
			$(MAKE) -C $(BUILD_DIR) PROFILE=$(OLDPROFILE) clean ; \
			echo;  \
			echo "Continuing build process for PROFILE=$(PROFILE)."; \
			echo;  \
		fi; \
	fi
	echo "$(PROFILE)" > $(BUILD_DIR)/.PROFILE

soft_links: $(HOSTTOOLS_DIR)/banner
# Create a link to the appropriate version of xChange
ifneq ($(strip $(BUILD_XCHANGE3_10)),)
	test -d $(XCHANGE_DIR) || ln -fs xChange3_10 $(XCHANGE_DIR)
endif 

chk4newer:
	@test ! -f $(VMLINUX) || find $(KERNEL_DIR) -newer $(VMLINUX) | awk 'END{if(NR>0){print "Newer kernel source files found, removing " f;system("rm " f)}}' f=$(VMLINUX) 

kernelconfig:
ifeq ($(wildcard $(KERNEL_DIR)/.hdepend),)
ifeq ($(strip $(WSTL_RELEASE_BUILD)),1)
	@echo "Creating Westell Release Build"
	sed '/CONFIG_BCM_SERIAL=y/s/CONFIG_BCM_SERIAL=y/# CONFIG_BCM_SERIAL is not set/' $(PROFILE_DIR)/defconfig > $(PROFILE_DIR)/defconfig.tmp1;\
	sed '/CONFIG_SERIAL_CONSOLE=y/s/CONFIG_SERIAL_CONSOLE=y/# CONFIG_SERIAL_CONSOLE is not set/' $(PROFILE_DIR)/defconfig.tmp1 > $(PROFILE_DIR)/defconfig.tmp2;\
	sed '/CONFIG_SERIAL_NONSTANDARD=y/s/CONFIG_SERIAL_NONSTANDARD=y/# CONFIG_SERIAL_NONSTANDARD is not set/' $(PROFILE_DIR)/defconfig.tmp2 > $(PROFILE_DIR)/defconfig.current; \
	rm -f $(PROFILE_DIR)/defconfig.tmp1 $(PROFILE_DIR)/defconfig.tmp2
else
	@echo "Creating Westell Debug Build"
	cp $(PROFILE_DIR)/defconfig $(PROFILE_DIR)/defconfig.current
endif
	@echo "Configuring Linux kernel"
	rm -f $(KERNEL_DIR)/.config
	cp $(PROFILE_DIR)/defconfig.current $(KERNEL_DIR)/arch/mips/defconfig
	$(MAKE) -C $(KERNEL_DIR) oldconfig
	@echo "Creating Linux dependancies"
	$(MAKE) -C $(KERNEL_DIR) dep > /dev/null
endif

kernelbuild: chk4newer kernel
 
#$(KERNEL_OBJ):
#	mkdir $(KERNEL_OBJ)

$(KERNEL_MOD):
	mkdir $(KERNEL_MOD)

$(KERNEL_CFG): $(TARGET_DIR)/config.linux $(TARGET_DIR)/$(PROFILE)
	@echo linux config missing or out of date, cleaning kernel
#	cd $(BUILD_DIR)/$(VENDOR_DIR); ./mklinks.sh
	$(MAKE) kernel_clean
#	mkdir $(KERNEL_OBJ) $(KERNEL_MOD)
	@echo "***** Configuring Linux kernel *****"
ifeq ($(BUILD_WESTELL_FTMAPP),y)
	cp -f $(TARGET_DIR)/../JWNR/config.linux_JNR $(KERNEL_CFG)
else
	cp -f $(TARGET_DIR)/config.linux $(KERNEL_CFG)
endif
#	cd $(BUILD_DIR)/$(VENDOR_DIR); ./mklinks.sh  # kernel_clean removes these links
#	$(MAKE) O=$(KERNEL_OBJ) -C $(KERNEL_DIR) oldconfig > /dev/null 

$(VMLINUX): $(KERNEL_CFG)
	@echo "***** Building Linux kernel *****"
	$(MAKE) -C $(KERNEL_DIR)

kernel: $(VMLINUX)

modbuild: $(KERNEL_MOD)
	@echo "***** Building Linux modules *****"
	$(MAKE) -C $(KERNEL_DIR) modules modules_install

ifeq ($(strip $(BRCM_CHIP)),6358)
ifeq ($(strip $(BRCM_DRIVER_BCMDSP)),m)
# what is kernelbuildlite?? you ask. great question says I.
# kernelbuildlite runs the script getDspModSizes.sh which patches in some new
# values for the DSPDD module after it's been built. But since the kernel is
# built before the module(s) and now we've modified a kernel file, we must
# rebuild the kernel with the new values. thus, kernelbuildlite.
kernelbuildlite:
	@echo "******************** Kernel Build Lite ********************"; \
$(BRCMDRIVERS_DIR)/broadcom/char/dspapp/bcm9$(BRCM_CHIP)/getDspModSizes.sh  $(BRCMDRIVERS_DIR)/broadcom/char/dspapp/bcm9$(BRCM_CHIP)/dspdd.ko $(KERNEL_DIR) $(CROSS_COMPILE) $(KERNEL_DEBUG);
	$(MAKE) -C $(KERNEL_DIR) 
else
kernelbuildlite:
endif
else
kernelbuildlite:
endif

modules: profile_check create_install modbuild kernelbuildlite tool buildimage

$(HOSTTOOLS_DIR)/gperf:
	$(MAKE) -C $(HOSTTOOLS_DIR) gperf

$(HOSTTOOLS_DIR)/banner:
	$(MAKE) -C $(HOSTTOOLS_DIR) banner

stop: $(HOSTTOOLS_DIR)/banner
	@banner "stop build"; exit 1

#appbuild: #$(INSTALL_DIR): $(OPENSOURCE_APPS) $(BRCM_APPS) $(WESTELL_APPS) $(BCRM_APP_WSTL_DEP) debug_agent
appbuild: create_install $(OPENSOURCE_APPS) $(REALTEK_APPS)


showapps:

	@echo OPENSOURCE_APPS=$(OPENSOURCE_APPS)

apps: appbuild buildimage

wstl: $(WESTELL_APPS) buildimage

#$(INSTALL_DIR):
create_install:
	mkdir -p $(INSTALL_DIR)
	cp -a $(TARGETS_DIR)/fs.src/* $(INSTALL_DIR)
	mkdir -p $(INSTALL_DIR)/bin 
	mkdir -p $(INSTALL_DIR)/sbin 
	mkdir -p $(INSTALL_DIR)/lib
ifeq ($(BUILD_LANGUPG_FEATURE),y)
	mkdir -p lang
endif

ifneq ($(strip $(BUILD_DEBUG_AGENT)),)
ifeq ($(ARCH),mipsel)
WRUA_DEFS = ARCH=mips ENDIAN=le
WRUA_ARCH = mipsle
else
WRUA_DEFS = ARCH=mips ENDIAN=be
WRUA_ARCH = mipsbe
endif
debug_agent:
	TARGET="" $(MAKE) $(WRUA_DEFS) PRE_LIBS="$(TOOLCHAIN)/bfd/lib/libbfd.a $(TOOLCHAIN)/bfd/lib/libiberty.a" PRE_INCLUDES="-I$(TOOLCHAIN)/bfd/include" LINUX_ROOT=$(KERNEL_DIR) -C $(WRUA_DIR)
ifneq ($(strip $(WSTL_RELEASE_BUILD)),)
	cp $(WRUA_DIR)/bin/$(WRUA_ARCH)/usermode-agent $(INSTALL_DIR)/bin
endif

debug_agent_clean:
	$(MAKE) $(WRUA_DEFS) LINUX_ROOT=$(KERNEL_DIR) -C $(WRUA_DIR) clean
else
debug_agent:
debug_agent_clean:
endif

# Build user applications depending on if they are
# specified in the profile

ifneq ($(strip $(BUILD_BUSYBOX)),)
busybox:
	cd $(BUSYBOX_DIR); test ! -f .config -o $(WSTLCFG) -nt .config && cp -f $(WSTLCFG) .config || true
	$(MAKE) -C $(BUSYBOX_DIR) CONFIG_PREFIX=$(INSTALL_DIR) LIBCDIR=$(LIBDIR)/.. install
else
busybox:
endif
ifneq ($(strip $(BUILD_LIBCREDUCTION)),)
libcreduction:
	$(MAKE) -C $(LIBC_OPTIMIZATION) install
else
libcreduction:
endif

# Web Server
ifneq ($(strip $(BUILD_GOAHEADWEB)),)
websvr:
	$(MAKE) -C $(WESTELL_APP_DIR)/WebServer/LINUX $(BUILD_GOAHEADWEB)
else
websvr:
endif

#langUtil
ifneq ($(strip $(BUILD_LANGUTIL)),)
langUtil:
	$(MAKE) -C $(WESTELL_APP_DIR)/WebServer/Util all
else
langUtil:
endif

#pcclinet
ifneq ($(strip $(FEATURE_PARENTALCONTROL)),)
pcapp:
	$(MAKE) -C $(WESTELL_APP_DIR)/pcapp all
else
pcapp:
endif

#bannersrv
ifneq ($(strip $(FEATURE_BLKSITESBANNER)),)
bannersrv:
	$(MAKE) -C $(WESTELL_APP_DIR)/bannersrv all
else
bannersrv:
endif

ifneq ($(strip $(BUILD_FEATURE_POTAPP)),)
potapp:
	$(MAKE) -C $(WESTELL_APP_DIR)/potapp all
else
potapp:
endif

# Bridge Control
ifneq ($(strip $(BUILD_BRCTL)),)
brctl:
	$(MAKE) -C $(OPENSOURCE_DIR)/bridge-utils $(BUILD_BRCTL)
else
brctl:
endif

# bftpd - ftp deamon
ifneq ($(strip $(BUILD_BFTPD)),)
bftpd:
	$(MAKE) -C $(BFTPD_DIR)
	cp $(BFTPD_DIR)/bftpd $(INSTALL_DIR)/bin/
	cp $(BFTPD_DIR)/bftpd.conf $(INSTALL_DIR)/etc/
else
bftpd:
endif

#ATM 2684
ifneq ($(strip $(BUILD_PVC2684CTL)),)
pvc2684ctl:
	$(MAKE) -C $(OPENSOURCE_DIR)/atm2684/pvc2684ctl LIB_PATH=$(LIBDIR) $(BUILD_PVC2684CTL)
else
pvc2684ctl:
	$(MAKE) -C $(OPENSOURCE_DIR)/atm2684/atm/lib all
endif

#netfilter conntrack-tools
ifneq ($(strip $(BUILD_CONNTRACK_TOOLS)),)
conntrack-tools:
	(rm -rf $(CONNTRACK_TOOLS_DIR)/build)
	(mkdir $(CONNTRACK_TOOLS_DIR)/build)
	(cd $(LIBNFNETLINK_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux --prefix=$(CONNTRACK_TOOLS_DIR)/build; fi)
	$(MAKE) -C $(LIBNFNETLINK_DIR) install
	(cd $(LIBNETFILTER_CONNTRACK_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux  --prefix=$(CONNTRACK_TOOLS_DIR)/build; fi)
	$(MAKE) -C $(LIBNETFILTER_CONNTRACK_DIR) -I$(LIBNFNETLINK_DIR)/include/ install
	(cd $(CONNTRACK_TOOLS_DIR); if [ ! -f Makefile ]; then bash ./configure --prefix=$(CONNTRACK_TOOLS_DIR)/build --host=mips-unknown-linux  ; fi)
	$(MAKE) -C $(CONNTRACK_TOOLS_DIR) -I$(LIBNETFILTER_CONNTRACK_DIR)/include/ install
	cp -f $(CONNTRACK_TOOLS_DIR)/build/sbin/conntrack $(INSTALL_DIR)/sbin/.
	cp -af $(CONNTRACK_TOOLS_DIR)/build/lib/*.so* $(INSTALL_DIR)/lib/.
else
conntrack-tools:
endif

ifneq ($(strip $(BUILD_BR2684CTL)),)
br2684ctl:
	$(MAKE) -C $(OPENSOURCE_DIR)/atm2684/br2684ctl $(BUILD_BR2684CTL)
else
br2684ctl:
endif

ifneq ($(strip $(BUILD_RT2684D)),)
rt2684d:
	$(MAKE) -C $(OPENSOURCE_DIR)/atm2684/atm/rt2684d $(BUILD_RT2684D)
else
rt2684d:
endif

# dnsmasq - DHCP and DNS Server
ifneq ($(strip $(BUILD_DNSMASQ)),)
dnsmasq:
	$(MAKE) -C $(DNSMASQ_DIR) $(BUILD_DNSMASQ)
	cp $(DNSMASQ_DIR)/src/dnsmasq $(INSTALL_DIR)/bin/
else
dnsmasq:
endif

# p910nd  - Print Server
ifneq ($(strip $(BUILD_P910ND)),)
p910nd:
	$(MAKE) -C $(P910_DIR)
	(cp -pP $(P910_DIR)/p910nd $(INSTALL_DIR)/sbin)
else
p910nd:
endif
# dconfig - DHCP and DNS Server Configuration Create Application
dconfig:
	$(MAKE) -C $(WESTELL_APP_DIR)/dconfig dynamic

# FTM - Factory Test Mode Application
FTM:
	$(MAKE) -C $(WESTELL_APP_DIR)/FTM dynamic
ifneq ($(strip $(BUILD_BRCM_ATMCTL)),)
atmctl:
	$(MAKE) -C $(BROADCOM_LIB_DIR)/atmctl 
	$(MAKE) -C $(BROADCOM_APP_DIR)/atmctl $(BUILD_BRCM_ATMCTL)
else
atmctl:
endif
#ethctl:
#	$(MAKE) -C $(ETHCTL_DIR)
#	cp $(ETHCTL_DIR)/ethctl $(INSTALL_DIR)/bin/

ifneq ($(strip $(BUILD_WLCTL)),)
WIRELESS=1
wlctl:
	$(MAKE) -C $(WLCTL_DIR) $(BUILD_WLCTL)
else
WIRELESS=0
wlctl:
endif

ifneq ($(strip $(BUILD_NAS)),)
nas:
	$(MAKE) -C $(NAS_DIR)/../shared install
	$(MAKE) -C $(NAS_DIR)/../../bcmcrypto install
	$(MAKE) -C $(NAS_DIR) install
	cp $(NAS_DIR)/nas $(INSTALL_DIR)/bin/
else
nas:
endif

ifneq ($(strip $(BUILD_NAS)),)
eapd:
	$(MAKE) -C $(EAPD_DIR) install
	cp $(EAPD_DIR)/eapd $(INSTALL_DIR)/bin/
else
eapd:
endif

ifneq ($(strip $(BUILD_NVRAM)),)
nvram:
	$(MAKE) -C $(NVRAM_DIR)
	cp $(NVRAM_DIR)/nvram $(INSTALL_DIR)/bin/
else
nvram:
endif

ifneq ($(strip $(BUILD_WSC)),)
export BUILD_WSC_CONFIG_UPNP_DISABLE=0
# BUILD_WSC_CONFIG_UPNP_DISABLE=1 to disable UPNP w/ AP config mode
# BUILD_WSC_CONFIG_UPNP_DISABLE=0 should be 0 for WiFi test
wps:
	$(MAKE) -C $(WPS_DIR) $(BUILD_WSC) install ;

else
wps:
	@echo "skipping $@ (not configured)"
endif


ifneq ($(strip $(BUILD_WSCCMD)),)
wsccmd:
	$(MAKE) -C $(WSCCMD_DIR)
	cp $(WSCCMD_DIR)/wsccmd $(INSTALL_DIR)/bin/
	mkdir -p $(INSTALL_DIR)/etc/wlan
	cp $(WSCCMD_DIR)/../common/*ap.txt $(INSTALL_DIR)/etc/wlan
	cp $(WSCCMD_DIR)/../common/*.bat $(INSTALL_DIR)/bin
else
wsccmd:
endif

# igmpproxy
ifneq ($(strip $(BUILD_IGMPPROXY)),)
igmpproxy:
	$(MAKE) -C $(IGMPPROXY_DIR)
else
igmpproxy:
endif

ifneq ($(strip $(BUILD_IGMP)),)
igmp:
	$(MAKE) -C $(IGMP_DIR) 
	cp $(IGMP_DIR)/igmp $(INSTALL_DIR)/bin/
else
igmp:
endif

# realtek igmpproxy
ifneq ($(strip $(BUILD_REALTEK_IGMPPROXY)),)
rt_igmpproxy:
	$(MAKE) -C $(RTIGMPPROXY_DIR)
	cp $(RTIGMPPROXY_DIR)/rt_igmpproxy $(INSTALL_DIR)/bin/
else
rt_igmpproxy:
endif

# ppp
ifneq ($(strip $(BUILD_PPPD)),)
ppp:
	(cd $(PPP_DIR); if [ ! -f Makefile ]; then bash ./configure; fi)
	$(MAKE) -C $(PPP_DIR)
	(cd $(RP_PPPOE_DIR)/src; if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux; fi)
	$(MAKE) -C $(RP_PPPOE_DIR)/src
	mkdir -p $(PPPPLUGINS_DIR)
	cp $(PPP_DIR)/pppd/pppd $(INSTALL_DIR)/bin/pppd
	-cp $(PPP_DIR)/pppd/plugins/pppoatm.so $(PPPPLUGINS_DIR)/pppoatm.so
	cp $(PPP_DIR)/pppd/plugins/rp-pppoe/pppoe-discovery $(INSTALL_DIR)/bin/pppoe-discovery
	cp $(PPP_DIR)/pppd/plugins/rp-pppoe/rp-pppoe.so $(PPPPLUGINS_DIR)/rp-pppoe33.so
ifneq ($(strip $(BUILD_L2TP)),)
	cp $(PPP_DIR)/pppd/plugins/pppol2tp/pppol2tp.so $(PPPPLUGINS_DIR)/pppol2tp.so
endif
	cp $(RP_PPPOE_DIR)/src/pppoe-relay $(INSTALL_DIR)/bin/pppoe-relay
else
ppp:
endif

# ethtool
ifneq ($(strip $(BUILD_ETHTOOL)),)
ethtool:
	$(MAKE) -C $(ETHTOOL)
else
ethtool:
endif
wireless_tools:
ifneq ($(strip $(BUILD_WIRELESS_TOOLS)),)
	$(MAKE) -C $(WIRELESS_TOOLS_DIR) -f prime.mk
	cp -pP $(WIRELESS_TOOLS_DIR)/build/sbin/* $(INSTALL_DIR)/sbin/
	cp -pP $(WIRELESS_TOOLS_DIR)/build/lib/* $(INSTALL_DIR)/lib/
endif

hostapd:
ifneq ($(strip $(BUILD_HOSTAPD)),)
	$(MAKE) -C $(HOSTAPD_DIR) -f prime.mk
	cp -rf $(HOSTAPD_DIR)/hostapd $(INSTALL_DIR)/bin/
endif


wpa2:
ifneq ($(strip $(BUILD_WPS)),)
	$(MAKE) -C $(WPA2_DIR) -f prime.mk
	cp -rfpP $(WPA2_DIR)/install/etc/hostapd.eap_user $(INSTALL_DIR)/etc/
	cp -rfpP $(WPA2_DIR)/install/etc/topology.conf $(INSTALL_DIR)/etc/
	cp -rfpP $(WPA2_DIR)/install/etc/topology1.conf $(INSTALL_DIR)/etc/
	cp -rfpP $(WPA2_DIR)/install/etc/topology2.conf $(INSTALL_DIR)/etc/
	cp -rfpP $(WPA2_DIR)/install/etc/topology3.conf $(INSTALL_DIR)/etc/
	cp -rfpP $(WPA2_DIR)/install/sbin/* $(INSTALL_DIR)/bin/
	cp -rfpP $(WPA2_DIR)/install/lib/*.so $(INSTALL_DIR)/lib/
endif

macchanger:
ifneq ($(strip $(BUILD_MACCHANGER)),)
	(cd $(MACCHANGER_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux --prefix=$(INSTALL_DIR); fi)
	$(MAKE) -C $(MACCHANGER_DIR) install
endif

nail: 
ifneq ($(strip $(FEATURE_EMAIL)),)
	$(MAKE) -C $(NAIL_DIR) -f prime.mk
	cp $(NAIL_DIR)/mailx $(INSTALL_DIR)/bin
	cp $(NAIL_DIR)/nail.rc  $(INSTALL_DIR)/etc
endif

# debugtools

EFENCE_DIR = $(DEBUGTOOLS_DIR)/ElectricFence-2.2.2
# DMALLOC_DIR = $(DEBUGTOOLS_DIR)/dmalloc-5.4.1
DMALLOC_DIR = $(DEBUGTOOLS_DIR)/dmalloc-5.5.2
MEMCHECK_DIR = $(DEBUGTOOLS_DIR)/memcheck-0.1.4
# STRACE_DIR = $(DEBUGTOOLS_DIR)/strace-4.5.7
STRACE_DIR = $(DEBUGTOOLS_DIR)/strace-4.6
LIBPCAP_DIR = $(DEBUGTOOLS_DIR)/libpcap-0.8.3
TCPDUMP_DIR = $(DEBUGTOOLS_DIR)/tcpdump-3.8.3
GDB_DIR = $(DEBUGTOOLS_DIR)/gdb-6.8
BINUTILS_DIR = $(OPENSOURCE_DIR)/debug/binutils-2.19.1
MPATROL_DIR	= $(DEBUGTOOLS_DIR)/mpatrol

DEBUGSUBDIRS = $(EFENCE_DIR) $(DMALLOC_DIR) $(MEMCHECK_DIR) \
				$(STRACE_DIR)\
				$(LIBPCAP_DIR) $(TCPDUMP_DIR) $(GDB_DIR) $(BINUTILS_DIR) $(MPATROL_DIR)


# Only make $(TGT) in directories that have a Makefile!
$(patsubst %, _dir_%, $(DEBUGSUBDIRS)) :
	@if [ -f $(patsubst _dir_%, %, $@)/Makefile ]; then \
		echo $(MAKE) -C $(patsubst _dir_%, %, $@) $(TGT); \
		$(MAKE) -C $(patsubst _dir_%, %, $@) $(TGT); \
	fi

debugsubdirs: $(patsubst %, _dir_%, $(DEBUGSUBDIRS))

debugtools_clean:
	$(MAKE) debugsubdirs TGT=clean

ifneq ($(strip $(BUILD_DEBUGTOOLS)),)
debugtools: memcheck tcpdump mpatrol dmalloc strace gdb efence
else
debugtools:
endif

#efence
ifneq ($(strip $(BUILD_DEBUG_EFENCE)),)
efence:
	(cd $(EFENCE_DIR); $(MAKE) )
	(cp $(EFENCE_DIR)/libefence.so.0.0 $(INSTALL_DIR)/lib)
	(cp $(EFENCE_DIR)/ef.sh  $(INSTALL_DIR)/bin)
else
efence:
endif
#dmalloc
ifneq ($(strip $(BUILD_DEBUG_DMALLOC)),)
dmalloc:
	(cd $(DMALLOC_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux; fi)
	(cd $(DMALLOC_DIR); $(MAKE) )
	(cd $(DMALLOC_DIR); $(MAKE) threadssl )
	(cd $(DMALLOC_DIR); $(MAKE) shlib )
	(cp -rf $(DMALLOC_DIR)/libdmalloc.so $(INSTALL_DIR)/lib)
	(cp -rf $(DMALLOC_DIR)/libdmallocth.so $(INSTALL_DIR)/lib)
	(cp -rf $(DMALLOC_DIR)/dmalloc $(INSTALL_DIR)/bin)
else
dmalloc:
endif

memcheck:
	(cd $(MEMCHECK_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux; fi)
	(cd $(MEMCHECK_DIR); $(MAKE) )
	(cp $(MEMCHECK_DIR)/.libs/*.so* $(INSTALL_DIR)/lib)

libpcap:
	(cd $(LIBPCAP_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux --with-pcap=linux ac_cv_linux_vers=2.4.25; fi)
	(cd $(LIBPCAP_DIR); $(MAKE) )
#strace
ifneq ($(strip $(BUILD_DEBUG_STRACE)),)
strace:
	(cd $(STRACE_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux; fi)
	(cd $(STRACE_DIR); $(MAKE) )
	(cp $(STRACE_DIR)/strace $(INSTALL_DIR)/bin)
else
strace:
endif

#gdb
ifneq ($(strip $(BUILD_DEBUG_GDB)),)
gdb:
	(cd $(GDB_DIR); if [ ! -f Makefile ]; then \
		bash ./configure --host=mips-unknown-linux --disable-sim ; fi)
	$(MAKE) -C $(GDB_DIR)
	cp -rf $(GDB_DIR)/gdb/gdbserver $(INSTALL_DIR)/sbin/
else
gdb:
endif

#mpatrol
ifneq ($(strip $(BUILD_DEBUG_MPATROL)),)
mpatrol:
	(cd $(BINUTILS_DIR)/intl; if [ ! -f Makefile ]; then \
                bash ./configure --host=mips-unknown-linux --enable-shared --with-pic ; fi)
	$(MAKE) -C $(BINUTILS_DIR)/intl
	$(MAKE) -C $(BINUTILS_DIR)/intl install
	cp -rf $(BINUTILS_DIR)/intl/libintl.a $(BINUTILS_DIR)/build/intl
	cp -rf $(BINUTILS_DIR)/build/intl/libintl.a $(INSTALL_DIR)/lib/

	(cd $(BINUTILS_DIR)/libiberty; if [ ! -f Makefile ]; then \
                bash ./configure --host=mips-unknown-linux --enable-shared --with-pic --prefix=$(BINUTILS_DIR)/build/libiberty; fi)
	$(MAKE) -C $(BINUTILS_DIR)/libiberty
	$(MAKE) -C $(BINUTILS_DIR)/libiberty install

	cp -rf $(BINUTILS_DIR)/build/libiberty/lib/libiberty.a $(INSTALL_DIR)/lib/


	(cd $(BINUTILS_DIR)/bfd; if [ ! -f Makefile ]; then \
                bash ./configure --host=mips-unknown-linux --enable-shared --with-pic --prefix=$(BINUTILS_DIR)/build/bfd; fi)
	$(MAKE) -C $(BINUTILS_DIR)/bfd
	$(MAKE) -C $(BINUTILS_DIR)/bfd install

	cp -rf $(BINUTILS_DIR)/build/bfd/lib/libbfd.so $(INSTALL_DIR)/lib/
	cp -rf $(BINUTILS_DIR)/build/bfd/lib/libbfd-2.19.1.so $(INSTALL_DIR)/lib/

	$(MAKE) -C $(MPATROL_DIR)/build/unix all
	cp -rf $(MPATROL_DIR)/build/unix/libm* $(INSTALL_DIR)/lib/
	cp -rf $(MPATROL_DIR)/build/unix/mpatrol $(INSTALL_DIR)/bin/
	cp -rf $(MPATROL_DIR)/build/unix/mprof $(INSTALL_DIR)/bin/
	cp -rf $(MPATROL_DIR)/build/unix/mptrace $(INSTALL_DIR)/bin/
	cp -rf $(MPATROL_DIR)/build/unix/mleak $(INSTALL_DIR)/bin/
else
mpatrol:
endif

tcpdump: libpcap
#	(cd $(TCPDUMP_DIR); if [ ! -f Makefile ]; then bash ./configure --host=mips-unknown-linux --with-libpcap=$(LIBPCAP_DIR) LDFLAGS="-L $(LIBPCAP_DIR)" CPPFLAGS="-I $(LIBPCAP_DIR)" ac_cv_linux_vers=2.4.25 V_INCLS=$(TOOLCHAIN)/include; fi)
# tcpdump's Makefile needed hand tweaking. See Makefile.local & Makefile.configure.
	$(MAKE) -C $(TCPDUMP_DIR)
	cp $(TCPDUMP_DIR)/$@ $(INSTALL_DIR)/bin

pmap:
	$(MAKE) -C $(OPENSOURCE_DIR)/debug/pmap install

# iptables
ifeq ($(strip $(BUILD_WESTELL_IPv6)),y)
        IPv6Enable = --enable-ipv6
else
        IPv6Enable = --disable-ipv6
endif

# iptables
ifneq ($(strip $(BUILD_IPTABLES)),)
iptables:
	(cd $(IPTABLES_DIR); if [ ! -f Makefile ]; then \
        bash  ./configure --target=mips-linux \
                --host=mips-linux --build=i386-redhat-linux \
                --prefix=$(IPTABLES_DIR)/install/ \
                --disable-devel \
                --bindir=$(INSTALL_DIR)/sbin/ \
                --sbindir=$(INSTALL_DIR)/sbin/ \
                --libexecdir=$(INSTALL_DIR)/lib \
                --enable-shared=no --enable-static=yes \
                --libdir=$(INSTALL_DIR)/lib \
                --disable-nls \
		$(IPv6Enable) \
                --disable-man \
                --with-kernel=$(KERNEL_DIR) \
                --with-xtlibdir=$(INSTALL_DIR)/lib/iptables; fi)
	$(MAKE) -C $(IPTABLES_DIR)
	$(MAKE) -C $(IPTABLES_DIR) install
else
iptables:
endif

# ebtables
ifneq ($(strip $(BUILD_EBTABLES)),)
ebtables:
	$(MAKE) -C $(EBTABLES_DIR)
	cp $(EBTABLES_DIR)/ebtables $(INSTALL_DIR)/sbin/
else
ebtables:
endif

# vconfig
ifneq ($(strip $(BUILD_VCONFIG)),)
vconfig:
	$(MAKE) -C $(VCONFIG_DIR)
	cp $(VCONFIG_DIR)/vconfig $(INSTALL_DIR)/bin/
else
vconfig:
endif

# net-tools
ifneq ($(strip $(BUILD_NETTOOLS)),)
net-tools-1.60:
	$(MAKE) -C $(NETTOOLS_DIR) all
	cp $(NETTOOLS_DIR)/arp $(INSTALL_DIR)/bin/
else
net-tools-1.60:
endif

ifneq ($(strip $(BUILD_LIBOPENSSL)),)
openssl:
	cd $(OPENSOURCE_DIR);   (tar xkfj openssl.tar.bz2 2> /dev/null || true)
	$(MAKE) -C $(OPENSOURCE_DIR)/openssl dynamic
else
openssl:
endif

# only export LIBOPENSSL_VER if we are conf'ed ON so buildFS doesn't complain
#ifneq ($(strip $(BUILD_LIBOPENSSL)),)
#LIBOPENSSL_VER = 0.9.7
#LIBOPENSSL_VER = 0.9.8
#openssl:
#	$(MAKE) -C $(LIBOPENSSL_DIR) dynamic
#	cp $(LIBOPENSSL_DIR)/libssl.so.$(LIBOPENSSL_VER) $(INSTALL_DIR)/lib/
#	ln -fs libssl.so.$(LIBOPENSSL_VER) $(INSTALL_DIR)/lib/libssl.so.0
#	ln -fs libssl.so.$(LIBOPENSSL_VER) $(INSTALL_DIR)/lib/libssl.so
#	cp $(LIBOPENSSL_DIR)/libcrypto.so.$(LIBOPENSSL_VER) $(INSTALL_DIR)/lib/
#	ln -fs libcrypto.so.$(LIBOPENSSL_VER) $(INSTALL_DIR)/lib/libcrypto.so.0
#	ln -fs libcrypto.so.$(LIBOPENSSL_VER) $(INSTALL_DIR)/lib/libcrypto.so
#else
#openssl:
#endif

# libosip2
ifneq ($(strip $(BUILD_LIBOSIP2)),)
libosip2:
	(cd $(LIBOSIP2_DIR); if [ ! -f Makefile ]; then \
		bash ./configure --host=mips-unknown-linux -disable-debug ; fi)
	$(MAKE) -C $(LIBOSIP2_DIR)
	$(MAKE) -C $(LIBOSIP2_DIR) install prefix=$(LIBOSIP2_DIR)/build/usr/local
	cp -a $(LIBOSIP2_DIR)/build/usr/local/lib/libosip2.so* $(INSTALL_DIR)/lib/
	cp -a $(LIBOSIP2_DIR)/build/usr/local/lib/libosipparser2.so* $(INSTALL_DIR)/lib/
else
libosip2:
endif

# siproxd
ifneq ($(strip $(BUILD_SIPROXD)),)
siproxd:
	(cd $(SIPROXD_DIR); if [ ! -f Makefile ]; then \
		bash ./configure --host=mips-unknown-linux --with-libosip-prefix=$(LIBOSIP2_DIR)/build/usr/local ; fi)
	$(MAKE) -C $(SIPROXD_DIR)
	$(MAKE) -C $(SIPROXD_DIR) install prefix=$(SIPROXD_DIR)/build/usr/local
	cp $(SIPROXD_DIR)/build/usr/local/sbin/siproxd $(INSTALL_DIR)/sbin/
else
siproxd:
endif


# Dynamic DNS Client
ifneq ($(strip $(BUILD_INADYN)),)
inadyn:
	$(MAKE) -C $(INADYN_DIR) all
	cp $(INADYN_DIR)/bin/linux/inadyn $(INSTALL_DIR)/bin/
else
inadyn:
endif

ifneq ($(strip $(BUILD_ORAY)),)
phddns:
	(cd $(PHDDNS_DIR); bash ./configure --host=mips-unknown-linux;)
	$(MAKE) -C $(PHDDNS_DIR)
	cp $(PHDDNS_DIR)/src/phddns $(INSTALL_DIR)/bin/
else
phddns:
endif

# ntpclient
ifneq ($(strip $(BUILD_NTPCLIENT)),)
ntpclient:
	(cd $(NTPCLIENT_DIR); if [ ! -f Makefile ]; then bash ./configure; fi)
	$(MAKE) -C $(NTPCLIENT_DIR)
	cp $(NTPCLIENT_DIR)/ntpclient $(INSTALL_DIR)/bin/
else
ntpclient:
endif

# iproute2
ifneq ($(strip $(BUILD_IPROUTE2)),)
iproute2:
	(cd $(IPROUTE2_DIR); rm -rf build; mkdir -p build/usr/share/man/man8 )
	$(MAKE) -C $(IPROUTE2_DIR) DESTDIR=$(IPROUTE2_DIR)/build KERNEL_INCLUDE=$(KERNEL_DIR)/include
	cp $(IPROUTE2_DIR)/ip/ip $(INSTALL_DIR)/sbin/ip 
	cp $(IPROUTE2_DIR)/misc/ifstat $(INSTALL_DIR)/sbin/ifstat 
	cp $(IPROUTE2_DIR)/misc/nstat $(INSTALL_DIR)/sbin/nstat 
	cp $(IPROUTE2_DIR)/misc/rtacct $(INSTALL_DIR)/sbin/rtacct 
	cp $(IPROUTE2_DIR)/misc/ss $(INSTALL_DIR)/sbin/ss 
	cp $(IPROUTE2_DIR)/tc/tc $(INSTALL_DIR)/sbin/
else
iproute2:
endif

# zebra
ifneq ($(strip $(BUILD_ZEBRA)),)
zebra:
	(cd $(ZEBRA_DIR); if [ ! -f Makefile ]; then bash ./cfg.sh; fi)
	(cd $(ZEBRA_DIR); bash ./mk.sh)
	cp $(ZEBRA_DIR)/zebra/zebra $(INSTALL_DIR)/sbin
	cp $(ZEBRA_DIR)/ripd/ripd   $(INSTALL_DIR)/sbin
else
zebra:
endif

# libgmp
libgmp: $(INSTALL_DIR)
ifneq ($(strip $(BUILD_STRONGSWAN)),)
	$(MAKE) -C $(LIBGMP_DIR) -f prime.mk
	-rm -f $(INSTALL_DIR)/lib/libgmp.so*
	cp $(LIBGMP_DIR)/libgmp.so $(INSTALL_DIR)/lib
	(cd $(LIBGMP_DIR)/.libs; lof=`echo libgmp.so.*`; cd $(INSTALL_DIR)/lib;\
	 for i in $$lof ; do echo link $$i; ln -s libgmp.so $$i; done )

endif

strongswan: $(HOSTTOOLS_DIR)/gperf libgmp
ifneq ($(strip $(BUILD_STRONGSWAN)),)
	$(MAKE) -C $(STRONGSWAN_DIR) -f prime.mk
	(cd $(STRONGSWAN_DIR)/install; cp -rp ipsec sbin $(INSTALL_DIR))
	(cd $(STRONGSWAN_DIR)/install; cp -rp lib/*.so* $(INSTALL_DIR)/lib)
endif

openl2tp:	
ifneq ($(strip $(BUILD_L2TP)),)
	$(MAKE) -C $(OPENL2TP_DIR) -f prime.mk
endif

pptp:
ifneq ($(strip $(BUILD_PPTP)),)
	$(MAKE) -C $(PPTP_DIR) 
	$(MAKE) -C $(PPTP_DIR) install
endif

upnp:
ifneq ($(strip $(BUILD_UPNP_IGD)),)
	$(MAKE) -C $(LIBUPNP_DIR) -f prime.mk
	$(MAKE) -C $(IGD_DIR) -f prime.mk
	(cd $(IGD_DIR)/install; cp -rp etc/* $(INSTALL_DIR)/etc)
	(cd $(IGD_DIR)/install; cp -p sbin/* $(INSTALL_DIR)/sbin)
endif

flex:
ifneq ($(strip $(BUILD_FLEX)),)
	$(MAKE) -C $(FLEX_DIR) -f prime.mk
endif

# We are no more using this from opensource.
# We are using the radvd from the Broadcom/userspace/gpl/apps
radvd:
ifneq ($(strip $(BUILD_RADVD)),)
	$(MAKE) -C $(RADVD_DIR) -f prime.mk
	(cd $(RADVD_DIR); cp -p radvd $(INSTALL_DIR)/bin)
endif

iputils:
ifneq ($(strip $(BUILD_IPUTILS)),)
	@echo BUILD_IPUTILS set, building...
	$(MAKE) -C $(IPUTILS_DIR) -f prime.mk
	(cd $(IPUTILS_DIR); cp -p traceroute6 $(INSTALL_DIR)/bin)
endif

dhcpv6:
ifneq ($(strip $(BUILD_DHCPV6)),)
	$(MAKE) -C $(DHCPV6_DIR) -f prime.mk
	(cd $(DHCPV6_DIR)/server; cp -p dhcpd $(INSTALL_DIR)/bin)
	(cd $(DHCPV6_DIR)/client; cp -p dhclient $(INSTALL_DIR)/sbin/dhclient)
	(cd $(DHCPV6_DIR)/client/scripts; cp -p linux $(INSTALL_DIR)/etc/dhclient.script)
endif

cli:
ifneq ($(strip $(BUILD_WSTLCLIUTILS)),)
	$(MAKE) -C $(CLIUTILS_DIR)
	mkdir -p $(INSTALL_DIR)/bin
	cd $(CLIUTILS_DIR); cp -p $$(cat lof) $(INSTALL_DIR)/bin
endif

# Network Manager
ifneq ($(strip $(BUILD_NET_MGR)),)
net_mgr:
	$(MAKE) -C $(NET_MGR_DIR) all
	cp $(NET_MGR_DIR)/bin/net_mgr $(INSTALL_DIR)/bin/
	cp $(NET_MGR_DIR)/bin/fw_cntl $(INSTALL_DIR)/bin/
	cp $(NET_MGR_DIR)/bin/netmgrutil $(INSTALL_DIR)/bin/
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/dnsisset
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/netmessage
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/wanlinkup
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/DebugLevel
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/netmgrPPD
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/pppoeterm
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/setconfigresolv
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/wait4
	ln -fs /bin/netmgrutil $(INSTALL_DIR)/bin/iptbld
	cp $(NET_MGR_DIR)/bin/holdoffrandom.so $(PPPPLUGINS_DIR)/holdoffrandom.so
	cp $(NET_MGR_DIR)/bin/ppphooker.so $(PPPPLUGINS_DIR)/ppphooker.so
	cp $(NET_MGR_DIR)/scripts/* $(INSTALL_DIR)/etc/
else
net_mgr:
endif

# lua - lightweight scripting engine
# 
LUA_HOST_CONFIG = $(LUA_DIR)/config_$(BUILD_HOST_TYPE)
LUA_TARG_CONFIG = $(LUA_DIR)/config_cross
LUA_CONFIG = $(LUA_DIR)/config

ifneq ($(strip $(BUILD_LUA)),)
lua: $(HOSTTOOLS_BIN)/lua
	cp $(LUA_TARG_CONFIG) $(LUA_CONFIG)
	$(MAKE) -C $(LUA_DIR) all
	mkdir -p $(INSTALL_DIR)/lib
ifneq ($(strip $(BUILD_WSTL_CFG)),)	
	cp $(LUA_DIR)/bin/*.so $(INSTALL_DIR)/lib
endif	
# Uncomment to copy the lua interperter (for debugging)
#	cp $(LUA_DIR)/bin/lua $(INSTALL_DIR)/bin
#	cp $(TOOLCHAIN)/lib/libm.so $(INSTALL_DIR)/lib

else
lua:

endif

# luatools - Lua tools for the build host
#  These are pre-built and checked into StarTeam.
#  The luatools and luacleantools targets are used to
#  rebuild them.
luatools $(HOSTTOOLS_BIN)/lua:
	cp $(LUA_HOST_CONFIG) $(LUA_CONFIG)
	$(MAKE) -C $(LUA_DIR) cleaner all
	cp $(LUA_DIR)/bin/* $(HOSTTOOLS_BIN)
	$(MAKE) -C $(LUA_DIR) cleaner
	rm -f $(LUA_CONFIG)

luacleantools:
	cp $(LUA_HOST_CONFIG) $(LUA_CONFIG)
	$(MAKE) -C $(LUA_DIR) cleaner
	rm -f $(HOSTTOOLS_DIR)/*lua*
	rm -f $(HOSTTOOLS_BIN)/*lua*
# Westell application libraries

ifneq ($(strip $(BUILD_WESTELL_LIBHTTP)),)
westellHTTP:
# libwstlHttp.so is used by the webserver, fireball
	@echo BUILD_WESTELL_LIBHTTP set, building...
	$(MAKE) -C $(LIBHTTP_DIR) 
#	cp $(LIBHTTP_DIR)/libwstlHttp.so $(INSTALL_DIR)/lib
else
westellHTTP:
endif

westellUTIL:
ifneq ($(strip $(BUILD_WSTL_LIBUTIL)),)
	@echo BUILD_WSTL_LIBUTIL set, building...
	$(MAKE) -C $(LIBUTIL_DIR)
	cp -pP $(LIBUTIL_DIR)/libwstlUtil.so $(INSTALL_DIR)/lib
endif

ifneq ($(strip $(BUILD_WESTELL_LIBXML)),)
westellXML:
# libxml.so is used by FTM, the webserver, ...
	@echo BUILD_WESTELL_LIBXML set, building...
	$(MAKE) -C $(LIBXML_DIR) 
	cp $(LIBXML_DIR)/libxml.so $(INSTALL_DIR)/lib
else
westellXML:
endif

IniParser:
# libIni.so is used by FTM, Management utility ...
	$(MAKE) -C $(LIBINIPARSER_DIR) 
	cp $(LIBINIPARSER_DIR)/libIni.so $(INSTALL_DIR)/lib

DebugPrint:
# libdebugPrint.so is used by all apps for controlling the debugs, Management utility ...
	$(MAKE) -C $(LIBDEBUGPRINT_DIR) 
	cp $(LIBDEBUGPRINT_DIR)/libdebugPrint.so $(INSTALL_DIR)/lib

upgrade:
# libupgrade.so is used by Envoy and provided by the flash manager app.
	$(MAKE) -C $(LIBUPGRADE_DIR) 
	cp $(LIBUPGRADE_DIR)/libupgrade.so $(INSTALL_DIR)/lib

TimeUtils:
# libtimeutils.so is used by cwmpd app.
	$(MAKE) -C $(TIMEUTILS_DIR) 
	cp $(TIMEUTILS_DIR)/libtimeutils.so $(INSTALL_DIR)/lib

CommonRoutines:
# libcommonroutines.so is used by WebServer,cwmpd..etc app.
	$(MAKE) -C $(COMMONROUTINES_DIR) 
	cp $(COMMONROUTINES_DIR)/libcommonroutines.so $(INSTALL_DIR)/lib

logRead:
# liblogread.so is used by WebServer,cwmpd..etc app.
	$(MAKE) -C $(LOGREAD_DIR) all
	cp $(LOGREAD_DIR)/liblogread.so $(INSTALL_DIR)/lib
	cp $(LOGREAD_DIR)/libUpnp.so $(INSTALL_DIR)/lib
	cp $(LOGREAD_DIR)/libNbios.so $(INSTALL_DIR)/lib

ftmshm:
# libftmshm.so is used by modemmgmt, wireless, and mgmtutil.
	$(MAKE) -C $(LIBFTMSHM_DIR)
	cp $(LIBFTMSHM_DIR)/libftmshm.so $(INSTALL_DIR)/lib
#Management Utility

ifneq ($(strip $(BUILD_MANAGEMENT_UTILITY)),)
mgmtutil:
	$(MAKE) -C $(WESTELL_APP_DIR)/ManagementUtility $(BUILD_MANAGEMENT_UTILITY)
	
else
mgmtutil:
endif

#led CONTROL
led:
	$(MAKE) -C $(WESTELL_APP_DIR)/Led dynamic
adslDiag:
	$(MAKE) -C $(WESTELL_APP_DIR)/adslDiag dynamic

ifneq ($(strip $(BUILD_WSTL_VOIP)),)
vcli:
	$(MAKE) -C $(WESTELL_APP_DIR)/VoiceCLI dynamic
else
vcli:
endif

mem_profiler:
	$(MAKE) -C $(WESTELL_APP_DIR)/mem_profiler dynamic

modemmgmt:
	$(MAKE) -C $(WESTELL_APP_DIR)/ModemMgmt $(BUILD_MANAGEMENT_UTILITY)

mmreboot:
	$(MAKE) -C $(WESTELL_APP_DIR)/MMReboot $(BUILD_MANAGEMENT_UTILITY)

wchk:
	$(MAKE) -C $(WESTELL_APP_DIR)/wchk $(BUILD_MANAGEMENT_UTILITY)

# Configuration Manager
ifneq ($(strip $(BUILD_WSTL_CFG)),)
wstlcfg: lua
	$(MAKE) -C $(WSTL_CFG_DIR) install
else
ifneq ($(strip $(BUILD_WSTL_CFG_C_BASED)),)
wstlcfg:
	$(MAKE) -C $(WSTL_CFG_DIR) install
else
wstlcfg:
endif
endif

ifneq ($(strip $(BUILD_WSTL_CFG)),)
wstlprecfg: lua
	$(MAKE) -C $(WSTL_CFG_DIR)/data all
else
ifneq ($(strip $(BUILD_WSTL_CFG_C_BASED)),)
wstlprecfg:
	$(MAKE) -C $(WSTL_CFG_DIR)/data all
else
wstlprecfg:
endif
endif

# Statistics deamon
ifneq ($(strip $(BUILD_WSTL_STATS)),)
wstlstats: wstlcfg
	$(MAKE) -C $(WSTL_STATS_DIR) install
else
wstlstats:
	$(warning BUILD_WSTL_STATS is OFF)
endif
# Wireless
wireless:
ifneq ($(strip $(BUILD_WSTL_WIRELESS)),)
	$(MAKE) -C $(WSTL_WIRELESS_DIR)
endif

auth:
	$(MAKE) -C $(AUTHSRC_DIR) 
	cp $(AUTHSRC_DIR)/auth  $(INSTALL_DIR)/sbin/
	$(MAKE) -C $(AUTHSRC_DIR)/dlisten
	cp $(AUTHSRC_DIR)/dlisten/iwcontrol $(INSTALL_DIR)/sbin/  

wscd: 	
	$(MAKE) -C $(WSCDSRC_DIR)/portingssl 
	$(MAKE) -C $(WSCDSRC_DIR)/src
	cp $(WSCDSRC_DIR)/src/wscd $(INSTALL_DIR)/bin/wscd
	cp $(WSCDSRC_DIR)/src/wscd.conf $(INSTALL_DIR)/etc/wscd.conf

miniupnp: 
	$(MAKE) -C $(MINIUPNP_DIR) 


mptool-daemon:
ifeq ($(BUILD_WESTELL_FTMAPP),y)
	$(MAKE) -C $(MPTOOL_DIR)
	cp $(MPTOOL_DIR)/UDPserver $(INSTALL_DIR)/bin/UDPserver
	cp $(MPTOOL_DIR)/irf $(INSTALL_DIR)/bin/irf
	cp $(MPTOOL_DIR)/orf $(INSTALL_DIR)/bin/orf
	
	$(MAKE) -C $(OPENSOURCE_DIR)/utelnetd-0.1.1 clean
	$(MAKE) -C $(OPENSOURCE_DIR)/utelnetd-0.1.1 install
endif


ifneq ($(strip $(BUILD_VZ_DDNS)),)
ipupdate-1.1.1:
		$(MAKE) -C $(DDNS_DIR)
else
ipupdate-1.1.1:
endif

# Westell Envoy daemon

ifneq ($(strip $(BUILD_WESTELL_CWMPD)),)
cwmpd:
	@echo BUILD_WESTELL_CWMPD set, building...
	$(MAKE) -C $(WSTL_CWMPD_DIR) 
else
cwmpd:
endif

# ERT Software Upgrade
ifneq ($(strip $(BUILD_NETGEAR_ERTUPGRADE)),)
ERTUpgrade:
	@echo BUILD_NETGEAR_ERTUPGRADE set, building...
	$(MAKE) -C $(WSTL_ERTUPGRADE_DIR)
else
ERTUpgrade:
endif


# Westell RemoteCfg daemon
#
#ifneq ($(strip $(BUILD_WSTL_REMOTECFG)),)
#RemoteCfg:
#   @echo BUILD_WESTELL_REMOTECFG set, building...
#	$(MAKE) -C $(WSTL_RECFG_DIR) 
#else
#RemoteCfg:
#endif

# Westell RemoteCfg daemon

ifneq ($(strip $(BUILD_WSTL_REMOTECFG)),)
RemoteCfg:
	@echo BUILD_WESTELL_REMOTECFG set, building...
	$(MAKE) -C $(WSTL_RECFG_DIR) 
else
RemoteCfg:
endif

# Westell Fireball daemon

ifneq ($(strip $(BUILD_WESTELL_FIREBALL)),)
export BUILD_WESTELL_FIREBALL
export WSTL_FIREBALL_DIR
fireball:
	@echo BUILD_WESTELL_FIREBALL set, building...
	$(MAKE) -C $(WSTL_FIREBALL_DIR) 
else
fireball:
	@echo BUILD_WESTELL_FIREBALL not set, fireball not configured, skipping...
endif

ifneq ($(strip $(BUILD_WESTELL_UPNP)),)
upnp_app:
	$(MAKE) -C $(WSTL_UPNP_DIR) 
else
upnp_app:
endif

# Westell Diagnostic Web Redirection
ifneq ($(strip $(BUILD_WESTELL_DIAG)),)
diag:
	@echo BUILD_WESTELL_DIAG set, building...
	$(MAKE) -C $(WSTL_DIAG_DIR)
else
diag:
	@echo BUILD_WESTELL_DIAG not set, skipping...
endif

# SMB/CIFS Server
ifneq ($(strip $(BUILD_CIFS_SERVER)),)
cifs_server:
	$(MAKE) -C $(CIFS_SRC_DIR) all
else
cifs_server:
endif

# Test Applications
ifneq ($(strip $(BUILD_TESTAPP)),)
testapp:
	$(MAKE) -C $(WESTELL_APP_DIR)/testapp
else
testapp:
endif
 
ifeq ($(BUILD_WESTELL_FTMAPP),y)
rssi_dump:
	$(MAKE) -C $(WESTELL_APP_DIR)/rssi
else
rssi_dump:
endif


ftest:
	$(MAKE) -C $(WESTELL_APP_DIR)/test

tool: $(FLASH_BUILD)
	find $(HOSTTOOLS_DIR) -name "*.o" | xargs rm -rf
	$(MAKE) -C $(HOSTTOOLS_DIR) HOSTCC=gcc

# Save information needed to decode a Kernel oops message
#
OOPS_DIR := $(PROFILE_DIR)/oops
oopsinfo: $(KERNEL_OBJ)/vmlinux
	mkdir -p $(OOPS_DIR)
	mkdir -p $(OOPS_DIR)/modules
	find $(PROFILE_DIR)/modules -name "*.o" |\
		xargs --replace cp {} $(OOPS_DIR)/modules/
	cp $(KERNEL_OBJ)/vmlinux $(OOPS_DIR)
	cp $(KERNEL_OBJ)/System.map $(OOPS_DIR)

$(FLASH_BUILD):
	make -C $(HOSTTOOLS_DIR)/FlashImageBld
	cp $(HOSTTOOLS_DIR)/FlashImageBld/FlashImageBuild$(HOST_EXE_EXT) $(HOSTTOOLS_DIR)

buildimage: tool $(INSTALL_DIR) upg 

upg: upg1 upg2
upg1:
	@echo "Build FS image"
	cp -a $(TARGETS_DIR)/fs.src/* $(INSTALL_DIR)
	cp -a ../fs.src/etc/* $(INSTALL_DIR)/etc
	bash $(TARGETS_DIR)/buildFS $(INSTALL_DIR)
upg2:
	rm -rf $(INSTALL_DIR)/uclibc
	rm -rf $(STRIPFS) && cp -a $(INSTALL_DIR) $(STRIPFS)
	-rm -f $(KERNEL_MOD)/lib/modules/$(KERNEL_VER)/modules.*
	$(DEPMOD_BUILD) -b $(KERNEL_MOD) -F $(KERNEL_DIR)/System.map -k $(KERNEL_DIR)/vmlinux
	cp -a $(KERNEL_MOD)/* $(STRIPFS)
ifeq ($(BUILD_LANGUPG_FEATURE),y)
	cp -a $(WESTELL_APP_DIR)/lang/* lang
endif
	-rm -rf $(STRIPFS)/lib/modules/$(KERNEL_VER)/build
	-rm -rf $(STRIPFS)/lib/modules/$(KERNEL_VER)/source
#
	STRIP=$(REAL_STRIP) bash $(HOSTTOOLS_DIR)/stripfs.sh $(STRIPFS)

	@echo "Running super strip..."
# 	find $(STRIPFS) | xargs file | grep "executable" | grep ELF | cut -f 1 -d : | xargs $(SSTRIP) 2> /dev/null
	find $(STRIPFS) | xargs file | grep "shared object" | grep ELF | cut -f 1 -d : | xargs $(SSTRIP) 2> /dev/null
	
	chmod +x $(TARGETS_DIR)/makeDevs
ifeq ($(BUILD_LANGUPG_FEATURE),y)
	chmod +x $(TARGETS_DIR)/make_langsqfs
	cd $(PROFILE_DIR) && $(HOSTTOOLS_DIR)/fakeroot/fakeroot ../make_langsqfs $(STRIPFS) 
else
	chmod +x $(TARGETS_DIR)/make_sqfs
	cd $(PROFILE_DIR) && $(HOSTTOOLS_DIR)/fakeroot/fakeroot ../make_sqfs $(STRIPFS) 
endif

	@echo "Build kernel image"
	cp $(KERNEL_DIR)/vmlinux $(PROFILE_DIR)
	cd $(PROFILE_DIR) && $(STRIP) \
		--remove-section=.note --remove-section=.comment vmlinux;
	cd $(PROFILE_DIR) && $(OBJCOPY) -O binary vmlinux vmlinux.bin;
	cd $(PROFILE_DIR) && $(HOSTTOOLS_DIR)/7zlzma e vmlinux.bin vmlinux.lz
	cd $(PROFILE_DIR) && $(HOSTTOOLS_DIR)/cmplzma vmlinux vmlinux.lz vmlinux.pkg
	@echo "Build App.upg"
	rm -f $(PROFILE_DIR)/App.upg
	rm -f $(PROFILE_DIR)/RootFs.upg
ifeq ($(BUILD_LANGUPG_FEATURE),y)
	rm -f $(PROFILE_DIR)/Lang.upg
endif
	@echo "+++ Building flash layout +++"
ifeq ($(BUILD_WESTELL_FTMAPP),y)
	cd $(PROFILE_DIR) && $(FLASH_BUILD) App.upg -u vmlinux.pkg ../build_number.cfg version.cfg -FTM
else
	cd $(PROFILE_DIR) && $(FLASH_BUILD) App.upg -u vmlinux.pkg ../build_number.cfg version.cfg
endif
	cd $(PROFILE_DIR) && $(FLASH_BUILD) App.upg -u $(ROOTFS_IMG) ../build_number.cfg rootfs.cfg
ifeq ($(BUILD_LANGUPG_FEATURE),y)
	cd $(PROFILE_DIR) && $(FLASH_BUILD) Lang.upg -u $(LANGFS_IMG) ../build_number.cfg lang.cfg
endif

# Rename using board id and build number, and save release and debug files to /Build/current	
ifdef SHELL_RELEASE_BUILD
 ifneq ($(BUILD_WESTELL_FTMAPP),y)
  ifeq ($(WSTL_RELEASE_BUILD),1)
	@echo "Renaming and saving release build files to build/current"
	cp $(PROFILE_DIR)/App.upg $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)App"="$(BUILD_NUMBER).rel.upg
	cp $(PROFILE_DIR)/FlashImage.bin $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)FlashImage"="$(BUILD_NUMBER).rel.bin
ifeq ($(BUILD_LANGUPG_FEATURE),y)
	cp $(PROFILE_DIR)/Bootlang.upg $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)Boot"="$(BUILD_NUMBER).upg
else
	cp $(PROFILE_DIR)/Boot.upg $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)Boot"="$(BUILD_NUMBER).upg
endif
	cp $(KERNEL_OBJ)/System.map $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)System"="$(BUILD_NUMBER).rel.map
	cp $(PROFILE_DIR)/App.upg $(BUILD_SAVE_DIR)/$(RELEASE_ID).rel.upg
  else
	@echo "Renaming and saving debug build files to build/current"
	cp $(PROFILE_DIR)/App.upg $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)App"="$(BUILD_NUMBER).upg
	cp $(PROFILE_DIR)/FlashImage.bin $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)FlashImage"="$(BUILD_NUMBER).bin
	cp $(PROFILE_DIR)/BootFlashImage.bin $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)BootFlashImage"="$(BUILD_NUMBER).bin
	cp $(KERNEL_OBJ)/System.map $(BUILD_SAVE_DIR)/$(WSTL_BOARD_ID)System"="$(BUILD_NUMBER).map
	cp $(PROFILE_DIR)/App.upg $(BUILD_SAVE_DIR)/$(RELEASE_ID).upg
  endif
 else
	@echo "Renaming and saving FTM build files to build/current"
	cp $(PROFILE_DIR)/App.upg $(BUILD_SAVE_DIR)/$(PROFILE)FTM_App"="$(BUILD_NUMBER).upg
	cp $(KERNEL_OBJ)/System.map $(BUILD_SAVE_DIR)/$(PROFILE)FTM_System"="$(BUILD_NUMBER).map
 endif
endif
	@echo
	@echo "Image file system contents size: " `du -sk $(STRIPFS) | cut -f 1`  "KB"
	@echo $(strip $(BRCM_KERNEL_ROOTFS)) " Image file system compressed size: " `du -sk $(PROFILE_DIR)/$(ROOTFS_IMG) | cut -f 1`  "KB"
	@echo "Kernel uncompressed size: " `du -sk $(PROFILE_DIR)/vmlinux | cut -f 1`  "KB"
	@echo "Kernel compressed size: " `du -sk $(PROFILE_DIR)/vmlinux.lz | cut -f 1`  "KB"
	@echo $(strip $(BRCM_KERNEL_ROOTFS)) " upgrade size: " `du -sk $(PROFILE_DIR)/App.upg | cut -f 1`  "KB"
	@echo -e "Done! Image $(PROFILE) has been built in $(PROFILE_DIR)."

# Only make $(TGT) in directories that have a Makefile!
$(patsubst %, _dir_%, $(APP_SUBDIRS)) :
	@if [ -f $(patsubst _dir_%, %, $@)/Makefile ]; then \
		echo $(MAKE) -C $(patsubst _dir_%, %, $@) $(TGT); \
		$(MAKE) -C $(patsubst _dir_%, %, $@) $(TGT); \
        fi

#This is used to flash App.upg directly from development view.
pump:
	test -f App.upg && lxatur -i 192.168.1.1 -f App.upg

subdirs: $(patsubst %, _dir_%, $(APP_SUBDIRS))

###########################################
#
# Rules for cleaning
#
###########################################

clean: sanity_check kernel_clean apps_clean hosttools_clean debugtools_clean
	rm -rf $(ROOTFS) $(STRIPFS)
	rm -f $(FAKEROOT_ENV) $(KERNEL_PKG) $(ROOTFS_IMG) $(APP_UPG) $(ROOT_UPG)
	rm -f vmlinux vmlinux.bin vmlinux.lz
	rm -f cfg_defaults.luc cfg_defaults.lua
	rm -rf oops
	rm -f default.cfg
ifeq ($(BUILD_LANGUPG_FEATURE),y)
	rm -rf lang
	rm -f langfs.img
	rm -f Lang.upg
endif

kernel_clean: mrproper 
#	cd $(BUILD_DIR)/$(VENDOR_DIR); ./rmlinks.sh
	rm -rf $(KERNEL_MOD) 

mrproper:
#	cd $(BUILD_DIR)/$(VENDOR_DIR); ./mklinks.sh
	$(MAKE) -C $(KERNEL_DIR) mrproper

conntrack_clean:
	(if [ -f $(LIBNFNETLINK_DIR)/Makefile ]; then $(MAKE) -C $(LIBNFNETLINK_DIR)/ distclean; fi)
	(if [ -f $(LIBNETFILTER_CONNTRACK_DIR)/Makefile ]; then $(MAKE) -C $(LIBNETFILTER_CONNTRACK_DIR)/ distclean; fi)
	(if [ -f $(CONNTRACK_TOOLS_DIR)/Makefile ]; then $(MAKE) -C $(CONNTRACK_TOOLS_DIR)/ distclean; fi)


subdirs_clean:
	@echo cleaning applications
	$(MAKE) subdirs TGT=clean

apps_clean: subdirs_clean
ifeq ($(wildcard $(OPENSOURCE_DIR)),)
	@echo "**** No Opensource Applications To Clean ****"
else

	rm -f $(BUSYBOX_DIR)/.depend
	rm -f $(LIBOSIP2_DIR)/Makefile $(SIPROXD_DIR)/Makefile
	cp $(LUA_TARG_CONFIG) $(LUA_CONFIG)
	$(MAKE) -C $(LUA_DIR) cleaner
	(if [ -f $(PPP_DIR)/Makefile ]; then $(MAKE) -C $(PPP_DIR) dist-clean; fi)
	(if [ -f $(DHCPV6_DIR)/Makefile ]; then $(MAKE) -C $(DHCPV6_DIR) distclean; fi)
	(if [ -f $(LIBUPNP_DIR)/Makefile ]; then $(MAKE) -C $(LIBUPNP_DIR) distclean; fi)
	(if [ -f $(FLEX_DIR)/Makefile ]; then $(MAKE) -C $(FLEX_DIR) distclean; fi)
	(if [ -f $(RP_PPPOE_DIR)/src/Makefile ]; then $(MAKE) -C $(RP_PPPOE_DIR)/src distclean; fi)
	(if [ -f $(LIBAPPPARSE_DIR)/Makefile ]; then $(MAKE) -C $(LIBAPPPARSE_DIR) clean; fi)
	(if [ -f $(LIBNFNETLINK_DIR)/Makefile ]; then $(MAKE) -C $(LIBNFNETLINK_DIR)/ distclean; fi)
	(if [ -f $(LIBNETFILTER_CONNTRACK_DIR)/Makefile ]; then $(MAKE) -C $(LIBNETFILTER_CONNTRACK_DIR)/ distclean; fi)
	(if [ -f $(CONNTRACK_TOOLS_DIR)/Makefile ]; then $(MAKE) -C $(CONNTRACK_TOOLS_DIR)/ distclean; fi)
	(if [ -f $(IPTABLES_DIR)/Makefile ]; then $(MAKE) -C $(IPTABLES_DIR)/ distclean; fi)
	rm -f $(BUSYBOX_DIR)/.depend
	rm -f $(DMALLOC_DIR)/Makefile $(MEMCHECK_DIR)/Makefile \
	  $(LIBPCAP_DIR)/Makefile $(STRACE_DIR)/Makefile \
	  $(LIBOSIP2_DIR)/Makefile $(SIPROXD_DIR)/Makefile \
	  $(ZEBRA_DIR)/Makefile
	find $(OPENSOURCE_DIR) -type f -name *.d | grep -v init.d | xargs rm -f
endif

hosttools_clean:
	$(MAKE) -C $(HOSTTOOLS_DIR) clean

openl2tp_clean:
	$(MAKE) -C $(OPENL2TP_DIR) clean
	
pptp_clean:
	$(MAKE) -C $(PPTP_DIR) clean

buildopts:
	@printf '\n\nthe following build options may be specified on the command line:\n\n'
	@printf 'V=1 - makes kernel build verbose\nECHORULES=1 - makes voip build verbose\n'
	@printf 'WSTL_USE_PHY=CBT - causes the DSL PHY to be the CBT specific version\n'
	@printf 'BUILD_DEBUGTOOLS=1 - builds target debug tools\n'
	@printf 'WSTL_RELEASE_BUILD=1 - turns off console and debugging tools\n'
	@printf 'GLOBAL_DEBUGGING_ENABLED=0 - turns off many debug messages\n'
	@printf 'WSTL_DEBUG_OUTPUT=0 - turns off certain debug messages\n'
	@printf '\n'

help:
	@echo "here are the available make targets:"
	@echo
	@# if you need to modify this, I'd suggest expanding it first!
	@# remember, make needs $$ for awk's $
	@awk 'FNR==1{if(++p==2)for(V in show){if(def[V]=="")continue;print def[V]"\n";split(def[V],a);for(i in a)seen[a[i]":"]=1;}}; \
	p==1&&/[A-Z_][A-Z_0-9]*_APPS *=/{V=$$1;v=$$0;gsub("[\t ]+"," ",v);def[V]=v;while($$0~/\\$$/){getline;v=$$0;gsub("[\t ]+"," ",v);def[V]=def[V]" "v;};gsub(/\\/,"",def[V]);gsub(/  +/," ",def[V]);gsub(/  /," ",def[V]);}; \
	$$1~/[a-z_]+:$$/{if($$1~"subdirs"||$$1~"EXPORT_ALL_VARIABLES"||$$1~"help")next;if(p==1){for(i=2;i<NF;i++)if($$i~/[$$][(]/){V=$$i;sub("[$$][(]","",V);sub(")","",V);show[V]=1;}}else{if(NF==1&&$$1 in stop)next;if(!($$1 in seen)){print;for(i=2;i<NF;i++)stop[$$i":"]=1;};seen[$$1]=1}}' Makefile Makefile
