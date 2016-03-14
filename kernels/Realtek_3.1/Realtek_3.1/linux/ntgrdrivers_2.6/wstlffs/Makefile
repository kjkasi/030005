# File: drivers/char/wstl/ffs/Makefile
#
# Makefile for the ffs Flash File System driver module
#

wstlffs-objs := inode.oo wfio.oo ffs.oo uncompr.oo compress.oo

obj-$(CONFIG_WSTL_FFS) += wstlffs.oo

EXTRA_CFLAGS += -I. -fno-exceptions

EXTRA_CFLAGS += -I$(WSTLDRIVERS_DIR)/include -I$(KERNEL_DIR)/include

-include $(TOPDIR)/Rules.make

clean:
	rm -f core *.o *.a *.s
