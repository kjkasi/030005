# Tools for build

# host tools should not use cross compiler
unexport AR AS LD CC CPP CXX NM STRIP SSTRIP OBJCOPY OBJDUMP RANLIB

CC = gcc
STRIP = strip
TOPDIR	:= $(shell /bin/pwd)

LZMA_TAR=lzma432.tar.bz2
LZMA_DIR=squashfs-lzma/lzma/lzma-4.65/CPP/7zip/Compress/LZMA_Alone

ifdef B_ENDIAN
LZFLAGS := -D B_ENDIAN=1
ESUFFIX := big
else
ESUFFIX := little
endif

#SQUASHFS_LZMA_DIR=squashfs-lzma/squashfs/squashfs3.2-r2/squashfs-tools
SQUASHFS_LZMA_DIR=squashfs-lzma/squashfs/squashfs4.0/squashfs-tools
export SQUASHFS_LZMALIB_DIR1=squashfs-lzma/lzma/lzma-443/C/7zip/Compress/LZMA_Alone
export SQUASHFS_LZMALIB_DIR2=squashfs-lzma/lzma/lzma-443/C/7zip/Compress/LZMA_C
FLASH_DIR=FlashImageBld
SSTRIP_DIR=sstrip_source

all: 7zlzma stripweb mksquashfs-lzma fakeroot sstrip gperf

FlashImageBuild:
	#$(MAKE) -C $(FLASH_DIR)
	#cp $(FLASH_DIR)/FlashImageBuild ./FlashImageBuild

sstrip:
	gcc  -I$(SSTRIP_DIR)/include -include byteswap.h -o ./sstrip $(SSTRIP_DIR)/src/sstrip.c

mksquashfs-lzma: 
	$(MAKE) -C $(SQUASHFS_LZMA_DIR)
	ln -fs ./$(SQUASHFS_LZMA_DIR)/mksquashfs ./mksquashfs-lzma

$(LZMA_DIR): 
	cd 7zip_lzma

7zlzma: $(LZMA_DIR)
	$(MAKE) -C $(LZMA_DIR) -f makefile.gcc
	ln -fs $(LZMA_DIR)/lzma_alone ./7zlzma


cmplzma: cmplzma.cpp
	#g++ $(LZFLAGS) -o $@ $<

gperf:
	$(MAKE) -C gperf-3.0.2

stripweb: stripweb.l
	$(LEX) $<
	gcc lex.yy.c -o $@ -ll
	rm lex.yy.c

export FAKEROOT_DIR = $(TOPDIR)/fakeroot

$(FAKEROOT_DIR)/.configured:
	(tar -jkxf fakeroot.tar.bz2 2> /dev/null || true)
	cd $(FAKEROOT_DIR); CFLAGS="$(CFLAGS_NOARCH)" ./configure --prefix=/usr --disable-nls
	touch $@

fakeroot: $(FAKEROOT_DIR)/.configured
	make -C $(FAKEROOT_DIR)
	sed -e 's,^PREFIX=.*,PREFIX=$(FAKEROOT_DIR),g' -e 's,^BINDIR=.*,BINDIR=$(FAKEROOT_DIR),g' -e 's,^PATHS=.*,PATHS=$(FAKEROOT_DIR)/.libs:/lib:/usr/lib,g' $(FAKEROOT_DIR)/scripts/fakeroot > $(FAKEROOT_DIR)/fakeroot
	chmod u+x $(FAKEROOT_DIR)/fakeroot

clean:
	#rm -f FlashImageBuild
	#rm -f 7zlzma cmplzma 
	rm -f 7zlzma 
	rm -f mksquashfs-lzma
	rm -f sstrip 
	rm -f stripweb
	rm -fr *.o core
	rm -f linux/*.so linux/lua linux/luac
	make -C libcreduction clean
	rm -f gperf
	$(MAKE) -C gperf-3.0.2 clean
	$(MAKE) -C $(SQUASHFS_LZMALIB_DIR1) -f sqlzma.mk clean
	$(MAKE) -C $(SQUASHFS_LZMALIB_DIR2) -f sqlzma.mk clean
	$(MAKE) -C $(SQUASHFS_LZMA_DIR) clean
	$(MAKE) -C $(LZMA_DIR) -f makefile.gcc clean
	$(MAKE) -C $(FLASH_DIR) clean
	rm -fr 7zip_lzma
	if [ -e $(FAKEROOT_DIR)/Makefile ];  then make -C $(FAKEROOT_DIR) distclean; fi
	rm -f $(FAKEROOT_DIR)/fakeroot
	rm -f $(FAKEROOT_DIR)/.configured
