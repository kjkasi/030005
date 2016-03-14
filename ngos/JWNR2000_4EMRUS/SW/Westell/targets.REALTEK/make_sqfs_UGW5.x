#!/bin/bash

../makeDevs $1 

#$HOSTTOOLS_DIR/mksquashfs-lzma $STRIPFS $ROOTFS_IMG -nopad -noappend -root-owned -be
#$HOSTTOOLS_DIR/mksquashfs-lzma $STRIPFS $ROOTFS_IMG -noappend -be -no-fragments -noI -all-root
#$HOSTTOOLS_DIR/mksquashfs-lzma $STRIPFS $ROOTFS_IMG -noappend -no-fragments -noI -all-root -comp lzma -processors 1
$HOSTTOOLS_DIR/mksquashfs-lzma $STRIPFS $ROOTFS_IMG -comp lzma -always-use-fragments 
