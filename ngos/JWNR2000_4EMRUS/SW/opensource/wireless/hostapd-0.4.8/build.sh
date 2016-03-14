#!/bin/sh
APPS_NAME="hostapd-0.4.8"
if [ -e sysconfig.sh ]; then
	. sysconfig.sh
	. config.sh
	. model_config.sh
else
        echo "Application "$APPS_NAME" not configured"
        exit 0
fi                                                                                                                                       

CONFIG_FULL_PACKAGE=y

display_info "------------------------------------------------"
display_info "-------------build hostapd ---------------------"
display_info "------------------------------------------------"

parse_args $@

if [ "$CONFIG_FULL_PACKAGE" = "y" ]; then

if [ $BUILD_CLEAN -eq 1 ]; then
	make clean
	[ ! $BUILD_CONFIGURE -eq 1 ] && exit 0
fi

if [ "$1" = "config_only" ] ;then
	exit 0
fi

fi

make all
ifx_error_check $?

cp -f hostapd ${BUILD_ROOTFS_DIR}/usr/sbin/hostapd
cp -f hostapd.conf ${BUILD_ROOTFS_DIR}/ramdisk_copy/etc/hostapd.conf



