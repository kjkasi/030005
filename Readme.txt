This package is only supported on Fedora Core and Red Hat variants.

How to install and build the open source package

You should have the following files:
	JWNR2000-4EMRUS_03.00.05.tar.bz2
	JWNR2000-4EMRUS_toolchain.tar.bz2

As root cd to /opt and install JWNR2000-4EMRUS_toolchain.tar.bz2 as follows:
	tar -xvjf JWNR2000-4EMRUS_toolchain.tar.bz2

From your working directory install the source as follows:
	tar -xvjf JWNR2000-4EMRUS_03.00.05.tar.bz2

To make the source package execute the following commands:
	cd ngos/JWNR2000_4EMRUS/SW
	make PROFILE=JWNR2000-40000S VENDOR=REALTEK

The resulting upgrade file App.upg can be found at
SW/targets.REALTEK/JWNR2000-40000S

This upgrade file can be applied from the modems GUI upgrade page if option is available.


