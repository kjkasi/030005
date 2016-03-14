# Makefile for gperf

# Copyright (C) 1989, 1992, 1993, 1998, 2002 Free Software Foundation, Inc.
# Written by Douglas C. Schmidt <schmidt@ics.uci.edu>
# and Bruno Haible <bruno@clisp.org>.
#
# This file is part of GNU GPERF.
#
# GNU GPERF is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GNU GPERF is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.
# If not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#### Start of system configuration section. ####

# Programs used by "make":
RM = rm -f


#### End of system configuration section. ####

SHELL = /bin/sh

all : force
	cd lib; $(MAKE) all
	cd src; $(MAKE) all
	cp src/gperf ..

clean : force
	cd lib; $(MAKE) clean
	cd src; $(MAKE) clean
	$(RM) ../gperf

distclean : force
	cd lib; if test -f Makefile; then $(MAKE) distclean; fi
	cd src; if test -f Makefile; then $(MAKE) distclean; fi
	$(RM) config.status config.log config.cache Makefile
	$(RM) ../gperf

maintainer-clean : force
	cd lib; if test -f Makefile; then $(MAKE) maintainer-clean; fi
	cd src; if test -f Makefile; then $(MAKE) maintainer-clean; fi
	$(RM) config.status config.log config.cache Makefile
	$(RM) ../gperf

force :

