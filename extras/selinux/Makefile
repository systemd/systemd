# Makefile for udev_selinux
#
# Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#

# Set the following to control the use of syslog
# Set it to `false' to remove all logging
USE_LOG = true

# Set the following to `true' to log the debug
# and make a unstripped, unoptimized  binary.
# Leave this set to `false' for production use.
DEBUG = false

PROG = udev_selinux

DESTDIR =

# override this to make udev look in a different location for it's config files
prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
usrbindir =	${exec_prefix}/usr/bin
usrsbindir =	${exec_prefix}/usr/sbin
mandir =	${prefix}/usr/share/man
devddir =	${etcdir}/dev.d/default
hotplugdir =	${etcdir}/hotplug.d/default
configdir =	${etcdir}/udev/
initdir = 	${etcdir}/init.d/
srcdir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}

all: $(PROG)

OBJS = udev_selinux.o

override CFLAGS  += -DUSE_SELINUX
override LIB_OBJS += -lselinux

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) -o $(PROG) $(CRT0) $(OBJS) ../../udev_lib.o $(LIB_OBJS) $(ARCH_LIB_OBJS)

clean:
	rm -f $(PROG) $(OBJS)

spotless: clean

install: all
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(sbindir)/$(PROG)
	- ln -s -f $(DESTDIR)$(sbindir)/$(PROG) $(DESTDIR)$(devddir)/$(PROG).dev

uninstall:
	- rm $(DESTDIR)$(devddir)/$(PROG).dev
	- rm $(DESTDIR)$(sbindir)/$(PROG)

