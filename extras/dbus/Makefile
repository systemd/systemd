# Makefile for udev_dbus
#
# Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#

# Set the following to `true' to log the debug
# and make a unstripped, unoptimized  binary.
# Leave this set to `false' for production use.
DEBUG = false

PROG = 	udev_dbus

all:	$(PROG)

# override this to make udev look in a different location for it's config files
prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
usrbindir =	${exec_prefix}/usr/bin
usrsbindir =	${exec_prefix}/usr/sbin
mandir =	${prefix}/usr/share/man
devddir =	${etcdir}/dev.d/default
dbusdir =	${etcdir}/dbus-1/system.d
configdir =	${etcdir}/udev/
initdir = 	${etcdir}/init.d/
srcdir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}

override CFLAGS+=-Wall -fno-builtin

override CFLAGS += -DUSE_DBUS
override CFLAGS += $(shell pkg-config --cflags dbus-1)
override LDFLAGS += $(shell pkg-config --libs dbus-1)
OBJS = udev_dbus.o

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) -o $(PROG) $(CRT0) $(OBJS) ../../udev_lib.o $(LIB_OBJS) $(ARCH_LIB_OBJS)

clean:
	rm -f $(PROG) $(OBJS)

spotless: clean


install-dbus-policy:
	$(INSTALL) -d $(DESTDIR)$(dbusdir)
	$(INSTALL_DATA) etc/dbus-1/system.d/udev_sysbus_policy.conf $(DESTDIR)$(dbusdir)
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(usrsbindir)/$(PROG)
	- ln -s -f $(DESTDIR)$(usrsbindir)/$(PROG) $(DESTDIR)$(devddir)/$(PROG).dev

uninstall-dbus-policy:
	- rm $(DESTDIR)$(dbusdir)/udev_sysbus_policy.conf
	- rm $(DESTDIR)$(devddir)/$(PROG).dev
	- rm $(DESTDIR)$(usrsbindir)/$(PROG)

install: install-dbus-policy all

uninstall: uninstall-dbus-policy

