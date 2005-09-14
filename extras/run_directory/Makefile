# Makefile for run_directory
#
# Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#

DEVD = udev_run_devd
HOTPLUGD = udev_run_hotplugd

all:	$(DEVD) $(HOTPLUGD)

prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
usrbindir =	${exec_prefix}/usr/bin
usrsbindir =	${exec_prefix}/usr/sbin
mandir =	${prefix}/usr/share/man
devddir =	${etcdir}/dev.d/default
configdir =	${etcdir}/udev/
initdir = 	${etcdir}/init.d/
srcdir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}

OBJS = $(LIBUDEV)

.c.o:
	$(QUIET) $(CC) $(CFLAGS) -c -o $@ $<

$(DEVD): $(HEADERS) $(DEVD).o run_directory.o
	$(QUIET) $(LD) $(LDFLAGS) -o $(DEVD) $(DEVD).o run_directory.o $(OBJS)

$(HOTPLUGD): $(HEADERS) $(HOTPLUGD).o run_directory.o
	$(QUIET) $(LD) $(LDFLAGS) -o $(HOTPLUGD) $(HOTPLUGD).o run_directory.o $(OBJS)

clean:
	rm -f $(DEVD) $(HOTPLUGD) run_directory.o

spotless: clean

install-bin: all
	$(INSTALL_PROGRAM) $(DEVD) $(DESTDIR)$(sbindir)/$(DEVD)
	$(INSTALL_PROGRAM) $(HOTPLUGD) $(DESTDIR)$(sbindir)/$(HOTPLUGD)

uninstall-bin:
	- rm $(DESTDIR)$(sbindir)/$(DEVD)
