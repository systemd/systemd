# Makefile for udev_volume_id
#
# Copyright (C) 2004 Kay Sievers <kay@vrfy.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#

PROG = udev_volume_id

all:	$(PROG)

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

override CFLAGS+=-Wall -fno-builtin
OBJS = volume_id.o udev_volume_id.o
HEADERS = volume_id.h

$(OBJS): $(HEADERS)

$(PROG): $(OBJS) $(HEADERS)
	$(LD) $(LDFLAGS) -o $(PROG) $(CRT0) $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)

clean:
	rm -f $(PROG) $(OBJS)

spotless: clean

install: all
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(usrsbindir)/$(PROG)

uninstall:
	- rm $(DESTDIR)$(usrsbindir)/$(PROG)

