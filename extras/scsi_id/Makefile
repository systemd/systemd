#
# Copyright (C) 2003 IBM
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

SCSI_ID_VERSION=0.2

prefix =
sbindir =	${prefix}/sbin
mandir =	${prefix}/usr/share/man

INSTALL  = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644

# Note some of the variables used here are set when built under udev, and
# otherwise might not be set.

override CFLAGS+=-DSCSI_ID_VERSION=\"$(SCSI_ID_VERSION)\" $(DEBUG) -Wall

PROG=scsi_id
SYSFS=-lsysfs

#
# Built static and stripped when built with udev.
#
# STRIP=-s
# LDFLAGS=$(STRIP)
LD=$(CC)

OBJS= scsi_id.o \
	scsi_serial.o \

all:	$(PROG)

# XXX use a compressed man page?

install: all
	$(INSTALL_PROGRAM) -D $(PROG) $(sbindir)/$(PROG)
	$(INSTALL_DATA) -D scsi_id.8 $(DESTDIR)$(mandir)/man8/scsi_id.8
	
uninstall:
	-rm $(sbindir)/$(PROG)
	-rm $(mandir)/man8/scsi_id.8

$(OBJS): scsi_id.h scsi.h

clean:
	rm -f $(PROG) $(OBJS)

$(PROG):	$(OBJS)
	$(LD) $(LDFLAGS) -o $(PROG) $(CRT0) $(OBJS) $(SYSFS) $(LIB_OBJS) $(ARCH_LIB_OBJS)
