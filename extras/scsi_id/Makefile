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

VERSION=0.1

prefix =
sbindir =	${prefix}/sbin

INSTALL  = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644

CFLAGS=-DVERSION=\"$(VERSION)\" $(DEBUG) -Wall

PROG=scsi_id

LIBSYSFS=-lsysfs
STRIP=-s
LDFLAGS=$(STRIP) --static

OBJS= scsi_id.o \
	scsi_serial.o \

all:	$(PROG)

install: all
	$(INSTALL_PROGRAM) -D $(PROG) $(sbindir)/$(PROG)
	
uninstall:
	-rm $(sbindir)/$(PROG)

$(OBJS): scsi_id.h scsi.h

clean:
	rm -f $(PROG) $(OBJS)

$(PROG):	$(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) $(LIBSYSFS) -o $(PROG)
