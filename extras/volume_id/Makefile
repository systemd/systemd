# Makefile for udev_volume_id
#
# Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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

override CFLAGS+=-D_FILE_OFFSET_BITS=64

VOLUME_ID_OBJS=					\
	volume_id/ext/ext.o			\
	volume_id/fat/fat.o			\
	volume_id/hfs/hfs.o			\
	volume_id/highpoint/highpoint.o		\
	volume_id/iso9660/iso9660.o		\
	volume_id/jfs/jfs.o			\
	volume_id/linux_raid/linux_raid.o	\
	volume_id/linux_swap/linux_swap.o	\
	volume_id/lvm/lvm.o			\
	volume_id/mac/mac.o			\
	volume_id/msdos/msdos.o			\
	volume_id/ntfs/ntfs.o			\
	volume_id/reiserfs/reiserfs.o		\
	volume_id/udf/udf.o			\
	volume_id/ufs/ufs.o			\
	volume_id/xfs/xfs.o			\
	volume_id/dasd/dasd.o			\
	volume_id/volume_id.o			\
	volume_id/util.o

VOLUME_ID_HEADERS=				\
	volume_id/ext/ext.h			\
	volume_id/fat/fat.h			\
	volume_id/hfs/hfs.h			\
	volume_id/highpoint/highpoint.h		\
	volume_id/iso9660/iso9660.h		\
	volume_id/jfs/jfs.h			\
	volume_id/linux_raid/linux_raid.h	\
	volume_id/linux_swap/linux_swap.h	\
	volume_id/lvm/lvm.h			\
	volume_id/mac/mac.h			\
	volume_id/msdos/msdos.h			\
	volume_id/ntfs/ntfs.h			\
	volume_id/reiserfs/reiserfs.h		\
	volume_id/udf/udf.h			\
	volume_id/ufs/ufs.h			\
	volume_id/xfs/xfs.h			\
	volume_id/dasd/dasd.h			\
	volume_id/volume_id.h			\
	volume_id/util.h

OBJS = udev_volume_id.o $(VOLUME_ID_OBJS) $(SYSFS)
HEADERS = $(VOLUME_ID_HEADERS)

$(OBJS): $(HEADERS)

.c.o:
	$(QUIET) $(CC) $(CFLAGS) -c -o $@ $<

$(PROG): $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $(PROG) $(CRT0) $(OBJS) $(LIB_OBJS) $(ARCH_LIB_OBJS)

clean:
	rm -f $(PROG) $(OBJS)

spotless: clean

install: all
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(sbindir)/$(PROG)

uninstall:
	- rm $(DESTDIR)$(sbindir)/$(PROG)
