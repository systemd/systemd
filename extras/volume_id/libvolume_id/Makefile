# Makefile for udev extra invoked from the udev main Makefile
#
# Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
#
# Released under the GNU General Public License, version 2.
#

LIBVOLUME_ID = libvolume_id.a

OBJS=				\
	ext.o			\
	fat.o			\
	hfs.o			\
	highpoint.o		\
	isw_raid.o		\
	lsi_raid.o		\
	via_raid.o		\
	silicon_raid.o		\
	nvidia_raid.o		\
	promise_raid.o		\
	iso9660.o		\
	jfs.o			\
	linux_raid.o		\
	linux_swap.o		\
	lvm.o			\
	mac.o			\
	msdos.o			\
	ntfs.o			\
	reiserfs.o		\
	udf.o			\
	ufs.o			\
	xfs.o			\
	cramfs.o		\
	hpfs.o			\
	romfs.o			\
	sysv.o			\
	minix.o			\
	luks.o			\
	ocfs.o			\
	vxfs.o			\
	volume_id.o		\
	util.o

HEADERS=			\
	volume_id.h		\
	util.h

AR = $(CROSS)ar
RANLIB = $(CROSS)ranlib

all: $(LIBVOLUME_ID)
.PHONY: all
.DEFAULT: all

%.o: %.c
	$(QUIET) $(CC) -c $(CFLAGS) $< -o $@

$(LIBVOLUME_ID): $(HEADERS) $(OBJS)
	@rm -f $@
	$(QUIET) $(AR) cq $@ $(OBJS)
	$(QUIET) $(RANLIB) $@

clean:
	rm -f $(LIBVOLUME_ID) $(OBJS)
.PHONY: clean

