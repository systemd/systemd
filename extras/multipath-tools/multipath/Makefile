# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@free.fr>

EXEC = multipath

prefix      = 
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/sbin
udevdir	    = ../../..
klibcdir    = $(udevdir)/klibc
sysfsdir    = $(udevdir)/libsysfs
mandir      = /usr/share/man/man8
libdmdir    = ../libdevmapper
arch        = i386
klibcarch   = $(klibcdir)/klibc/arch/$(arch)/include

CC = gcc
GZIP = /bin/gzip -9 -c

GCCINCDIR := ${shell $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}
KERNEL_DIR = /lib/modules/${shell uname -r}/build
CFLAGS = -pipe -g -O2 -Wall -Wunused -Wstrict-prototypes -nostdinc \
         -I$(klibcdir)/klibc/include -I$(klibcdir)/klibc/include/bits32 \
         -I$(GCCINCDIR) -I$(KERNEL_DIR)/include -I$(sysfsdir) -I. -I$(klibcarch)

OBJS = devinfo.o main.o
CRT0 = $(klibcdir)/klibc/crt0.o
LIB = $(klibcdir)/klibc/libc.a
LIBGCC := $(shell $(CC) -print-libgcc-file-name )

DMOBJS = $(libdmdir)/libdm-common.o $(libdmdir)/ioctl/libdevmapper.o
SYSFSOBJS = $(sysfsdir)/dlist.o $(sysfsdir)/sysfs_bus.o \
	    $(sysfsdir)/sysfs_class.o $(sysfsdir)/sysfs_device.o \
	    $(sysfsdir)/sysfs_dir.o $(sysfsdir)/sysfs_driver.o \
	    $(sysfsdir)/sysfs_utils.o

$(EXEC): $(OBJS)
	$(LD) -o $(EXEC) $(CRT0) $(OBJS) $(SYSFSOBJS) $(DMOBJS) $(LIB) $(LIBGCC)
	strip $(EXEC)
	$(GZIP) $(EXEC).8 > $(EXEC).8.gz

clean:
	rm -f core *.o $(EXEC) *.gz

install:
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(EXEC) $(DESTDIR)$(bindir)/
	install -d $(DESTDIR)/etc/hotplug.d/scsi/
	install -m 755 multipath.hotplug $(DESTDIR)/etc/hotplug.d/scsi/
	install -d $(DESTDIR)$(mandir)
	install -m 644 multipath.8.gz $(DESTDIR)$(mandir)

uninstall:
	rm $(DESTDIR)/etc/hotplug.d/scsi/multipath.hotplug
	rm $(DESTDIR)$(bindir)/$(EXEC)
	rm $(DESTDIR)$(mandir)/multipath.8.gz

# Code dependencies
main.o: main.c main.h sg_include.h devinfo.h
