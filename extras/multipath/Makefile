# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@free.fr>

EXEC = multipath

prefix      = 
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/sbin
udevdir	    = ../..
klibcdir    = $(udevdir)/klibc
sysfsdir    = $(udevdir)/libsysfs

CC = gcc
GCCINCDIR := ${shell $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}
CFLAGS = -pipe -g -O2 -Wall -Wunused -Wstrict-prototypes -nostdinc \
         -I$(klibcdir)/klibc/include -I$(klibcdir)/klibc/include/bits32 \
         -I$(GCCINCDIR) -I$(KERNEL_DIR)/include -I$(sysfsdir) -I.

OBJS = main.o
CRT0 = ../../klibc/klibc/crt0.o
LIB = ../../klibc/klibc/libc.a
LIBGCC := $(shell $(CC) -print-libgcc-file-name )

DMOBJS = libdevmapper/libdm-common.o libdevmapper/ioctl/libdevmapper.o
SYSFSOBJS = ../../libsysfs/dlist.o ../../libsysfs/sysfs_bus.o \
	    ../../libsysfs/sysfs_class.o ../../libsysfs/sysfs_device.o \
	    ../../libsysfs/sysfs_dir.o ../../libsysfs/sysfs_driver.o \
	    ../../libsysfs/sysfs_utils.o

SUBDIRS = libdevmapper

recurse:
	@for dir in $(SUBDIRS); do\
	$(MAKE) KERNEL_DIR=$(KERNEL_DIR) -C $$dir ; \
	done
	$(MAKE) $(EXEC)

all:	recurse
	@echo ""
	@echo "Make complete"


$(EXEC): $(OBJS)
	$(LD) -o $(EXEC) $(CRT0) $(OBJS) $(SYSFSOBJS) $(DMOBJS) $(LIB) $(LIBGCC)
	strip $(EXEC)

clean:
	rm -f core *.o $(EXEC)
	$(MAKE) -C libdevmapper clean

install:
	install -d $(bindir)
	install -m 755 $(EXEC) $(bindir)/
	install -d /etc/hotplug.d/scsi/
	install -m 755 multipath.hotplug /etc/hotplug.d/scsi/

uninstall:
	rm /etc/hotplug.d/scsi/multipath.hotplug
	rm $(bindir)/$(EXEC)

# Code dependencies
main.o: main.c main.h sg_include.h
