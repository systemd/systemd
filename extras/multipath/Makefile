# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@free.fr>

EXEC = multipath

prefix      = /usr/local
exec_prefix = ${prefix}
bindir     = ${exec_prefix}/bin

CC = gcc
CFLAGS = -pipe -g -O2 -Wall -Wunused -Wstrict-prototypes -nostdinc -I../../klibc/klibc/include -I../../klibc/klibc/include/bits32 -I/usr/lib/gcc-lib/i586-mandrake-linux-gnu/3.3.1/include -I../../klibc/linux/include -I../../libsysfs -I.
LDFLAGS = -lsysfs -ldevmapper -ldlist

OBJS = main.o
CRT0 = ../../klibc/klibc/crt0.o
LIB = ../../klibc/klibc/libc.a
LIBGCC = /usr/lib/gcc-lib/i586-mandrake-linux-gnu/3.3.1/libgcc.a
DMOBJS = libdevmapper/libdm-common.o libdevmapper/ioctl/libdevmapper.o
SYSFSOBJS = ../../libsysfs/dlist.o ../../libsysfs/sysfs_bus.o \
	    ../../libsysfs/sysfs_class.o ../../libsysfs/sysfs_device.o \
	    ../../libsysfs/sysfs_dir.o ../../libsysfs/sysfs_driver.o \
	    ../../libsysfs/sysfs_utils.o

SUBDIRS = libdevmapper

recurse:
	@for dir in $(SUBDIRS); do\
	$(MAKE) -C $$dir ; \
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

# Code dependencies
main.o: main.c main.h sg_include.h
