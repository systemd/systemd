# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@free.fr>

EXEC = devmap_name

prefix      = 
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/sbin
udevdir	    = ../../..
klibcdir    = $(udevdir)/klibc
mandir      = /usr/share/man/man8
libdmdir    = ../libdevmapper

CC = gcc
GZIP = /bin/gzip -9 -c

GCCINCDIR := ${shell $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}
KERNEL_DIR = /lib/modules/${shell uname -r}/build
CFLAGS = -pipe -g -O2 -Wall -Wunused -Wstrict-prototypes -nostdinc \
         -I$(klibcdir)/klibc/include -I$(klibcdir)/klibc/include/bits32 \
         -I$(GCCINCDIR) -I$(KERNEL_DIR)/include -I$(sysfsdir) -I.

OBJS = devmap_name.o
CRT0 = $(klibcdir)/klibc/crt0.o
LIB = $(klibcdir)/klibc/libc.a
LIBGCC := $(shell $(CC) -print-libgcc-file-name )

DMOBJS = $(libdmdir)/libdm-common.o $(libdmdir)/ioctl/libdevmapper.o

$(EXEC): $(OBJS)
	$(LD) -o $(EXEC) $(CRT0) $(OBJS) $(DMOBJS) $(LIB) $(LIBGCC)
	strip $(EXEC)
	$(GZIP) $(EXEC).8 > $(EXEC).8.gz

clean:
	rm -f core *.o $(EXEC) *.gz

install:
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(EXEC) $(DESTDIR)$(bindir)/
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(EXEC).8.gz $(DESTDIR)$(mandir)

uninstall:
	rm $(DESTDIR)$(bindir)/$(EXEC)
	rm $(DESTDIR)$(mandir)/$(EXEC).8.gz
