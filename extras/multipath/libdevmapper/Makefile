# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@free.fr>

CC = gcc
udevdir     = ../../..
klibcdir    = $(udevdir)/klibc

CC = gcc
GCCINCDIR := ${shell $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}
CFLAGS = -pipe -g -O2 -Wall -Wunused -Wstrict-prototypes -nostdinc \
         -I$(klibcdir)/klibc/include -I$(klibcdir)/klibc/include/bits32 \
         -I$(GCCINCDIR) -I$(klibcdir)/linux/include -I. -Iioctl

OBJS = ioctl/libdevmapper.o libdm-common.o

all:	$(OBJS)
	@echo ""
	@echo "Make complete"

clean:
	rm -f core *.o ioctl/*.o ioctl/*.so
