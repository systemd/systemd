# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@free.fr>

CC = gcc
CFLAGS = -pipe -g -O2 -Wall -Wunused -Wstrict-prototypes -nostdinc -I../../../klibc/klibc/include -I../../../klibc/klibc/include/bits32 -I/usr/lib/gcc-lib/i586-mandrake-linux-gnu/3.3.1/include -I../../../klibc/linux/include -I. -Iioctl

OBJS = ioctl/libdevmapper.o libdm-common.o

all:	$(OBJS)
	@echo ""
	@echo "Make complete"

clean:
	rm -f core *.o ioctl/*.o ioctl/*.so
