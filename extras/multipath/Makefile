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

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(EXEC) $(LDFLAGS) $(CFLAGS)

clean:
	rm -f core *.o $(EXEC)

install:
	install -d $(bindir)
	install -m 755 $(EXEC) $(bindir)/

# Code dependencies
main.o: main.c main.h sg_include.h
