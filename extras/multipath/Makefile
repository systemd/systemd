# Makefile
#
# Copyright (C) 2003 Christophe Varoqui, <christophe.varoqui@free.fr>

EXEC = multipath

prefix      = /usr/local
exec_prefix = ${prefix}
bindir     = ${exec_prefix}/bin

CC = gcc
CFLAGS = -g -O2 -Wall -Wunused -Wstrict-prototypes
LDFLAGS = -lsysfs -ldevmapper

OBJS = main.o sg_err.o

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(EXEC) $(LDFLAGS)

clean:
	rm -f core *.o $(EXEC)

install:
	install -d $(bindir)
	install -m 755 $(EXEC) $(bindir)/

# Code dependencies
main.o: main.c main.h sg_err.h sg_include.h
sg_err.o: sg_err.c sg_err.h sg_include.h
