# Makefile for libsysfs.a
# Copyright (c) International Business Machines Corp., 2003

H_INCLUDE=../include
LIB_INCLUDE=.
OBJS=sysfs_bus.o sysfs_class.o sysfs_device.o sysfs_dir.o sysfs_driver.o \
	sysfs_utils.o

# Install directory

# Options
CFLAGS=-O2 -Wall -ansi -g

# sysfs library
LIBSYSFS=libsysfs.a

RM=rm -f

libsysfs.a: $(OBJS)
	$(AR) cru $(LIBSYSFS) $(OBJS)
	$(RANLIB) $(LIBSYSFS)

sysfs_bus.o: sysfs_bus.c
	$(CC) -I$(H_INCLUDE) -I$(LIB_INCLUDE) $(CFLAGS) -c sysfs_bus.c

sysfs_class.o: sysfs_class.c
	$(CC) -I$(H_INCLUDE) -I$(LIB_INCLUDE) $(CFLAGS) -c sysfs_class.c

sysfs_device.o: sysfs_device.c
	$(CC) -I$(H_INCLUDE) -I$(LIB_INCLUDE) $(CFLAGS) -c sysfs_device.c

sysfs_dir.o: sysfs_dir.c
	$(CC) -I$(H_INCLUDE) -I$(LIB_INCLUDE) $(CFLAGS) -c sysfs_dir.c

sysfs_driver.o: sysfs_driver.c
	$(CC) -I$(H_INCLUDE) -I$(LIB_INCLUDE) $(CFLAGS) -c sysfs_driver.c

sysfs_utils.o: sysfs_utils.c
	$(CC) -I$(H_INCLUDE) -I$(LIB_INCLUDE) $(CFLAGS) -c sysfs_utils.c

clean:
	$(RM) *.o *~ core $(LIBSYSFS)
