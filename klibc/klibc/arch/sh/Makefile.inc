# -*- makefile -*-
#
# arch/sh/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = arch/sh/setjmp.o \
	   arch/sh/syscall.o

ARCHSOOBJS = $(patsubst %.o,%.lo,$(ARCHOBJS))

archclean:
