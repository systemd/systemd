# -*- makefile -*-
#
# arch/s390x/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = \
	arch/$(ARCH)/setjmp.o \
	arch/$(ARCH)/mmap.o \
	arch/$(ARCH)/syscall.o

ARCHSOOBJS = $(patsubst %.o,%.lo,$(ARCHOBJS))


archclean:
