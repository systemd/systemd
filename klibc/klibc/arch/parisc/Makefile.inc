# -*- makefile -*-
#
# arch/parisc/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = \
	arch/$(ARCH)/setjmp.o \
	arch/$(ARCH)/syscall.o

ARCHOOBJS = $(patsubst %o,%.lo,%(ARCHOBJS))

archclean:

arch/$(ARCH)/syscall.o: arch/$(ARCH)/syscall.c
	$(CC) $(CFLAGS) -ffixed-r20 -c -o $@ $<
