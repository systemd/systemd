# -*- makefile -*-
#
# arch/sparc64/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = \
	arch/$(ARCH)/setjmp.o \
	arch/$(ARCH)/syscall.o \
	arch/$(ARCH)/sysfork.o

archclean:
