# -*- makefile -*-
#
# arch/ia64/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = \
	arch/$(ARCH)/vfork.o \
	arch/$(ARCH)/setjmp.o

ARCHSOOBJS = $(patsubst %o,%.lo,%(ARCHOBJS))

archclean:
