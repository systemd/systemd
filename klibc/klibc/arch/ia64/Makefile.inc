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
	arch/$(ARCH)/setjmp.o \
	arch/$(ARCH)/pipe.o \
	arch/$(ARCH)/syscall.o \
	libgcc/__divdi3.o \
	libgcc/__divsi3.o \
	libgcc/__udivdi3.o \
	libgcc/__udivsi3.o \
	libgcc/__umodsi3.o \
	libgcc/__umoddi3.o \
	libgcc/__udivmodsi4.o \
	libgcc/__udivmoddi4.o

ARCHSOOBJS = $(patsubst %o,%.lo,%(ARCHOBJS))

archclean:
