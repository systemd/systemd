# -*- makefile -*-
#
# arch/arm/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = \
	libgcc/__divsi3.o \
	libgcc/__modsi3.o \
	libgcc/__udivsi3.o \
	libgcc/__umodsi3.o \
	libgcc/__udivmodsi4.o \
	libgcc/__divdi3.o \
	libgcc/__moddi3.o \
	libgcc/__udivdi3.o \
	libgcc/__umoddi3.o \
	libgcc/__udivmoddi4.o

ifeq ($(THUMB),y)
ARCHOBJS += arch/arm/setjmp-thumb.o
LIBGCC   =
else
ARCHOBJS += arch/arm/setjmp-arm.o
endif

ARCHSOOBJS = $(patsubst %.o,%.lo,$(ARCHOBJS))

archclean:
