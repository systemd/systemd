# -*- makefile -*-
#
# arch/cris/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = \
	arch/$(ARCH)/__Umod.o \
	arch/$(ARCH)/__Udiv.o \
	arch/$(ARCH)/__Mod.o \
	arch/$(ARCH)/__Div.o \
	arch/$(ARCH)/__negdi2.o \
	arch/$(ARCH)/setjmp.o \
	arch/$(ARCH)/syscall.o \
	libgcc/__divdi3.o \
	libgcc/__moddi3.o \
	libgcc/__udivdi3.o \
	libgcc/__umoddi3.o \
	libgcc/__udivmoddi4.o

arch/$(ARCH)/__Umod.o: arch/$(ARCH)/divide.c
	$(CC) $(CFLAGS) -DSIGNED=0 -DREM=1 -DBITS=32 -DNAME=__Umod -c -o $@ $<
arch/$(ARCH)/__Udiv.o: arch/$(ARCH)/divide.c
	$(CC) $(CFLAGS) -DSIGNED=0 -DREM=0 -DBITS=32 -DNAME=__Udiv -c -o $@ $<
arch/$(ARCH)/__Mod.o: arch/$(ARCH)/divide.c
	$(CC) $(CFLAGS) -DSIGNED=1 -DREM=1 -DBITS=32 -DNAME=__Mod -c -o $@ $<
arch/$(ARCH)/__Div.o: arch/$(ARCH)/divide.c
	$(CC) $(CFLAGS) -DSIGNED=1 -DREM=0 -DBITS=32 -DNAME=__Div -c -o $@ $<

archclean:
