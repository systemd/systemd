# -*- makefile -*-
#
# arch/sparc/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

ARCHOBJS = \
	arch/$(ARCH)/sdiv.o \
	arch/$(ARCH)/udiv.o \
	arch/$(ARCH)/srem.o \
	arch/$(ARCH)/urem.o \
	arch/$(ARCH)/smul.o \
	arch/$(ARCH)/umul.o \
	arch/$(ARCH)/setjmp.o \
	arch/$(ARCH)/syscall.o \
	arch/$(ARCH)/sysfork.o \
	libgcc/__divdi3.o \
	libgcc/__moddi3.o \
	libgcc/__udivdi3.o \
	libgcc/__umoddi3.o \
	libgcc/__udivmoddi4.o

arch/$(ARCH)/sdiv.S: arch/$(ARCH)/divrem.m4
	@echo 'building $@ from $^'
	@(echo "define(NAME,\`.div')define(OP,\`div')define(S,\`true')"; \
	 cat $^) | m4 > $@
	@chmod 444 $@

arch/$(ARCH)/udiv.S: arch/$(ARCH)/divrem.m4
	@echo 'building $@ from $^'
	@(echo "define(NAME,\`.udiv')define(OP,\`div')define(S,\`false')"; \
	 cat $^) | m4 > $@
	@chmod 444 $@

arch/$(ARCH)/srem.S: arch/$(ARCH)/divrem.m4
	@echo 'building $@ from $^'
	@(echo "define(NAME,\`.rem')define(OP,\`rem')define(S,\`true')"; \
	 cat $^) | m4 > $@
	@chmod 444 $@

arch/$(ARCH)/urem.S: arch/$(ARCH)/divrem.m4
	@echo 'building $@ from $^'
	@(echo "define(NAME,\`.urem')define(OP,\`rem')define(S,\`false')"; \
	 cat $^) | m4 > $@
	@chmod 444 $@

archclean:
	rm -f arch/$(ARCH)/?div.S arch/$(ARCH)/?rem.S
