# -*- makefile -*-
#
# arch/alpha/Makefile.inc
#
# Special rules for this architecture.  Note that this is actually
# included from the main Makefile, and that pathnames should be
# accordingly.
#

# Special CFLAGS for the divide code
DIVCFLAGS = $(REQFLAGS) \
	-O3 -fomit-frame-pointer -fcall-saved-1 -fcall-saved-2 \
	-fcall-saved-3 -fcall-saved-4 -fcall-saved-5 -fcall-saved-6 \
	-fcall-saved-7 -fcall-saved-8 -fcall-saved-15 -fcall-saved-16 \
	-fcall-saved-17 -fcall-saved-18 -fcall-saved-19 -fcall-saved-20 \
	-fcall-saved-21 -fcall-saved-22 -ffixed-23 -fcall-saved-24 \
	-ffixed-25 -ffixed-27

ARCHOBJS = \
	arch/$(ARCH)/__divqu.o \
	arch/$(ARCH)/__remqu.o \
	arch/$(ARCH)/__divq.o \
	arch/$(ARCH)/__remq.o \
	arch/$(ARCH)/__divlu.o \
	arch/$(ARCH)/__remlu.o \
	arch/$(ARCH)/__divl.o \
	arch/$(ARCH)/__reml.o \
	arch/$(ARCH)/pipe.o \
	arch/$(ARCH)/setjmp.o

ARCHSOOBJS = $(patsubst %.o,%.lo,$(ARCHOBJS))

arch/$(ARCH)/%.s: arch/$(ARCH)/%.ss
	sed -e 's/\$$0\b/$$27/g' -e 's/\$$24\b/$$99/g' \
	    -e 's/\$$16\b/$$24/g' -e 's/\$$17\b/$$25/g' \
            -e 's/\$$26\b/$$23/g' -e 's/\$$99\b/$$16/g' < $< > $@

arch/$(ARCH)/%.ls: arch/$(ARCH)/%.lss
	sed -e 's/\$$0\b/$$27/g' -e 's/\$$24\b/$$99/g' \
	    -e 's/\$$16\b/$$24/g' -e 's/\$$17\b/$$25/g' \
            -e 's/\$$26\b/$$23/g' -e 's/\$$99\b/$$16/g' < $< > $@

arch/$(ARCH)/__divqu.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=0 -DREM=0 -DBITS=64 -DNAME=__divqu -S -o $@ $<

arch/$(ARCH)/__remqu.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=0 -DREM=1 -DBITS=64 -DNAME=__remqu -S -o $@ $<

arch/$(ARCH)/__divq.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=1 -DREM=0 -DBITS=64 -DNAME=__divq -S -o $@ $<

arch/$(ARCH)/__remq.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=1 -DREM=1 -DBITS=64 -DNAME=__remq -S -o $@ $<

arch/$(ARCH)/__divlu.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=0 -DREM=0 -DBITS=32 -DNAME=__divlu -S -o $@ $<

arch/$(ARCH)/__remlu.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=0 -DREM=1 -DBITS=32 -DNAME=__remlu -S -o $@ $<

arch/$(ARCH)/__divl.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=1 -DREM=0 -DBITS=32 -DNAME=__divl -S -o $@ $<

arch/$(ARCH)/__reml.ss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -DSIGNED=1 -DREM=1 -DBITS=32 -DNAME=__reml -S -o $@ $<

arch/$(ARCH)/__divqu.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=0 -DREM=0 -DBITS=64 -DNAME=__divqu -S -o $@ $<

arch/$(ARCH)/__remqu.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=0 -DREM=1 -DBITS=64 -DNAME=__remqu -S -o $@ $<

arch/$(ARCH)/__divq.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=1 -DREM=0 -DBITS=64 -DNAME=__divq -S -o $@ $<

arch/$(ARCH)/__remq.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=1 -DREM=1 -DBITS=64 -DNAME=__remq -S -o $@ $<

arch/$(ARCH)/__divlu.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=0 -DREM=0 -DBITS=32 -DNAME=__divlu -S -o $@ $<

arch/$(ARCH)/__remlu.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=0 -DREM=1 -DBITS=32 -DNAME=__remlu -S -o $@ $<

arch/$(ARCH)/__divl.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=1 -DREM=0 -DBITS=32 -DNAME=__divl -S -o $@ $<

arch/$(ARCH)/__reml.lss: arch/$(ARCH)/divide.c
	$(CC) $(DIVCFLAGS) -fPIC -DSIGNED=1 -DREM=1 -DBITS=32 -DNAME=__reml -S -o $@ $<

archclean:
	rm -f arch/$(ARCH)/*.ss arch/$(ARCH)/*.lss

