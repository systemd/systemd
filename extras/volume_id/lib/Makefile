# libvolume_id - read filesystem label/uuid
#
# Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
#
# Released under the GNU General Public License, version 2.
#
includedir = 	${prefix}/usr/include
libdir =	${prefix}/lib
usrlibdir =	${prefix}/usr/lib

INSTALL = install -c
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_LIB = ${INSTALL} -m 755

SHLIB_CUR = 0
SHLIB_REV = 75
SHLIB_AGE = 0
SHLIB = libvolume_id.so.$(SHLIB_CUR).$(SHLIB_REV).$(SHLIB_AGE)

OBJS=				\
	ext.o			\
	fat.o			\
	hfs.o			\
	highpoint.o		\
	isw_raid.o		\
	lsi_raid.o		\
	via_raid.o		\
	silicon_raid.o		\
	nvidia_raid.o		\
	promise_raid.o		\
	adaptec_raid.o		\
	jmicron_raid.o		\
	iso9660.o		\
	jfs.o			\
	linux_raid.o		\
	linux_swap.o		\
	lvm.o			\
	ntfs.o			\
	reiserfs.o		\
	udf.o			\
	ufs.o			\
	xfs.o			\
	cramfs.o		\
	hpfs.o			\
	romfs.o			\
	sysv.o			\
	minix.o			\
	gfs.o			\
	luks.o			\
	ocfs.o			\
	vxfs.o			\
	squashfs.o		\
	netware.o		\
	volume_id.o		\
	util.o

HEADERS=			\
	libvolume_id.h		\
	util.h

all: libvolume_id.a $(SHLIB) libvolume_id.pc
.PHONY: all
.DEFAULT: all

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

.shlib:
	$(Q) mkdir .shlib

.shlib/%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) -fPIC $< -o $@

libvolume_id.a: $(HEADERS) $(OBJS)
	$(Q) rm -f $@
	$(E) "  AR      " $@
	$(Q) $(AR) cq $@ $(OBJS)
	$(E) "  RANLIB  " $@
	$(Q) $(RANLIB) $@

$(SHLIB): $(HEADERS) .shlib $(addprefix .shlib/,$(OBJS))
	$(E) "  CC      " $@
	$(Q) $(CC) -shared $(CFLAGS) -o $@ \
		-Wl,-soname,libvolume_id.so.$(SHLIB_CUR),--version-script,exported_symbols \
		$(addprefix .shlib/,$(OBJS))
	$(Q) ln -sf $@ libvolume_id.so.$(SHLIB_CUR)
	$(Q) ln -sf $@ libvolume_id.so

libvolume_id.pc:
	$(E) "  GENPC   " $@
	$(Q) echo "prefix=${prefix}" > $@
	$(Q) echo "libdir=${libdir}" >> $@
	$(Q) echo "includedir=${includedir}" >> $@
	$(Q) echo "" >> $@
	$(Q) echo "Name: libvolume_id" >> $@
	$(Q) echo "Description: Filesystem label and uuid access" >> $@
	$(Q) echo "Version: $(SHLIB_CUR).$(SHLIB_REV).$(SHLIB_AGE)" >> $@
	$(Q) echo "Libs: -L\$${libdir} -lvolume_id" >> $@
	$(Q) echo "Cflags: -I\$${includedir}" >> $@

install: all
	$(INSTALL_DATA) -D libvolume_id.h $(DESTDIR)$(includedir)/libvolume_id.h
	$(INSTALL_LIB) -D libvolume_id.a $(DESTDIR)$(usrlibdir)/libvolume_id.a
	$(INSTALL_LIB) -D $(SHLIB) $(DESTDIR)$(libdir)/$(SHLIB)
	ln -sf $(SHLIB) $(DESTDIR)$(libdir)/libvolume_id.so.$(SHLIB_CUR)
	ln -sf $(libdir)/$(SHLIB) $(DESTDIR)$(usrlibdir)/libvolume_id.so
	$(INSTALL_DATA) -D libvolume_id.pc $(DESTDIR)$(usrlibdir)/pkgconfig/libvolume_id.pc
.PHONY: install

uninstall:
	rm -f $(DESTDIR)$(includedir)/libvolume_id.h
	rm -f $(DESTDIR)$(usrlibdir)/libvolume_id.a
	rm -f $(DESTDIR)$(libdir)/$(SHLIB)
	rm -f $(DESTDIR)$(libdir)/libvolume_id.so.$(SHLIB_CUR)
	rm -f $(DESTDIR)$(libdir)/libvolume_id.so
.PHONY: uninstall

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f libvolume_id.a $(OBJS)
	$(Q) rm -f $(SHLIB) libvolume_id.so.$(SHLIB_CUR) libvolume_id.so
	$(Q) rm -rf .shlib
	$(Q) rm -f libvolume_id.pc
.PHONY: clean

