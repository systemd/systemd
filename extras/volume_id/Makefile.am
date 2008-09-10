SUBDIRS = \
	lib

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	vol_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\" \
	-D_LIBUDEV_COMPILATION

vol_id_SOURCES = \
	vol_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-util.c

vol_id_LDADD = \
	lib/libvolume_id.la

if USE_SELINUX
vol_id_LDADD += \
	$(SELINUX_LIBS)
endif

dist_man_MANS = \
	vol_id.8

EXTRA_DIST = \
	vol_id.xml

%.7 %.8 : %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

distclean-local:
	rm -f Makefile.in
	rm -f $(dist_man_MANS)

