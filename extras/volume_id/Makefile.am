SUBDIRS = \
	lib

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	vol_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

vol_id_SOURCES = \
	vol_id.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

vol_id_LDADD = \
	lib/libvolume_id.la

dist_man_MANS = \
	vol_id.8

EXTRA_DIST = \
	vol_id.xml

%.7 %.8 : %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

distclean-local:
	rm -f Makefile.in
	rm -f $(dist_man_MANS)

