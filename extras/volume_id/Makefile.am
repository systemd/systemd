include $(top_srcdir)/Makefile.am.inc

SUBDIRS = \
	lib

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	vol_id

vol_id_SOURCES = \
	vol_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-list.c \
	../../udev/lib/libudev-util.c

vol_id_LDADD = \
	lib/libvolume_id.la

dist_man_MANS = \
	vol_id.8

EXTRA_DIST = \
	vol_id.xml

%.7 %.8 : %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

MAINTAINERCLEANFILES= \
	$(dist_man_MANS)

