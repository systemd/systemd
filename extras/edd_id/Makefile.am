include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	edd_id

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	61-persistent-storage-edd.rules

edd_id_SOURCES = \
	edd_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-list.c \
	../../udev/lib/libudev-util.c

dist_man_MANS = \
	edd_id.8

distclean-local:
	rm -f Makefile.in
