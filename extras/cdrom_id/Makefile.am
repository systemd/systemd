include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	cdrom_id

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	60-cdrom_id.rules

cdrom_id_SOURCES = \
	cdrom_id.c \
	../../libudev/libudev.h \
	../../libudev/libudev-private.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c

dist_man_MANS = \
	cdrom_id.8
