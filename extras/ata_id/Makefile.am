include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	ata_id

ata_id_SOURCES = \
	ata_id.c \
	../../libudev/libudev.h \
	../../libudev/libudev-private.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c

dist_man_MANS = \
	ata_id.8
