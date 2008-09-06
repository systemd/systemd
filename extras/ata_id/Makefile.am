udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	ata_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\" \
	-D_LIBUDEV_COMPILATION

ata_id_SOURCES = \
	ata_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/udev_sysfs.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

dist_man_MANS = \
	ata_id.8

distclean-local:
	rm -f Makefile.in

