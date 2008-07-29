udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	ata_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

ata_id_SOURCES = \
	ata_id.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

dist_man_MANS = \
	ata_id.8

distclean-local:
	rm -f Makefile.in

