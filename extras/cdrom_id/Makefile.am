udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	cdrom_id

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	60-cdrom_id.rules

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

cdrom_id_SOURCES = \
	cdrom_id.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

dist_man_MANS = \
	cdrom_id.8

distclean-local:
	rm -f Makefile.in

