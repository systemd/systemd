udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	edd_id

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	61-persistent-storage-edd.rules

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

edd_id_SOURCES = \
	edd_id.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

dist_man_MANS = \
	edd_id.8

distclean-local:
	rm -f Makefile.in

