udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	usb_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

usb_id_SOURCES = \
	usb_id.c \
	../../udev/udev_sysfs.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

distclean-local:
	rm -f Makefile.in

