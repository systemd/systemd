include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	usb_id

usb_id_SOURCES = \
	usb_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-util.c \
	../../udev/udev_sysfs.c \
	../../udev/udev_utils.c

distclean-local:
	rm -f Makefile.in
