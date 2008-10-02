include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	usb_id

usb_id_SOURCES = \
	usb_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-list.c \
	../../udev/lib/libudev-util.c \
	../../udev/lib/libudev-device.c \
	../../udev/lib/libudev-enumerate.c

distclean-local:
	rm -f Makefile.in
