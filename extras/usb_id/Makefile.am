include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	usb_id

usb_id_SOURCES = \
	usb_id.c \
	../../libudev/libudev.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c \
	../../libudev/libudev-device.c \
	../../libudev/libudev-enumerate.c

dist_man_MANS = \
	usb_id.8
