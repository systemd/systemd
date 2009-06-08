include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	path_id

path_id_SOURCES = \
	path_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-device.c \
	../../udev/lib/libudev-enumerate.c \
	../../udev/lib/libudev-list.c \
	../../udev/lib/libudev-util.c

dist_man_MANS = \
	path_id.8
