include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	path_id

path_id_SOURCES = \
	path_id.c \
	../../libudev/libudev.h \
	../../libudev/libudev.c \
	../../libudev/libudev-device.c \
	../../libudev/libudev-enumerate.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c

dist_man_MANS = \
	path_id.8
