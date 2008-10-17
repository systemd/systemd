include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	collect

collect_SOURCES = \
	collect.c \
	../../udev/lib/libudev \
	../../udev/lib/libudev-private.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-util.c \
	../../udev/lib/libudev-list.c

distclean-local:
	rm -f Makefile.in

