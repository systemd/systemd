udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	usb_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\" \
	-D_LIBUDEV_COMPILATION

usb_id_SOURCES = \
	usb_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/udev_sysfs.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

if USE_SELINUX
usb_id_LDADD = \
	$(SELINUX_LIBS)
endif

distclean-local:
	rm -f Makefile.in

