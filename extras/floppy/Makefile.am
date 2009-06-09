include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	create_floppy_devices

create_floppy_devices_SOURCES = \
	create_floppy_devices.c \
	../../libudev/libudev.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c \
	../../libudev/libudev-device.c \
	../../libudev/libudev-enumerate.c \
	../../udev/udev.h \
	../../udev/udev-util.c

if USE_SELINUX
create_floppy_devices_SOURCES += \
	../../udev/udev-selinux.c
create_floppy_devices_LDADD = \
	$(SELINUX_LIBS)
endif

dist_man_MANS = \
	create_floppy_devices.8
