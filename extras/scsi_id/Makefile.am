udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	scsi_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\" \
	-D_LIBUDEV_COMPILATION

scsi_id_SOURCES = \
	scsi_id.c \
	scsi_serial.c \
	scsi.h \
	scsi_id.h \
	bsg.h \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-utils.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

if USE_SELINUX
scsi_id_LDADD = \
	$(SELINUX_LIBS)
endif

dist_sysconf_DATA = \
	scsi_id.config

dist_man_MANS = \
	scsi_id.8

distclean-local:
	rm -f Makefile.in

