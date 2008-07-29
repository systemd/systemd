udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	scsi_id

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

scsi_id_SOURCES = \
	scsi_id.c \
	scsi_serial.c \
	scsi.h \
	scsi_id.h \
	bsg.h \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

dist_sysconf_DATA = \
	scsi_id.config

dist_man_MANS = \
	scsi_id.8

distclean-local:
	rm -f Makefile.in

