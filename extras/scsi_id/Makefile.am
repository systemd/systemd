include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	scsi_id

scsi_id_SOURCES = \
	scsi_id.c \
	scsi_serial.c \
	scsi.h \
	scsi_id.h \
	bsg.h \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-util.c

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

