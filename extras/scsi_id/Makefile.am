include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	scsi_id

scsi_id_SOURCES = \
	scsi_id.c \
	scsi_serial.c \
	scsi.h \
	scsi_id.h \
	bsg.h \
	../../libudev/libudev.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c

dist_man_MANS = \
	scsi_id.8

