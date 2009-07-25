include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	scsi_id

scsi_id_SOURCES = \
	scsi_id.c \
	scsi_serial.c \
	scsi.h \
	scsi_id.h \
	bsg.h

scsi_id_LDADD = \
	$(top_builddir)/libudev/libudev-private.la

dist_man_MANS = \
	scsi_id.8

