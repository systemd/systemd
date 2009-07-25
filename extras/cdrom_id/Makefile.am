include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	cdrom_id

dist_udevrules_DATA = \
	60-cdrom_id.rules

cdrom_id_SOURCES = \
	cdrom_id.c

cdrom_id_LDADD = \
	$(top_builddir)/libudev/libudev-private.la
