include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	edd_id

dist_udevrules_DATA = \
	61-persistent-storage-edd.rules

edd_id_SOURCES = \
	edd_id.c

edd_id_LDADD = \
	$(top_builddir)/libudev/libudev-private.la

