include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	fstab_import

dist_udevrules_DATA = \
	79-fstab_import.rules

fstab_import_SOURCES = \
	fstab_import.c

fstab_import_LDADD = \
	$(top_builddir)/libudev/libudev-private.la
