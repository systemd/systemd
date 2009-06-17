include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	fstab_import

dist_udevrules_DATA = \
	79-fstab_import.rules

fstab_import_SOURCES = \
	fstab_import.c \
	../../libudev/libudev.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c

