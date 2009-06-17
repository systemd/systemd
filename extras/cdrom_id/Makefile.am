include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	cdrom_id

dist_udevrules_DATA = \
	60-cdrom_id.rules

cdrom_id_SOURCES = \
	cdrom_id.c \
	../../libudev/libudev.h \
	../../libudev/libudev-private.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c
