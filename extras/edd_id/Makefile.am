include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	edd_id

dist_udevrules_DATA = \
	61-persistent-storage-edd.rules

edd_id_SOURCES = \
	edd_id.c \
	../../libudev/libudev.h \
	../../libudev/libudev.c \
	../../libudev/libudev-list.c \
	../../libudev/libudev-util.c
