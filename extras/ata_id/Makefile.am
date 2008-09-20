include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	ata_id

ata_id_SOURCES = \
	ata_id.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-util.c

if USE_SELINUX
ata_id_LDADD = \
	$(SELINUX_LIBS)
endif

dist_man_MANS = \
	ata_id.8

distclean-local:
	rm -f Makefile.in
