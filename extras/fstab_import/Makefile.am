include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	fstab_import

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	79-fstab_import.rules

fstab_import_SOURCES = \
	fstab_import.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/lib/libudev-util.c

if USE_SELINUX
fstab_import_LDADD = \
	$(SELINUX_LIBS)
endif

distclean-local:
	rm -f Makefile.in

