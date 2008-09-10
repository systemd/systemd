udevhomedir = $(udev_prefix)/lib/udev
udevhome_PROGRAMS = \
	fstab_import

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	79-fstab_import.rules

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\" \
	-D_LIBUDEV_COMPILATION

fstab_import_SOURCES = \
	fstab_import.c \
	../../udev/lib/libudev.h \
	../../udev/lib/libudev.c \
	../../udev/udev_sysdeps.c \
	../../udev/udev_utils.c \
	../../udev/udev_utils_string.c

if USE_SELINUX
fstab_import_LDADD = \
	$(SELINUX_LIBS)
endif

distclean-local:
	rm -f Makefile.in

