include $(top_srcdir)/Makefile.am.inc

libexec_PROGRAMS = \
	create_floppy_devices

create_floppy_devices_SOURCES = \
	create_floppy_devices.c

create_floppy_devices_LDADD = \
	$(top_builddir)/libudev/libudev-private.la

if WITH_SELINUX
create_floppy_devices_LDADD += \
	$(SELINUX_LIBS)
endif
