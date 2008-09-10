SUBDIRS = \
	lib

sbin_PROGRAMS = \
	udevd \
	udevadm

noinst_PROGRAMS = \
	test-udev

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\" \
	-D_LIBUDEV_COMPILATION

common_ldadd =

common_files = \
	list.h \
	logging.h \
	udev.h \
	udev_rules.h \
	udev_sysdeps.h \
	udev_db.c \
	udev_device.c \
	udev_device_event.c \
	udev_node.c \
	udev_rules.c \
	udev_rules_parse.c \
	udev_sysdeps.c \
	udev_sysfs.c \
	udev_utils.c \
	udev_utils_file.c \
	udev_utils_string.c \
	lib/libudev.h \
	lib/libudev-private.h \
	lib/libudev.c \
	lib/libudev-device.c \
	lib/libudev-monitor.c \
	lib/libudev-util.c \
	lib/libudev-ctrl.c

if USE_SELINUX
common_ldadd += \
	$(SELINUX_LIBS)
endif

udevd_SOURCES = \
	$(common_files) \
	udevd.c

udevd_LDADD = \
	$(common_ldadd)


udevadm_SOURCES = \
	$(common_files) \
	udevadm.c \
	udevadm-info.c \
	udevadm-control.c \
	udevadm-test.c \
	udevadm-monitor.c \
	udevadm-settle.c \
	udevadm-trigger.c

udevadm_LDADD = \
	$(common_ldadd)


test_udev_SOURCES = \
	$(common_files) \
	test-udev.c

test_udev_LDADD = \
	$(common_ldadd)


dist_man_MANS = \
	udev.7 \
	udevadm.8 \
	udevd.8

EXTRA_DIST = \
	udev.xml \
	udevadm.xml \
	udevd.xml

%.7 %.8 : %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

distclean-local:
	rm -f Makefile.in
	rm -f $(dist_man_MANS)
