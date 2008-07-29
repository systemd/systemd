sbin_PROGRAMS = \
	udevd \
	udevadm

noinst_PROGRAMS = \
	test-udev

AM_CPPFLAGS = \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DUDEV_PREFIX=\""$(udev_prefix)"\"

udevd_SOURCES = \
	list.h \
	logging.h \
	udev.h \
	udev_rules.h \
	udev_selinux.h \
	udev_sysdeps.h \
	udevd.h \
	udevd.c \
	udev_config.c \
	udev_db.c \
	udev_device.c \
	udev_node.c \
	udev_rules.c \
	udev_rules_parse.c \
	udev_sysdeps.c \
	udev_sysfs.c \
	udev_utils.c \
	udev_utils_file.c \
	udev_utils_string.c
if USE_SELINUX
udevd_SOURCES += \
	udev_selinux.c

udevd_LDADD = \
	$(SELINUX_LIBS)
endif

udevadm_SOURCES = \
	list.h \
	logging.h \
	udev.h \
	udev_rules.h \
	udev_selinux.h \
	udev_sysdeps.h \
	udevadm.c \
	udevinfo.c \
	udevcontrol.c \
	udevtest.c \
	udevmonitor.c \
	udevsettle.c \
	udevtrigger.c \
	udev_config.c \
	udev_db.c \
	udev_device.c \
	udev_node.c \
	udev_rules.c \
	udev_rules_parse.c \
	udev_sysdeps.c \
	udev_sysfs.c \
	udev_utils.c \
	udev_utils_file.c \
	udev_utils_string.c
if USE_SELINUX
udevadm_SOURCES += \
	udev_selinux.c

udevadm_LDADD = \
	$(SELINUX_LIBS)
endif

test_udev_SOURCES = \
	list.h \
	logging.h \
	udev.h \
	udev_rules.h \
	udev_selinux.h \
	udev_sysdeps.h \
	test-udev.c \
	udev_config.c \
	udev_db.c \
	udev_device.c \
	udev_node.c \
	udev_rules.c \
	udev_rules_parse.c \
	udev_sysdeps.c \
	udev_sysfs.c \
	udev_utils.c \
	udev_utils_file.c \
	udev_utils_string.c
if USE_SELINUX
test_udev_SOURCES += \
	udev_selinux.c

test_udev_LDADD = \
	$(SELINUX_LIBS)
endif

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
