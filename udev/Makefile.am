include $(top_srcdir)/Makefile.am.inc

sbin_PROGRAMS = \
	udevd \
	udevadm

noinst_PROGRAMS = \
	test-udev

common_ldadd =

common_files = \
	udev.h \
	udev-event.c \
	udev-watch.c \
	udev-node.c \
	udev-rules.c \
	../libudev/libudev.h \
	../libudev/libudev-private.h \
	../libudev/libudev.c \
	../libudev/libudev-list.c \
	../libudev/libudev-util.c \
	../libudev/libudev-util-private.c \
	../libudev/libudev-device.c \
	../libudev/libudev-device-private.c \
	../libudev/libudev-monitor.c \
	../libudev/libudev-enumerate.c \
	../libudev/libudev-queue.c \
	../libudev/libudev-queue-private.c \
	../libudev/libudev-ctrl.c

if USE_SELINUX
common_files += \
	../libudev/libudev-selinux-private.c
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

MAINTAINERCLEANFILES = \
	$(dist_man_MANS)

git-clean:
	rm -f Makefile.in
