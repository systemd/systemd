# ------------------------------------------------------------------------------
# Copyright (C) 2008-2009 Kay Sievers <kay.sievers@vrfy.org>
# Copyright (C) 2009 Diego Elio 'Flameeyes' Pettenò <flameeyes@gmail.com>
# ------------------------------------------------------------------------------

SUBDIRS = .

EXTRA_DIST = autogen.sh

ACLOCAL_AMFLAGS = -I m4

AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/libudev \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\"

AM_CFLAGS = \
	-fvisibility=hidden \
	-ffunction-sections \
	-fdata-sections

AM_LDFLAGS = \
	-Wl,--gc-sections \
	-Wl,--as-needed

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

CLEANFILES =
BUILT_SOURCES =
INSTALL_EXEC_HOOKS =
INSTALL_DATA_HOOKS =
UNINSTALL_EXEC_HOOKS =
DISTCHECK_HOOKS =
dist_libexec_SCRIPTS =

# ------------------------------------------------------------------------------
# libudev
# ------------------------------------------------------------------------------
LIBUDEV_CURRENT=12
LIBUDEV_REVISION=0
LIBUDEV_AGE=12

SUBDIRS += libudev/docs

include_HEADERS = libudev/libudev.h
lib_LTLIBRARIES = libudev/libudev.la

libudev_libudev_la_SOURCES =\
	libudev/libudev-private.h \
	libudev/libudev.c \
	libudev/libudev-list.c \
	libudev/libudev-util.c \
	libudev/libudev-device.c \
	libudev/libudev-enumerate.c \
	libudev/libudev-monitor.c \
	libudev/libudev-queue.c

libudev_libudev_la_LDFLAGS = \
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE)

noinst_LTLIBRARIES = \
	libudev/libudev-private.la

libudev_libudev_private_la_SOURCES =\
	$(libudev_libudev_la_SOURCES) \
	libudev/libudev-util-private.c \
	libudev/libudev-device-private.c \
	libudev/libudev-queue-private.c

if WITH_SELINUX
libudev_libudev_private_la_SOURCES += libudev/libudev-selinux-private.c
libudev_libudev_private_la_LIBADD = $(SELINUX_LIBS)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libudev/libudev.pc

EXTRA_DIST += libudev/COPYING
# move lib from $(libdir) to $(rootlib_execdir) and update devel link, if needed
libudev-install-move-hook:
	if test "$(libdir)" != "$(rootlib_execdir)"; then \
		mkdir -p $(DESTDIR)$(rootlib_execdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libudev.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlib_execdir)/$$so_img_name $(DESTDIR)$(libdir)/libudev.so && \
		mv $(DESTDIR)$(libdir)/libudev.so.* $(DESTDIR)$(rootlib_execdir); \
	fi

libudev-uninstall-move-hook:
	rm -f $(DESTDIR)$(rootlib_execdir)/libudev.so*

INSTALL_EXEC_HOOKS += libudev-install-move-hook
UNINSTALL_EXEC_HOOKS += libudev-uninstall-move-hook

# ------------------------------------------------------------------------------
# main udev
# ------------------------------------------------------------------------------
udev-confdirs:
	-mkdir -p $(DESTDIR)$(sysconfdir)/udev/rules.d
	-mkdir -p $(DESTDIR)$(libexecdir)/devices

INSTALL_DATA_HOOKS += udev-confdirs

EXTRA_DIST += \
	rules/arch \
	rules/misc

udevrulesdir = $(libexecdir)/rules.d
dist_udevrules_DATA = \
	rules/rules.d/50-udev-default.rules \
	rules/rules.d/60-persistent-storage.rules \
	rules/rules.d/60-persistent-storage-tape.rules \
	rules/rules.d/60-persistent-serial.rules \
	rules/rules.d/60-persistent-input.rules \
	rules/rules.d/60-persistent-alsa.rules \
	rules/rules.d/80-drivers.rules \
	rules/rules.d/95-udev-late.rules

udevconfdir = $(sysconfdir)/udev
dist_udevconf_DATA = udev.conf

sharepkgconfigdir = $(datadir)/pkgconfig
sharepkgconfig_DATA = udev/udev.pc

if WITH_SYSTEMD
systemdsystemunit_DATA = \
	init/udev-control.socket \
	init/udev-kernel.socket \
	init/udev.service \
	init/udev-trigger.service \
	init/udev-settle.service

EXTRA_DIST += \
	init/udev-control.socket \
	init/udev-kernel.socket

systemd-install-hook:
	mkdir -p $(DESTDIR)$(systemdsystemunitdir)/sockets.target.wants
	ln -sf ../udev-control.socket $(DESTDIR)$(systemdsystemunitdir)/sockets.target.wants/udev-control.socket
	ln -sf ../udev-kernel.socket $(DESTDIR)$(systemdsystemunitdir)/sockets.target.wants/udev-kernel.socket
	mkdir -p $(DESTDIR)$(systemdsystemunitdir)/basic.target.wants
	ln -sf ../udev.service $(DESTDIR)$(systemdsystemunitdir)/basic.target.wants/udev.service
	ln -sf ../udev-trigger.service $(DESTDIR)$(systemdsystemunitdir)/basic.target.wants/udev-trigger.service

INSTALL_DATA_HOOKS += systemd-install-hook
endif

sbin_PROGRAMS = \
	udev/udevd \
	udev/udevadm

udev_common_sources =\
	udev/udev.h \
	udev/udev-event.c \
	udev/udev-watch.c \
	udev/udev-node.c \
	udev/udev-rules.c \
	udev/udev-ctrl.c

udev_udevd_SOURCES = \
	$(udev_common_sources) \
	udev/udevd.c \
	udev/sd-daemon.h \
	udev/sd-daemon.c
udev_udevd_LDADD = libudev/libudev-private.la

udev_udevadm_SOURCES = \
	$(udev_common_sources) \
	udev/udevadm.c \
	udev/udevadm-info.c \
	udev/udevadm-control.c \
	udev/udevadm-test.c \
	udev/udevadm-monitor.c \
	udev/udevadm-settle.c \
	udev/udevadm-trigger.c
udev_udevadm_LDADD = libudev/libudev-private.la

# ------------------------------------------------------------------------------
# udev man pages
# ------------------------------------------------------------------------------
dist_man_MANS = \
	udev/udev.7 \
	udev/udevadm.8 \
	udev/udevd.8

dist_noinst_DATA = \
	udev/udev.html \
	udev/udevadm.html \
	udev/udevd.html

EXTRA_DIST += \
	udev/udev.xml \
	udev/udevadm.xml \
	udev/udevd.xml

udev/%.7 udev/%.8 : udev/%.xml
	$(AM_V_GEN)$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

udev/%.html : udev/%.xml
	$(AM_V_GEN)$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

# ------------------------------------------------------------------------------
# udev tests
# ------------------------------------------------------------------------------
TESTS = test/udev-test.pl test/rules-test.sh

check_PROGRAMS = \
	libudev/test-libudev \
	udev/test-udev

libudev_test_libudev_SOURCES = libudev/test-libudev.c
libudev_test_libudev_LDADD = libudev/libudev.la

udev_test_udev_SOURCES = \
	$(udev_common_sources) \
	udev/test-udev.c
udev_test_udev_LDADD = libudev/libudev-private.la

# ------------------------------------------------------------------------------
# firmware - firmware loading
# ------------------------------------------------------------------------------
extras_firmware_firmware_SOURCES = extras/firmware/firmware.c
extras_firmware_firmware_LDADD = libudev/libudev-private.la
extras_firmware_firmware_CPPFLAGS = $(AM_CPPFLAGS) -DFIRMWARE_PATH="$(FIRMWARE_PATH)"
dist_udevrules_DATA += extras/firmware/50-firmware.rules
libexec_PROGRAMS = extras/firmware/firmware

# ------------------------------------------------------------------------------
# ata_id - ATA identify
# ------------------------------------------------------------------------------
extras_ata_id_ata_id_SOURCES = extras/ata_id/ata_id.c
extras_ata_id_ata_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/ata_id/ata_id

# ------------------------------------------------------------------------------
# cdrom_id - optical drive/media capability
# ------------------------------------------------------------------------------
extras_cdrom_id_cdrom_id_SOURCES = extras/cdrom_id/cdrom_id.c
extras_cdrom_id_cdrom_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/cdrom_id/cdrom_id
dist_udevrules_DATA += extras/cdrom_id/60-cdrom_id.rules

# ------------------------------------------------------------------------------
# collect - trigger action when a collection of devices appeared
# ------------------------------------------------------------------------------
extras_collect_collect_SOURCES = extras/collect/collect.c
extras_collect_collect_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/collect/collect

# ------------------------------------------------------------------------------
# input_id - import input device class
# ------------------------------------------------------------------------------
extras_input_id_input_id_SOURCES = extras/input_id/input_id.c
extras_input_id_input_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/input_id/input_id

# ------------------------------------------------------------------------------
# path_id - compose identifier of persistent elements of the parent buses
# ------------------------------------------------------------------------------
extras_path_id_path_id_SOURCES = extras/path_id/path_id.c
extras_path_id_path_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/path_id/path_id

# ------------------------------------------------------------------------------
# scsi_id - SCSI inquiry to get various serial numbers
# ------------------------------------------------------------------------------
extras_scsi_id_scsi_id_SOURCES =\
	extras/scsi_id/scsi_id.c \
	extras/scsi_id/scsi_serial.c \
	extras/scsi_id/scsi.h \
	extras/scsi_id/scsi_id.h
extras_scsi_id_scsi_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/scsi_id/scsi_id
dist_man_MANS += extras/scsi_id/scsi_id.8
EXTRA_DIST += extras/scsi_id/README

# ------------------------------------------------------------------------------
# usb_id - USB device property import
# ------------------------------------------------------------------------------
extras_usb_id_usb_id_SOURCES = extras/usb_id/usb_id.c
extras_usb_id_usb_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/usb_id/usb_id

# ------------------------------------------------------------------------------
# v4l_id - video4linux capabilities
# ------------------------------------------------------------------------------
extras_v4l_id_v4l_id_SOURCES = extras/v4l_id/v4l_id.c
extras_v4l_id_v4l_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/v4l_id/v4l_id
dist_udevrules_DATA += extras/v4l_id/60-persistent-v4l.rules

# ------------------------------------------------------------------------------
# accelerometer - updates device orientation
# ------------------------------------------------------------------------------
extras_accelerometer_accelerometer_SOURCES = extras/accelerometer/accelerometer.c
extras_accelerometer_accelerometer_LDADD = libudev/libudev-private.la -lm
libexec_PROGRAMS += extras/accelerometer/accelerometer
dist_udevrules_DATA += extras/accelerometer/61-accelerometer.rules

# ------------------------------------------------------------------------------
# qemu -- qemu/kvm guest tweaks
# ------------------------------------------------------------------------------
dist_udevrules_DATA += extras/qemu/42-qemu-usb.rules

if ENABLE_GUDEV
# ------------------------------------------------------------------------------
# GUdev - libudev gobject interface
# ------------------------------------------------------------------------------
LIBGUDEV_CURRENT=1
LIBGUDEV_REVISION=0
LIBGUDEV_AGE=1

SUBDIRS += extras/gudev/docs

libgudev_includedir=$(includedir)/gudev-1.0/gudev
libgudev_include_HEADERS = \
	extras/gudev/gudev.h \
	extras/gudev/gudevenums.h \
	extras/gudev/gudevenumtypes.h \
	extras/gudev/gudevtypes.h \
	extras/gudev/gudevclient.h \
	extras/gudev/gudevdevice.h \
	extras/gudev/gudevenumerator.h

lib_LTLIBRARIES += extras/gudev/libgudev-1.0.la
pkgconfig_DATA += extras/gudev/gudev-1.0.pc

extras_gudev_libgudev_1_0_la_SOURCES = \
	extras/gudev/gudevenums.h \
	extras/gudev/gudevenumtypes.h \
	extras/gudev/gudevenumtypes.h\
	extras/gudev/gudevtypes.h \
	extras/gudev/gudevclient.h \
	extras/gudev/gudevclient.c \
	extras/gudev/gudevdevice.h \
	extras/gudev/gudevdevice.c \
	extras/gudev/gudevenumerator.h \
	extras/gudev/gudevenumerator.c \
	extras/gudev/gudevprivate.h

dist_extras_gudev_libgudev_1_0_la_SOURCES = \
	extras/gudev/gudevmarshal.h \
	extras/gudev/gudevmarshal.c \
	extras/gudev/gudevenumtypes.h \
	extras/gudev/gudevenumtypes.c
BUILT_SOURCES += $(dist_extras_gudev_libgudev_1_0_la_SOURCES)

extras_gudev_libgudev_1_0_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_builddir)/extras \
	-I$(top_srcdir)/extras \
	-I$(top_builddir)/extras/gudev \
	-I$(top_srcdir)/extras/gudev \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
	-D_GUDEV_COMPILATION \
	-DG_LOG_DOMAIN=\"GUdev\"

extras_gudev_libgudev_1_0_la_CFLAGS = \
	-fvisibility=default \
	$(GLIB_CFLAGS)

extras_gudev_libgudev_1_0_la_LIBADD = libudev/libudev.la $(GLIB_LIBS)

extras_gudev_libgudev_1_0_la_LDFLAGS = \
	-version-info $(LIBGUDEV_CURRENT):$(LIBGUDEV_REVISION):$(LIBGUDEV_AGE) \
	-export-dynamic -no-undefined \
	-export-symbols-regex '^g_udev_.*'

EXTRA_DIST += \
	extras/gudev/COPYING \
	extras/gudev/gudevmarshal.list \
	extras/gudev/gudevenumtypes.h.template \
	extras/gudev/gudevenumtypes.c.template \
	extras/gudev/gjs-example.js \
	extras/gudev/seed-example-enum.js \
	extras/gudev/seed-example.js

extras/gudev/gudevmarshal.h: extras/gudev/gudevmarshal.list
	$(AM_V_GEN)glib-genmarshal $< --prefix=g_udev_marshal --header > $@

extras/gudev/gudevmarshal.c: extras/gudev/gudevmarshal.list
	$(AM_V_GEN)echo "#include \"gudevmarshal.h\"" > $@ && \
	glib-genmarshal $< --prefix=g_udev_marshal --body >> $@

extras/gudev/gudevenumtypes.h: extras/gudev/gudevenumtypes.h.template extras/gudev/gudevenums.h
	$(AM_V_GEN)glib-mkenums --template $^ > \
	    $@.tmp && mv $@.tmp $@

extras/gudev/gudevenumtypes.c: extras/gudev/gudevenumtypes.c.template extras/gudev/gudevenums.h
	$(AM_V_GEN)glib-mkenums --template $^ > \
	    $@.tmp && mv $@.tmp $@

if ENABLE_INTROSPECTION
extras/gudev/GUdev-1.0.gir: extras/gudev/libgudev-1.0.la $(G_IR_SCANNER)
	$(AM_V_GEN)$(G_IR_SCANNER) -v \
		--warn-all \
		--namespace GUdev \
		--nsversion=1.0 \
		--include=GObject-2.0 \
		--library=gudev-1.0 \
		--library-path=$(top_builddir)/libudev \
		--library-path=$(top_builddir)/extras/gudev \
		--output $@ \
		--pkg=glib-2.0 \
		--pkg=gobject-2.0 \
		-I$(top_srcdir)/extras \
		-I$(top_builddir)/extras \
		-D_GUDEV_COMPILATION \
		-D_GUDEV_WORK_AROUND_DEV_T_BUG \
		$(top_srcdir)/extras/gudev/gudev.h \
		$(top_srcdir)/extras/gudev/gudevtypes.h \
		$(top_srcdir)/extras/gudev/gudevenums.h \
		$(or $(wildcard $(top_builddir)/extras/gudev/gudevenumtypes.h),$(top_srcdir)/extras/gudev/gudevenumtypes.h) \
		$(top_srcdir)/extras/gudev/gudevclient.h \
		$(top_srcdir)/extras/gudev/gudevdevice.h \
		$(top_srcdir)/extras/gudev/gudevenumerator.h \
		$(top_srcdir)/extras/gudev/gudevclient.c \
		$(top_srcdir)/extras/gudev/gudevdevice.c \
		$(top_srcdir)/extras/gudev/gudevenumerator.c

extras/gudev/GUdev-1.0.typelib: extras/gudev/GUdev-1.0.gir $(G_IR_COMPILER)
	$(AM_V_GEN)g-ir-compiler $< -o $@

girdir = $(GIRDIR)
gir_DATA = extras/gudev/GUdev-1.0.gir

typelibsdir = $(GIRTYPELIBDIR)
typelibs_DATA = extras/gudev/GUdev-1.0.typelib

CLEANFILES += $(gir_DATA) $(typelibs_DATA)
endif # ENABLE_INTROSPECTION

# move lib from $(libdir) to $(rootlib_execdir) and update devel link, if needed
libgudev-install-move-hook:
	if test "$(libdir)" != "$(rootlib_execdir)"; then \
		mkdir -p $(DESTDIR)$(rootlib_execdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libgudev-1.0.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlib_execdir)/$$so_img_name $(DESTDIR)$(libdir)/libgudev-1.0.so && \
		mv $(DESTDIR)$(libdir)/libgudev-1.0.so.* $(DESTDIR)$(rootlib_execdir); \
	fi

libgudev-uninstall-move-hook:
	rm -f $(DESTDIR)$(rootlib_execdir)/libgudev-1.0.so*

INSTALL_EXEC_HOOKS += libgudev-install-move-hook
UNINSTALL_EXEC_HOOKS += libgudev-uninstall-move-hook
endif

if ENABLE_HWDB
# ------------------------------------------------------------------------------
# usb/pci-db - read vendor/device string database
# ------------------------------------------------------------------------------
extras_usb_db_usb_db_SOURCES = extras/usb-db/usb-db.c
extras_usb_db_usb_db_CPPFLAGS = $(AM_CPPFLAGS) -DUSB_DATABASE=\"$(USB_DATABASE)\" -DBUILD_FOR_USB
extras_usb_db_usb_db_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/usb-db/usb-db
dist_udevrules_DATA += \
	rules/rules.d/75-net-description.rules \
	rules/rules.d/75-tty-description.rules \
	rules/rules.d/78-sound-card.rules

extras_usb_db_pci_db_SOURCES = extras/usb-db/usb-db.c
extras_usb_db_pci_db_CPPFLAGS = $(AM_CPPFLAGS) -DPCI_DATABASE=\"$(PCI_DATABASE)\" -DBUILD_FOR_PCI
extras_usb_db_pci_db_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/usb-db/pci-db
endif

if ENABLE_KEYMAP
# ------------------------------------------------------------------------------
# keymap - map custom hardware's multimedia keys
# ------------------------------------------------------------------------------
extras_keymap_keymap_SOURCES = extras/keymap/keymap.c
extras_keymap_keymap_CPPFLAGS = $(AM_CPPFLAGS) -I extras/keymap
nodist_extras_keymap_keymap_SOURCES = \
	extras/keymap/keys-from-name.h \
	extras/keymap/keys-to-name.h
BUILT_SOURCES += $(nodist_extras_keymap_keymap_SOURCES)

EXTRA_DIST += extras/keymap/check-keymaps.sh
dist_udevrules_DATA += extras/keymap/95-keymap.rules
dist_udevrules_DATA += extras/keymap/95-keyboard-force-release.rules
libexec_PROGRAMS += extras/keymap/keymap
dist_libexec_SCRIPTS += extras/keymap/findkeyboards
dist_libexec_SCRIPTS += extras/keymap/keyboard-force-release.sh
dist_doc_DATA = extras/keymap/README.keymap.txt
CLEANFILES += \
	extras/keymap/keys.txt \
	extras/keymap/keys-from-name.gperf

udevkeymapdir = $(libexecdir)/keymaps
dist_udevkeymap_DATA = \
	extras/keymap/keymaps/acer \
	extras/keymap/keymaps/acer-aspire_5720 \
	extras/keymap/keymaps/acer-aspire_8930 \
	extras/keymap/keymaps/acer-aspire_5920g \
	extras/keymap/keymaps/acer-aspire_6920 \
	extras/keymap/keymaps/acer-travelmate_c300 \
	extras/keymap/keymaps/asus \
	extras/keymap/keymaps/compaq-e_evo \
	extras/keymap/keymaps/dell \
	extras/keymap/keymaps/dell-latitude-xt2 \
	extras/keymap/keymaps/everex-xt5000 \
	extras/keymap/keymaps/fujitsu-amilo_pa_2548 \
	extras/keymap/keymaps/fujitsu-amilo_pro_edition_v3505 \
	extras/keymap/keymaps/fujitsu-amilo_pro_v3205 \
	extras/keymap/keymaps/fujitsu-amilo_si_1520 \
	extras/keymap/keymaps/fujitsu-esprimo_mobile_v5 \
	extras/keymap/keymaps/fujitsu-esprimo_mobile_v6 \
	extras/keymap/keymaps/hewlett-packard \
	extras/keymap/keymaps/hewlett-packard-2510p_2530p \
	extras/keymap/keymaps/hewlett-packard-compaq_elitebook \
	extras/keymap/keymaps/hewlett-packard-pavilion \
	extras/keymap/keymaps/hewlett-packard-presario-2100 \
	extras/keymap/keymaps/hewlett-packard-tablet \
	extras/keymap/keymaps/hewlett-packard-tx2 \
	extras/keymap/keymaps/ibm-thinkpad-usb-keyboard-trackpoint \
	extras/keymap/keymaps/inventec-symphony_6.0_7.0 \
	extras/keymap/keymaps/lenovo-3000 \
	extras/keymap/keymaps/lenovo-ideapad \
	extras/keymap/keymaps/lenovo-thinkpad-usb-keyboard-trackpoint \
	extras/keymap/keymaps/lenovo-thinkpad_x6_tablet \
	extras/keymap/keymaps/lenovo-thinkpad_x200_tablet \
	extras/keymap/keymaps/lg-x110 \
	extras/keymap/keymaps/logitech-wave \
	extras/keymap/keymaps/logitech-wave-cordless \
	extras/keymap/keymaps/logitech-wave-pro-cordless \
	extras/keymap/keymaps/maxdata-pro_7000 \
	extras/keymap/keymaps/medion-fid2060 \
	extras/keymap/keymaps/medionnb-a555 \
	extras/keymap/keymaps/micro-star \
	extras/keymap/keymaps/module-asus-w3j \
	extras/keymap/keymaps/module-ibm \
	extras/keymap/keymaps/module-lenovo \
	extras/keymap/keymaps/module-sony \
	extras/keymap/keymaps/module-sony-old \
	extras/keymap/keymaps/module-sony-vgn \
	extras/keymap/keymaps/olpc-xo \
	extras/keymap/keymaps/onkyo \
	extras/keymap/keymaps/oqo-model2 \
	extras/keymap/keymaps/samsung-other \
	extras/keymap/keymaps/samsung-sq1us \
	extras/keymap/keymaps/samsung-sx20s \
	extras/keymap/keymaps/toshiba-satellite_a100 \
	extras/keymap/keymaps/toshiba-satellite_a110 \
	extras/keymap/keymaps/toshiba-satellite_m30x \
	extras/keymap/keymaps/zepto-znote

udevkeymapforcereldir = $(libexecdir)/keymaps/force-release
dist_udevkeymapforcerel_DATA = \
	extras/keymap/force-release-maps/dell-touchpad \
	extras/keymap/force-release-maps/hp-other \
	extras/keymap/force-release-maps/samsung-other \
	extras/keymap/force-release-maps/common-volume-keys

extras/keymap/keys.txt: $(INCLUDE_PREFIX)/linux/input.h
	$(AM_V_at)mkdir -p extras/keymap
	$(AM_V_GEN)$(AWK) '/^#define.*KEY_[^ ]+[ \t]+[0-9]/ { if ($$2 != "KEY_MAX") { print $$2 } }' < $< | sed 's/^KEY_COFFEE$$/KEY_SCREENLOCK/' > $@

extras/keymap/keys-from-name.gperf: extras/keymap/keys.txt
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

extras/keymap/keys-from-name.h: extras/keymap/keys-from-name.gperf Makefile
	$(AM_V_GEN)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

extras/keymap/keys-to-name.h: extras/keymap/keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@

keymaps-distcheck-hook: extras/keymap/keys.txt
	$(top_srcdir)/extras/keymap/check-keymaps.sh $(top_srcdir) $^
DISTCHECK_HOOKS += keymaps-distcheck-hook
endif

if ENABLE_MTD_PROBE
# ------------------------------------------------------------------------------
# mtd_probe - autoloads FTL module for mtd devices
# ------------------------------------------------------------------------------
extras_mtd_probe_mtd_probe_SOURCES =  \
	extras/mtd_probe/mtd_probe.c \
	extras/mtd_probe/mtd_probe.h \
	extras/mtd_probe/probe_smartmedia.c
extras_mtd_probe_mtd_probe_CPPFLAGS = $(AM_CPPFLAGS)
dist_udevrules_DATA += extras/mtd_probe/75-probe_mtd.rules
libexec_PROGRAMS += extras/mtd_probe/mtd_probe
endif

if ENABLE_RULE_GENERATOR
# ------------------------------------------------------------------------------
# rule_generator - persistent network and optical device rule generator
# ------------------------------------------------------------------------------
dist_libexec_SCRIPTS += \
	extras/rule_generator/write_cd_rules \
	extras/rule_generator/write_net_rules

udevhomedir = $(libexecdir)
dist_udevhome_DATA = extras/rule_generator/rule_generator.functions

dist_udevrules_DATA += \
	extras/rule_generator/75-cd-aliases-generator.rules \
	extras/rule_generator/75-persistent-net-generator.rules
endif

if ENABLE_UDEV_ACL
# ------------------------------------------------------------------------------
# udev_acl - apply ACLs for users with local forground sessions
# ------------------------------------------------------------------------------
extras_udev_acl_udev_acl_SOURCES = extras/udev-acl/udev-acl.c
extras_udev_acl_udev_acl_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)
extras_udev_acl_udev_acl_LDADD = libudev/libudev-private.la -lacl $(GLIB_LIBS)
dist_udevrules_DATA += extras/udev-acl/70-udev-acl.rules
libexec_PROGRAMS += extras/udev-acl/udev-acl

udevacl-install-hook:
	mkdir -p $(DESTDIR)$(prefix)/lib/ConsoleKit/run-seat.d
	ln -sf $(libexecdir)/udev-acl $(DESTDIR)$(prefix)/lib/ConsoleKit/run-seat.d/udev-acl.ck

INSTALL_EXEC_HOOKS += udevacl-install-hook
endif

if ENABLE_FLOPPY
# ------------------------------------------------------------------------------
# create_floppy_devices - historical floppy kernel device nodes (/dev/fd0h1440, ...)
# ------------------------------------------------------------------------------
extras_floppy_create_floppy_devices_SOURCES = extras/floppy/create_floppy_devices.c
extras_floppy_create_floppy_devices_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/floppy/create_floppy_devices
dist_udevrules_DATA += extras/floppy/60-floppy.rules
endif

if ENABLE_EDD
# ------------------------------------------------------------------------------
# edd_id - create /dev/disk/by-id/edd-* links for BIOS EDD data
# ------------------------------------------------------------------------------
extras_edd_id_edd_id_SOURCES = extras/edd_id/edd_id.c
extras_edd_id_edd_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/edd_id/edd_id
dist_udevrules_DATA += extras/edd_id/61-persistent-storage-edd.rules
endif

# ------------------------------------------------------------------------------
# install, uninstall, clean hooks
# ------------------------------------------------------------------------------
clean-local:
	rm -rf udev-test-install

distclean-local:
	rm -rf autom4te.cache

CLEANFILES += \
	udev-$(VERSION).tar.gz \
	udev-$(VERSION).tar.bz2 \
	$(BUILT_SOURCES)

EXTRA_DIST += $(TESTS)
EXTRA_DIST += test/rule-syntax-check.py

install-exec-hook: $(INSTALL_EXEC_HOOKS)

install-data-hook: $(INSTALL_DATA_HOOKS)

uninstall-hook: $(UNINSTALL_EXEC_HOOKS)

distcheck-hook: $(DISTCHECK_HOOKS)

# ------------------------------------------------------------------------------
# custom release helpers
# ------------------------------------------------------------------------------
PREVIOUS_VERSION = `expr $(VERSION) - 1`
changelog:
	@ head -1 ChangeLog | grep -q "to v$(PREVIOUS_VERSION)"
	@ mv ChangeLog ChangeLog.tmp
	@ echo "Summary of changes from v$(PREVIOUS_VERSION) to v$(VERSION)" >> ChangeLog
	@ echo "============================================" >> ChangeLog
	@ echo >> ChangeLog
	@ git log --pretty=short $(PREVIOUS_VERSION)..HEAD | git shortlog  >> ChangeLog
	@ echo >> ChangeLog
	@ cat ChangeLog
	@ cat ChangeLog.tmp >> ChangeLog
	@ rm ChangeLog.tmp

test-install:
	rm -rf $(PWD)/udev-test-install/
	make DESTDIR=$(PWD)/udev-test-install install
	tree $(PWD)/udev-test-install/

git-release:
	head -1 ChangeLog | grep -q "to v$(VERSION)"
	head -1 NEWS | grep -q "udev $(VERSION)"
	git commit -a -m "release $(VERSION)"
	git tag $(VERSION)
	git gc --prune=0

git-sync:
	git push
	git push --tags $(VERSION)

tar-sync:
	scp udev-$(VERSION).tar.gz master.kernel.org:/pub/linux/utils/kernel/hotplug/

doc-sync:
	rsync -av udev/*.html master.kernel.org:/pub/linux/utils/kernel/hotplug/udev/
	rsync -av --delete libudev/docs/html/ master.kernel.org:/pub/linux/utils/kernel/hotplug/libudev/
	rsync -av --delete extras/gudev/docs/html/ master.kernel.org:/pub/linux/utils/kernel/hotplug/gudev/
