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

AM_LDFLAGS = \
	-Wl,--as-needed

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

CLEANFILES =

INSTALL_EXEC_HOOKS =
INSTALL_DATA_HOOKS =
UNINSTALL_EXEC_HOOKS =
DISTCHECK_HOOKS =

# ------------------------------------------------------------------------------
# libudev
# ------------------------------------------------------------------------------
LIBUDEV_CURRENT=9
LIBUDEV_REVISION=3
LIBUDEV_AGE=9

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
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE) \
	-export-symbols $(top_srcdir)/libudev/exported_symbols

noinst_LTLIBRARIES = \
	libudev/libudev-private.la

libudev_libudev_private_la_SOURCES =\
	$(libudev_libudev_la_SOURCES) \
	libudev/libudev-ctrl.c \
	libudev/libudev-util-private.c \
	libudev/libudev-device-private.c \
	libudev/libudev-queue-private.c

if WITH_SELINUX
libudev_libudev_private_la_SOURCES += libudev/libudev-selinux-private.c
libudev_libudev_private_la_LIBADD = $(SELINUX_LIBS)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libudev/libudev.pc

EXTRA_DIST += libudev/exported_symbols libudev/COPYING
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
	init/udev.service \
	init/udev-settle.service \
	init/udev-retry.service

systemd-install-hook:
	mkdir -p $(DESTDIR)$(systemdsystemunitdir)/basic.target.wants
	ln -sf ../udev.service $(DESTDIR)$(systemdsystemunitdir)/basic.target.wants/udev.service
	ln -sf ../udev-settle.service $(DESTDIR)$(systemdsystemunitdir)/basic.target.wants/udev-settle.service
	ln -sf ../udev-retry.service $(DESTDIR)$(systemdsystemunitdir)/basic.target.wants/udev-retry.service

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
	udev/udev-rules.c

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

EXTRA_DIST += \
	udev/udev.xml \
	udev/udevadm.xml \
	udev/udevd.xml

%.7 %.8 : %.xml
	$(AM_V_GEN)$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

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
# rule_generator - persistent network and optical device rule generator
# ------------------------------------------------------------------------------
dist_libexec_SCRIPTS = \
	extras/rule_generator/write_cd_rules \
	extras/rule_generator/write_net_rules

udevhomedir = $(libexecdir)
dist_udevhome_DATA = extras/rule_generator/rule_generator.functions

dist_udevrules_DATA += \
	extras/rule_generator/75-cd-aliases-generator.rules \
	extras/rule_generator/75-persistent-net-generator.rules

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
# edd_id - BIOS EDD block device match
# ------------------------------------------------------------------------------
extras_edd_id_edd_id_SOURCES = extras/edd_id/edd_id.c
extras_edd_id_edd_id_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/edd_id/edd_id
dist_udevrules_DATA += extras/edd_id/61-persistent-storage-edd.rules

# ------------------------------------------------------------------------------
# create_floppy_devices - historical floppy kernel device nodes (/dev/fd0h1440, ...)
# ------------------------------------------------------------------------------
extras_floppy_create_floppy_devices_SOURCES = extras/floppy/create_floppy_devices.c
extras_floppy_create_floppy_devices_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/floppy/create_floppy_devices
dist_udevrules_DATA += extras/floppy/60-floppy.rules

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
# fstab_import - import /etc/fstab entry for block device
# ------------------------------------------------------------------------------
extras_fstab_import_fstab_import_SOURCES = extras/fstab_import/fstab_import.c
extras_fstab_import_fstab_import_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/fstab_import/fstab_import
dist_udevrules_DATA += extras/fstab_import/79-fstab_import.rules

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

if ENABLE_EXTRAS
# ------------------------------------------------------------------------------
# conditional extras (need glib, libusb, libacl, ...)
# ------------------------------------------------------------------------------
dist_udevrules_DATA += \
	rules/rules.d/75-net-description.rules \
	rules/rules.d/75-tty-description.rules \
	rules/rules.d/78-sound-card.rules

# ------------------------------------------------------------------------------
# GUdev - libudev gobject interface
# ------------------------------------------------------------------------------
LIBGUDEV_CURRENT=0
LIBGUDEV_REVISION=1
LIBGUDEV_AGE=0

SUBDIRS += extras/gudev/docs

libgudev_includedir=$(includedir)/gudev-1.0/gudev
libgudev_include_HEADERS = \
	extras/gudev/gudev.h \
	extras/gudev/gudevenums.h \
	extras/gudev/gudevenumtypes.h \
	extras/gudev/gudevtypes.h \
	extras/gudev/gudevclient.h \
	extras/gudev/gudevdevice.h

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
	extras/gudev/gudevprivate.h

dist_extras_gudev_libgudev_1_0_la_SOURCES = \
	extras/gudev/gudevmarshal.h \
	extras/gudev/gudevmarshal.c \
	extras/gudev/gudevenumtypes.h \
	extras/gudev/gudevenumtypes.c
BUILT_SOURCES = $(dist_extras_gudev_libgudev_1_0_la_SOURCES)

extras_gudev_libgudev_1_0_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_builddir)/extras \
	-I$(top_srcdir)/extras \
	-I$(top_builddir)/extras/gudev \
	-I$(top_srcdir)/extras/gudev \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
	-D_GUDEV_COMPILATION \
	-DG_LOG_DOMAIN=\"GUdev\"
extras_gudev_libgudev_1_0_la_CFLAGS = $(GLIB_CFLAGS)
extras_gudev_libgudev_1_0_la_LIBADD = libudev/libudev.la $(GLIB_LIBS)

extras_gudev_libgudev_1_0_la_LDFLAGS = \
	-version-info $(LIBGUDEV_CURRENT):$(LIBGUDEV_REVISION):$(LIBGUDEV_AGE) \
	-export-dynamic -no-undefined \
	-export-symbols-regex '^g_udev_.*'

EXTRA_DIST += \
	extras/gudev/COPYING \
	extras/gudev/gudevmarshal.list \
	extras/gudev/gudevenumtypes.h.template \
	extras/gudev/gudevenumtypes.c.template

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
extras/gudev/GUdev-1.0.gir: extras/gudev/libgudev-1.0.la $(G_IR_SCANNER) Makefile.am
	$(AM_V_GEN)PKG_CONFIG_PATH=$(top_builddir)/data:$$PKG_CONFIG_PATH \
	LD_LIBRARY_PATH=$(top_builddir)/extras/gudev:$$LD_LIBRARY_PATH \
	$(G_IR_SCANNER) -v \
		--namespace GUdev \
		--nsversion=1.0 \
		--include=GObject-2.0 \
		--library=gudev-1.0 \
		--library-path=extras/gudev \
		--output $@ \
		--pkg=glib-2.0 \
		--pkg=gobject-2.0 \
		-I$(top_builddir)/extras \
		-I$(top_srcdir)/extras \
		-D_GUDEV_COMPILATION \
		-D_GUDEV_WORK_AROUND_DEV_T_BUG \
		$(top_srcdir)/extras/gudev/gudev.h \
		$(top_srcdir)/extras/gudev/gudevtypes.h \
		$(top_srcdir)/extras/gudev/gudevenums.h \
		$(or $(wildcard $(top_builddir)/extras/gudev/gudevenumtypes.h),$(top_srcdir)/extras/gudev/gudevenumtypes.h) \
		$(top_srcdir)/extras/gudev/gudevclient.h \
		$(top_srcdir)/extras/gudev/gudevdevice.h \
		$(top_srcdir)/extras/gudev/gudevclient.c \
		$(top_srcdir)/extras/gudev/gudevdevice.c

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

# ------------------------------------------------------------------------------
# Bluetooth HID devices with special magic to switch the device
# ------------------------------------------------------------------------------
extras_hid2hci_hid2hci_SOURCES = extras/hid2hci/hid2hci.c
extras_hid2hci_hid2hci_CPPFLAGS = $(AM_CPPFLAGS) $(LIBUSB_CFLAGS)
extras_hid2hci_hid2hci_LDADD = libudev/libudev-private.la $(LIBUSB_LIBS)
dist_udevrules_DATA += extras/hid2hci/70-hid2hci.rules
libexec_PROGRAMS += extras/hid2hci/hid2hci

# ------------------------------------------------------------------------------
# udev_acl - apply ACLs for users with local forground sessions
# ------------------------------------------------------------------------------
extras_udev_acl_udev_acl_SOURCES = extras/udev-acl/udev-acl.c
extras_udev_acl_udev_acl_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)
extras_udev_acl_udev_acl_LDADD = libudev/libudev-private.la -lacl $(GLIB_LIBS)
dist_udevrules_DATA += extras/udev-acl/70-acl.rules
libexec_PROGRAMS += extras/udev-acl/udev-acl

udevacl-install-hook:
	mkdir -p $(DESTDIR)$(prefix)/lib/ConsoleKit/run-seat.d
	ln -sf $(libexecdir)/udev-acl $(DESTDIR)$(prefix)/lib/ConsoleKit/run-seat.d/udev-acl.ck

INSTALL_EXEC_HOOKS += udevacl-install-hook

# ------------------------------------------------------------------------------
# usb-db - read USB vendor/device string database
# ------------------------------------------------------------------------------
extras_usb_db_usb_db_SOURCES = extras/usb-db/usb-db.c
extras_usb_db_usb_db_CPPFLAGS = $(AM_CPPFLAGS) -DUSB_DATABASE=\"$(USB_DATABASE)\" -DBUILD_FOR_USB
extras_usb_db_usb_db_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/usb-db/usb-db

# ------------------------------------------------------------------------------
# pci-db - read PCI vendor/device string database
# ------------------------------------------------------------------------------
extras_usb_db_pci_db_SOURCES = extras/usb-db/usb-db.c
extras_usb_db_pci_db_CPPFLAGS = $(AM_CPPFLAGS) -DPCI_DATABASE=\"$(PCI_DATABASE)\" -DBUILD_FOR_PCI
extras_usb_db_pci_db_LDADD = libudev/libudev-private.la
libexec_PROGRAMS += extras/usb-db/pci-db

# ------------------------------------------------------------------------------
# mobile-action-modeswitch - switch Mobile Action cables into serial mode
# ------------------------------------------------------------------------------
extras_mobile_action_modeswitch_mobile_action_modeswitch_SOURCES =\
	extras/mobile-action-modeswitch/mobile-action-modeswitch.c \
	extras/mobile-action-modeswitch/utils.c \
	extras/mobile-action-modeswitch/utils.h \
	extras/mobile-action-modeswitch/ma8280p_us.c \
	extras/mobile-action-modeswitch/ma8280p_us.h
extras_mobile_action_modeswitch_mobile_action_modeswitch_CPPFLAGS = $(AM_CPPFLAGS) $(LIBUSB_CFLAGS)
extras_mobile_action_modeswitch_mobile_action_modeswitch_LDADD = libudev/libudev-private.la $(LIBUSB_LIBS)

dist_udevrules_DATA += \
	extras/mobile-action-modeswitch/61-mobile-action.rules

libexec_PROGRAMS += extras/mobile-action-modeswitch/mobile-action-modeswitch

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
	extras/keymap/keymaps/acer-aspire_5920g \
	extras/keymap/keymaps/acer-aspire_6920 \
	extras/keymap/keymaps/acer-travelmate_c300 \
	extras/keymap/keymaps/asus \
	extras/keymap/keymaps/compaq-e_evo \
	extras/keymap/keymaps/dell \
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

endif # ENABLE_EXTRAS

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
	cat .git/refs/heads/master > .git/refs/tags/$(VERSION)
	git gc
	git prune

doc-sync:
	rsync -av --delete libudev/docs/html/ master.kernel.org:/pub/linux/utils/kernel/hotplug/libudev/
	rsync -av --delete extras/gudev/docs/html/ master.kernel.org:/pub/linux/utils/kernel/hotplug/gudev/
