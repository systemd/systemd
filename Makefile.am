include $(top_srcdir)/Makefile.am.inc

SUBDIRS = . libudev/docs

udevconfdir = $(sysconfdir)/udev
dist_udevconf_DATA = \
	udev.conf

EXTRA_DIST = \
	autogen.sh \
	libudev/exported_symbols

CLEANFILES = \
	udev-$(VERSION).tar.gz udev-$(VERSION).tar.bz2

BUILT_SOURCES =

ACLOCAL_AMFLAGS = -I m4

AM_MAKEFLAGS = --no-print-directory

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
	--enable-extras

clean-local:
	rm -rf udev-test-install

distclean-local:
	rm -rf autom4te.cache

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

INSTALL_EXEC_HOOKS = libudev-install-move-hook
UNINSTALL_EXEC_HOOKS = libudev-uninstall-move-hook

include_HEADERS = libudev/libudev.h

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------
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

LIBUDEV_CURRENT=5
LIBUDEV_REVISION=0
LIBUDEV_AGE=5
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

libudev_libudev_private_la_LIBADD =

# ------------------------------------------------------------------------------
# Programs
# ------------------------------------------------------------------------------

sbin_PROGRAMS = \
	udev/udevd \
	udev/udevadm

udev_common_sources =\
	udev/udev.h \
	udev/udev-event.c \
	udev/udev-watch.c \
	udev/udev-node.c \
	udev/udev-rules.c
udev_common_libs = libudev/libudev-private.la

udev_udevd_SOURCES = \
	$(udev_common_sources) \
	udev/udevd.c

udev_udevd_LDADD = $(udev_common_libs)

udev_udevadm_SOURCES = \
	$(udev_common_sources) \
	udev/udevadm.c \
	udev/udevadm-info.c \
	udev/udevadm-control.c \
	udev/udevadm-test.c \
	udev/udevadm-monitor.c \
	udev/udevadm-settle.c \
	udev/udevadm-trigger.c

udev_udevadm_LDADD = $(udev_common_libs)

libexec_PROGRAMS = \
	extras/ata_id/ata_id \
	extras/cdrom_id/cdrom_id \
	extras/collect/collect \
	extras/edd_id/edd_id \
	extras/floppy/create_floppy_devices \
	extras/path_id/path_id \
	extras/fstab_import/fstab_import \
	extras/scsi_id/scsi_id \
	extras/usb_id/usb_id \
	extras/v4l_id/v4l_id

dist_libexec_SCRIPTS = \
	extras/firmware/firmware.sh \
	extras/rule_generator/write_cd_rules \
	extras/rule_generator/write_net_rules

udevhomedir = $(libexecdir)
dist_udevhome_DATA = \
	extras/rule_generator/rule_generator.functions

extras_ata_id_ata_id_SOURCES = extras/ata_id/ata_id.c
extras_ata_id_ata_id_LDADD = libudev/libudev-private.la

extras_cdrom_id_cdrom_id_SOURCES = extras/cdrom_id/cdrom_id.c
extras_cdrom_id_cdrom_id_LDADD = libudev/libudev-private.la

extras_collect_collect_SOURCES = extras/collect/collect.c
extras_collect_collect_LDADD = libudev/libudev-private.la

extras_edd_id_edd_id_SOURCES = extras/edd_id/edd_id.c
extras_edd_id_edd_id_LDADD = libudev/libudev-private.la

extras_floppy_create_floppy_devices_SOURCES = extras/floppy/create_floppy_devices.c
extras_floppy_create_floppy_devices_LDADD = libudev/libudev-private.la

extras_path_id_path_id_SOURCES = extras/path_id/path_id.c
extras_path_id_path_id_LDADD = libudev/libudev-private.la

extras_fstab_import_fstab_import_SOURCES = extras/fstab_import/fstab_import.c
extras_fstab_import_fstab_import_LDADD = libudev/libudev-private.la

extras_scsi_id_scsi_id_SOURCES =\
	extras/scsi_id/scsi_id.c \
	extras/scsi_id/scsi_serial.c \
	extras/scsi_id/scsi.h \
	extras/scsi_id/scsi_id.h \
	extras/scsi_id/bsg.h
extras_scsi_id_scsi_id_LDADD = libudev/libudev-private.la

extras_usb_id_usb_id_SOURCES = extras/usb_id/usb_id.c
extras_usb_id_usb_id_LDADD = libudev/libudev-private.la

extras_v4l_id_v4l_id_SOURCES = extras/v4l_id/v4l_id.c
extras_v4l_id_v4l_id_LDADD = libudev/libudev-private.la

extras_hid2hci_hid2hci_SOURCES = extras/hid2hci/hid2hci.c
extras_hid2hci_hid2hci_CPPFLAGS = $(AM_CPPFLAGS) $(LIBUSB_CFLAGS)
extras_hid2hci_hid2hci_LDADD = libudev/libudev-private.la $(LIBUSB_LIBS)

extras_udev_acl_udev_acl_SOURCES = extras/udev-acl/udev-acl.c
extras_udev_acl_udev_acl_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)
extras_udev_acl_udev_acl_LDADD = libudev/libudev-private.la -lacl $(GLIB_LIBS)

extras_usb_db_usb_db_SOURCES = extras/usb-db/usb-db.c
extras_usb_db_usb_db_CPPFLAGS = $(AM_CPPFLAGS) -DUSB_DATABASE=\"$(USB_DATABASE)\" -DBUILD_FOR_USB
extras_usb_db_usb_db_LDADD = libudev/libudev-private.la

extras_usb_db_pci_db_SOURCES = extras/usb-db/usb-db.c
extras_usb_db_pci_db_CPPFLAGS = $(AM_CPPFLAGS) -DPCI_DATABASE=\"$(USB_DATABASE)\" -DBUILD_FOR_PCI
extras_usb_db_pci_db_LDADD = libudev/libudev-private.la

extras_modem_modeswitch_modem_modeswitch_SOURCES =\
	extras/modem-modeswitch/modem-modeswitch.c \
	extras/modem-modeswitch/utils.c \
	extras/modem-modeswitch/utils.h \
	extras/modem-modeswitch/ma8280p_us.c \
	extras/modem-modeswitch/ma8280p_us.h \
	extras/modem-modeswitch/option.c \
	extras/modem-modeswitch/option.h
extras_modem_modeswitch_modem_modeswitch_CPPFLAGS = $(AM_CPPFLAGS) $(LIBUSB_CFLAGS)
extras_modem_modeswitch_modem_modeswitch_LDADD = libudev/libudev-private.la $(LIBUSB_LIBS)

extras_keymap_keymap_SOURCES = extras/keymap/keymap.c
nodist_extras_keymap_keymap_SOURCES = \
	extras/keymap/keys-from-name.h \
	extras/keymap/keys-to-name.h

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

TESTS = test/udev-test.pl

check_PROGRAMS = \
	libudev/test-libudev \
	udev/test-udev

libudev_test_libudev_SOURCES = libudev/test-libudev.c
libudev_test_libudev_LDADD = libudev/libudev.la

udev_test_udev_SOURCES = \
	$(udev_common_sources) \
	udev/test-udev.c
udev_test_udev_LDADD = $(udev_common_libs)

# ------------------------------------------------------------------------------
# Basic rules
# ------------------------------------------------------------------------------

dist_udevrules_DATA = \
	rules/rules.d/50-udev-default.rules \
	rules/rules.d/60-persistent-storage.rules \
	rules/rules.d/60-persistent-storage-tape.rules \
	rules/rules.d/60-persistent-serial.rules \
	rules/rules.d/60-persistent-input.rules \
	rules/rules.d/60-persistent-alsa.rules \
	rules/rules.d/80-drivers.rules \
	rules/rules.d/95-udev-late.rules \
	extras/rule_generator/75-cd-aliases-generator.rules \
	extras/rule_generator/75-persistent-net-generator.rules \
	extras/cdrom_id/60-cdrom_id.rules \
	extras/edd_id/61-persistent-storage-edd.rules \
	extras/firmware/50-firmware.rules \
	extras/fstab_import/79-fstab_import.rules \
	extras/v4l_id/60-persistent-v4l.rules

EXTRA_DIST += \
	rules/packages \
	rules/redhat \
	rules/suse \
	rules/gentoo

# ------------------------------------------------------------------------------
# Conditionals (SElinux, etc…)
# ------------------------------------------------------------------------------
if WITH_SELINUX
libudev_libudev_private_la_SOURCES += \
	libudev/libudev-selinux-private.c
libudev_libudev_private_la_LIBADD += \
	$(SELINUX_LIBS)
endif

if ENABLE_EXTRAS
INSTALL_EXEC_HOOKS += udevacl-install-hook

dist_udevrules_DATA += \
	rules/rules.d/75-net-description.rules \
	rules/rules.d/75-tty-description.rules \
	rules/rules.d/78-sound-card.rules \
	extras/hid2hci/70-hid2hci.rules \
	extras/modem-modeswitch/61-option-modem-modeswitch.rules \
	extras/modem-modeswitch/61-mobile-action.rules \
	extras/keymap/95-keymap.rules

libexec_PROGRAMS += \
	extras/hid2hci/hid2hci \
	extras/udev-acl/udev-acl \
	extras/usb-db/usb-db \
	extras/usb-db/pci-db \
	extras/modem-modeswitch/modem-modeswitch \
	extras/keymap/keymap

dist_libexec_SCRIPTS += \
	extras/keymap/findkeyboards

BUILT_SOURCES += \
	extras/keymap/keys-from-name.h \
	extras/keymap/keys-to-name.h

TESTS += extras/keymap/check-keymaps.sh

check_DATA = extras/keymap/keys.txt

CLEANFILES += \
	extras/keymap/keys.txt \
	extras/keymap/keys-from-name.gperf \
	extras/keymap/keys-from-name.h \
	extras/keymap/keys-to-name.h

dist_doc_DATA = extras/keymap/README.keymap.txt

udevkeymapdir = $(libexecdir)/keymaps
dist_udevkeymap_DATA = \
	extras/keymap/keymaps/acer \
	extras/keymap/keymaps/acer-aspire_5920g \
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
	extras/keymap/keymaps/inventec-symphony_6.0_7.0 \
	extras/keymap/keymaps/lenovo-3000 \
	extras/keymap/keymaps/lenovo-thinkpad_x6_tablet \
	extras/keymap/keymaps/lenovo-thinkpad_x200_tablet \
	extras/keymap/keymaps/maxdata-pro_7000 \
	extras/keymap/keymaps/medion-fid2060 \
	extras/keymap/keymaps/medionnb-a555 \
	extras/keymap/keymaps/micro-star \
	extras/keymap/keymaps/module-asus-w3j \
	extras/keymap/keymaps/module-ibm \
	extras/keymap/keymaps/module-lenovo \
	extras/keymap/keymaps/module-sony \
	extras/keymap/keymaps/module-sony-old \
	extras/keymap/keymaps/oqo-model2 \
	extras/keymap/keymaps/samsung-other \
	extras/keymap/keymaps/samsung-sq1us \
	extras/keymap/keymaps/samsung-sx20s \
	extras/keymap/keymaps/toshiba-satellite_a100 \
	extras/keymap/keymaps/toshiba-satellite_a110 \
	extras/keymap/keymaps/zepto-znote

SUBDIRS += \
	extras/gudev
endif

# ------------------------------------------------------------------------------
# Pkg-config, docs and man pages
# ------------------------------------------------------------------------------
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libudev/libudev.pc \
	udev/udev.pc

writing_udev_rulesdir = $(docdir)/writing_udev_rules
dist_writing_udev_rules_DATA = \
	docs/writing_udev_rules/index.html

dist_man_MANS = \
	udev/udev.7 \
	udev/udevadm.8 \
	udev/udevd.8 \
	extras/scsi_id/scsi_id.8

EXTRA_DIST += \
	udev/udev.xml \
	udev/udevadm.xml \
	udev/udevd.xml

%.7 %.8 : %.xml
	$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

# ------------------------------------------------------------------------------
# Install and uninstall hooks
# ------------------------------------------------------------------------------
install-exec-hook: $(INSTALL_EXEC_HOOKS)

uninstall-hook: $(UNINSTALL_EXEC_HOOKS)

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

udevacl-install-hook:
	mkdir -p $(DESTDIR)$(prefix)/lib/ConsoleKit/run-session.d
	ln -sf $(libexecdir)/udev-acl $(DESTDIR)$(prefix)/lib/ConsoleKit/run-session.d/udev-acl.ck

# ------------------------------------------------------------------------------
# Custom rules
# ------------------------------------------------------------------------------

extras/keymap/keys.txt: /usr/include/linux/input.h
	$(AWK) '/^#define.*KEY_/ { if ($$2 != "KEY_MAX" && $$2 != "KEY_CNT") { print $$2 } }' < $< > $@

extras/keymap/keys-from-name.gperf: extras/keymap/keys.txt
	$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

extras/keymap/keys-from-name.h: extras/keymap/keys-from-name.gperf Makefile
	$(GPERF) -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

extras/keymap/keys-to-name.h: extras/keymap/keys.txt Makefile
	$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@
