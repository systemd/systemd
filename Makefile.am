#  -*- Mode: makefile; indent-tabs-mode: t -*-
#
#  This file is part of systemd.
#
#  Copyright 2010-2012 Lennart Poettering
#  Copyright 2010-2012 Kay Sievers
#  Copyright 2013 Zbigniew Jędrzejewski-Szmek
#  Copyright 2013 David Strauss
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

SUBDIRS = . po

# remove targets if the command fails
.DELETE_ON_ERROR:

# keep intermediate files
.SECONDARY:

# Keep the test-suite.log
.PRECIOUS: $(TEST_SUITE_LOG) Makefile

LIBUDEV_CURRENT=6
LIBUDEV_REVISION=0
LIBUDEV_AGE=5

LIBGUDEV_CURRENT=2
LIBGUDEV_REVISION=0
LIBGUDEV_AGE=2

LIBSYSTEMD_CURRENT=3
LIBSYSTEMD_REVISION=1
LIBSYSTEMD_AGE=3

# The following four libraries only exist for compatibility reasons,
# their version info should not be bumped anymore
LIBSYSTEMD_LOGIN_CURRENT=9
LIBSYSTEMD_LOGIN_REVISION=3
LIBSYSTEMD_LOGIN_AGE=9

LIBSYSTEMD_DAEMON_CURRENT=0
LIBSYSTEMD_DAEMON_REVISION=12
LIBSYSTEMD_DAEMON_AGE=0

LIBSYSTEMD_ID128_CURRENT=0
LIBSYSTEMD_ID128_REVISION=28
LIBSYSTEMD_ID128_AGE=0

LIBSYSTEMD_JOURNAL_CURRENT=11
LIBSYSTEMD_JOURNAL_REVISION=5
LIBSYSTEMD_JOURNAL_AGE=11

# Dirs of external packages
dbuspolicydir=@dbuspolicydir@
dbussessionservicedir=@dbussessionservicedir@
dbussystemservicedir=@dbussystemservicedir@
pamlibdir=@pamlibdir@
pamconfdir=@pamconfdir@
pkgconfigdatadir=$(datadir)/pkgconfig
pkgconfiglibdir=$(libdir)/pkgconfig
polkitpolicydir=$(datadir)/polkit-1/actions
bashcompletiondir=@bashcompletiondir@
zshcompletiondir=@zshcompletiondir@
rpmmacrosdir=$(prefix)/lib/rpm/macros.d
sysvinitdir=$(SYSTEM_SYSVINIT_PATH)
sysvrcnddir=$(SYSTEM_SYSVRCND_PATH)
varlogdir=$(localstatedir)/log
systemdstatedir=$(localstatedir)/lib/systemd
catalogstatedir=$(systemdstatedir)/catalog

# Our own, non-special dirs
pkgsysconfdir=$(sysconfdir)/systemd
userunitdir=$(prefix)/lib/systemd/user
userpresetdir=$(prefix)/lib/systemd/user-preset
tmpfilesdir=$(prefix)/lib/tmpfiles.d
sysusersdir=$(prefix)/lib/sysusers.d
sysctldir=$(prefix)/lib/sysctl.d
binfmtdir=$(prefix)/lib/binfmt.d
modulesloaddir=$(prefix)/lib/modules-load.d
networkdir=$(rootprefix)/lib/systemd/network
pkgincludedir=$(includedir)/systemd
systemgeneratordir=$(rootlibexecdir)/system-generators
usergeneratordir=$(prefix)/lib/systemd/user-generators
systemshutdowndir=$(rootlibexecdir)/system-shutdown
systemsleepdir=$(rootlibexecdir)/system-sleep
systemunitdir=$(rootprefix)/lib/systemd/system
systempresetdir=$(rootprefix)/lib/systemd/system-preset
udevlibexecdir=$(rootprefix)/lib/udev
udevhomedir=$(udevlibexecdir)
udevrulesdir=$(udevlibexecdir)/rules.d
udevhwdbdir=$(udevlibexecdir)/hwdb.d
catalogdir=$(prefix)/lib/systemd/catalog
kernelinstalldir = $(prefix)/lib/kernel/install.d
ntpunitsdir=$(prefix)/lib/systemd/ntp-units.d

# And these are the special ones for /
rootprefix=@rootprefix@
rootbindir=$(rootprefix)/bin
rootlibexecdir=$(rootprefix)/lib/systemd

CLEANFILES = $(BUILT_SOURCES)
DISTCLEANFILES =
EXTRA_DIST =
BUILT_SOURCES =
INSTALL_EXEC_HOOKS =
UNINSTALL_EXEC_HOOKS =
INSTALL_DATA_HOOKS =
UNINSTALL_DATA_HOOKS =
DISTCLEAN_LOCAL_HOOKS =
CLEAN_LOCAL_HOOKS =
pkginclude_HEADERS =
noinst_LTLIBRARIES =
lib_LTLIBRARIES =
include_HEADERS =
noinst_DATA =
pkgconfiglib_DATA =
polkitpolicy_in_in_files =
polkitpolicy_in_files =
polkitpolicy_files =
dist_udevrules_DATA =
nodist_udevrules_DATA =
nodist_pkgsysconf_DATA =
dist_pkgsysconf_DATA =
dist_pkgdata_DATA =
dist_dbuspolicy_DATA =
dist_dbussystemservice_DATA =
check_PROGRAMS =
check_DATA =
tests=
manual_tests =
if ENABLE_TESTS
noinst_PROGRAMS = $(manual_tests) $(tests)
TESTS = $(tests)
else
noinst_PROGRAMS =
TESTS =
endif
udevlibexec_PROGRAMS =

.PHONY: $(INSTALL_EXEC_HOOKS) $(UNINSTALL_EXEC_HOOKS) \
	$(INSTALL_DATA_HOOKS) $(UNINSTALL_DATA_HOOKS) \
	$(DISTCLEAN_LOCAL_HOOKS) $(CLEAN_LOCAL_HOOKS)

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DPKGSYSCONFDIR=\"$(pkgsysconfdir)\" \
	-DSYSTEM_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/system\" \
	-DSYSTEM_DATA_UNIT_PATH=\"$(systemunitdir)\" \
	-DSYSTEM_SYSVINIT_PATH=\"$(SYSTEM_SYSVINIT_PATH)\" \
	-DSYSTEM_SYSVRCND_PATH=\"$(SYSTEM_SYSVRCND_PATH)\" \
	-DUSER_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/user\" \
	-DUSER_DATA_UNIT_PATH=\"$(userunitdir)\" \
	-DCATALOG_DATABASE=\"$(catalogstatedir)/database\" \
	-DSYSTEMD_CGROUP_AGENT_PATH=\"$(rootlibexecdir)/systemd-cgroups-agent\" \
	-DSYSTEMD_BINARY_PATH=\"$(rootlibexecdir)/systemd\" \
	-DSYSTEMD_SHUTDOWN_BINARY_PATH=\"$(rootlibexecdir)/systemd-shutdown\" \
	-DSYSTEMD_SLEEP_BINARY_PATH=\"$(rootlibexecdir)/systemd-sleep\" \
	-DSYSTEMCTL_BINARY_PATH=\"$(rootbindir)/systemctl\" \
	-DSYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH=\"$(rootbindir)/systemd-tty-ask-password-agent\" \
	-DSYSTEMD_STDIO_BRIDGE_BINARY_PATH=\"$(bindir)/systemd-stdio-bridge\" \
	-DROOTPREFIX=\"$(rootprefix)\" \
	-DRANDOM_SEED_DIR=\"$(localstatedir)/lib/systemd/\" \
	-DRANDOM_SEED=\"$(localstatedir)/lib/systemd/random-seed\" \
	-DSYSTEMD_CRYPTSETUP_PATH=\"$(rootlibexecdir)/systemd-cryptsetup\" \
	-DSYSTEM_GENERATOR_PATH=\"$(systemgeneratordir)\" \
	-DUSER_GENERATOR_PATH=\"$(usergeneratordir)\" \
	-DSYSTEM_SHUTDOWN_PATH=\"$(systemshutdowndir)\" \
	-DSYSTEM_SLEEP_PATH=\"$(systemsleepdir)\" \
	-DSYSTEMD_KBD_MODEL_MAP=\"$(pkgdatadir)/kbd-model-map\" \
	-DX_SERVER=\"$(bindir)/X\" \
	-DUDEVLIBEXECDIR=\"$(udevlibexecdir)\" \
	-DPOLKIT_AGENT_BINARY_PATH=\"$(bindir)/pkttyagent\" \
	-DQUOTACHECK=\"$(QUOTACHECK)\" \
	-DKEXEC=\"$(KEXEC)\" \
	-DLIBDIR=\"$(libdir)\" \
	-DROOTLIBDIR=\"$(rootlibdir)\" \
	-I $(top_srcdir)/src \
	-I $(top_builddir)/src/shared \
	-I $(top_srcdir)/src/shared \
	-I $(top_srcdir)/src/network \
	-I $(top_srcdir)/src/login \
	-I $(top_srcdir)/src/journal \
	-I $(top_srcdir)/src/timedate \
	-I $(top_srcdir)/src/timesync \
	-I $(top_srcdir)/src/resolve \
	-I $(top_srcdir)/src/systemd \
	-I $(top_builddir)/src/core \
	-I $(top_srcdir)/src/core \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev \
	-I $(top_srcdir)/src/udev/net \
	-I $(top_builddir)/src/udev \
	-I $(top_srcdir)/src/libsystemd/sd-bus \
	-I $(top_srcdir)/src/libsystemd/sd-event \
	-I $(top_srcdir)/src/libsystemd/sd-rtnl \
	-I $(top_srcdir)/src/libsystemd-network \
	$(OUR_CPPFLAGS)

AM_CFLAGS = $(OUR_CFLAGS)
AM_LDFLAGS = $(OUR_LDFLAGS)

# ------------------------------------------------------------------------------
define move-to-rootlibdir
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/$$libname) && \
		rm -f $(DESTDIR)$(libdir)/$$libname && \
		$(LN_S) --relative -f $(DESTDIR)$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/$$libname && \
		mv $(DESTDIR)$(libdir)/$$libname.* $(DESTDIR)$(rootlibdir); \
	fi
endef

INSTALL_DIRS =

RUNLEVEL1_TARGET_WANTS =
RUNLEVEL2_TARGET_WANTS =
RUNLEVEL3_TARGET_WANTS =
RUNLEVEL4_TARGET_WANTS =
RUNLEVEL5_TARGET_WANTS =
SHUTDOWN_TARGET_WANTS =
LOCAL_FS_TARGET_WANTS =
MULTI_USER_TARGET_WANTS =
SYSINIT_TARGET_WANTS =
SOCKETS_TARGET_WANTS =
BUSNAMES_TARGET_WANTS =
TIMERS_TARGET_WANTS =
USER_SOCKETS_TARGET_WANTS =
USER_BUSNAMES_TARGET_WANTS =

SYSTEM_UNIT_ALIASES =
USER_UNIT_ALIASES =
GENERAL_ALIASES =

install-target-wants-hook:
	what="$(RUNLEVEL1_TARGET_WANTS)" && wants=runlevel1.target && dir=$(systemunitdir) && $(add-wants)
	what="$(RUNLEVEL2_TARGET_WANTS)" && wants=runlevel2.target && dir=$(systemunitdir) && $(add-wants)
	what="$(RUNLEVEL3_TARGET_WANTS)" && wants=runlevel3.target && dir=$(systemunitdir) && $(add-wants)
	what="$(RUNLEVEL4_TARGET_WANTS)" && wants=runlevel4.target && dir=$(systemunitdir) && $(add-wants)
	what="$(RUNLEVEL5_TARGET_WANTS)" && wants=runlevel5.target && dir=$(systemunitdir) && $(add-wants)
	what="$(SHUTDOWN_TARGET_WANTS)" && wants=shutdown.target && dir=$(systemunitdir) && $(add-wants)
	what="$(LOCAL_FS_TARGET_WANTS)" && wants=local-fs.target && dir=$(systemunitdir) && $(add-wants)
	what="$(MULTI_USER_TARGET_WANTS)" && wants=multi-user.target && dir=$(systemunitdir) && $(add-wants)
	what="$(SYSINIT_TARGET_WANTS)" && wants=sysinit.target && dir=$(systemunitdir) && $(add-wants)
	what="$(SOCKETS_TARGET_WANTS)" && wants=sockets.target && dir=$(systemunitdir) && $(add-wants)
	what="$(BUSNAMES_TARGET_WANTS)" && wants=busnames.target && dir=$(systemunitdir) && $(add-wants)
	what="$(TIMERS_TARGET_WANTS)" && wants=timers.target && dir=$(systemunitdir) && $(add-wants)
	what="$(SLICES_TARGET_WANTS)" && wants=slices.target && dir=$(systemunitdir) && $(add-wants)
	what="$(USER_SOCKETS_TARGET_WANTS)" && wants=sockets.target && dir=$(userunitdir) && $(add-wants)
	what="$(USER_BUSNAMES_TARGET_WANTS)" && wants=busnames.target && dir=$(userunitdir) && $(add-wants)

define add-wants
	[ -z "$$what" ] || ( \
	  dir=$(DESTDIR)$$dir/$$wants.wants && \
	  $(MKDIR_P) -m 0755 $$dir && \
	  cd $$dir && \
	  rm -f $$what && \
	  for i in $$what; do $(LN_S) ../$$i . || exit $$? ; done )
endef

install-directories-hook:
	$(MKDIR_P) $(addprefix $(DESTDIR),$(INSTALL_DIRS))

install-aliases-hook:
	set -- $(SYSTEM_UNIT_ALIASES) && \
		dir=$(systemunitdir) && $(install-aliases)
	set -- $(USER_UNIT_ALIASES) && \
		dir=$(userunitdir) && $(install-relative-aliases)
	set -- $(GENERAL_ALIASES) && \
		dir= && $(install-relative-aliases)

define install-aliases
	while [ -n "$$1" ]; do \
		$(MKDIR_P) `dirname $(DESTDIR)$$dir/$$2` && \
		rm -f $(DESTDIR)$$dir/$$2 && \
		$(LN_S) $$1 $(DESTDIR)$$dir/$$2 && \
		shift 2 || exit $$?; \
	done
endef

define install-relative-aliases
	while [ -n "$$1" ]; do \
		$(MKDIR_P) `dirname $(DESTDIR)$$dir/$$2` && \
		rm -f $(DESTDIR)$$dir/$$2 && \
		$(LN_S) --relative $(DESTDIR)$$1 $(DESTDIR)$$dir/$$2 && \
		shift 2 || exit $$?; \
	done
endef

install-touch-usr-hook:
	touch -c $(DESTDIR)/$(prefix)

INSTALL_EXEC_HOOKS += \
	install-target-wants-hook \
	install-directories-hook \
	install-aliases-hook \
	install-touch-usr-hook

# ------------------------------------------------------------------------------
AM_V_M4 = $(AM_V_M4_$(V))
AM_V_M4_ = $(AM_V_M4_$(AM_DEFAULT_VERBOSITY))
AM_V_M4_0 = @echo "  M4      " $@;

AM_V_XSLT = $(AM_V_XSLT_$(V))
AM_V_XSLT_ = $(AM_V_XSLT_$(AM_DEFAULT_VERBOSITY))
AM_V_XSLT_0 = @echo "  XSLT    " $@;

AM_V_GPERF = $(AM_V_GPERF_$(V))
AM_V_GPERF_ = $(AM_V_GPERF_$(AM_DEFAULT_VERBOSITY))
AM_V_GPERF_0 = @echo "  GPERF   " $@;

AM_V_LN = $(AM_V_LN_$(V))
AM_V_LN_ = $(AM_V_LN_$(AM_DEFAULT_VERBOSITY))
AM_V_LN_0 = @echo "  LN      " $@;

AM_V_RM = $(AM_V_RM_$(V))
AM_V_RM_ = $(AM_V_RM_$(AM_DEFAULT_VERBOSITY))
AM_V_RM_0 = @echo "  RM      " $@;

# ------------------------------------------------------------------------------
rootbin_PROGRAMS = \
	systemctl \
	systemd-notify \
	systemd-ask-password \
	systemd-tty-ask-password-agent \
	systemd-machine-id-setup

bin_PROGRAMS = \
	systemd-cgls \
	systemd-cgtop \
	systemd-nspawn \
	systemd-detect-virt \
	systemd-delta \
	systemd-analyze \
	systemd-run \
	systemd-path

dist_bin_SCRIPTS = \
	src/kernel-install/kernel-install

dist_kernelinstall_SCRIPTS = \
	src/kernel-install/50-depmod.install \
	src/kernel-install/90-loaderentry.install

rootlibexec_PROGRAMS = \
	systemd \
	systemd-cgroups-agent \
	systemd-initctl \
	systemd-update-utmp \
	systemd-shutdownd \
	systemd-shutdown \
	systemd-remount-fs \
	systemd-reply-password \
	systemd-fsck \
	systemd-ac-power \
	systemd-sysctl \
	systemd-sleep \
	systemd-bus-proxyd \
	systemd-socket-proxyd \
	systemd-update-done

systemgenerator_PROGRAMS = \
	systemd-getty-generator \
	systemd-fstab-generator \
	systemd-system-update-generator \
	systemd-debug-generator

dist_bashcompletion_DATA = \
	shell-completion/bash/busctl \
	shell-completion/bash/journalctl \
	shell-completion/bash/systemctl \
	shell-completion/bash/systemd-analyze \
	shell-completion/bash/systemd-cat \
	shell-completion/bash/systemd-cgls \
	shell-completion/bash/systemd-cgtop \
	shell-completion/bash/systemd-delta \
	shell-completion/bash/systemd-detect-virt \
	shell-completion/bash/systemd-nspawn \
	shell-completion/bash/systemd-run \
	shell-completion/bash/udevadm \
	shell-completion/bash/kernel-install

dist_zshcompletion_DATA = \
	shell-completion/zsh/_systemctl \
	shell-completion/zsh/_journalctl \
	shell-completion/zsh/_udevadm \
	shell-completion/zsh/_kernel-install \
	shell-completion/zsh/_systemd-nspawn \
	shell-completion/zsh/_systemd-analyze \
	shell-completion/zsh/_systemd-run \
	shell-completion/zsh/_sd_hosts_or_user_at_host \
	shell-completion/zsh/_systemd-delta \
	shell-completion/zsh/_systemd

dist_sysctl_DATA = \
	sysctl.d/50-default.conf

dist_systemunit_DATA = \
	units/graphical.target \
	units/multi-user.target \
	units/emergency.service \
	units/emergency.target \
	units/sysinit.target \
	units/basic.target \
	units/getty.target \
	units/halt.target \
	units/kexec.target \
	units/local-fs.target \
	units/local-fs-pre.target \
	units/initrd.target \
	units/initrd-fs.target \
	units/initrd-root-fs.target \
	units/remote-fs.target \
	units/remote-fs-pre.target \
	units/network.target \
	units/network-pre.target \
	units/network-online.target \
	units/nss-lookup.target \
	units/nss-user-lookup.target \
	units/hibernate.target \
	units/hybrid-sleep.target \
	units/poweroff.target \
	units/reboot.target \
	units/rescue.target \
	units/rpcbind.target \
	units/time-sync.target \
	units/shutdown.target \
	units/final.target \
	units/umount.target \
	units/sigpwr.target \
	units/sleep.target \
	units/sockets.target \
	units/busnames.target \
	units/timers.target \
	units/paths.target \
	units/suspend.target \
	units/swap.target \
	units/slices.target \
	units/system.slice \
	units/x-.slice \
	units/systemd-initctl.socket \
	units/systemd-shutdownd.socket \
	units/syslog.socket \
	units/dev-hugepages.mount \
	units/dev-mqueue.mount \
	units/sys-kernel-config.mount \
	units/sys-kernel-debug.mount \
	units/sys-fs-fuse-connections.mount \
	units/tmp.mount \
	units/printer.target \
	units/sound.target \
	units/bluetooth.target \
	units/smartcard.target \
	units/systemd-ask-password-wall.path \
	units/systemd-ask-password-console.path \
	units/systemd-udevd-control.socket \
	units/systemd-udevd-kernel.socket \
	units/system-update.target \
	units/initrd-switch-root.target \
	units/ldconfig.service

nodist_systemunit_DATA = \
	units/getty@.service \
	units/serial-getty@.service \
	units/console-shell.service \
	units/console-getty.service \
	units/container-getty@.service \
	units/systemd-initctl.service \
	units/systemd-shutdownd.service \
	units/systemd-remount-fs.service \
	units/systemd-update-utmp.service \
	units/systemd-update-utmp-runlevel.service \
	units/systemd-ask-password-wall.service \
	units/systemd-ask-password-console.service \
	units/systemd-sysctl.service \
	units/emergency.service \
	units/rescue.service \
	units/user@.service \
	units/systemd-hibernate.service \
	units/systemd-hybrid-sleep.service \
	units/systemd-suspend.service \
	units/systemd-halt.service \
	units/systemd-poweroff.service \
	units/systemd-reboot.service \
	units/systemd-kexec.service \
	units/systemd-fsck@.service \
	units/systemd-fsck-root.service \
	units/systemd-udevd.service \
	units/systemd-udev-trigger.service \
	units/systemd-udev-settle.service \
	units/systemd-udev-hwdb-update.service \
	units/debug-shell.service \
	units/initrd-parse-etc.service \
	units/initrd-cleanup.service \
	units/initrd-udevadm-cleanup-db.service \
	units/initrd-switch-root.service \
	units/systemd-nspawn@.service \
	units/systemd-update-done.service

dist_userunit_DATA = \
	units/user/basic.target \
	units/user/default.target \
	units/user/exit.target

nodist_userunit_DATA = \
	units/user/systemd-exit.service

dist_systempreset_DATA = \
	system-preset/90-systemd.preset

EXTRA_DIST += \
	units/getty@.service.m4 \
	units/serial-getty@.service.m4 \
	units/console-shell.service.m4.in \
	units/console-getty.service.m4.in \
	units/container-getty@.service.m4.in \
	units/rescue.service.m4.in \
	units/systemd-initctl.service.in \
	units/systemd-shutdownd.service.in \
	units/systemd-remount-fs.service.in \
	units/systemd-update-utmp.service.in \
	units/systemd-update-utmp-runlevel.service.in \
	units/systemd-ask-password-wall.service.in \
	units/systemd-ask-password-console.service.in \
	units/systemd-sysctl.service.in \
	units/emergency.service.in \
	units/systemd-halt.service.in \
	units/systemd-poweroff.service.in \
	units/systemd-reboot.service.in \
	units/systemd-kexec.service.in \
	units/user/systemd-exit.service.in \
	units/systemd-fsck@.service.in \
	units/systemd-fsck-root.service.in \
	units/user@.service.in \
	units/debug-shell.service.in \
	units/systemd-hibernate.service.in \
	units/systemd-hybrid-sleep.service.in \
	units/systemd-suspend.service.in \
	units/quotaon.service.in \
	units/initrd-parse-etc.service.in \
	units/initrd-cleanup.service.in \
	units/initrd-udevadm-cleanup-db.service.in \
	units/initrd-switch-root.service.in \
	units/systemd-nspawn@.service.in \
	units/systemd-update-done.service.in

CLEANFILES += \
	units/console-shell.service.m4 \
	units/console-getty.service.m4 \
	units/container-getty@.service.m4 \
	units/rescue.service.m4 \
	units/user@.service.m4

if HAVE_SYSV_COMPAT
nodist_systemunit_DATA += \
	units/rc-local.service \
	units/halt-local.service

systemgenerator_PROGRAMS += \
	systemd-sysv-generator \
	systemd-rc-local-generator
endif

EXTRA_DIST += \
	units/rc-local.service.in \
	units/halt-local.service.in

# automake is broken and can't handle files with a dash in front
# http://debbugs.gnu.org/cgi/bugreport.cgi?bug=14728#8
units-install-hook:
	mv $(DESTDIR)$(systemunitdir)/x-.slice $(DESTDIR)/$(systemunitdir)/-.slice

units-uninstall-hook:
	rm -f $(DESTDIR)/$(systemunitdir)/-.slice

INSTALL_DATA_HOOKS += units-install-hook
UNINSTALL_DATA_HOOKS += units-uninstall-hook

dist_doc_DATA = \
	README \
	NEWS \
	LICENSE.LGPL2.1 \
	LICENSE.GPL2 \
	LICENSE.MIT \
	DISTRO_PORTING \
	src/libsystemd/sd-bus/PORTING-DBUS1 \
	src/libsystemd/sd-bus/DIFFERENCES \
	src/libsystemd/sd-bus/GVARIANT-SERIALIZATION

@INTLTOOL_POLICY_RULE@

# ------------------------------------------------------------------------------

MANPAGES =
MANPAGES_ALIAS =

include Makefile-man.am

.PHONY: man update-man-list
man: $(MANPAGES) $(MANPAGES_ALIAS) $(HTML_FILES) $(HTML_ALIAS)

XML_FILES = \
	${patsubst %.1,%.xml,${patsubst %.3,%.xml,${patsubst %.5,%.xml,${patsubst %.7,%.xml,${patsubst %.8,%.xml,$(MANPAGES)}}}}}
HTML_FILES = \
	${XML_FILES:.xml=.html}
HTML_ALIAS = \
	${patsubst %.1,%.html,${patsubst %.3,%.html,${patsubst %.5,%.html,${patsubst %.7,%.html,${patsubst %.8,%.html,$(MANPAGES_ALIAS)}}}}}

if ENABLE_MANPAGES
man_MANS = \
	$(MANPAGES) \
	$(MANPAGES_ALIAS)

noinst_DATA += \
	$(HTML_FILES) \
	$(HTML_ALIAS)

CLEANFILES += \
	$(man_MANS) \
	$(HTML_FILES) \
	$(HTML_ALIAS)

docs/html/man:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_LN)$(LN_S) -f ../../man $@

noinst_DATA += \
	docs/html/man

CLEANFILES += \
	docs/html/man

if HAVE_PYTHON
man/index.html: man/systemd.index.html
	$(AM_V_LN)$(LN_S) -f systemd.index.html $@

noinst_DATA += \
	man/index.html

CLEANFILES += \
	man/index.html

XML_GLOB = $(wildcard $(top_srcdir)/man/*.xml $(top_builddir)/man/*.xml)
NON_INDEX_XML_FILES = $(filter-out man/systemd.index.xml,$(XML_FILES))
SOURCE_XML_FILES = $(filter-out man/systemd.directives.xml,$(NON_INDEX_XML_FILES))

update-man-list: $(top_srcdir)/tools/make-man-rules.py $(XML_GLOB)
	$(AM_V_GEN)$(PYTHON) $^ > $(top_srcdir)/Makefile-man.tmp
	$(AM_V_at)mv $(top_srcdir)/Makefile-man.tmp $(top_srcdir)/Makefile-man.am
	@echo "Makefile-man.am has been regenerated"

man/systemd.index.xml: $(top_srcdir)/tools/make-man-index.py $(NON_INDEX_XML_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $< $@ $(filter-out $<,$^)

man/systemd.directives.xml: $(top_srcdir)/tools/make-directive-index.py $(SOURCE_XML_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $< $@ $(filter-out $<,$^)

EXTRA_DIST += \
	man/systemd.index.xml \
	man/index.html \
	man/systemd.directives.xml

CLEANFILES += \
	man/systemd.index.xml \
	man/systemd.directives.xml

endif

endif

EXTRA_DIST += \
	$(XML_FILES) \
	$(HTML_FILES) \
	$(HTML_ALIAS) \
	$(man_MANS) \
	tools/make-man-index.py \
	tools/make-directive-index.py \
	tools/make-man-rules.py \
	tools/xml_helper.py

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-shared.la

libsystemd_shared_la_SOURCES = \
	src/shared/linux/auto_dev-ioctl.h \
	src/shared/linux/fanotify.h \
	src/shared/ioprio.h \
	src/shared/missing.h \
	src/shared/initreq.h \
	src/shared/securebits.h \
	src/shared/special.h \
	src/shared/list.h \
	src/shared/macro.h \
	src/shared/def.h \
	src/shared/sparse-endian.h \
	src/shared/refcnt.h \
	src/shared/udev-util.h \
	src/shared/bus-errors.h \
	src/shared/device-nodes.c \
	src/shared/device-nodes.h \
	src/shared/util.c \
	src/shared/util.h \
	src/shared/virt.c \
	src/shared/virt.h \
	src/shared/architecture.c \
	src/shared/architecture.h \
	src/shared/efivars.c \
	src/shared/efivars.h \
	src/shared/path-util.c \
	src/shared/path-util.h \
	src/shared/time-util.c \
	src/shared/time-util.h \
	src/shared/hashmap.c \
	src/shared/hashmap.h \
	src/shared/siphash24.c \
	src/shared/siphash24.h \
	src/shared/set.c \
	src/shared/set.h \
	src/shared/fdset.c \
	src/shared/fdset.h \
	src/shared/prioq.c \
	src/shared/prioq.h \
	src/shared/sleep-config.c \
	src/shared/sleep-config.h \
	src/shared/strv.c \
	src/shared/strv.h \
	src/shared/env-util.c \
	src/shared/env-util.h \
	src/shared/strbuf.c \
	src/shared/strbuf.h \
	src/shared/strxcpyx.c \
	src/shared/strxcpyx.h \
	src/shared/conf-parser.c \
	src/shared/conf-parser.h \
	src/shared/log.c \
	src/shared/log.h \
	src/shared/ratelimit.h \
	src/shared/ratelimit.c \
	src/shared/exit-status.c \
	src/shared/exit-status.h \
	src/shared/utf8.c \
	src/shared/utf8.h \
	src/shared/gunicode.c \
	src/shared/gunicode.h \
	src/shared/pager.c \
	src/shared/pager.h \
	src/shared/socket-util.c \
	src/shared/socket-util.h \
	src/shared/conf-files.c \
	src/shared/conf-files.h \
	src/shared/cgroup-util.c \
	src/shared/cgroup-util.h \
	src/shared/cgroup-show.c \
	src/shared/cgroup-show.h \
	src/shared/unit-name.c \
	src/shared/unit-name.h \
	src/shared/utmp-wtmp.c \
	src/shared/utmp-wtmp.h \
	src/shared/watchdog.c \
	src/shared/watchdog.h \
	src/shared/spawn-ask-password-agent.c \
	src/shared/spawn-ask-password-agent.h \
	src/shared/replace-var.c \
	src/shared/replace-var.h \
	src/shared/spawn-polkit-agent.c \
	src/shared/spawn-polkit-agent.h \
	src/shared/clock-util.c \
	src/shared/clock-util.h \
	src/shared/time-dst.c \
	src/shared/time-dst.h \
	src/shared/calendarspec.c \
	src/shared/calendarspec.h \
	src/shared/fileio.c \
	src/shared/fileio.h \
	src/shared/output-mode.h \
	src/shared/MurmurHash2.c \
	src/shared/MurmurHash2.h \
	src/shared/acpi-fpdt.h \
	src/shared/acpi-fpdt.c \
	src/shared/boot-timestamps.h \
	src/shared/boot-timestamps.c \
	src/shared/mkdir.c \
	src/shared/mkdir.h \
	src/shared/smack-util.c \
	src/shared/smack-util.h \
	src/shared/apparmor-util.c \
	src/shared/apparmor-util.h \
	src/shared/ima-util.c \
	src/shared/ima-util.h \
	src/shared/ptyfwd.c \
	src/shared/ptyfwd.h \
	src/shared/errno-list.c \
	src/shared/errno-list.h \
	src/shared/af-list.c \
	src/shared/af-list.h \
	src/shared/audit.c \
	src/shared/audit.h \
	src/shared/xml.c \
	src/shared/xml.h \
	src/shared/condition-util.c \
	src/shared/condition-util.h \
	src/shared/bus-label.c \
	src/shared/bus-label.h \
	src/shared/gpt.h \
	src/shared/clean-ipc.h \
	src/shared/clean-ipc.c \
	src/shared/login-shared.c \
	src/shared/login-shared.h \
	src/shared/ring.c \
	src/shared/ring.h \
	src/shared/async.c \
	src/shared/async.h \
	src/shared/eventfd-util.c \
	src/shared/eventfd-util.h \
	src/shared/copy.c \
	src/shared/copy.h \
	src/shared/base-filesystem.c \
	src/shared/base-filesystem.h

nodist_libsystemd_shared_la_SOURCES = \
	src/shared/errno-from-name.h \
	src/shared/errno-to-name.h \
	src/shared/af-from-name.h \
	src/shared/af-to-name.h

libsystemd_shared_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	-pthread

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-units.la

libsystemd_units_la_SOURCES = \
	src/shared/install.c \
	src/shared/install.h \
	src/shared/install-printf.c \
	src/shared/install-printf.h \
	src/shared/path-lookup.c \
	src/shared/path-lookup.h \
	src/shared/specifier.c \
	src/shared/specifier.h

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-label.la

libsystemd_label_la_SOURCES = \
	src/shared/socket-label.c \
	src/shared/label.c \
	src/shared/label.h \
	src/shared/selinux-util.c \
	src/shared/selinux-util.h \
	src/shared/mkdir-label.c \
	src/shared/ask-password-api.c \
	src/shared/ask-password-api.h \
	src/shared/fileio-label.c \
	src/shared/fileio-label.h \
	src/shared/dev-setup.c \
	src/shared/dev-setup.h \
	src/shared/dropin.c \
	src/shared/dropin.h \
	src/shared/generator.h \
	src/shared/generator.c

libsystemd_label_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SELINUX_CFLAGS)

libsystemd_label_la_LIBADD = \
	$(SELINUX_LIBS)

# ------------------------------------------------------------------------------

if HAVE_SECCOMP
noinst_LTLIBRARIES += \
	libsystemd-seccomp.la

libsystemd_seccomp_la_SOURCES = \
	src/shared/seccomp-util.h \
	src/shared/seccomp-util.c

libsystemd_seccomp_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

libsystemd_seccomp_la_LIBADD = \
	$(SECCOMP_LIBS)
endif

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-logs.la

libsystemd_logs_la_SOURCES = \
	src/shared/logs-show.c \
	src/shared/logs-show.h

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-capability.la

libsystemd_capability_la_SOURCES = \
	src/shared/capability.c \
	src/shared/capability.h

libsystemd_capability_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS)

libsystemd_capability_la_LIBADD = \
	$(CAP_LIBS)

# ------------------------------------------------------------------------------
if HAVE_ACL
noinst_LTLIBRARIES += \
	libsystemd-acl.la

libsystemd_acl_la_SOURCES = \
	src/shared/acl-util.c \
	src/shared/acl-util.h

libsystemd_acl_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(ACL_CFLAGS)

libsystemd_acl_la_LIBADD = \
	$(ACL_LIBS)
endif

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-core.la

libsystemd_core_la_SOURCES = \
	src/core/unit.c \
	src/core/unit.h \
	src/core/unit-printf.c \
	src/core/unit-printf.h \
	src/core/job.c \
	src/core/job.h \
	src/core/manager.c \
	src/core/manager.h \
	src/core/transaction.c \
	src/core/transaction.h \
	src/core/load-fragment.c \
	src/core/load-fragment.h \
	src/core/service.c \
	src/core/service.h \
	src/core/socket.c \
	src/core/socket.h \
	src/core/busname.c \
	src/core/busname.h \
	src/core/target.c \
	src/core/target.h \
	src/core/snapshot.c \
	src/core/snapshot.h \
	src/core/device.c \
	src/core/device.h \
	src/core/mount.c \
	src/core/mount.h \
	src/core/automount.c \
	src/core/automount.h \
	src/core/swap.c \
	src/core/swap.h \
	src/core/timer.c \
	src/core/timer.h \
	src/core/path.c \
	src/core/path.h \
	src/core/slice.c \
	src/core/slice.h \
	src/core/scope.c \
	src/core/scope.h \
	src/core/load-dropin.c \
	src/core/load-dropin.h \
	src/core/execute.c \
	src/core/execute.h \
	src/core/kill.c \
	src/core/kill.h \
	src/core/dbus.c \
	src/core/dbus.h \
	src/core/dbus-manager.c \
	src/core/dbus-manager.h \
	src/core/dbus-unit.c \
	src/core/dbus-unit.h \
	src/core/dbus-job.c \
	src/core/dbus-job.h \
	src/core/dbus-service.c \
	src/core/dbus-service.h \
	src/core/dbus-socket.c \
	src/core/dbus-socket.h \
	src/core/dbus-busname.c \
	src/core/dbus-busname.h \
	src/core/dbus-target.c \
	src/core/dbus-target.h \
	src/core/dbus-snapshot.c \
	src/core/dbus-snapshot.h \
	src/core/dbus-device.c \
	src/core/dbus-device.h \
	src/core/dbus-mount.c \
	src/core/dbus-mount.h \
	src/core/dbus-automount.c \
	src/core/dbus-automount.h \
	src/core/dbus-swap.c \
	src/core/dbus-swap.h \
	src/core/dbus-timer.c \
	src/core/dbus-timer.h \
	src/core/dbus-path.c \
	src/core/dbus-path.h \
	src/core/dbus-slice.c \
	src/core/dbus-slice.h \
	src/core/dbus-scope.c \
	src/core/dbus-scope.h \
	src/core/dbus-execute.c \
	src/core/dbus-execute.h \
	src/core/dbus-kill.c \
	src/core/dbus-kill.h \
	src/core/dbus-cgroup.c \
	src/core/dbus-cgroup.h \
	src/core/cgroup.c \
	src/core/cgroup.h \
	src/core/selinux-access.c \
	src/core/selinux-access.h \
	src/core/selinux-setup.c \
	src/core/selinux-setup.h \
	src/core/smack-setup.c \
	src/core/smack-setup.h \
	src/core/ima-setup.c \
	src/core/ima-setup.h \
	src/core/locale-setup.h \
	src/core/locale-setup.c \
	src/core/hostname-setup.c \
	src/core/hostname-setup.h \
	src/core/machine-id-setup.c \
	src/core/machine-id-setup.h \
	src/core/mount-setup.c \
	src/core/mount-setup.h \
	src/core/loopback-setup.h \
	src/core/loopback-setup.c \
	src/core/condition.c \
	src/core/condition.h \
	src/core/namespace.c \
	src/core/namespace.h \
	src/core/build.h \
	src/core/sysfs-show.h \
	src/core/switch-root.h \
	src/core/switch-root.c \
	src/core/killall.h \
	src/core/killall.c \
	src/core/audit-fd.c \
	src/core/audit-fd.h \
	src/core/show-status.c \
	src/core/show-status.h

if HAVE_KMOD
libsystemd_core_la_SOURCES += \
	src/core/kmod-setup.c \
	src/core/kmod-setup.h
endif

nodist_libsystemd_core_la_SOURCES = \
	src/core/load-fragment-gperf.c \
	src/core/load-fragment-gperf-nulstr.c

libsystemd_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PAM_CFLAGS) \
	$(AUDIT_CFLAGS) \
	$(CAP_CFLAGS) \
	$(KMOD_CFLAGS) \
	$(APPARMOR_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	-pthread

libsystemd_core_la_LIBADD = \
	libsystemd-capability.la \
	libsystemd-units.la \
	libsystemd-label.la \
	libudev-internal.la \
	libsystemd-shared.la \
	libsystemd-internal.la \
	$(PAM_LIBS) \
	$(AUDIT_LIBS) \
	$(CAP_LIBS) \
	$(KMOD_LIBS) \
	$(APPARMOR_LIBS) \
	$(SECCOMP_LIBS)

if HAVE_SECCOMP
libsystemd_core_la_LIBADD += \
	libsystemd-seccomp.la
endif

src/core/load-fragment-gperf-nulstr.c: src/core/load-fragment-gperf.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ keywords=0 ; FS="," ; print "extern const char load_fragment_gperf_nulstr[];" ; print "const char load_fragment_gperf_nulstr[] ="} ; keyword==1 { print "\"" $$1 "\\0\"" } ; /%%/ { keyword=1} ; END { print ";" }' < $< > $@

EXTRA_DIST += \
	src/core/load-fragment-gperf.gperf.m4

CLEANFILES += \
	src/core/load-fragment-gperf.gperf \
	src/core/load-fragment-gperf.c \
	src/core/load-fragment-gperf-nulstr.c \
	src/shared/errno-list.txt \
	src/shared/errno-from-name.gperf \
	src/shared/af-list.txt \
	src/shared/af-from-name.gperf

BUILT_SOURCES += \
	src/shared/errno-from-name.h \
	src/shared/errno-to-name.h \
	src/shared/af-from-name.h \
	src/shared/af-to-name.h

src/shared/errno-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include errno.h - < /dev/null | $(AWK) '/^#define[ \t]+E[^ _]+[ \t]+/ { print $$2; }'  > $@

src/shared/errno-from-name.gperf: src/shared/errno-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct errno_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { printf "%s, %s\n", $$1, $$1 }' < $< > $@

src/shared/errno-from-name.h: src/shared/errno-from-name.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_errno -H hash_errno_name -p -C < $< > $@

src/shared/errno-to-name.h: src/shared/errno-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "static const char* const errno_names[] = { "} !/EDEADLOCK/ && !/EWOULDBLOCK/ && !/ENOTSUP/ { printf "[%s] = \"%s\",\n", $$1, $$1 } END{print "};"}' < $< > $@

src/shared/af-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include sys/socket.h - < /dev/null | grep -v AF_UNSPEC | grep -v AF_MAX | $(AWK) '/^#define[ \t]+AF_[^ \t]+[ \t]+PF_[^ \t]/ { print $$2; }'  > $@

src/shared/af-from-name.gperf: src/shared/af-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct af_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { printf "%s, %s\n", $$1, $$1 }' < $< > $@

src/shared/af-from-name.h: src/shared/af-from-name.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_af -H hash_af_name -p -C < $< > $@

src/shared/af-to-name.h: src/shared/af-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "static const char* const af_names[] = { "} !/AF_FILE/ && !/AF_ROUTE/ && !/AF_LOCAL/ { printf "[%s] = \"%s\",\n", $$1, $$1 } END{print "};"}' < $< > $@

# ------------------------------------------------------------------------------
systemd_SOURCES = \
	src/core/main.c

systemd_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

systemd_LDADD = \
	libsystemd-core.la \
	$(RT_LIBS)

dist_pkgsysconf_DATA += \
	src/core/system.conf \
	src/core/user.conf

dist_dbuspolicy_DATA += \
	src/core/org.freedesktop.systemd1.conf

dist_dbussystemservice_DATA += \
	src/core/org.freedesktop.systemd1.service

polkitpolicy_in_in_files += \
	src/core/org.freedesktop.systemd1.policy.in.in

pkgconfigdata_DATA = \
	src/core/systemd.pc

nodist_rpmmacros_DATA = \
	src/core/macros.systemd

EXTRA_DIST += \
	src/core/systemd.pc.in \
	src/core/macros.systemd.in

CLEANFILES += \
	src/core/macros.systemd \
	src/core/org.freedesktop.systemd1.policy.in

# ------------------------------------------------------------------------------
manual_tests += \
	test-engine \
	test-ns \
	test-loopback \
	test-hostname \
	test-daemon \
	test-cgroup \
	test-cgroup-mask \
	test-install \
	test-watchdog \
	test-log \
	test-ipcrm

if HAVE_KMOD
manual_tests += \
	test-rtnl-manual
endif

tests += \
	test-job-type \
	test-env-replace \
	test-strbuf \
	test-strv \
	test-path-util \
	test-strxcpyx \
	test-unit-name \
	test-unit-file \
	test-utf8 \
	test-ellipsize \
	test-util \
	test-ring \
	test-tmpfiles \
	test-namespace \
	test-date \
	test-sleep \
	test-replace-var \
	test-sched-prio \
	test-calendarspec \
	test-strip-tab-ansi \
	test-cgroup-util \
	test-prioq \
	test-fileio \
	test-time \
	test-hashmap \
	test-list \
	test-tables \
	test-device-nodes \
	test-xml \
	test-architecture \
	test-socket-util \
	test-fdset \
	test-conf-files \
	test-capability \
	test-async \
	test-ratelimit

EXTRA_DIST += \
	test/sched_idle_bad.service \
	test/sched_idle_ok.service \
	test/sched_rr_bad.service \
	test/sched_rr_ok.service \
	test/sched_rr_change.service \
	test/son.service \
	test/daughter.service \
	test/parent.slice

EXTRA_DIST += \
	src/test/test-helper.h

test_device_nodes_SOURCES = \
	src/test/test-device-nodes.c

test_device_nodes_LDADD = \
	libsystemd-shared.la

test_engine_SOURCES = \
	src/test/test-engine.c

test_engine_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_engine_LDADD = \
	libsystemd-core.la \
	$(RT_LIBS)

test_job_type_SOURCES = \
	src/test/test-job-type.c

test_job_type_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_job_type_LDADD = \
	libsystemd-core.la \
	$(RT_LIBS)

test_ns_SOURCES = \
	src/test/test-ns.c

test_ns_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_ns_LDADD = \
	libsystemd-core.la

test_loopback_SOURCES = \
	src/test/test-loopback.c

test_loopback_LDADD = \
	libsystemd-core.la

test_hostname_SOURCES = \
	src/test/test-hostname.c

test_hostname_LDADD = \
	libsystemd-core.la

if ENABLE_EFI
manual_tests += \
	test-boot-timestamp

test_boot_timestamp_SOURCES = \
	src/test/test-boot-timestamps.c

test_boot_timestamp_LDADD = \
	libsystemd-shared.la
endif

test_unit_name_SOURCES = \
	src/test/test-unit-name.c

test_unit_name_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_unit_name_LDADD = \
	libsystemd-core.la \
	$(RT_LIBS)

test_unit_file_SOURCES = \
	src/test/test-unit-file.c

test_unit_file_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_unit_file_LDADD = \
	libsystemd-core.la \
	$(RT_LIBS)

test_utf8_SOURCES = \
	src/test/test-utf8.c

test_utf8_LDADD = \
	libsystemd-shared.la

test_capability_SOURCES = \
	src/test/test-capability.c

test_capability_LDADD = \
	libsystemd-shared.la \
	libsystemd-capability.la

test_async_SOURCES = \
	src/test/test-async.c

test_async_LDADD = \
	libsystemd-shared.la

test_fdset_SOURCES = \
	src/test/test-fdset.c

test_fdset_LDADD = \
	libsystemd-core.la

test_ratelimit_SOURCES = \
	src/test/test-ratelimit.c

test_ratelimit_LDADD = \
	libsystemd-shared.la

test_util_SOURCES = \
	src/test/test-util.c

test_util_LDADD = \
	libsystemd-core.la

test_socket_util_SOURCES = \
	src/test/test-socket-util.c

test_socket_util_LDADD = \
	libsystemd-core.la

test_ring_SOURCES = \
	src/test/test-ring.c

test_ring_LDADD = \
	libsystemd-core.la

test_tmpfiles_SOURCES = \
	src/test/test-tmpfiles.c

test_tmpfiles_LDADD = \
	libsystemd-shared.la

test_namespace_SOURCES = \
	src/test/test-namespace.c

test_namespace_LDADD = \
	libsystemd-core.la

test_hashmap_SOURCES = \
	src/test/test-hashmap.c

test_hashmap_LDADD = \
	libsystemd-core.la

test_xml_SOURCES = \
	src/test/test-xml.c

test_xml_LDADD = \
	libsystemd-shared.la

test_list_SOURCES = \
	src/test/test-list.c

test_list_LDADD = \
	libsystemd-core.la

test_tables_SOURCES = \
	src/test/test-tables.c \
	src/shared/test-tables.h

test_tables_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_tables_LDADD = \
	libsystemd-logs.la \
	libsystemd-journal-internal.la \
	libsystemd-core.la \
	$(RT_LIBS)

test_prioq_SOURCES = \
	src/test/test-prioq.c

test_prioq_LDADD = \
	libsystemd-core.la

test_fileio_SOURCES = \
	src/test/test-fileio.c

test_fileio_LDADD = \
	libsystemd-core.la

test_time_SOURCES = \
	src/test/test-time.c

test_time_LDADD = \
	libsystemd-core.la

test_architecture_SOURCES = \
	src/test/test-architecture.c

test_architecture_LDADD = \
	libsystemd-shared.la

test_log_SOURCES = \
	src/test/test-log.c

test_log_LDADD = \
	libsystemd-core.la

test_ipcrm_SOURCES = \
	src/test/test-ipcrm.c

test_ipcrm_LDADD = \
	libsystemd-shared.la \
	-lrt

test_rtnl_manual_SOURCES = \
	src/test/test-rtnl-manual.c

test_rtnl_manual_CFLAGS = \
	$(AM_CFLAGS) \
	$(KMOD_CFLAGS)

test_rtnl_manual_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	$(KMOD_LIBS)

test_ellipsize_SOURCES = \
	src/test/test-ellipsize.c

test_ellipsize_LDADD = \
	libsystemd-core.la

test_date_SOURCES = \
	src/test/test-date.c

test_date_LDADD = \
	libsystemd-core.la

test_sleep_SOURCES = \
	src/test/test-sleep.c

test_sleep_LDADD = \
	libsystemd-core.la

test_replace_var_SOURCES = \
	src/test/test-replace-var.c

test_replace_var_LDADD = \
	libsystemd-shared.la

test_calendarspec_SOURCES = \
	src/test/test-calendarspec.c

test_calendarspec_LDADD = \
	libsystemd-shared.la

test_strip_tab_ansi_SOURCES = \
	src/test/test-strip-tab-ansi.c

test_strip_tab_ansi_LDADD = \
	libsystemd-shared.la

test_daemon_SOURCES = \
	src/test/test-daemon.c

test_daemon_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_cgroup_SOURCES = \
	src/test/test-cgroup.c

test_cgroup_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-internal.la

test_cgroup_mask_SOURCES = \
	src/test/test-cgroup-mask.c

test_cgroup_mask_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DTEST_DIR=\"$(abs_top_srcdir)/test\"

test_cgroup_mask_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_cgroup_mask_LDADD = \
	libsystemd-core.la \
	$(RT_LIBS)

test_cgroup_util_SOURCES = \
	src/test/test-cgroup-util.c

test_cgroup_util_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_env_replace_SOURCES = \
	src/test/test-env-replace.c

test_env_replace_LDADD = \
	libsystemd-shared.la

test_strbuf_SOURCES = \
	src/test/test-strbuf.c

test_strbuf_LDADD = \
	libsystemd-shared.la

test_strv_SOURCES = \
	src/test/test-strv.c

test_strv_LDADD = \
	libsystemd-units.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_path_util_SOURCES = \
	src/test/test-path-util.c

test_path_util_LDADD = \
	libsystemd-shared.la

test_strxcpyx_SOURCES = \
	src/test/test-strxcpyx.c

test_strxcpyx_LDADD = \
	libsystemd-shared.la

test_install_SOURCES = \
	src/test/test-install.c

test_install_LDADD = \
	libsystemd-units.la \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-internal.la

test_watchdog_SOURCES = \
	src/test/test-watchdog.c

test_watchdog_LDADD = \
	libsystemd-shared.la

test_sched_prio_SOURCES = \
	src/test/test-sched-prio.c

test_sched_prio_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DTEST_DIR=\"$(abs_top_srcdir)/test\"

test_sched_prio_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_sched_prio_LDADD = \
	libsystemd-core.la \
	$(RT_LIBS)

test_conf_files_SOURCES = \
	src/test/test-conf-files.c

test_conf_files_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
## .PHONY so it always rebuilds it
.PHONY: coverage lcov-run lcov-report coverage-sync

# run lcov from scratch, always
coverage: all
	$(MAKE) lcov-run
	$(MAKE) lcov-report

coverage_dir = coverage
coverage_opts = --base-directory $(srcdir) --directory $(builddir) --rc 'geninfo_adjust_src_path=$(abspath $(srcdir))=>$(abspath $(builddir))'

if ENABLE_COVERAGE
# reset run coverage tests
lcov-run:
	@rm -rf $(coverage_dir)
	lcov $(coverage_opts) --zerocounters
	-$(MAKE) check

# generate report based on current coverage data
lcov-report:
	$(MKDIR_P) $(coverage_dir)
	lcov $(coverage_opts) --compat-libtool --capture --no-external \
		| sed 's|$(abspath $(builddir))|$(abspath $(srcdir))|' > $(coverage_dir)/.lcov.info
	genhtml -t "systemd test coverage" -o $(coverage_dir) $(coverage_dir)/.lcov.info
	@echo "Coverage report generated in $(abs_builddir)/$(coverage_dir)/index.html"

# lcov doesn't work properly with vpath builds, make sure that bad
# output is not uploaded by mistake.
coverage-sync: coverage
	test "$(builddir)" = "$(srcdir)"
	rsync -rlv --delete --omit-dir-times coverage/ $(www_target)/coverage

else
lcov-run lcov-report:
	echo "Need to reconfigure with --enable-coverage"
endif

# ------------------------------------------------------------------------------
systemd_analyze_SOURCES = \
	src/analyze/analyze.c

systemd_analyze_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_initctl_SOURCES = \
	src/initctl/initctl.c

systemd_initctl_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_update_utmp_SOURCES = \
	src/update-utmp/update-utmp.c

systemd_update_utmp_CFLAGS = \
	$(AM_CFLAGS) \
	$(AUDIT_CFLAGS)

systemd_update_utmp_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	$(AUDIT_LIBS)

# ------------------------------------------------------------------------------
systemd_update_done_SOURCES = \
	src/update-done/update-done.c

systemd_update_done_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_shutdownd_SOURCES = \
	src/shutdownd/shutdownd.c

systemd_shutdownd_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

dist_doc_DATA += \
	src/systemd/sd-shutdown.h

# ------------------------------------------------------------------------------
systemd_shutdown_SOURCES = \
	src/core/umount.c \
	src/core/umount.h \
	src/core/shutdown.c \
	src/core/mount-setup.c \
	src/core/mount-setup.h \
	src/core/killall.h \
	src/core/killall.c

systemd_shutdown_LDADD = \
	libsystemd-label.la \
	libudev-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
if HAVE_KMOD
systemd_modules_load_SOURCES = \
	src/modules-load/modules-load.c

systemd_modules_load_CFLAGS = \
	$(AM_CFLAGS) \
	$(KMOD_CFLAGS)

systemd_modules_load_LDADD = \
	libsystemd-shared.la \
	$(KMOD_LIBS)

rootlibexec_PROGRAMS += \
	systemd-modules-load

nodist_systemunit_DATA += \
	units/systemd-modules-load.service

SYSINIT_TARGET_WANTS += \
	systemd-modules-load.service

if ENABLE_TMPFILES
nodist_systemunit_DATA += \
	units/kmod-static-nodes.service

SYSINIT_TARGET_WANTS += \
	kmod-static-nodes.service
endif
endif

EXTRA_DIST += \
	units/systemd-modules-load.service.in \
	units/kmod-static-nodes.service.in

# ------------------------------------------------------------------------------
if ENABLE_TMPFILES
systemd_tmpfiles_SOURCES = \
	src/tmpfiles/tmpfiles.c

systemd_tmpfiles_LDADD = \
	libsystemd-units.la \
	libsystemd-label.la \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	systemd-tmpfiles

dist_systemunit_DATA += \
	units/systemd-tmpfiles-clean.timer

nodist_systemunit_DATA += \
	units/systemd-tmpfiles-setup-dev.service \
	units/systemd-tmpfiles-setup.service \
	units/systemd-tmpfiles-clean.service

dist_tmpfiles_DATA = \
	tmpfiles.d/systemd.conf \
	tmpfiles.d/systemd-nologin.conf \
	tmpfiles.d/tmp.conf \
	tmpfiles.d/x11.conf \
	tmpfiles.d/var.conf \
	tmpfiles.d/etc.conf

if HAVE_SYSV_COMPAT
dist_tmpfiles_DATA += \
	tmpfiles.d/legacy.conf
endif

SYSINIT_TARGET_WANTS += \
	systemd-tmpfiles-setup-dev.service \
	systemd-tmpfiles-setup.service

dist_zshcompletion_DATA += \
	shell-completion/zsh/_systemd-tmpfiles

TIMERS_TARGET_WANTS += \
	systemd-tmpfiles-clean.timer

INSTALL_DIRS += \
	$(tmpfilesdir) \
	$(sysconfdir)/tmpfiles.d
endif

EXTRA_DIST += \
	units/systemd-tmpfiles-setup-dev.service.in \
	units/systemd-tmpfiles-setup.service.in \
	units/systemd-tmpfiles-clean.service.in

# ------------------------------------------------------------------------------
if ENABLE_SYSUSERS
systemd_sysusers_SOURCES = \
	src/sysusers/sysusers.c

systemd_sysusers_LDADD = \
	libsystemd-units.la \
	libsystemd-label.la \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	systemd-sysusers

nodist_systemunit_DATA += \
	units/systemd-sysusers.service

SYSINIT_TARGET_WANTS += \
	systemd-sysusers.service

dist_sysusers_DATA = \
	sysusers.d/systemd.conf

nodist_sysusers_DATA = \
	sysusers.d/basic.conf

EXTRA_DIST += \
	units/systemd-sysusers.service.in \
	sysusers.d/basic.conf.in

CLEANFILES += \
	sysusers.d/basic.conf

INSTALL_DIRS += \
	$(sysusersdir)
endif

# ------------------------------------------------------------------------------
systemd_machine_id_setup_SOURCES = \
	src/machine-id-setup/machine-id-setup-main.c \
	src/core/machine-id-setup.c \
	src/core/machine-id-setup.h

systemd_machine_id_setup_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_sysctl_SOURCES = \
	src/sysctl/sysctl.c

systemd_sysctl_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_sleep_SOURCES = \
	src/sleep/sleep.c

systemd_sleep_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_fsck_SOURCES = \
	src/fsck/fsck.c

systemd_fsck_LDADD = \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_ac_power_SOURCES = \
	src/ac-power/ac-power.c

systemd_ac_power_LDADD = \
	libudev-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_detect_virt_SOURCES = \
	src/detect-virt/detect-virt.c

systemd_detect_virt_LDADD = \
	libsystemd-shared.la

INSTALL_EXEC_HOOKS += \
	systemd-detect-virt-install-hook

# ------------------------------------------------------------------------------
systemd_delta_SOURCES = \
	src/delta/delta.c

systemd_delta_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_getty_generator_SOURCES = \
	src/getty-generator/getty-generator.c

systemd_getty_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_debug_generator_SOURCES = \
	src/debug-generator/debug-generator.c

systemd_debug_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_fstab_generator_SOURCES = \
	src/fstab-generator/fstab-generator.c \
	src/core/mount-setup.c

systemd_fstab_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_system_update_generator_SOURCES = \
	src/system-update-generator/system-update-generator.c

systemd_system_update_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

if ENABLE_EFI
# ------------------------------------------------------------------------------
systemgenerator_PROGRAMS +=  \
	systemd-efi-boot-generator

systemd_efi_boot_generator_SOURCES = \
	src/efi-boot-generator/efi-boot-generator.c

systemd_efi_boot_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
bootctl_SOURCES = \
	src/boot/boot.h \
	src/boot/boot-loader.h \
	src/boot/bootctl.c \
	src/boot/boot-loader.c \
	src/boot/boot-efi.c

bootctl_LDADD = \
	libsystemd-shared.la \
	libsystemd-internal.la

bin_PROGRAMS += \
	bootctl

dist_bashcompletion_DATA += \
	shell-completion/bash/bootctl

dist_zshcompletion_DATA += \
	shell-completion/zsh/_bootctl

endif

# ------------------------------------------------------------------------------
if HAVE_BLKID
systemgenerator_PROGRAMS +=  \
	systemd-gpt-auto-generator

systemd_gpt_auto_generator_SOURCES = \
	src/gpt-auto-generator/gpt-auto-generator.c \
	src/shared/blkid-util.h

systemd_gpt_auto_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la \
	$(BLKID_LIBS)

systemd_gpt_auto_generator_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS)
endif

# ------------------------------------------------------------------------------
if ENABLE_KDBUS
systemgenerator_PROGRAMS +=  \
	systemd-dbus1-generator

systemd_dbus1_generator_SOURCES = \
	src/dbus1-generator/dbus1-generator.c

systemd_dbus1_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-internal.la

dbus1-generator-install-hook:
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(usergeneratordir)
	$(AM_V_RM)rm -f $(DESTDIR)$(usergeneratordir)/systemd-dbus1-generator
	$(AM_V_LN)$(LN_S) --relative -f $(DESTDIR)$(systemgeneratordir)/systemd-dbus1-generator $(DESTDIR)$(usergeneratordir)/systemd-dbus1-generator

dbus1-generator-uninstall-hook:
	rm -f $(DESTDIR)$(usergeneratordir)/systemd-dbus1-generator

INSTALL_EXEC_HOOKS += dbus1-generator-install-hook
UNINSTALL_EXEC_HOOKS += dbus1-generator-uninstall-hook
endif

# ------------------------------------------------------------------------------
systemd_sysv_generator_SOURCES = \
	src/sysv-generator/sysv-generator.c

systemd_sysv_generator_LDADD = \
	libsystemd-core.la \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_rc_local_generator_SOURCES = \
	src/rc-local-generator/rc-local-generator.c

systemd_rc_local_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_remount_fs_SOURCES = \
	src/remount-fs/remount-fs.c \
	src/core/mount-setup.c \
	src/core/mount-setup.h

systemd_remount_fs_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_cgroups_agent_SOURCES = \
	src/cgroups-agent/cgroups-agent.c

systemd_cgroups_agent_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemctl_SOURCES = \
	src/systemctl/systemctl.c

systemctl_LDADD = \
	libsystemd-units.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-logs.la \
	libsystemd-journal-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_notify_SOURCES = \
	src/notify/notify.c \
	src/readahead/sd-readahead.c

systemd_notify_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_path_SOURCES = \
	src/path/path.c

systemd_path_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_ask_password_SOURCES = \
	src/ask-password/ask-password.c

systemd_ask_password_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_reply_password_SOURCES = \
	src/reply-password/reply-password.c

systemd_reply_password_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_cgls_SOURCES = \
	src/cgls/cgls.c

systemd_cgls_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_cgtop_SOURCES = \
	src/cgtop/cgtop.c

systemd_cgtop_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_nspawn_SOURCES = \
	src/nspawn/nspawn.c \
	src/core/mount-setup.c \
	src/core/mount-setup.h \
	src/core/loopback-setup.c \
	src/core/loopback-setup.h

systemd_nspawn_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(BLKID_CFLAGS)

systemd_nspawn_LDADD = \
	libsystemd-label.la \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la \
	$(BLKID_LIBS)

if HAVE_SECCOMP
systemd_nspawn_LDADD += \
	libsystemd-seccomp.la \
	$(SECCOMP_LIBS)
endif

# ------------------------------------------------------------------------------
systemd_run_SOURCES = \
	src/run/run.c

systemd_run_LDADD = \
	libsystemd-label.la \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_bus_proxyd_SOURCES = \
	src/bus-proxyd/bus-proxyd.c \
	src/bus-proxyd/bus-policy.c \
	src/bus-proxyd/bus-policy.h

systemd_bus_proxyd_LDADD = \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libsystemd-shared.la

bus-proxyd-install-hook:
	$(AM_V_at)$(MKDIR_P) $(DESTDIR)$(bindir)
	$(AM_V_RM)rm -f $(DESTDIR)$(bindir)/systemd-stdio-bridge
	$(AM_V_LN)$(LN_S) --relative -f $(DESTDIR)$(rootlibexecdir)/systemd-bus-proxyd $(DESTDIR)$(bindir)/systemd-stdio-bridge

bus-proxyd-uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/systemd-stdio-bridge

INSTALL_EXEC_HOOKS += bus-proxyd-install-hook
UNINSTALL_EXEC_HOOKS += bus-proxyd-uninstall-hook

if ENABLE_KDBUS
nodist_systemunit_DATA += \
	units/systemd-bus-proxyd@.service

dist_systemunit_DATA += \
	units/systemd-bus-proxyd.socket

dist_userunit_DATA += \
	units/user/systemd-bus-proxyd.socket \
	units/user/systemd-bus-proxyd@.service
endif

EXTRA_DIST += \
	units/systemd-bus-proxyd@.service.in

# ------------------------------------------------------------------------------
systemd_tty_ask_password_agent_SOURCES = \
	src/tty-ask-password-agent/tty-ask-password-agent.c

systemd_tty_ask_password_agent_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
libsystemd_internal_la_SOURCES = \
	src/systemd/sd-bus.h \
	src/systemd/sd-bus-protocol.h \
	src/systemd/sd-bus-vtable.h \
	src/systemd/sd-memfd.h \
	src/systemd/sd-utf8.h \
	src/systemd/sd-event.h \
	src/systemd/sd-rtnl.h \
	src/systemd/sd-resolve.h \
	src/systemd/sd-login.h \
	src/systemd/sd-id128.h \
	src/systemd/sd-daemon.h \
	src/systemd/sd-path.h \
	src/libsystemd/sd-bus/sd-bus.c \
	src/libsystemd/sd-bus/bus-control.c \
	src/libsystemd/sd-bus/bus-control.h \
	src/libsystemd/sd-bus/bus-error.c \
	src/libsystemd/sd-bus/bus-error.h \
	src/libsystemd/sd-bus/bus-internal.c \
	src/libsystemd/sd-bus/bus-internal.h \
	src/libsystemd/sd-bus/bus-socket.c \
	src/libsystemd/sd-bus/bus-socket.h \
	src/libsystemd/sd-bus/bus-kernel.c \
	src/libsystemd/sd-bus/bus-kernel.h \
	src/libsystemd/sd-bus/bus-container.c \
	src/libsystemd/sd-bus/bus-container.h \
	src/libsystemd/sd-bus/bus-message.c \
	src/libsystemd/sd-bus/bus-message.h \
	src/libsystemd/sd-bus/bus-creds.c \
	src/libsystemd/sd-bus/bus-creds.h \
	src/libsystemd/sd-bus/bus-signature.c \
	src/libsystemd/sd-bus/bus-signature.h \
	src/libsystemd/sd-bus/bus-type.c \
	src/libsystemd/sd-bus/bus-type.h \
	src/libsystemd/sd-bus/bus-match.c \
	src/libsystemd/sd-bus/bus-match.h \
	src/libsystemd/sd-bus/bus-bloom.c \
	src/libsystemd/sd-bus/bus-bloom.h \
	src/libsystemd/sd-bus/bus-introspect.c \
	src/libsystemd/sd-bus/bus-introspect.h \
	src/libsystemd/sd-bus/bus-objects.c \
	src/libsystemd/sd-bus/bus-objects.h \
	src/libsystemd/sd-bus/bus-gvariant.c \
	src/libsystemd/sd-bus/bus-gvariant.h \
	src/libsystemd/sd-bus/bus-convenience.c \
	src/libsystemd/sd-bus/bus-track.c \
	src/libsystemd/sd-bus/bus-track.h \
	src/libsystemd/sd-bus/bus-util.c \
	src/libsystemd/sd-bus/bus-util.h \
	src/libsystemd/sd-bus/bus-slot.c \
	src/libsystemd/sd-bus/bus-slot.h \
	src/libsystemd/sd-bus/bus-protocol.h \
	src/libsystemd/sd-bus/kdbus.h \
	src/libsystemd/sd-bus/sd-memfd.c \
	src/libsystemd/sd-utf8/sd-utf8.c \
	src/libsystemd/sd-event/sd-event.c \
	src/libsystemd/sd-event/event-util.h \
	src/libsystemd/sd-rtnl/sd-rtnl.c \
	src/libsystemd/sd-rtnl/rtnl-internal.h \
	src/libsystemd/sd-rtnl/rtnl-message.c \
	src/libsystemd/sd-rtnl/rtnl-types.h \
	src/libsystemd/sd-rtnl/rtnl-types.c \
	src/libsystemd/sd-rtnl/rtnl-util.h \
	src/libsystemd/sd-rtnl/rtnl-util.c \
	src/libsystemd/sd-id128/sd-id128.c \
	src/libsystemd/sd-daemon/sd-daemon.c \
	src/libsystemd/sd-login/sd-login.c \
	src/libsystemd/sd-path/sd-path.c

nodist_libsystemd_internal_la_SOURCES = \
	src/libsystemd/libsystemd.sym \
	src/libsystemd/sd-bus/bus-error-mapping.c

libsystemd_internal_la_CFLAGS = \
	$(AM_CFLAGS) \
	-pthread

libsystemd_internal_la_LIBADD = \
	$(RT_LIBS)

libsystemd_resolve_la_SOURCES = \
	src/libsystemd/sd-resolve/sd-resolve.c \
	src/libsystemd/sd-resolve/resolve-util.h

libsystemd_resolve_la_CFLAGS = \
	$(AM_CFLAGS) \
	-pthread

libsystemd_resolve_la_LIBADD = \
	-lresolv

noinst_LTLIBRARIES += \
	libsystemd-internal.la \
	libsystemd-resolve.la

libsystemd_dump_la_SOURCES = \
	src/libsystemd/sd-bus/bus-dump.c \
	src/libsystemd/sd-bus/bus-dump.h

libsystemd_dump_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS)

noinst_LTLIBRARIES += \
	libsystemd-dump.la

EXTRA_DIST += \
	src/libsystemd/libsystemd.sym.m4 \
	src/libsystemd/libsystemd.pc.in \
	src/libsystemd/sd-bus/bus-error-mapping.gperf \
	src/libsystemd/sd-bus/DIFFERENCES \
	src/libsystemd/sd-bus/GVARIANT-SERIALIZATION

CLEANFILES += \
	src/libsystemd/libsystemd.sym \
	src/libsystemd/sd-bus/bus-error-mapping.c

BUILT_SOURCES += \
	src/libsystemd/libsystemd.sym

libsystemd_la_SOURCES = \
	$(libsystemd_internal_la_SOURCES) \
	$(libsystemd_resolve_la_SOURCES) \
	$(libsystemd_journal_internal_la_SOURCES)

nodist_libsystemd_la_SOURCES = \
	$(nodist_libsystemd_internal_la_SOURCES)

libsystemd_la_CFLAGS = \
	$(libsystemd_internal_la_CFLAGS) \
	$(libsystemd_resolve_la_CFLAGS) \
	$(libsystemd_journal_internal_la_CFLAGS)

libsystemd_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBSYSTEMD_CURRENT):$(LIBSYSTEMD_REVISION):$(LIBSYSTEMD_AGE) \
	-Wl,--version-script=$(top_builddir)/src/libsystemd/libsystemd.sym

libsystemd_la_LIBADD = \
	libsystemd-shared.la \
	$(libsystemd_internal_la_LIBADD) \
	$(libsystemd_journal_internal_la_LIBADD) \
	$(libsystemd_resolve_la_LIBADD)

libsystemd-install-hook:
	libname=libsystemd.so && $(move-to-rootlibdir)

libsystemd-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd.so*

INSTALL_EXEC_HOOKS += libsystemd-install-hook
UNINSTALL_EXEC_HOOKS += libsystemd-uninstall-hook

pkgconfiglib_DATA += \
	src/libsystemd/libsystemd.pc

pkginclude_HEADERS += \
	src/systemd/sd-login.h \
	src/systemd/sd-id128.h \
	src/systemd/sd-daemon.h

if ENABLE_KDBUS
pkginclude_HEADERS += \
	src/systemd/sd-bus.h \
	src/systemd/sd-bus-protocol.h \
	src/systemd/sd-bus-vtable.h \
	src/systemd/sd-memfd.h \
	src/systemd/sd-utf8.h \
	src/systemd/sd-event.h \
	src/systemd/sd-rtnl.h \
	src/systemd/sd-resolve.h \
	src/systemd/sd-path.h
endif

lib_LTLIBRARIES += \
	libsystemd.la

tests += \
	test-bus-marshal \
	test-bus-signature \
	test-bus-chat \
	test-bus-cleanup \
	test-bus-server \
	test-bus-match \
	test-bus-kernel \
	test-bus-kernel-bloom \
	test-bus-kernel-benchmark \
	test-bus-memfd \
	test-bus-zero-copy \
	test-bus-introspect \
	test-bus-objects \
	test-bus-error \
	test-bus-creds \
	test-bus-gvariant \
	test-event \
	test-rtnl \
	test-resolve

bin_PROGRAMS += \
	busctl

test_bus_marshal_SOURCES = \
	src/libsystemd/sd-bus/test-bus-marshal.c

test_bus_marshal_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	libsystemd-dump.la \
	libsystemd-capability.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(CAP_LIBS)

test_bus_marshal_CFLAGS = \
	$(AM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(CAP_CFLAGS)

test_bus_signature_SOURCES = \
	src/libsystemd/sd-bus/test-bus-signature.c

test_bus_signature_LDADD = \
	libsystemd-shared.la \
	libsystemd-internal.la

test_bus_chat_SOURCES = \
	src/libsystemd/sd-bus/test-bus-chat.c

test_bus_chat_CFLAGS = \
	$(AM_CFLAGS) \
	-pthread

test_bus_chat_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_cleanup_SOURCES = \
	src/libsystemd/sd-bus/test-bus-cleanup.c

test_bus_cleanup_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_bus_cleanup_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_server_SOURCES = \
	src/libsystemd/sd-bus/test-bus-server.c

test_bus_server_CFLAGS = \
	$(AM_CFLAGS) \
	-pthread

test_bus_server_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_objects_SOURCES = \
	src/libsystemd/sd-bus/test-bus-objects.c

test_bus_objects_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS) \
	-pthread

test_bus_objects_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	libsystemd-dump.la \
	libsystemd-capability.la \
	$(CAP_LIBS)

test_bus_error_SOURCES = \
	src/libsystemd/sd-bus/test-bus-error.c

test_bus_error_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_gvariant_SOURCES = \
	src/libsystemd/sd-bus/test-bus-gvariant.c

test_bus_gvariant_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	libsystemd-dump.la \
	libsystemd-capability.la \
	$(GLIB_LIBS) \
	$(CAP_LIBS)

test_bus_gvariant_CFLAGS = \
	$(AM_CFLAGS) \
	$(GLIB_CFLAGS)
	$(CAP_CFLAGS)

test_bus_creds_SOURCES = \
	src/libsystemd/sd-bus/test-bus-creds.c

test_bus_creds_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	libsystemd-dump.la \
	libsystemd-capability.la

test_bus_match_SOURCES = \
	src/libsystemd/sd-bus/test-bus-match.c

test_bus_match_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_kernel_SOURCES = \
	src/libsystemd/sd-bus/test-bus-kernel.c

test_bus_kernel_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	libsystemd-dump.la \
	libsystemd-capability.la \
	$(CAP_LIBS)

test_bus_kernel_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS)

test_bus_kernel_bloom_SOURCES = \
	src/libsystemd/sd-bus/test-bus-kernel-bloom.c

test_bus_kernel_bloom_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_kernel_benchmark_SOURCES = \
	src/libsystemd/sd-bus/test-bus-kernel-benchmark.c

test_bus_kernel_benchmark_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_memfd_SOURCES = \
	src/libsystemd/sd-bus/test-bus-memfd.c

test_bus_memfd_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_bus_zero_copy_SOURCES = \
	src/libsystemd/sd-bus/test-bus-zero-copy.c

test_bus_zero_copy_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	libsystemd-dump.la \
	libsystemd-capability.la \
	$(CAP_LIBS)

test_bus_zero_copy_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS)

test_bus_introspect_SOURCES = \
	src/libsystemd/sd-bus/test-bus-introspect.c

test_bus_introspect_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_event_SOURCES = \
	src/libsystemd/sd-event/test-event.c

test_event_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_rtnl_SOURCES = \
	src/libsystemd/sd-rtnl/test-rtnl.c

test_rtnl_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_resolve_SOURCES = \
	src/libsystemd/sd-resolve/test-resolve.c

test_resolve_LDADD = \
	libsystemd-resolve.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_resolve_CFLAGS = \
	$(AM_CFLAGS) \
	-pthread

busctl_SOURCES = \
	src/libsystemd/sd-bus/busctl.c

busctl_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la \
	libsystemd-dump.la \
	libsystemd-capability.la \
	$(CAP_LIBS)

busctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS)

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-network.la

libsystemd_network_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(KMOD_CFLAGS)

libsystemd_network_la_SOURCES = \
	src/systemd/sd-network.h \
	src/systemd/sd-dhcp-client.h \
	src/systemd/sd-dhcp-server.h \
	src/systemd/sd-dhcp-lease.h \
	src/systemd/sd-ipv4ll.h \
	src/network/sd-network.c \
	src/network/network-util.h \
	src/libsystemd-network/sd-dhcp-client.c \
	src/libsystemd-network/sd-dhcp-server.c \
	src/libsystemd-network/dhcp-network.c \
	src/libsystemd-network/dhcp-option.c \
	src/libsystemd-network/dhcp-packet.c \
	src/libsystemd-network/dhcp-internal.h \
	src/libsystemd-network/dhcp-server-internal.h \
	src/libsystemd-network/dhcp-protocol.h \
	src/libsystemd-network/dhcp-lease-internal.h \
	src/libsystemd-network/sd-dhcp-lease.c \
	src/libsystemd-network/sd-ipv4ll.c \
	src/libsystemd-network/ipv4ll-network.c \
	src/libsystemd-network/ipv4ll-packet.c \
	src/libsystemd-network/ipv4ll-internal.h \
	src/libsystemd-network/network-internal.c \
	src/libsystemd-network/network-internal.h \
	src/systemd/sd-icmp6-nd.h \
	src/systemd/sd-dhcp6-client.h \
	src/systemd/sd-dhcp6-lease.h \
	src/libsystemd-network/sd-icmp6-nd.c \
	src/libsystemd-network/sd-dhcp6-client.c \
	src/libsystemd-network/dhcp6-internal.h \
	src/libsystemd-network/dhcp6-protocol.h \
	src/libsystemd-network/dhcp6-network.c \
	src/libsystemd-network/dhcp6-option.c \
	src/libsystemd-network/dhcp6-lease-internal.h \
	src/libsystemd-network/sd-dhcp6-lease.c

libsystemd_network_la_LIBADD = \
	libudev-internal.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la \
	$(KMOD_LIBS)

test_dhcp_option_SOURCES = \
	src/libsystemd-network/dhcp-protocol.h \
	src/libsystemd-network/dhcp-internal.h \
	src/libsystemd-network/test-dhcp-option.c

test_dhcp_option_LDADD = \
	libsystemd-network.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_dhcp_client_SOURCES = \
	src/systemd/sd-dhcp-client.h \
	src/libsystemd-network/dhcp-protocol.h \
	src/libsystemd-network/dhcp-internal.h \
	src/libsystemd-network/test-dhcp-client.c

test_dhcp_client_LDADD = \
	libsystemd-network.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_dhcp_server_SOURCES = \
	src/libsystemd-network/test-dhcp-server.c

test_dhcp_server_LDADD = \
	libsystemd-network.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_ipv4ll_SOURCES = \
	src/systemd/sd-ipv4ll.h \
	src/libsystemd-network/ipv4ll-internal.h \
	src/libsystemd-network/test-ipv4ll.c

test_ipv4ll_LDADD = \
	libsystemd-network.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_icmp6_rs_SOURCES = \
	src/systemd/sd-dhcp6-client.h \
	src/systemd/sd-icmp6-nd.h \
	src/libsystemd-network/dhcp6-internal.h \
	src/libsystemd-network/test-icmp6-rs.c

test_icmp6_rs_LDADD = \
	libsystemd-network.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_dhcp6_client_SOURCES = \
	src/systemd/sd-dhcp6-client.h \
	src/libsystemd-network/dhcp6-internal.h \
	src/libsystemd-network/test-dhcp6-client.c

test_dhcp6_client_LDADD = \
	libsystemd-network.la \
	libsystemd-internal.la \
	libsystemd-shared.la

tests += \
	test-dhcp-option \
	test-dhcp-client \
	test-dhcp-server \
	test-ipv4ll \
	test-icmp6-rs \
	test-dhcp6-client

# ------------------------------------------------------------------------------
if ENABLE_GTK_DOC
SUBDIRS += \
	docs/libudev

noinst_DATA += \
	docs/html/libudev \
	docs/html/gudev
endif

include_HEADERS += \
	src/libudev/libudev.h

lib_LTLIBRARIES += \
	libudev.la

libudev_la_SOURCES =\
	src/libudev/libudev.sym \
	src/libudev/libudev-private.h \
	src/libudev/libudev.c \
	src/libudev/libudev-list.c \
	src/libudev/libudev-util.c \
	src/libudev/libudev-device.c \
	src/libudev/libudev-enumerate.c \
	src/libudev/libudev-monitor.c \
	src/libudev/libudev-queue.c \
	src/libudev/libudev-hwdb-def.h \
	src/libudev/libudev-hwdb.c

libudev_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libudev_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libudev/libudev.sym

libudev_la_LIBADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

pkgconfiglib_DATA += \
	src/libudev/libudev.pc

EXTRA_DIST += \
	src/libudev/libudev.pc.in

CLEANFILES += \
	src/libudev/libudev.pc \
	docs/html/libudev \
	docs/html/gudev

docs/html/libudev:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_LN)$(LN_S) -f ../libudev/html $@

docs/html/gudev:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_LN)$(LN_S) -f ../gudev/html $@

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libudev-install-hook:
	libname=libudev.so && $(move-to-rootlibdir)

libudev-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libudev.so*

INSTALL_EXEC_HOOKS += libudev-install-hook
UNINSTALL_EXEC_HOOKS += libudev-uninstall-hook

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libudev-internal.la

libudev_internal_la_SOURCES =\
	$(libudev_la_SOURCES) \
	src/libudev/libudev-device-private.c

libudev_internal_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default

# ------------------------------------------------------------------------------
INSTALL_DIRS += \
	$(sysconfdir)/udev/rules.d \
	$(sysconfdir)/udev/hwdb.d

dist_network_DATA = \
	network/99-default.link \
	network/80-container-host0.network \
	network/80-container-ve.network

dist_udevrules_DATA += \
	rules/42-usb-hid-pm.rules \
	rules/50-udev-default.rules \
	rules/60-drm.rules \
	rules/60-keyboard.rules \
	rules/60-persistent-storage-tape.rules \
	rules/60-persistent-serial.rules \
	rules/60-persistent-input.rules \
	rules/60-persistent-alsa.rules \
	rules/60-persistent-storage.rules \
	rules/64-btrfs.rules \
	rules/75-net-description.rules \
	rules/75-tty-description.rules \
	rules/78-sound-card.rules \
	rules/80-net-setup-link.rules \
	rules/95-udev-late.rules

nodist_udevrules_DATA += \
	rules/99-systemd.rules

dist_udevhwdb_DATA = \
	hwdb/20-pci-vendor-model.hwdb \
	hwdb/20-pci-classes.hwdb \
	hwdb/20-usb-vendor-model.hwdb \
	hwdb/20-usb-classes.hwdb \
	hwdb/20-sdio-vendor-model.hwdb \
	hwdb/20-sdio-classes.hwdb \
	hwdb/20-bluetooth-vendor-product.hwdb \
	hwdb/20-acpi-vendor.hwdb \
	hwdb/20-OUI.hwdb \
	hwdb/20-net-ifname.hwdb \
	hwdb/60-keyboard.hwdb

udevconfdir = $(sysconfdir)/udev
dist_udevconf_DATA = \
	src/udev/udev.conf

sharepkgconfigdir = $(datadir)/pkgconfig
sharepkgconfig_DATA = \
	src/udev/udev.pc

EXTRA_DIST += \
	rules/99-systemd.rules.in \
	src/udev/udev.pc.in

CLEANFILES += \
	rules/99-systemd.rules \
	src/udev/udev.pc

EXTRA_DIST += \
	units/systemd-udevd.service.in \
	units/systemd-udev-trigger.service.in \
	units/systemd-udev-settle.service.in \
	units/systemd-udev-hwdb-update.service.in

CLEANFILES += \
	units/systemd-udevd.service \
	units/systemd-udev-trigger.service \
	units/systemd-udev-settle.service \
	units/systemd-udev-hwdb-update.service

SOCKETS_TARGET_WANTS += \
	systemd-udevd-control.socket \
	systemd-udevd-kernel.socket

SYSINIT_TARGET_WANTS += \
	systemd-udevd.service \
	systemd-udev-trigger.service \
	systemd-udev-hwdb-update.service

rootbin_PROGRAMS += \
	udevadm

rootlibexec_PROGRAMS += \
	systemd-udevd

noinst_LTLIBRARIES += \
	libudev-core.la

src/udev/keyboard-keys.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9]/ { if ($$2 != "KEY_MAX") { print $$2 } }' | sed 's/^KEY_COFFEE$$/KEY_SCREENLOCK/' > $@

src/udev/keyboard-keys-from-name.gperf: src/udev/keyboard-keys.txt
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print tolower(substr($$1 ,5)) ", " $$1 }' < $< > $@

src/udev/keyboard-keys-from-name.h: src/udev/keyboard-keys-from-name.gperf
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t -N keyboard_lookup_key -H hash_key_name -p -C < $< > $@

src/udev/keyboard-keys-to-name.h: src/udev/keyboard-keys.txt
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@

libudev_core_la_SOURCES = \
	src/udev/udev.h \
	src/udev/udev-event.c \
	src/udev/udev-watch.c \
	src/udev/udev-node.c \
	src/udev/udev-rules.c \
	src/udev/udev-ctrl.c \
	src/udev/udev-builtin.c \
	src/udev/udev-builtin-btrfs.c \
	src/udev/udev-builtin-hwdb.c \
	src/udev/udev-builtin-input_id.c \
	src/udev/udev-builtin-keyboard.c \
	src/udev/udev-builtin-net_id.c \
	src/udev/udev-builtin-net_setup_link.c \
	src/udev/udev-builtin-path_id.c \
	src/udev/udev-builtin-usb_id.c \
	src/udev/net/link-config.h \
	src/udev/net/link-config.c \
	src/udev/net/ethtool-util.h \
	src/udev/net/ethtool-util.c

nodist_libudev_core_la_SOURCES = \
	src/udev/keyboard-keys-from-name.h \
	src/udev/keyboard-keys-to-name.h \
	src/udev/net/link-config-gperf.c

BUILT_SOURCES += \
	$(nodist_libudev_core_la_SOURCES)

CLEANFILES += \
	src/udev/keyboard-keys-from-name.gperf \
	src/udev/keyboard-keys.txt \
	src/udev/net/link-config-gperf.c

EXTRA_DIST += \
	src/udev/net/link-config-gperf.gperf

libudev_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(KMOD_CFLAGS)

libudev_core_la_LIBADD = \
	libudev-internal.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-network.la \
	libsystemd-shared.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS)

libudev_core_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DFIRMWARE_PATH="$(FIRMWARE_PATH)"

if ENABLE_FIRMWARE
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-firmware.c

dist_udevrules_DATA += \
	rules/50-firmware.rules
endif

if HAVE_KMOD
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-kmod.c

dist_udevrules_DATA += \
	rules/80-drivers.rules
endif

if HAVE_BLKID
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-blkid.c
endif

if HAVE_ACL
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-uaccess.c \
	src/login/logind-acl.c \
	src/libsystemd/sd-login/sd-login.c \
	src/systemd/sd-login.h

libudev_core_la_LIBADD += \
	libsystemd-acl.la
endif

systemd_udevd_SOURCES = \
	src/udev/udevd.c

systemd_udevd_LDADD = \
	libudev-core.la

udevadm_SOURCES = \
	src/udev/udevadm.c \
	src/udev/udevadm-info.c \
	src/udev/udevadm-control.c \
	src/udev/udevadm-monitor.c \
	src/udev/udevadm-hwdb.c \
	src/udev/udevadm-settle.c \
	src/udev/udevadm-trigger.c \
	src/udev/udevadm-test.c \
	src/udev/udevadm-test-builtin.c

udevadm_LDADD = \
	libudev-core.la

# Update hwdb on installation. Do not bother if installing
# in DESTDIR, since this is likely for packaging purposes.
hwdb-update-hook:
	-test -n "$(DESTDIR)" || $(rootbindir)/udevadm hwdb --update

INSTALL_DATA_HOOKS += \
	hwdb-update-hook

hwdb-remove-hook:
	-test -n "$(DESTDIR)" || rm -f /etc/udev/hwdb.bin

# ------------------------------------------------------------------------------
TESTS += \
	test/udev-test.pl \
	test/rules-test.sh

manual_tests += \
	test-libudev \
	test-udev

test_libudev_SOURCES = \
	src/test/test-libudev.c

test_libudev_LDADD = \
	libsystemd-label.la \
	libudev-internal.la \
	libsystemd-shared.la

test_udev_SOURCES = \
	src/test/test-udev.c

test_udev_LDADD = \
	libudev-core.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS) \
	$(SELINUX_LIBS)

if HAVE_ACL
test_udev_LDADD += \
	libsystemd-acl.la
endif

check_DATA += \
	test/sys

# packed sysfs test tree
test/sys:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)tar -C test/ -xJf $(top_srcdir)/test/sys.tar.xz

test-sys-distclean:
	-rm -rf test/sys
DISTCLEAN_LOCAL_HOOKS += test-sys-distclean

EXTRA_DIST += \
	test/sys.tar.xz \
	test/udev-test.pl \
	test/rules-test.sh \
	test/rule-syntax-check.py

# ------------------------------------------------------------------------------
ata_id_SOURCES = \
	src/udev/ata_id/ata_id.c

ata_id_LDADD = \
	libudev-internal.la \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	ata_id

# ------------------------------------------------------------------------------
cdrom_id_SOURCES = \
	src/udev/cdrom_id/cdrom_id.c

cdrom_id_LDADD = \
	libudev-internal.la \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	cdrom_id

dist_udevrules_DATA += \
	rules/60-cdrom_id.rules

# ------------------------------------------------------------------------------
collect_SOURCES = \
	src/udev/collect/collect.c

collect_LDADD = \
	libudev-internal.la \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	collect

# ------------------------------------------------------------------------------
scsi_id_SOURCES =\
	src/udev/scsi_id/scsi_id.c \
	src/udev/scsi_id/scsi_serial.c \
	src/udev/scsi_id/scsi.h \
	src/udev/scsi_id/scsi_id.h

scsi_id_LDADD = \
	libudev-internal.la \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	scsi_id

EXTRA_DIST += \
	src/udev/scsi_id/README

# ------------------------------------------------------------------------------
v4l_id_SOURCES = \
	src/udev/v4l_id/v4l_id.c

v4l_id_LDADD = \
	libudev-internal.la

udevlibexec_PROGRAMS += \
	v4l_id

dist_udevrules_DATA += \
	rules/60-persistent-v4l.rules

# ------------------------------------------------------------------------------
accelerometer_SOURCES = \
	src/udev/accelerometer/accelerometer.c

accelerometer_LDADD = \
	libudev-internal.la -lm \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	accelerometer

dist_udevrules_DATA += \
	rules/61-accelerometer.rules

# ------------------------------------------------------------------------------
if ENABLE_GUDEV
if ENABLE_GTK_DOC
SUBDIRS += \
	docs/gudev
endif

libgudev_includedir = \
	$(includedir)/gudev-1.0/gudev

libgudev_include_HEADERS = \
	src/gudev/gudev.h \
	src/gudev/gudevenums.h \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevtypes.h \
	src/gudev/gudevclient.h \
	src/gudev/gudevdevice.h \
	src/gudev/gudevenumerator.h

lib_LTLIBRARIES += libgudev-1.0.la

pkgconfiglib_DATA += \
	src/gudev/gudev-1.0.pc

CLEANFILES += \
	src/gudev/gudev-1.0.pc

libgudev_1_0_la_SOURCES = \
	src/gudev/libgudev-1.0.sym \
	src/gudev/gudevenums.h \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevenumtypes.h\
	src/gudev/gudevtypes.h \
	src/gudev/gudevclient.h \
	src/gudev/gudevclient.c \
	src/gudev/gudevdevice.h \
	src/gudev/gudevdevice.c \
	src/gudev/gudevenumerator.h \
	src/gudev/gudevenumerator.c \
	src/gudev/gudevprivate.h

nodist_libgudev_1_0_la_SOURCES = \
	src/gudev/gudevmarshal.h \
	src/gudev/gudevmarshal.c \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevenumtypes.c

BUILT_SOURCES += \
	$(nodist_libgudev_1_0_la_SOURCES)

libgudev_1_0_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_builddir)/src\
	-I$(top_srcdir)/src\
	-I$(top_builddir)/src/gudev \
	-I$(top_srcdir)/src/gudev \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
	-D_GUDEV_COMPILATION \
	-DG_LOG_DOMAIN=\"GUdev\"

libgudev_1_0_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(GLIB_CFLAGS)

libgudev_1_0_la_LIBADD = \
	libudev.la \
	$(GLIB_LIBS)

libgudev_1_0_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBGUDEV_CURRENT):$(LIBGUDEV_REVISION):$(LIBGUDEV_AGE) \
	-export-dynamic \
	-no-undefined \
	-Wl,--version-script=$(top_srcdir)/src/gudev/libgudev-1.0.sym

src/gudev/gudevmarshal.h: src/gudev/gudevmarshal.list
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)glib-genmarshal $< --prefix=g_udev_marshal --header > $@

src/gudev/gudevmarshal.c: src/gudev/gudevmarshal.list
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)echo '#include "gudevmarshal.h"' > $@ && \
	glib-genmarshal $< --prefix=g_udev_marshal --body >> $@

src/gudev/gudevenumtypes.%: src/gudev/gudevenumtypes.%.template src/gudev/gudevenums.h
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)glib-mkenums --template $^ > $@

if HAVE_INTROSPECTION
-include $(INTROSPECTION_MAKEFILE)

src/gudev/GUdev-1.0.gir: libgudev-1.0.la

src_gudev_GUdev_1_0_gir_INCLUDES = GObject-2.0

src_gudev_GUdev_1_0_gir_CFLAGS = \
	$(AM_CFLAGS) \
	$(INCLUDES) \
	-D_GUDEV_COMPILATION \
	-D_GUDEV_WORK_AROUND_DEV_T_BUG \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src/gudev \
	-I$(top_builddir)/src/gudev

src_gudev_GUdev_1_0_gir_LIBS = libgudev-1.0.la

src_gudev_GUdev_1_0_gir_SCANNERFLAGS = \
	--pkg-export=gudev-1.0 \
	--warn-all

src_gudev_GUdev_1_0_gir_FILES = \
	src/gudev/gudev.h \
	src/gudev/gudevtypes.h \
	src/gudev/gudevenums.h \
	src/gudev/gudevenumtypes.h \
	src/gudev/gudevclient.h \
	src/gudev/gudevdevice.h \
	src/gudev/gudevenumerator.h \
	src/gudev/gudevclient.c \
	src/gudev/gudevdevice.c \
	src/gudev/gudevenumerator.c

INTROSPECTION_GIRS = src/gudev/GUdev-1.0.gir
INTROSPECTION_SCANNER_ARGS = --c-include=gudev/gudev.h

girdir = $(datadir)/gir-1.0
gir_DATA = \
	src/gudev/GUdev-1.0.gir

typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = \
	src/gudev/GUdev-1.0.typelib

CLEANFILES += $(gir_DATA) $(typelibs_DATA)
endif # HAVE_INTROSPECTION

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libgudev-install-hook:
	libname=libgudev-1.0.so && $(move-to-rootlibdir)

libgudev-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libgudev-1.0.so*

INSTALL_EXEC_HOOKS += libgudev-install-hook
UNINSTALL_EXEC_HOOKS += libgudev-uninstall-hook
endif

EXTRA_DIST += \
	src/gudev/gudev-1.0.pc.in \
	src/gudev/gudevmarshal.list \
	src/gudev/gudevenumtypes.h.template \
	src/gudev/gudevenumtypes.c.template \
	src/gudev/gjs-example.js \
	src/gudev/seed-example-enum.js \
	src/gudev/seed-example.js

# ------------------------------------------------------------------------------
mtd_probe_SOURCES =  \
	src/udev/mtd_probe/mtd_probe.c \
	src/udev/mtd_probe/mtd_probe.h \
	src/udev/mtd_probe/probe_smartmedia.c

dist_udevrules_DATA += \
	rules/75-probe_mtd.rules

udevlibexec_PROGRAMS += \
	mtd_probe

# ------------------------------------------------------------------------------
test_id128_SOURCES = \
	src/test/test-id128.c

test_id128_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

tests += \
	test-id128

# ------------------------------------------------------------------------------

rootlibexec_PROGRAMS += \
	systemd-activate

systemd_activate_SOURCES = \
	src/activate/activate.c

systemd_activate_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_journald_SOURCES = \
	src/journal/journald.c \
	src/journal/journald-server.h

systemd_journald_LDADD = \
	libsystemd-journal-core.la \
	libsystemd-internal.la \
	libsystemd-shared.la

systemd_cat_SOURCES = \
	src/journal/cat.c

systemd_cat_LDADD = \
	libsystemd-journal-core.la

if HAVE_MICROHTTPD
rootlibexec_PROGRAMS += \
	systemd-journal-remote

systemd_journal_remote_SOURCES = \
	src/journal/journal-remote-parse.h \
	src/journal/journal-remote-parse.c \
	src/journal/journal-remote-write.h \
	src/journal/journal-remote-write.c \
	src/journal/journal-remote.c

systemd_journal_remote_LDADD = \
	libsystemd-internal.la \
	libsystemd-journal-core.la

systemd_journal_remote_SOURCES += \
	src/journal/microhttpd-util.h \
	src/journal/microhttpd-util.c

systemd_journal_remote_CFLAGS = \
	$(AM_CFLAGS) \
	$(MICROHTTPD_CFLAGS)

systemd_journal_remote_LDADD += \
	$(MICROHTTPD_LIBS)

if HAVE_GNUTLS
systemd_journal_remote_LDADD += \
	$(GNUTLS_LIBS)
endif
endif

# using _CFLAGS = in the conditional below would suppress AM_CFLAGS
journalctl_CFLAGS = \
	$(AM_CFLAGS)

journalctl_SOURCES = \
	src/journal/journalctl.c

journalctl_LDADD = \
	libsystemd-journal-internal.la \
	libsystemd-internal.la \
	libsystemd-logs.la \
	libsystemd-shared.la

if HAVE_ACL
journalctl_LDADD += \
	libsystemd-acl.la
endif

if HAVE_QRENCODE
journalctl_SOURCES += \
	src/journal/journal-qrcode.c \
	src/journal/journal-qrcode.h

journalctl_CFLAGS += \
	$(QRENCODE_CFLAGS)

journalctl_LDADD += \
	$(QRENCODE_LIBS)
endif

test_journal_SOURCES = \
	src/journal/test-journal.c

test_journal_LDADD = \
	libsystemd-journal-core.la

test_journal_send_SOURCES = \
	src/journal/test-journal-send.c

test_journal_send_LDADD = \
	libsystemd-journal-core.la

test_journal_syslog_SOURCES = \
	src/journal/test-journal-syslog.c

test_journal_syslog_LDADD = \
	libsystemd-journal-core.la

test_journal_match_SOURCES = \
	src/journal/test-journal-match.c

test_journal_match_LDADD = \
	libsystemd-journal-core.la

test_journal_enum_SOURCES = \
	src/journal/test-journal-enum.c

test_journal_enum_LDADD = \
	libsystemd-journal-core.la

test_journal_stream_SOURCES = \
	src/journal/test-journal-stream.c

test_journal_stream_LDADD = \
	libsystemd-journal-core.la

test_journal_flush_SOURCES = \
	src/journal/test-journal-flush.c

test_journal_flush_LDADD = \
	libsystemd-journal-core.la

test_journal_init_SOURCES = \
	src/journal/test-journal-init.c

test_journal_init_LDADD = \
	libsystemd-journal-core.la

test_journal_verify_SOURCES = \
	src/journal/test-journal-verify.c

test_journal_verify_LDADD = \
	libsystemd-journal-core.la

test_journal_interleaving_SOURCES = \
	src/journal/test-journal-interleaving.c

test_journal_interleaving_LDADD = \
	libsystemd-journal-core.la

test_mmap_cache_SOURCES = \
	src/journal/test-mmap-cache.c

test_mmap_cache_LDADD = \
	libsystemd-journal-core.la

test_catalog_SOURCES = \
	src/journal/test-catalog.c

test_catalog_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DCATALOG_DIR=\"$(abs_top_srcdir)/catalog\"

test_catalog_LDADD = \
	libsystemd-journal-core.la

if HAVE_XZ
test_compress_SOURCES = \
	src/journal/test-compress.c

test_compress_LDADD = \
	libsystemd-journal-internal.la \
	libsystemd-shared.la
endif

libsystemd_journal_core_la_SOURCES = \
	src/journal/journald-kmsg.c \
	src/journal/journald-kmsg.h \
	src/journal/journald-syslog.c \
	src/journal/journald-syslog.h \
	src/journal/journald-stream.c \
	src/journal/journald-stream.h \
	src/journal/journald-server.c \
	src/journal/journald-server.h \
	src/journal/journald-console.c \
	src/journal/journald-console.h \
	src/journal/journald-wall.c \
	src/journal/journald-wall.h \
	src/journal/journald-native.c \
	src/journal/journald-native.h \
	src/journal/journald-rate-limit.c \
	src/journal/journald-rate-limit.h \
	src/journal/journal-internal.h

nodist_libsystemd_journal_core_la_SOURCES = \
	src/journal/journald-gperf.c

libsystemd_journal_core_la_LIBADD = \
	libsystemd-journal-internal.la \
	libudev-internal.la \
	libsystemd-capability.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

if HAVE_ACL
libsystemd_journal_core_la_LIBADD += \
	libsystemd-acl.la
endif

noinst_LTLIBRARIES += \
	libsystemd-journal-core.la

journal-install-hook:
	-$(MKDIR_P) $(DESTDIR)/var/log/journal
	-chown 0:0 $(DESTDIR)/var/log/journal
	-chmod 755 $(DESTDIR)/var/log/journal
	-setfacl -nm g:adm:rx,d:g:adm:rx $(DESTDIR)/var/log/journal/
	-setfacl -nm g:wheel:rx,d:g:wheel:rx $(DESTDIR)/var/log/journal/

journal-uninstall-hook:
	-rmdir $(DESTDIR)/var/log/journal/

INSTALL_EXEC_HOOKS += journal-install-hook
UNINSTALL_EXEC_HOOKS += journal-uninstall-hook

# ------------------------------------------------------------------------------
# Update catalog on installation. Do not bother if installing
# in DESTDIR, since this is likely for packaging purposes.
catalog-update-hook:
	-test -n "$(DESTDIR)" || $(rootbindir)/journalctl --update-catalog

INSTALL_DATA_HOOKS += \
	catalog-update-hook

catalog-remove-hook:
	-test -n "$(DESTDIR)" || rm -f $(catalogstatedir)/database

UNINSTALL_DATA_HOOKS += \
	catalog-remove-hook

manual_tests += \
	test-journal-enum

tests += \
	test-journal \
	test-journal-send \
	test-journal-syslog \
	test-journal-match \
	test-journal-stream \
	test-journal-init \
	test-journal-verify \
	test-journal-interleaving \
	test-journal-flush \
	test-mmap-cache \
	test-catalog

if HAVE_XZ
tests += test-compress
endif

pkginclude_HEADERS += \
	src/systemd/sd-journal.h \
	src/systemd/sd-messages.h \
	src/systemd/_sd-common.h

libsystemd_journal_internal_la_SOURCES = \
	src/journal/sd-journal.c \
	src/systemd/sd-journal.h \
	src/systemd/_sd-common.h \
	src/journal/journal-file.c \
	src/journal/journal-file.h \
	src/journal/journal-vacuum.c \
	src/journal/journal-vacuum.h \
	src/journal/journal-verify.c \
	src/journal/journal-verify.h \
	src/journal/lookup3.c \
	src/journal/lookup3.h \
	src/journal/journal-send.c \
	src/journal/journal-def.h \
	src/journal/compress.h \
	src/journal/catalog.c \
	src/journal/catalog.h \
	src/journal/mmap-cache.c \
	src/journal/mmap-cache.h

# using _CFLAGS = in the conditional below would suppress AM_CFLAGS
libsystemd_journal_internal_la_CFLAGS = \
	$(AM_CFLAGS)

libsystemd_journal_internal_la_LIBADD =

if HAVE_XZ
libsystemd_journal_internal_la_SOURCES += \
	src/journal/compress.c

libsystemd_journal_internal_la_CFLAGS += \
	$(XZ_CFLAGS)

libsystemd_journal_internal_la_LIBADD += \
	$(XZ_LIBS)
endif

if HAVE_GCRYPT
libsystemd_journal_internal_la_SOURCES += \
	src/journal/journal-authenticate.c \
	src/journal/journal-authenticate.h \
	src/journal/fsprg.c \
	src/journal/fsprg.h

libsystemd_journal_internal_la_LIBADD += \
	$(GCRYPT_LIBS)

# fsprg.c is a drop-in file using void pointer arithmetic
libsystemd_journal_internal_la_CFLAGS += \
	$(GCRYPT_CFLAGS) \
	-Wno-pointer-arith
endif

noinst_LTLIBRARIES += \
	libsystemd-journal-internal.la

rootlibexec_PROGRAMS += \
	systemd-journald

rootbin_PROGRAMS += \
	journalctl

bin_PROGRAMS += \
	systemd-cat

dist_systemunit_DATA += \
	units/systemd-journald.socket \
	units/systemd-journald-dev-log.socket

nodist_systemunit_DATA += \
	units/systemd-journald.service \
	units/systemd-journal-flush.service \
	units/systemd-journal-catalog-update.service

dist_pkgsysconf_DATA += \
	src/journal/journald.conf

dist_catalog_DATA = \
	catalog/systemd.fr.catalog \
	catalog/systemd.ru.catalog \
	catalog/systemd.it.catalog \
	catalog/systemd.catalog

SOCKETS_TARGET_WANTS += \
	systemd-journald.socket \
	systemd-journald-dev-log.socket

SYSINIT_TARGET_WANTS += \
	systemd-journald.service \
	systemd-journal-flush.service \
	systemd-journal-catalog-update.service

EXTRA_DIST += \
	units/systemd-journald.service.in \
	units/systemd-journal-flush.service.in \
	units/systemd-journal-catalog-update.service.in \
	src/journal/journald-gperf.gperf

CLEANFILES += \
	src/journal/journald-gperf.c

# ------------------------------------------------------------------------------
if HAVE_MICROHTTPD
gatewayddocumentrootdir=$(pkgdatadir)/gatewayd

rootlibexec_PROGRAMS += \
	systemd-journal-gatewayd

systemd_journal_gatewayd_SOURCES = \
	src/journal/journal-gatewayd.c \
	src/journal/microhttpd-util.h \
	src/journal/microhttpd-util.c

systemd_journal_gatewayd_LDADD = \
	libsystemd-logs.la \
	libsystemd-journal-internal.la \
	libsystemd-internal.la \
	libsystemd-shared.la \
	$(MICROHTTPD_LIBS)

if HAVE_GNUTLS
systemd_journal_gatewayd_LDADD += \
	$(GNUTLS_LIBS)
endif

systemd_journal_gatewayd_CFLAGS = \
	$(AM_CFLAGS) \
	$(MICROHTTPD_CFLAGS)

systemd_journal_gatewayd_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DDOCUMENT_ROOT=\"$(gatewayddocumentrootdir)\"

dist_systemunit_DATA += \
	units/systemd-journal-gatewayd.socket

nodist_systemunit_DATA += \
	units/systemd-journal-gatewayd.service

dist_gatewayddocumentroot_DATA = \
	src/journal/browse.html

endif

EXTRA_DIST += \
	units/systemd-journal-gatewayd.service.in

# ------------------------------------------------------------------------------

systemd_socket_proxyd_SOURCES = \
	src/socket-proxy/socket-proxyd.c

systemd_socket_proxyd_LDADD = \
	libsystemd-logs.la \
	libsystemd-internal.la \
	libsystemd-journal-internal.la \
	libsystemd-shared.la \
	libsystemd-resolve.la

# ------------------------------------------------------------------------------
if ENABLE_COREDUMP
systemd_coredump_SOURCES = \
	src/journal/coredump.c \
	src/journal/coredump-vacuum.c \
	src/journal/coredump-vacuum.h

systemd_coredump_LDADD = \
	libsystemd-journal-internal.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

if HAVE_ELFUTILS
systemd_coredump_SOURCES += \
	src/journal/stacktrace.c \
	src/journal/stacktrace.h

systemd_coredump_LDADD += \
	$(ELFUTILS_LIBS)
endif

rootlibexec_PROGRAMS += \
	systemd-coredump

dist_pkgsysconf_DATA += \
	src/journal/coredump.conf

if HAVE_ACL
systemd_coredump_LDADD += \
	libsystemd-acl.la
endif

coredumpctl_SOURCES = \
	src/journal/coredumpctl.c

coredumpctl_LDADD = \
	libsystemd-journal-internal.la \
	libsystemd-internal.la \
	libsystemd-shared.la

bin_PROGRAMS += \
	coredumpctl

manual_tests += \
	test-coredump-vacuum

test_coredump_vacuum_SOURCES = \
	src/journal/test-coredump-vacuum.c  \
	src/journal/coredump-vacuum.c \
	src/journal/coredump-vacuum.h

test_coredump_vacuum_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

dist_bashcompletion_DATA += \
	shell-completion/bash/coredumpctl

dist_zshcompletion_DATA += \
	shell-completion/zsh/_coredumpctl

GENERAL_ALIASES += \
	$(bindir)/coredumpctl $(bindir)/systemd-coredumpctl

sysctl_DATA = \
	sysctl.d/50-coredump.conf

CLEANFILES += \
	sysctl.d/50-coredump.conf
endif

EXTRA_DIST += \
	sysctl.d/50-coredump.conf.in

# ------------------------------------------------------------------------------
if ENABLE_BINFMT
systemd_binfmt_SOURCES = \
	src/binfmt/binfmt.c

systemd_binfmt_LDADD = \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-binfmt

dist_systemunit_DATA += \
	units/proc-sys-fs-binfmt_misc.automount \
	units/proc-sys-fs-binfmt_misc.mount

nodist_systemunit_DATA += \
	units/systemd-binfmt.service

INSTALL_DIRS += \
	$(prefix)/lib/binfmt.d \
	$(sysconfdir)/binfmt.d

SYSINIT_TARGET_WANTS += \
	systemd-binfmt.service \
	proc-sys-fs-binfmt_misc.automount

endif

EXTRA_DIST += \
	units/systemd-binfmt.service.in

# ------------------------------------------------------------------------------
if ENABLE_VCONSOLE
systemd_vconsole_setup_SOURCES = \
	src/vconsole/vconsole-setup.c

systemd_vconsole_setup_LDADD = \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-vconsole-setup

nodist_systemunit_DATA += \
	units/systemd-vconsole-setup.service

SYSINIT_TARGET_WANTS += \
	systemd-vconsole-setup.service
endif

EXTRA_DIST += \
	units/systemd-vconsole-setup.service.in

# ------------------------------------------------------------------------------
if ENABLE_READAHEAD
systemd_readahead_SOURCES = \
	src/readahead/readahead.c \
	src/readahead/readahead-collect.c \
	src/readahead/readahead-replay.c \
	src/readahead/readahead-analyze.c \
	src/readahead/readahead-common.c \
	src/readahead/readahead-common.h

systemd_readahead_LDADD = \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la

dist_doc_DATA += \
	src/readahead/sd-readahead.c \
	src/systemd/sd-readahead.h

rootlibexec_PROGRAMS += \
	systemd-readahead

dist_systemunit_DATA += \
	units/systemd-readahead-drop.service \
	units/systemd-readahead-done.timer

nodist_systemunit_DATA += \
	units/systemd-readahead-collect.service \
	units/systemd-readahead-replay.service \
	units/systemd-readahead-done.service

manual_tests += \
	test-ssd

test_ssd_SOURCES = \
	src/readahead/test-ssd.c \
	src/readahead/readahead-common.c \
	src/readahead/readahead-common.h

test_ssd_LDADD = \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la

endif

EXTRA_DIST += \
	units/systemd-readahead-collect.service.in \
	units/systemd-readahead-replay.service.in \
	units/systemd-readahead-done.service.in

# ------------------------------------------------------------------------------
if ENABLE_BOOTCHART
systemd_bootchart_SOURCES = \
	src/bootchart/bootchart.c \
	src/bootchart/bootchart.h \
	src/bootchart/store.c \
	src/bootchart/store.h \
	src/bootchart/svg.c \
	src/bootchart/svg.h

systemd_bootchart_LDADD = \
	libsystemd-journal-internal.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-bootchart

dist_pkgsysconf_DATA += \
	src/bootchart/bootchart.conf
endif

# ------------------------------------------------------------------------------
if ENABLE_QUOTACHECK
rootlibexec_PROGRAMS += \
	systemd-quotacheck

nodist_systemunit_DATA += \
	units/systemd-quotacheck.service

systemd_quotacheck_SOURCES = \
	src/quotacheck/quotacheck.c

systemd_quotacheck_LDADD = \
	libsystemd-shared.la
endif

EXTRA_DIST += \
	units/systemd-quotacheck.service.in

nodist_systemunit_DATA += \
	units/quotaon.service

# ------------------------------------------------------------------------------
if ENABLE_RANDOMSEED
rootlibexec_PROGRAMS += \
	systemd-random-seed

nodist_systemunit_DATA += \
	units/systemd-random-seed.service

systemd_random_seed_SOURCES = \
	src/random-seed/random-seed.c

systemd_random_seed_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

SYSINIT_TARGET_WANTS += \
	systemd-random-seed.service

endif

EXTRA_DIST += \
	units/systemd-random-seed.service.in

# ------------------------------------------------------------------------------
if ENABLE_BACKLIGHT
rootlibexec_PROGRAMS += \
	systemd-backlight

nodist_systemunit_DATA += \
	units/systemd-backlight@.service

systemd_backlight_SOURCES = \
	src/backlight/backlight.c

systemd_backlight_LDADD = \
	libsystemd-label.la \
	libudev-internal.la \
	libsystemd-shared.la
endif

EXTRA_DIST += \
	units/systemd-backlight@.service.in

# ------------------------------------------------------------------------------
if ENABLE_RFKILL
rootlibexec_PROGRAMS += \
	systemd-rfkill

nodist_systemunit_DATA += \
	units/systemd-rfkill@.service

systemd_rfkill_SOURCES = \
	src/rfkill/rfkill.c

systemd_rfkill_LDADD = \
	libsystemd-label.la \
	libudev-internal.la \
	libsystemd-shared.la
endif

EXTRA_DIST += \
	units/systemd-rfkill@.service.in

# ------------------------------------------------------------------------------
if HAVE_LIBCRYPTSETUP
rootlibexec_PROGRAMS += \
	systemd-cryptsetup

systemgenerator_PROGRAMS += \
	systemd-cryptsetup-generator

dist_systemunit_DATA += \
	units/cryptsetup.target \
	units/cryptsetup-pre.target

systemd_cryptsetup_SOURCES = \
	src/cryptsetup/cryptsetup.c

systemd_cryptsetup_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBCRYPTSETUP_CFLAGS)

systemd_cryptsetup_LDADD = \
	libsystemd-label.la \
	libudev-internal.la \
	libsystemd-shared.la \
	$(LIBCRYPTSETUP_LIBS)

systemd_cryptsetup_generator_SOURCES = \
	src/cryptsetup/cryptsetup-generator.c

systemd_cryptsetup_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

SYSINIT_TARGET_WANTS += \
	cryptsetup.target

endif

# ------------------------------------------------------------------------------
if ENABLE_HOSTNAMED
systemd_hostnamed_SOURCES = \
	src/hostname/hostnamed.c

systemd_hostnamed_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-hostnamed

nodist_systemunit_DATA += \
	units/systemd-hostnamed.service

dist_systemunit_DATA += \
	units/org.freedesktop.hostname1.busname

dist_dbuspolicy_DATA += \
	src/hostname/org.freedesktop.hostname1.conf

dist_dbussystemservice_DATA += \
	src/hostname/org.freedesktop.hostname1.service

polkitpolicy_files += \
	src/hostname/org.freedesktop.hostname1.policy

SYSTEM_UNIT_ALIASES += \
	systemd-hostnamed.service dbus-org.freedesktop.hostname1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.hostname1.busname

hostnamectl_SOURCES = \
	src/hostname/hostnamectl.c

hostnamectl_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

bin_PROGRAMS += \
	hostnamectl

dist_bashcompletion_DATA += \
	shell-completion/bash/hostnamectl

dist_zshcompletion_DATA += \
	shell-completion/zsh/_hostnamectl

endif

polkitpolicy_in_files += \
	src/hostname/org.freedesktop.hostname1.policy.in

EXTRA_DIST += \
	units/systemd-hostnamed.service.in

# ------------------------------------------------------------------------------
if ENABLE_KDBUS
dist_systemunit_DATA += \
	units/org.freedesktop.systemd1.busname

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.systemd1.busname
endif

# ------------------------------------------------------------------------------
if ENABLE_LOCALED
systemd_localed_SOURCES = \
	src/locale/localed.c

systemd_localed_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

nodist_systemunit_DATA += \
	units/systemd-localed.service

dist_systemunit_DATA += \
	units/org.freedesktop.locale1.busname

rootlibexec_PROGRAMS += \
	systemd-localed

dist_dbuspolicy_DATA += \
	src/locale/org.freedesktop.locale1.conf

dist_dbussystemservice_DATA += \
	src/locale/org.freedesktop.locale1.service

polkitpolicy_files += \
	src/locale/org.freedesktop.locale1.policy

SYSTEM_UNIT_ALIASES += \
	systemd-localed.service dbus-org.freedesktop.locale1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.locale1.busname

dist_pkgdata_DATA += \
	src/locale/kbd-model-map

dist_noinst_SCRIPT = \
	src/locale/generate-kbd-model-map

update-kbd-model-map: src/locale/generate-kbd-model-map
	$PYTHON $< >src/locale/kbd-model-map

localectl_SOURCES = \
	src/locale/localectl.c

localectl_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

bin_PROGRAMS += \
	localectl

dist_bashcompletion_DATA += \
	shell-completion/bash/localectl

dist_zshcompletion_DATA += \
	shell-completion/zsh/_localectl

endif

.PHONY: update-kbd-model-map

polkitpolicy_in_files += \
	src/locale/org.freedesktop.locale1.policy.in

EXTRA_DIST += \
	units/systemd-localed.service.in

# ------------------------------------------------------------------------------
if ENABLE_TIMEDATED
systemd_timedated_SOURCES = \
	src/timedate/timedated.c

systemd_timedated_LDADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-timedated

dist_dbussystemservice_DATA += \
	src/timedate/org.freedesktop.timedate1.service

dist_dbuspolicy_DATA += \
	src/timedate/org.freedesktop.timedate1.conf

nodist_systemunit_DATA += \
	units/systemd-timedated.service

dist_systemunit_DATA += \
	units/org.freedesktop.timedate1.busname

polkitpolicy_files += \
	src/timedate/org.freedesktop.timedate1.policy

INSTALL_DIRS += \
	$(prefix)/lib/systemd/ntp-units.d \
	$(sysconfdir)/systemd/ntp-units.d

SYSTEM_UNIT_ALIASES += \
	systemd-timedated.service dbus-org.freedesktop.timedate1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.timedate1.busname

timedatectl_SOURCES = \
	src/timedate/timedatectl.c

timedatectl_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

bin_PROGRAMS += \
	timedatectl

dist_bashcompletion_DATA += \
	shell-completion/bash/timedatectl

dist_zshcompletion_DATA += \
	shell-completion/zsh/_timedatectl
endif

polkitpolicy_in_files += \
	src/timedate/org.freedesktop.timedate1.policy.in

EXTRA_DIST += \
	units/systemd-timedated.service.in

# ------------------------------------------------------------------------------
if ENABLE_TIMESYNCD
systemd_timesyncd_SOURCES = \
	src/timesync/timesyncd.c \
	src/timesync/timesyncd.h

nodist_systemd_timesyncd_SOURCES = \
	src/timesync/timesyncd-gperf.c

EXTRA_DIST += \
	src/timesync/timesyncd-gperf.gperf

CLEANFILES += \
	src/timesync/timesyncd-gperf.c

systemd_timesyncd_LDADD = \
	libsystemd-resolve.la \
	libsystemd-network.la \
	libsystemd-label.la \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libsystemd-shared.la \
	-lm

rootlibexec_PROGRAMS += \
	systemd-timesyncd

nodist_systemunit_DATA += \
	units/systemd-timesyncd.service

GENERAL_ALIASES += \
	$(systemunitdir)/systemd-timesyncd.service $(pkgsysconfdir)/system/multi-user.target.wants/systemd-timesyncd.service

EXTRA_DIST += \
	units/systemd-timesyncd.service.in

nodist_pkgsysconf_DATA += \
	src/timesync/timesyncd.conf

EXTRA_DIST += \
	src/timesync/timesyncd.conf.in

CLEANFILES += \
	src/timesync/timesyncd.conf

dist_ntpunits_DATA = \
	src/timesync/90-systemd.list

endif

# ------------------------------------------------------------------------------
if HAVE_MYHOSTNAME
libnss_myhostname_la_SOURCES = \
	src/nss-myhostname/nss-myhostname.c \
	src/nss-myhostname/ifconf.h \
	src/nss-myhostname/netlink.c

libnss_myhostname_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.2

libnss_myhostname_la_LIBADD = \
	libsystemd-shared.la \
	libsystemd-internal.la

lib_LTLIBRARIES += \
	libnss_myhostname.la
endif

# ------------------------------------------------------------------------------
if ENABLE_MACHINED
systemd_machined_SOURCES = \
	src/machine/machined.c \
	src/machine/machined.h

systemd_machined_LDADD = \
	libsystemd-machine-core.la

rootlibexec_PROGRAMS += \
	systemd-machined

libsystemd_machine_core_la_SOURCES = \
	src/machine/machined-dbus.c \
	src/machine/machine.c \
	src/machine/machine.h \
	src/machine/machine-dbus.c

libsystemd_machine_core_la_LIBADD = \
	libsystemd-label.la \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la

noinst_LTLIBRARIES += \
	libsystemd-machine-core.la

machinectl_SOURCES = \
	src/machine/machinectl.c

machinectl_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	machinectl

dist_bashcompletion_DATA += \
	shell-completion/bash/machinectl

test_machine_tables_SOURCES = \
	src/machine/test-machine-tables.c

test_machine_tables_LDADD = \
	libsystemd-machine-core.la

tests += \
	test-machine-tables

nodist_systemunit_DATA += \
	units/systemd-machined.service

dist_systemunit_DATA += \
	units/machine.slice \
	units/org.freedesktop.machine1.busname

dist_dbussystemservice_DATA += \
	src/machine/org.freedesktop.machine1.service

dist_dbuspolicy_DATA += \
	src/machine/org.freedesktop.machine1.conf

dist_zshcompletion_DATA += \
	shell-completion/zsh/_machinectl \
	shell-completion/zsh/_sd_machines

SYSTEM_UNIT_ALIASES += \
	systemd-machined.service dbus-org.freedesktop.machine1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.machine1.busname

EXTRA_DIST += \
	units/systemd-machined.service.in

endif

# ------------------------------------------------------------------------------
if ENABLE_RESOLVED
systemd_resolved_SOURCES = \
	src/resolve/resolved.h \
	src/resolve/resolved.c \
	src/resolve/resolved-manager.c

systemd_resolved_CFLAGS = \
	$(AM_CFLAGS) \
	$(KMOD_CFLAGS)

nodist_systemd_resolved_SOURCES = \
	src/resolve/resolved-gperf.c

EXTRA_DIST += \
	src/resolve/resolved-gperf.gperf

CLEANFILES += \
	src/resolve/resolved-gperf.c

systemd_resolved_LDADD = \
	libsystemd-capability.la \
	libsystemd-network.la \
	libsystemd-label.la \
	libsystemd-internal.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-resolved

nodist_systemunit_DATA += \
	units/systemd-resolved.service

EXTRA_DIST += \
	units/systemd-resolved.service.in

GENERAL_ALIASES += \
	$(systemunitdir)/systemd-resolved.service $(pkgsysconfdir)/system/multi-user.target.wants/systemd-resolved.service

nodist_pkgsysconf_DATA += \
	src/resolve/resolved.conf

EXTRA_DIST += \
	src/resolve/resolved.conf.in

CLEANFILES += \
	src/resolve/resolved.conf

endif

# ------------------------------------------------------------------------------
if ENABLE_NETWORKD
rootlibexec_PROGRAMS += \
	systemd-networkd

systemd_networkd_SOURCES = \
	src/network/networkd.c

systemd_networkd_LDADD = \
	libsystemd-networkd-core.la \
	libsystemd-capability.la

noinst_LTLIBRARIES += \
	libsystemd-networkd-core.la

libsystemd_networkd_core_la_CFLAGS = \
	$(AM_CFLAGS)

libsystemd_networkd_core_la_SOURCES = \
	src/libsystemd-network/network-internal.h \
	src/network/networkd.h \
	src/network/networkd-link.c \
	src/network/networkd-netdev.c \
	src/network/networkd-tunnel.c \
	src/network/networkd-veth.c \
	src/network/networkd-vxlan.c \
	src/network/networkd-vlan.c \
	src/network/networkd-macvlan.c \
	src/network/networkd-dummy.c \
	src/network/networkd-tuntap.c \
	src/network/networkd-network.c \
	src/network/networkd-address.c \
	src/network/networkd-route.c \
	src/network/networkd-manager.c \
	src/network/networkd-address-pool.c

nodist_libsystemd_networkd_core_la_SOURCES = \
	src/network/networkd-network-gperf.c \
	src/network/networkd-netdev-gperf.c

libsystemd_networkd_core_la_LIBADD = \
	libudev-internal.la \
	libsystemd-internal.la \
	libsystemd-network.la \
	libsystemd-label.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-networkd-wait-online

systemd_networkd_wait_online_CFLAGS = \
	$(AM_CFLAGS)

systemd_networkd_wait_online_SOURCES = \
	src/libsystemd-network/network-internal.h \
	src/network/networkd-wait-online.c \
	src/network/networkd-wait-online.h

systemd_networkd_wait_online_LDADD = \
	libsystemd-network.la \
	libudev-internal.la \
	libsystemd-internal.la \
	libsystemd-shared.la

test_network_SOURCES = \
	src/network/test-network.c

test_network_CFLAGS = \
	$(AM_CFLAGS)

test_network_LDADD = \
	libsystemd-networkd-core.la

tests += \
	test-network

nodist_systemunit_DATA += \
	units/systemd-networkd.service \
	units/systemd-networkd-wait-online.service

GENERAL_ALIASES += \
	$(systemunitdir)/systemd-networkd.service $(pkgsysconfdir)/system/multi-user.target.wants/systemd-networkd.service \
	$(systemunitdir)/systemd-networkd-wait-online.service $(pkgsysconfdir)/system/network-online.target.wants/systemd-networkd-wait-online.service

EXTRA_DIST += \
	src/network/networkd-network-gperf.gperf \
	src/network/networkd-netdev-gperf.gperf \
	units/systemd-networkd.service.in \
	units/systemd-networkd-wait-online.service.in

CLEANFILES += \
	src/network/networkd-network-gperf.c \
	src/network/networkd-netdev-gperf.c
endif

# ------------------------------------------------------------------------------
if ENABLE_LOGIND
systemd_logind_SOURCES = \
	src/login/logind.c \
	src/login/logind.h

nodist_systemd_logind_SOURCES = \
	src/login/logind-gperf.c

systemd_logind_LDADD = \
	libsystemd-logind-core.la

libsystemd_logind_core_la_SOURCES = \
	src/login/logind-core.c \
	src/login/logind-device.c \
	src/login/logind-device.h \
	src/login/logind-button.c \
	src/login/logind-button.h \
	src/login/logind-action.c \
	src/login/logind-action.h \
	src/login/logind-seat.c \
	src/login/logind-seat.h \
	src/login/logind-session.c \
	src/login/logind-session.h \
	src/login/logind-session-device.c \
	src/login/logind-session-device.h \
	src/login/logind-user.c \
	src/login/logind-user.h \
	src/login/logind-inhibit.c \
	src/login/logind-inhibit.h \
	src/login/logind-dbus.c \
	src/login/logind-session-dbus.c \
	src/login/logind-seat-dbus.c \
	src/login/logind-user-dbus.c \
	src/login/logind-acl.h

libsystemd_logind_core_la_LIBADD = \
	libsystemd-label.la \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la

if HAVE_ACL
libsystemd_logind_core_la_SOURCES += \
	src/login/logind-acl.c

libsystemd_logind_core_la_LIBADD += \
	libsystemd-acl.la
endif

noinst_LTLIBRARIES += \
	libsystemd-logind-core.la

systemd_user_sessions_SOURCES = \
	src/login/user-sessions.c

systemd_user_sessions_LDADD = \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-logind \
	systemd-user-sessions

loginctl_SOURCES = \
	src/login/loginctl.c \
	src/login/sysfs-show.c

loginctl_LDADD = \
	libsystemd-internal.la \
	libudev-internal.la \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	loginctl

dist_bashcompletion_DATA += \
	shell-completion/bash/loginctl

dist_zshcompletion_DATA += \
	shell-completion/zsh/_loginctl \
	shell-completion/zsh/_systemd-inhibit

systemd_inhibit_SOURCES = \
	src/login/inhibit.c

systemd_inhibit_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	systemd-inhibit

test_login_SOURCES = \
	src/libsystemd/sd-login/test-login.c

test_login_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_login_shared_SOURCES = \
	src/login/test-login-shared.c

test_login_shared_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_inhibit_SOURCES = \
	src/login/test-inhibit.c

test_inhibit_LDADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

test_login_tables_SOURCES = \
	src/login/test-login-tables.c

test_login_tables_LDADD = \
	libsystemd-logind-core.la

manual_tests += \
	test-login \
	test-inhibit

tests += \
	test-login-tables \
	test-login-shared

if HAVE_PAM
pam_systemd_la_SOURCES = \
	src/login/pam_systemd.sym \
	src/login/pam_systemd.c

pam_systemd_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PAM_CFLAGS) \
	-fvisibility=hidden

pam_systemd_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-Wl,--version-script=$(top_srcdir)/src/login/pam_systemd.sym

pam_systemd_la_LIBADD = \
	libsystemd-capability.la \
	libsystemd-internal.la \
	libsystemd-shared.la \
	$(PAM_LIBS)

pamlib_LTLIBRARIES = \
	pam_systemd.la

dist_pamconf_DATA = \
	src/login/systemd-user
endif

nodist_systemunit_DATA += \
	units/systemd-logind.service \
	units/systemd-user-sessions.service

dist_systemunit_DATA += \
	units/user.slice \
	units/org.freedesktop.login1.busname

dist_dbussystemservice_DATA += \
	src/login/org.freedesktop.login1.service

dist_dbuspolicy_DATA += \
	src/login/org.freedesktop.login1.conf

dist_pkgsysconf_DATA += \
	src/login/logind.conf

polkitpolicy_files += \
	src/login/org.freedesktop.login1.policy

INSTALL_DIRS += \
	$(systemdstatedir)

MULTI_USER_TARGET_WANTS += \
	systemd-logind.service \
	systemd-user-sessions.service

SYSTEM_UNIT_ALIASES += \
	systemd-logind.service dbus-org.freedesktop.login1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.login1.busname

if ENABLE_MULTI_SEAT_X

systemd_multi_seat_x_SOURCES = \
	src/login/multi-seat-x.c

systemd_multi_seat_x_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-multi-seat-x

endif

dist_udevrules_DATA += \
	src/login/70-uaccess.rules \
	src/login/70-power-switch.rules

nodist_udevrules_DATA += \
	src/login/71-seat.rules \
	src/login/73-seat-late.rules

CLEANFILES += \
	src/login/logind-gperf.c \
	src/login/71-seat.rules \
	src/login/73-seat-late.rules
endif

polkitpolicy_in_files += \
	src/login/org.freedesktop.login1.policy.in

EXTRA_DIST += \
	src/login/logind-gperf.gperf \
	src/login/71-seat.rules.in \
	src/login/73-seat-late.rules.in \
	units/systemd-logind.service.in \
	units/systemd-user-sessions.service.in

# ------------------------------------------------------------------------------
if HAVE_PYTHON_DEVEL
pkgpyexec_LTLIBRARIES = \
	_journal.la \
	id128.la \
	_daemon.la \
	_reader.la \
	login.la

_journal_la_SOURCES = \
	src/python-systemd/_journal.c

_journal_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(PYTHON_DEVEL_CFLAGS)

_journal_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

_journal_la_LIBADD = \
	$(PYTHON_DEVEL_LIBS) \
	libsystemd.la

id128_la_SOURCES = \
	src/python-systemd/id128.c \
	src/python-systemd/pyutil.c \
	src/python-systemd/pyutil.h

nodist_id128_la_SOURCES = \
	src/python-systemd/id128-constants.h

id128_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(PYTHON_DEVEL_CFLAGS) \
	-I$(top_builddir)/src/python-systemd

id128_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

id128_la_LIBADD = \
	$(PYTHON_DEVEL_LIBS) \
	libsystemd-shared.la \
	libsystemd.la

_daemon_la_SOURCES = \
	src/python-systemd/_daemon.c \
	src/python-systemd/pyutil.c \
	src/python-systemd/pyutil.h

_daemon_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(PYTHON_DEVEL_CFLAGS) \
	-I$(top_builddir)/src/python-systemd

_daemon_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

_daemon_la_LIBADD = \
	$(PYTHON_DEVEL_LIBS) \
	libsystemd-shared.la \
	libsystemd.la

_reader_la_SOURCES = \
	src/python-systemd/_reader.c \
	src/python-systemd/pyutil.c \
	src/python-systemd/pyutil.h

_reader_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(PYTHON_DEVEL_CFLAGS)

_reader_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

_reader_la_LIBADD = \
	$(PYTHON_DEVEL_LIBS) \
	libsystemd-shared.la \
	libsystemd.la

login_la_SOURCES = \
	src/python-systemd/login.c \
	src/python-systemd/pyutil.c \
	src/python-systemd/pyutil.h

login_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default \
	$(PYTHON_DEVEL_CFLAGS)

login_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

login_la_LIBADD = \
	$(PYTHON_DEVEL_LIBS) \
	libsystemd-shared.la \
	libsystemd.la

dist_pkgpyexec_PYTHON = \
	src/python-systemd/journal.py \
	src/python-systemd/daemon.py \
	src/python-systemd/__init__.py

src/python-systemd/id128-constants.h: src/systemd/sd-messages.h
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(SED) -n -r 's/,//g; s/#define (SD_MESSAGE_[A-Z0-9_]+)\s.*/add_id(m, "\1", \1) JOINER/p' <$< >$@

BUILT_SOURCES += \
	src/python-systemd/id128-constants.h

SPHINXOPTS = -D version=$(VERSION) -D release=$(VERSION)
sphinx-%:
	$(AM_V_at)test -n "$(SPHINX_BUILD)" || { echo " *** sphinx-build is not available"; exit 1; }
	$(AM_V_GEN)PYTHONPATH=$(DESTDIR)$(pyexecdir) LD_LIBRARY_PATH=$(DESTDIR)$(libdir) $(SPHINX_BUILD) -b $* $(SPHINXOPTS) $(top_srcdir)/src/python-systemd/docs $(top_builddir)/docs/html/python-systemd/
	$(AM_V_at)echo Output has been generated in $(abs_top_builddir)/docs/html/python-systemd/

python-shell:
	$(AM_V_at)echo "Starting python with $(DESTDIR)$(pyexecdir)"
	$(AM_V_at)PYTHONPATH=$(DESTDIR)$(pyexecdir) LD_LIBRARY_PATH=$(DESTDIR)$(libdir) $(PYTHON)

destdir-sphinx: all
	dir="$$(mktemp -d /tmp/systemd-install.XXXXXX)" && \
		$(MAKE) DESTDIR="$$dir" install && \
		$(MAKE) DESTDIR="$$dir" sphinx-html && \
		rm -rf "$$dir"

endif

CLEAN_LOCAL_HOOKS += clean-sphinx

.PHONY: python-shell destdir-sphinx clean-sphinx clean-python

clean-sphinx:
	-rm -rf docs/html/python-systemd/

# Remove Python stuff, e.g. to force rebuilding for a different Python version.
clean-python:
	-rm -rf src/python-systemd/.libs src/python-systemd/*.l[ao]
	-rm -f _daemon.la id128.la _journal.la login.la _reader.la

# ------------------------------------------------------------------------------
if ENABLE_COMPAT_LIBS
EXTRA_DIST += \
	src/compat-libs/linkwarning.h

libsystemd-%.c: src/compat-libs/libsystemd-%.sym
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed -r -n 's/^ +(sd_.*);/obsolete_lib(\1,$(notdir $(basename $<)));/p' <$< >$@

BUILT_SOURCES += \
	libsystemd-journal.c \
	libsystemd-login.c \
	libsystemd-id128.c \
	libsystemd-daemon.c

libsystemd_journal_la_SOURCES = \
	libsystemd-journal.c \
	src/compat-libs/libsystemd-journal.sym

libsystemd_journal_la_CPPFLAGS = \
	$(AM_CFLAGS) \
	-imacros$(top_srcdir)/src/compat-libs/linkwarning.h

libsystemd_journal_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBSYSTEMD_JOURNAL_CURRENT):$(LIBSYSTEMD_JOURNAL_REVISION):$(LIBSYSTEMD_JOURNAL_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/compat-libs/libsystemd-journal.sym

libsystemd_journal_la_LIBADD = \
	libsystemd-journal-internal.la \
	libsystemd-internal.la \
	libsystemd-shared.la

libsystemd_login_la_SOURCES = \
	libsystemd-login.c \
	src/compat-libs/libsystemd-login.sym

libsystemd_login_la_CPPFLAGS = \
	$(AM_CFLAGS) \
	-imacros$(top_srcdir)/src/compat-libs/linkwarning.h

libsystemd_login_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBSYSTEMD_LOGIN_CURRENT):$(LIBSYSTEMD_LOGIN_REVISION):$(LIBSYSTEMD_LOGIN_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/compat-libs/libsystemd-login.sym

libsystemd_login_la_LIBADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

libsystemd_id128_la_SOURCES = \
	libsystemd-id128.c \
	src/compat-libs/libsystemd-id128.sym

libsystemd_id128_la_CPPFLAGS = \
	$(AM_CFLAGS) \
	-imacros$(top_srcdir)/src/compat-libs/linkwarning.h

libsystemd_id128_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBSYSTEMD_ID128_CURRENT):$(LIBSYSTEMD_ID128_REVISION):$(LIBSYSTEMD_ID128_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/compat-libs/libsystemd-id128.sym

libsystemd_id128_la_LIBADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

libsystemd_daemon_la_SOURCES = \
	libsystemd-daemon.c \
	src/compat-libs/libsystemd-daemon.sym

libsystemd_daemon_la_CPPFLAGS = \
	$(AM_CFLAGS) \
	-imacros$(top_srcdir)/src/compat-libs/linkwarning.h

libsystemd_daemon_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBSYSTEMD_DAEMON_CURRENT):$(LIBSYSTEMD_DAEMON_REVISION):$(LIBSYSTEMD_DAEMON_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/compat-libs/libsystemd-daemon.sym

libsystemd_daemon_la_LIBADD = \
	libsystemd-internal.la \
	libsystemd-shared.la

lib_LTLIBRARIES += \
	libsystemd-journal.la \
	libsystemd-login.la \
	libsystemd-id128.la \
	libsystemd-daemon.la

pkgconfiglib_DATA += \
	src/compat-libs/libsystemd-journal.pc \
	src/compat-libs/libsystemd-login.pc \
	src/compat-libs/libsystemd-id128.pc \
	src/compat-libs/libsystemd-daemon.pc

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
compat-lib-install-hook:
	libname=libsystemd-login.so && $(move-to-rootlibdir)
	libname=libsystemd-journal.so && $(move-to-rootlibdir)
	libname=libsystemd-id128.so && $(move-to-rootlibdir)
	libname=libsystemd-daemon.so && $(move-to-rootlibdir)

compat-lib-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-login.so*
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-journal.so*
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-id128.so*
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-daemon.so*

INSTALL_EXEC_HOOKS += compat-lib-install-hook
UNINSTALL_EXEC_HOOKS += compat-lib-uninstall-hook
endif

EXTRA_DIST += \
	src/compat-libs/libsystemd-journal.pc.in \
	src/compat-libs/libsystemd-login.pc.in \
	src/compat-libs/libsystemd-id128.pc.in \
	src/compat-libs/libsystemd-daemon.pc.in

# ------------------------------------------------------------------------------
substitutions = \
       '|rootlibexecdir=$(rootlibexecdir)|' \
       '|rootbindir=$(rootbindir)|' \
       '|bindir=$(bindir)|' \
       '|SYSTEMCTL=$(rootbindir)/systemctl|' \
       '|SYSTEMD_NOTIFY=$(rootbindir)/systemd-notify|' \
       '|pkgsysconfdir=$(pkgsysconfdir)|' \
       '|SYSTEM_CONFIG_UNIT_PATH=$(pkgsysconfdir)/system|' \
       '|USER_CONFIG_UNIT_PATH=$(pkgsysconfdir)/user|' \
       '|pkgdatadir=$(pkgdatadir)|' \
       '|systemunitdir=$(systemunitdir)|' \
       '|userunitdir=$(userunitdir)|' \
       '|systempresetdir=$(systempresetdir)|' \
       '|userpresetdir=$(userpresetdir)|' \
       '|udevhwdbdir=$(udevhwdbdir)|' \
       '|udevrulesdir=$(udevrulesdir)|' \
       '|catalogdir=$(catalogdir)|' \
       '|tmpfilesdir=$(tmpfilesdir)|' \
       '|sysusersdir=$(sysusersdir)|' \
       '|sysctldir=$(sysctldir)|' \
       '|systemgeneratordir=$(systemgeneratordir)|' \
       '|usergeneratordir=$(usergeneratordir)|' \
       '|PACKAGE_VERSION=$(PACKAGE_VERSION)|' \
       '|PACKAGE_NAME=$(PACKAGE_NAME)|' \
       '|PACKAGE_URL=$(PACKAGE_URL)|' \
       '|RANDOM_SEED_DIR=$(localstatedir)/lib/systemd/|' \
       '|RANDOM_SEED=$(localstatedir)/lib/systemd/random-seed|' \
       '|prefix=$(prefix)|' \
       '|exec_prefix=$(exec_prefix)|' \
       '|libdir=$(libdir)|' \
       '|includedir=$(includedir)|' \
       '|VERSION=$(VERSION)|' \
       '|rootprefix=$(rootprefix)|' \
       '|udevlibexecdir=$(udevlibexecdir)|' \
       '|SUSHELL=$(SUSHELL)|' \
       '|DEBUGTTY=$(DEBUGTTY)|' \
       '|KILL=$(KILL)|' \
       '|KMOD=$(KMOD)|' \
       '|MKDIR_P=$(MKDIR_P)|' \
       '|QUOTAON=$(QUOTAON)|' \
       '|QUOTACHECK=$(QUOTACHECK)|' \
       '|SYSTEM_SYSVINIT_PATH=$(sysvinitdir)|' \
       '|VARLOGDIR=$(varlogdir)|' \
       '|RC_LOCAL_SCRIPT_PATH_START=$(RC_LOCAL_SCRIPT_PATH_START)|' \
       '|RC_LOCAL_SCRIPT_PATH_STOP=$(RC_LOCAL_SCRIPT_PATH_STOP)|' \
       '|PYTHON=$(PYTHON)|' \
       '|PYTHON_BINARY=$(PYTHON_BINARY)|' \
       '|NTP_SERVERS=$(NTP_SERVERS)|' \
       '|DNS_SERVERS=$(DNS_SERVERS)|' \
       '|systemuidmax=$(SYSTEM_UID_MAX)|' \
       '|systemgidmax=$(SYSTEM_GID_MAX)|' \
       '|TTY_GID=$(TTY_GID)|' \
       '|systemsleepdir=$(systemsleepdir)|' \
       '|systemshutdowndir=$(systemshutdowndir)|' \
       '|binfmtdir=$(binfmtdir)|' \
       '|modulesloaddir=$(modulesloaddir)|'

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED) $(subst '|,-e 's|@,$(subst =,\@|,$(subst |',|g',$(substitutions)))) \
		< $< > $@

units/%: units/%.in
	$(SED_PROCESS)

man/%: man/%.in
	$(SED_PROCESS)

sysctl.d/%: sysctl.d/%.in
	$(SED_PROCESS)

%.pc: %.pc.in
	$(SED_PROCESS)

src/core/macros.%: src/core/macros.%.in
	$(SED_PROCESS)

src/%.policy.in: src/%.policy.in.in
	$(SED_PROCESS)

%.rules: %.rules.in
	$(SED_PROCESS)

%.conf: %.conf.in
	$(SED_PROCESS)

%.sh: %.sh.in
	$(SED_PROCESS)
	$(AM_V_GEN)chmod +x $@

src/%.c: src/%.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) < $< > $@

src/%: src/%.m4
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) < $< > $@

units/%: units/%.m4
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) -DFOR_SYSTEM=1 < $< > $@

units/user/%: units/%.m4
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) -DFOR_USER=1 < $< > $@

if ENABLE_POLKIT
dist_polkitpolicy_DATA = \
	$(polkitpolicy_files) \
	$(polkitpolicy_in_in_files:.policy.in.in=.policy)
endif

EXTRA_DIST += \
	$(polkitpolicy_in_files) \
	$(polkitpolicy_in_in_files)

CLEANFILES += \
	$(nodist_systemunit_DATA) \
	$(nodist_userunit_DATA) \
	$(pkgconfigdata_DATA) \
	$(pkgconfiglib_DATA) \
	$(nodist_polkitpolicy_DATA)

# ------------------------------------------------------------------------------
if ENABLE_MANPAGES
man/custom-entities.ent: configure.ac
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)(echo '<?xml version="1.0" encoding="utf-8" ?>' && \
	 printf '$(subst '|,<!ENTITY ,$(subst =, ",$(subst |',">\n,$(substitutions))))') \
	 > $@ # '

DISTCLEANFILES += \
	man/custom-entities.ent

XSLTPROC_FLAGS = \
	--nonet \
	--xinclude \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0 \
	--stringparam systemd.version $(VERSION) \
	--path '$(builddir)/man:$(srcdir)/man'

XSLTPROC_PROCESS_MAN = \
	$(AM_V_XSLT)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-man.xsl $<

XSLTPROC_PROCESS_HTML = \
	$(AM_V_XSLT)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-html.xsl $<

man/%.1: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.3: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.5: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.7: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.8: man/%.xml man/custom-man.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_MAN)

man/%.html: man/%.xml man/custom-html.xsl man/custom-entities.ent
	$(XSLTPROC_PROCESS_HTML)

define html-alias
	$(AM_V_LN)$(LN_S) -f $(notdir $<) $@
endef

endif

EXTRA_DIST += \
	man/custom-html.xsl \
	man/custom-man.xsl

# ------------------------------------------------------------------------------
if HAVE_SYSV_COMPAT
sysvinit_DATA = \
	docs/sysvinit/README

varlog_DATA = \
	docs/var-log/README

docs/sysvinit/README: docs/sysvinit/README.in
	$(SED_PROCESS)

docs/var-log/README: docs/var-log/README.in
	$(SED_PROCESS)

CLEANFILES += \
	docs/sysvinit/README \
	docs/var-log/README
endif

EXTRA_DIST += \
	docs/sysvinit/README.in \
	docs/var-log/README.in

SOCKETS_TARGET_WANTS += \
	systemd-initctl.socket \
	systemd-shutdownd.socket

if HAVE_SYSV_COMPAT
RUNLEVEL1_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
RUNLEVEL2_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
RUNLEVEL3_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
RUNLEVEL4_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
RUNLEVEL5_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
endif

SYSINIT_TARGET_WANTS += \
	systemd-update-utmp.service \
	systemd-update-done.service \
	ldconfig.service

LOCAL_FS_TARGET_WANTS += \
	systemd-remount-fs.service \
	tmp.mount

MULTI_USER_TARGET_WANTS += \
	getty.target \
	systemd-ask-password-wall.path

SYSINIT_TARGET_WANTS += \
	dev-hugepages.mount \
	dev-mqueue.mount \
	sys-kernel-config.mount \
	sys-kernel-debug.mount \
	sys-fs-fuse-connections.mount \
	systemd-sysctl.service \
	systemd-ask-password-console.path

if HAVE_SYSV_COMPAT
SYSTEM_UNIT_ALIASES += \
	poweroff.target runlevel0.target \
	rescue.target runlevel1.target \
	multi-user.target runlevel2.target \
	multi-user.target runlevel3.target \
	multi-user.target runlevel4.target \
	graphical.target runlevel5.target \
	reboot.target runlevel6.target
endif

SYSTEM_UNIT_ALIASES += \
	graphical.target default.target \
	reboot.target ctrl-alt-del.target \
	getty@.service autovt@.service

USER_UNIT_ALIASES += \
	$(systemunitdir)/shutdown.target shutdown.target \
	$(systemunitdir)/sockets.target sockets.target \
	$(systemunitdir)/busnames.target busnames.target \
	$(systemunitdir)/timers.target timers.target \
	$(systemunitdir)/paths.target paths.target \
	$(systemunitdir)/bluetooth.target bluetooth.target \
	$(systemunitdir)/printer.target printer.target \
	$(systemunitdir)/sound.target sound.target \
	$(systemunitdir)/smartcard.target smartcard.target

GENERAL_ALIASES += \
	$(systemunitdir)/remote-fs.target $(pkgsysconfdir)/system/multi-user.target.wants/remote-fs.target \
	$(systemunitdir)/getty@.service $(pkgsysconfdir)/system/getty.target.wants/getty@tty1.service \
	$(pkgsysconfdir)/user $(sysconfdir)/xdg/systemd/user \
	$(dbussystemservicedir)/org.freedesktop.systemd1.service $(dbussessionservicedir)/org.freedesktop.systemd1.service

if HAVE_SYSV_COMPAT
INSTALL_DIRS += \
	$(systemunitdir)/runlevel1.target.wants \
	$(systemunitdir)/runlevel2.target.wants \
	$(systemunitdir)/runlevel3.target.wants \
	$(systemunitdir)/runlevel4.target.wants \
	$(systemunitdir)/runlevel5.target.wants
endif

INSTALL_DIRS += \
	$(prefix)/lib/modules-load.d \
	$(sysconfdir)/modules-load.d \
	$(prefix)/lib/systemd/network \
	$(sysconfdir)/systemd/network \
	$(prefix)/lib/sysctl.d \
	$(sysconfdir)/sysctl.d \
	$(prefix)/lib/kernel/install.d \
	$(sysconfdir)/kernel/install.d \
	$(systemshutdowndir) \
	$(systemsleepdir) \
	$(systemgeneratordir) \
	$(usergeneratordir) \
	\
	$(userunitdir) \
	$(pkgsysconfdir)/system \
	$(pkgsysconfdir)/system/multi-user.target.wants \
	$(pkgsysconfdir)/system/getty.target.wants \
	$(pkgsysconfdir)/user \
	$(dbussessionservicedir) \
	$(sysconfdir)/xdg/systemd

install-exec-hook: $(INSTALL_EXEC_HOOKS)

uninstall-hook: $(UNINSTALL_DATA_HOOKS) $(UNINSTALL_EXEC_HOOKS)

install-data-hook: $(INSTALL_DATA_HOOKS)

distclean-local: $(DISTCLEAN_LOCAL_HOOKS)

clean-local: $(CLEAN_LOCAL_HOOKS)
	rm -rf $(abs_srcdir)/install-tree
	rm -f $(abs_srcdir)/hwdb/usb.ids $(abs_srcdir)/hwdb/pci.ids $(abs_srcdir)/hwdb/oui.txt \
	      $(abs_srcdir)/hwdb/iab.txt

DISTCHECK_CONFIGURE_FLAGS = \
	--with-dbuspolicydir=$$dc_install_base/$(dbuspolicydir) \
	--with-dbussessionservicedir=$$dc_install_base/$(dbussessionservicedir) \
	--with-dbussystemservicedir=$$dc_install_base/$(dbussystemservicedir) \
	--with-bashcompletiondir=$$dc_install_base/$(bashcompletiondir) \
	--with-zshcompletiondir=$$dc_install_base/$(zshcompletiondir) \
	--with-pamlibdir=$$dc_install_base/$(pamlibdir) \
	--with-pamconfdir=$$dc_install_base/$(pamconfdir) \
	--with-rootprefix=$$dc_install_base \
	--disable-split-usr \
	--enable-kdbus \
	--enable-compat-libs

if HAVE_SYSV_COMPAT
DISTCHECK_CONFIGURE_FLAGS += \
	--with-sysvinit-path=$$dc_install_base/$(sysvinitdir) \
	--with-sysvrcnd-path=$$dc_install_base/$(sysvrcnddir)
else
DISTCHECK_CONFIGURE_FLAGS += \
	--with-sysvinit-path= \
	--with-sysvrcnd-path=
endif

if HAVE_PYTHON
DISTCHECK_CONFIGURE_FLAGS += \
	--with-python
endif

if ENABLE_GTK_DOC
DISTCHECK_CONFIGURE_FLAGS += \
	--enable-gtk-doc
endif

#
# Require python when making dist
#
.PHONY: dist-check-python
dist-check-python:
if !HAVE_PYTHON
	@echo "*** python and python-lxml module must be installed and enabled in order to make dist"
	@false
endif

dist-check-compat-libs:
if !ENABLE_COMPAT_LIBS
	@echo "*** compat-libs must be enabled in order to make dist"
	@false
endif

dist: dist-check-python dist-check-compat-libs

# check "broken" platforms limited toolchains for link breakage before we release
.PHONY: linkcheck
linkcheck:
	$(MAKE) CFLAGS='-fno-lto' LDFLAGS='-Wl,-fuse-ld=gold -Wl,--as-needed -Wl,--no-gc-sections' distcheck

.PHONY: hwdb-update
hwdb-update:
	( cd $(top_srcdir)/hwdb && \
	wget -N http://www.linux-usb.org/usb.ids \
		http://pci-ids.ucw.cz/v2.2/pci.ids \
		http://standards.ieee.org/develop/regauth/oui/oui.txt \
		http://standards.ieee.org/develop/regauth/iab/iab.txt && \
	./ids-update.pl )

.PHONY: kdbus-update
kdbus-update:
	( cd $(top_srcdir)/src/libsystemd/sd-bus/ && \
	wget -N https://d-bus.googlecode.com/git/kdbus.h )

.PHONY: git-tag
git-tag:
	git tag -s "v$(VERSION)" -m "systemd $(VERSION)"

www_target = www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd
.PHONY: upload
upload: all check dist
	scp systemd-$(VERSION).tar.xz $(www_target)

.PHONY: doc-sync
doc-sync: all destdir-sphinx
	gtkdoc-rebase --html-dir=docs/libudev/html --online
	rsync -rlv --delete docs/libudev/html/ --omit-dir-times $(www_target)/libudev/
	gtkdoc-rebase --html-dir=docs/gudev/html --online
	rsync -rlv --delete docs/gudev/html/ --omit-dir-times $(www_target)/gudev/
	rsync -rlv --delete-excluded --include="*.html" --exclude="*" --omit-dir-times man/ $(www_target)/man/
	rsync -rlv --delete --omit-dir-times docs/html/python-systemd/ $(www_target)/python-systemd/

.PHONY: tango
tango: upload
	cp -v systemd-$(VERSION).tar.xz /home/lennart/git.fedora/systemd/
	scp man/*.html tango:public/systemd-man/

.PHONY: install-tree
install-tree: all
	rm -rf $(abs_srcdir)/install-tree
	$(MAKE) install DESTDIR=$(abs_srcdir)/install-tree
	tree $(abs_srcdir)/install-tree

# Let's run all tests of the test suite, but under valgrind. Let's
# exclude the one perl script we have in there
.PHONY: valgrind-tests
valgrind-tests: $(TESTS)
	$(AM_V_GEN)for f in $(filter-out %.pl, $^); do \
		if file $$f | grep -q shell; then \
		echo -e "$${x}Skipping non-binary $$f"; else \
		echo -e "$${x}Running $$f"; \
		libtool --mode=execute valgrind -q --leak-check=full --max-stackframe=5242880 --error-exitcode=55 $(builddir)/$$f ; fi; \
		x="\n\n"; \
	done

exported-%: %
	$(AM_V_GEN)$(NM) -g --defined-only $(builddir)/.libs/$(<:.la=.so) 2>&1 /dev/null | grep " T " | cut -d" " -f3 > $@

exported: $(addprefix exported-, $(lib_LTLIBRARIES))
	$(AM_V_GEN)cat $^ > $@

.PHONY: check-api-docs
check-api-docs: exported man
	$(AM_V_GEN)for symbol in `cat exported` ; do \
		if test -f $(builddir)/man/$$symbol.html ; then \
			echo "  Symbol $$symbol() is documented." ; \
		else \
			echo "‣ Symbol $$symbol() lacks documentation." ; \
		fi ; \
	done

OBJECT_VARIABLES:=$(filter %_OBJECTS,$(.VARIABLES))
ALL_OBJECTS:=$(foreach v,$(OBJECT_VARIABLES),$($(v)))

undefined defined: $(ALL_OBJECTS)
	$(AM_V_GEN)for f in $(ALL_OBJECTS) ; do \
		$(NM) -g --$@-only `echo $(builddir)/"$$f" | sed -e 's,\([^/]*\).lo$$,.libs/\1.o,'` ; \
	done | cut -c 20- | cut -d @ -f 1 | sort -u > $@

CLEANFILES += \
	defined \
	undefined

.PHONY: check-api-unused
check-api-unused: defined undefined exported
	( cat exported undefined ) | sort -u  | diff -u - defined | grep ^+ | grep -v ^+++ | cut -c2-

.PHONY: check-includes
check-includes: $(top_srcdir)/tools/check-includes.pl
	$(AM_V_GEN) find * -name '*.[hcS]' -type f -print | sort -u \
		| xargs $(top_srcdir)/tools/check-includes.pl

EXTRA_DIST += \
	$(top_srcdir)/tools/check-includes.pl

# Stupid test that everything purported to be exported really is
define generate-sym-test
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_at)printf '#include <stdio.h>\n' > $@
	$(AM_V_at)printf '#include "%s"\n' $(notdir $(filter %.h, $^)) >> $@
	$(AM_V_at)printf 'void* functions[] = {\n' >> $@
	$(AM_V_GEN)sed -r -n 's/^ +([a-zA-Z0-9_]+);/\1,/p' $< >> $@
	$(AM_V_at)printf '};\nint main(void) {\n' >> $@
	$(AM_V_at)printf 'unsigned i; for (i=0;i<sizeof(functions)/sizeof(void*);i++) printf("%%p\\n", functions[i]);\n' >> $@
	$(AM_V_at)printf 'return 0; }\n' >> $@
endef

test-libsystemd-sym.c: \
		$(top_builddir)/src/libsystemd/libsystemd.sym \
		src/systemd/sd-journal.h \
		src/systemd/sd-daemon.h \
		src/systemd/sd-login.h \
		src/systemd/sd-bus.h \
		src/systemd/sd-utf8.h \
		src/systemd/sd-resolve.h
	$(generate-sym-test)

test-libudev-sym.c: \
		src/libudev/libudev.sym \
		src/udev/udev.h
	$(generate-sym-test)

test_libsystemd_sym_SOURCES = \
	test-libsystemd-sym.c
test_libsystemd_sym_LDADD = \
	libsystemd.la

test_libudev_sym_SOURCES = \
	test-libudev-sym.c
test_libudev_sym_CFLAGS = \
	$(AM_CFLAGS) \
	-Wno-deprecated-declarations
test_libudev_sym_LDADD = \
	libudev.la

BUILT_SOURCES += \
	$(test_libsystemd_sym_SOURCES) \
	$(test_libudev_sym_SOURCES)

tests += \
	test-libsystemd-sym \
	test-libudev-sym

.PHONY: cppcheck
cppcheck:
	cppcheck --enable=all -q $(top_srcdir)

# Used to extract compile flags for YCM.
print-%:
	@echo $($*)

git-contrib:
	@git shortlog -s `git describe --abbrev=0`.. | cut -c8- | awk '{ print $$0 "," }' | sort -u
