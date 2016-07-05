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

GCC_COLORS ?= 'ooh, shiny!'
export GCC_COLORS

SUBDIRS = . po

# remove targets if the command fails
.DELETE_ON_ERROR:

# keep intermediate files
.SECONDARY:

# Keep the test-suite.log
.PRECIOUS: $(TEST_SUITE_LOG) Makefile

LIBUDEV_CURRENT=7
LIBUDEV_REVISION=4
LIBUDEV_AGE=6

LIBSYSTEMD_CURRENT=15
LIBSYSTEMD_REVISION=0
LIBSYSTEMD_AGE=15

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
xinitrcdir=$(sysconfdir)/X11/xinit/xinitrc.d

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
factory_etcdir = $(datadir)/factory/etc
factory_pamdir = $(datadir)/factory/etc/pam.d
bootlibdir = $(prefix)/lib/systemd/boot/efi

# And these are the special ones for /
rootprefix=@rootprefix@
rootbindir=$(rootprefix)/bin
rootlibexecdir=$(rootprefix)/lib/systemd

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
rootlibexec_LTLIBRARIES =
include_HEADERS =
noinst_DATA =
pkgconfigdata_DATA =
pkgconfiglib_DATA =
polkitpolicy_in_in_files =
polkitpolicy_in_files =
polkitpolicy_files =
dist_udevrules_DATA =
nodist_udevrules_DATA =
dist_pkgsysconf_DATA =
nodist_pkgsysconf_DATA =
dist_dbuspolicy_DATA =
dist_dbussystemservice_DATA =
dist_systemunit_DATA_busnames =
dist_sysusers_DATA =
check_PROGRAMS =
check_DATA =
dist_rootlibexec_DATA =
tests=
manual_tests =
TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)
DISABLE_HARD_ERRORS = yes
if ENABLE_TESTS
noinst_PROGRAMS = $(manual_tests) $(tests) $(unsafe_tests)
TESTS = $(tests)
if ENABLE_UNSAFE_TESTS
TESTS += \
	$(unsafe_tests)
endif
else
noinst_PROGRAMS =
TESTS =
endif
AM_TESTS_ENVIRONMENT = \
	export SYSTEMD_KBD_MODEL_MAP=$(abs_top_srcdir)/src/locale/kbd-model-map; \
	export SYSTEMD_LANGUAGE_FALLBACK_MAP=$(abs_top_srcdir)/src/locale/language-fallback-map;

if ENABLE_BASH_COMPLETION
dist_bashcompletion_DATA = $(dist_bashcompletion_data)
nodist_bashcompletion_DATA = $(nodist_bashcompletion_data)
endif
if ENABLE_ZSH_COMPLETION
dist_zshcompletion_DATA = $(dist_zshcompletion_data)
nodist_zshcompletion_DATA = $(nodist_zshcompletion_data)
endif
udevlibexec_PROGRAMS =
gperf_gperf_sources =

in_files = $(filter %.in,$(EXTRA_DIST))
in_in_files = $(filter %.in.in, $(in_files))
m4_files = $(filter %.m4,$(EXTRA_DIST) $(in_files:.m4.in=.m4))

CLEANFILES = $(BUILT_SOURCES) \
	$(pkgconfigdata_DATA) \
	$(pkgconfiglib_DATA) \
	$(nodist_bashcompletion_data) \
	$(nodist_zshcompletion_data) \
	$(in_files:.in=) $(in_in_files:.in.in=) \
	$(m4_files:.m4=)

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
	-DCERTIFICATE_ROOT=\"$(CERTIFICATEROOT)\" \
	-DCATALOG_DATABASE=\"$(catalogstatedir)/database\" \
	-DSYSTEMD_CGROUP_AGENT_PATH=\"$(rootlibexecdir)/systemd-cgroups-agent\" \
	-DSYSTEMD_BINARY_PATH=\"$(rootlibexecdir)/systemd\" \
	-DSYSTEMD_FSCK_PATH=\"$(rootlibexecdir)/systemd-fsck\" \
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
	-DSYSTEMD_LANGUAGE_FALLBACK_MAP=\"$(pkgdatadir)/language-fallback-map\" \
	-DUDEVLIBEXECDIR=\"$(udevlibexecdir)\" \
	-DPOLKIT_AGENT_BINARY_PATH=\"$(bindir)/pkttyagent\" \
	-DQUOTACHECK=\"$(QUOTACHECK)\" \
	-DKEXEC=\"$(KEXEC)\" \
	-DMOUNT_PATH=\"$(MOUNT_PATH)\" \
	-DUMOUNT_PATH=\"$(UMOUNT_PATH)\" \
	-DLIBDIR=\"$(libdir)\" \
	-DROOTLIBDIR=\"$(rootlibdir)\" \
	-DROOTLIBEXECDIR=\"$(rootlibexecdir)\" \
	-DTEST_DIR=\"$(abs_top_srcdir)/test\" \
	-I $(top_srcdir)/src \
	-I $(top_builddir)/src/basic \
	-I $(top_srcdir)/src/basic \
	-I $(top_srcdir)/src/shared \
	-I $(top_builddir)/src/shared \
	-I $(top_srcdir)/src/network \
	-I $(top_srcdir)/src/locale \
	-I $(top_srcdir)/src/login \
	-I $(top_srcdir)/src/journal \
	-I $(top_builddir)/src/journal \
	-I $(top_srcdir)/src/timedate \
	-I $(top_srcdir)/src/timesync \
	-I $(top_srcdir)/src/nspawn \
	-I $(top_srcdir)/src/resolve \
	-I $(top_builddir)/src/resolve \
	-I $(top_srcdir)/src/systemd \
	-I $(top_builddir)/src/core \
	-I $(top_srcdir)/src/core \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev \
	-I $(top_srcdir)/src/udev/net \
	-I $(top_builddir)/src/udev \
	-I $(top_srcdir)/src/libsystemd/sd-bus \
	-I $(top_srcdir)/src/libsystemd/sd-event \
	-I $(top_srcdir)/src/libsystemd/sd-login \
	-I $(top_srcdir)/src/libsystemd/sd-netlink \
	-I $(top_srcdir)/src/libsystemd/sd-network \
	-I $(top_srcdir)/src/libsystemd/sd-hwdb \
	-I $(top_srcdir)/src/libsystemd/sd-device \
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

SHUTDOWN_TARGET_WANTS =
LOCAL_FS_TARGET_WANTS =
MULTI_USER_TARGET_WANTS =
GRAPHICAL_TARGET_WANTS =
RESCUE_TARGET_WANTS =
SYSINIT_TARGET_WANTS =
SOCKETS_TARGET_WANTS =
BUSNAMES_TARGET_WANTS =
TIMERS_TARGET_WANTS =
USER_SOCKETS_TARGET_WANTS =
USER_DEFAULT_TARGET_WANTS =
USER_BUSNAMES_TARGET_WANTS =

SYSTEM_UNIT_ALIASES =
USER_UNIT_ALIASES =
GENERAL_ALIASES =

install-target-wants-hook:
	what="$(SHUTDOWN_TARGET_WANTS)" && wants=shutdown.target && dir=$(systemunitdir) && $(add-wants)
	what="$(LOCAL_FS_TARGET_WANTS)" && wants=local-fs.target && dir=$(systemunitdir) && $(add-wants)
	what="$(MULTI_USER_TARGET_WANTS)" && wants=multi-user.target && dir=$(systemunitdir) && $(add-wants)
	what="$(GRAPHICAL_TARGET_WANTS)" && wants=graphical.target && dir=$(systemunitdir) && $(add-wants)
	what="$(RESCUE_TARGET_WANTS)" && wants=rescue.target && dir=$(systemunitdir) && $(add-wants)
	what="$(SYSINIT_TARGET_WANTS)" && wants=sysinit.target && dir=$(systemunitdir) && $(add-wants)
	what="$(SOCKETS_TARGET_WANTS)" && wants=sockets.target && dir=$(systemunitdir) && $(add-wants)
	what="$(TIMERS_TARGET_WANTS)" && wants=timers.target && dir=$(systemunitdir) && $(add-wants)
	what="$(SLICES_TARGET_WANTS)" && wants=slices.target && dir=$(systemunitdir) && $(add-wants)
	what="$(USER_SOCKETS_TARGET_WANTS)" && wants=sockets.target && dir=$(userunitdir) && $(add-wants)
	what="$(USER_DEFAULT_TARGET_WANTS)" && wants=default.target && dir=$(userunitdir) && $(add-wants)

install-busnames-target-wants-hook:
	what="$(BUSNAMES_TARGET_WANTS)" && wants=busnames.target && dir=$(systemunitdir) && $(add-wants)
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

INSTALL_EXEC_HOOKS += \
	install-busnames-target-wants-hook

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
	systemd-machine-id-setup \
	systemd-escape

bin_PROGRAMS = \
	systemd-cgls \
	systemd-cgtop \
	systemd-nspawn \
	systemd-detect-virt \
	systemd-delta \
	systemd-analyze \
	systemd-run \
	systemd-stdio-bridge \
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
	systemd-shutdown \
	systemd-remount-fs \
	systemd-reply-password \
	systemd-fsck \
	systemd-ac-power \
	systemd-sysctl \
	systemd-sleep \
	systemd-socket-proxyd \
	systemd-update-done

if HAVE_UTMP
rootlibexec_PROGRAMS += \
	systemd-update-utmp
endif

systemgenerator_PROGRAMS = \
	systemd-getty-generator \
	systemd-fstab-generator \
	systemd-system-update-generator \
	systemd-debug-generator

dist_bashcompletion_data = \
	shell-completion/bash/busctl \
	shell-completion/bash/journalctl \
	shell-completion/bash/systemd-analyze \
	shell-completion/bash/systemd-cat \
	shell-completion/bash/systemd-cgls \
	shell-completion/bash/systemd-cgtop \
	shell-completion/bash/systemd-delta \
	shell-completion/bash/systemd-detect-virt \
	shell-completion/bash/systemd-nspawn \
	shell-completion/bash/systemd-path \
	shell-completion/bash/systemd-run \
	shell-completion/bash/udevadm \
	shell-completion/bash/kernel-install

nodist_bashcompletion_data = \
	shell-completion/bash/systemctl

dist_zshcompletion_data = \
	shell-completion/zsh/_busctl \
	shell-completion/zsh/_journalctl \
	shell-completion/zsh/_udevadm \
	shell-completion/zsh/_kernel-install \
	shell-completion/zsh/_systemd-nspawn \
	shell-completion/zsh/_systemd-analyze \
	shell-completion/zsh/_systemd-run \
	shell-completion/zsh/_sd_hosts_or_user_at_host \
	shell-completion/zsh/_sd_outputmodes \
	shell-completion/zsh/_sd_unit_files \
	shell-completion/zsh/_systemd-delta \
	shell-completion/zsh/_systemd

nodist_zshcompletion_data = \
	shell-completion/zsh/_systemctl

EXTRA_DIST += \
	shell-completion/bash/systemctl.in \
	shell-completion/zsh/_systemctl.in

dist_sysctl_DATA = \
	sysctl.d/50-default.conf

dist_systemunit_DATA = \
	units/graphical.target \
	units/multi-user.target \
	units/emergency.target \
	units/sysinit.target \
	units/basic.target \
	units/getty.target \
	units/halt.target \
	units/kexec.target \
	units/exit.target \
	units/local-fs.target \
	units/local-fs-pre.target \
	units/initrd.target \
	units/initrd-fs.target \
	units/initrd-root-device.target \
	units/initrd-root-fs.target \
	units/remote-fs.target \
	units/remote-fs-pre.target \
	units/network.target \
	units/network-pre.target \
	units/network-online.target \
	units/nss-lookup.target \
	units/nss-user-lookup.target \
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
	units/timers.target \
	units/paths.target \
	units/suspend.target \
	units/swap.target \
	units/slices.target \
	units/system.slice \
	units/x-.slice \
	units/systemd-initctl.socket \
	units/syslog.socket \
	units/dev-hugepages.mount \
	units/dev-mqueue.mount \
	units/sys-kernel-config.mount \
	units/sys-kernel-debug.mount \
	units/sys-fs-fuse-connections.mount \
	units/tmp.mount \
	units/var-lib-machines.mount \
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
	units/machines.target

dist_systemunit_DATA += \
	$(dist_systemunit_DATA_busnames)

dist_systemunit_DATA_busnames += \
	units/busnames.target

nodist_systemunit_DATA = \
	units/getty@.service \
	units/serial-getty@.service \
	units/console-shell.service \
	units/console-getty.service \
	units/container-getty@.service \
	units/systemd-initctl.service \
	units/systemd-remount-fs.service \
	units/systemd-ask-password-wall.service \
	units/systemd-ask-password-console.service \
	units/systemd-sysctl.service \
	units/emergency.service \
	units/rescue.service \
	units/user@.service \
	units/systemd-suspend.service \
	units/systemd-halt.service \
	units/systemd-poweroff.service \
	units/systemd-reboot.service \
	units/systemd-kexec.service \
	units/systemd-exit.service \
	units/systemd-fsck@.service \
	units/systemd-fsck-root.service \
	units/systemd-machine-id-commit.service \
	units/systemd-udevd.service \
	units/systemd-udev-trigger.service \
	units/systemd-udev-settle.service \
	units/systemd-hwdb-update.service \
	units/debug-shell.service \
	units/initrd-parse-etc.service \
	units/initrd-cleanup.service \
	units/initrd-udevadm-cleanup-db.service \
	units/initrd-switch-root.service \
	units/systemd-nspawn@.service \
	units/systemd-update-done.service

if HAVE_UTMP
nodist_systemunit_DATA += \
	units/systemd-update-utmp.service \
	units/systemd-update-utmp-runlevel.service
endif

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
	units/rescue.service.in \
	units/systemd-initctl.service.in \
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
	units/systemd-exit.service.in \
	units/user/systemd-exit.service.in \
	units/systemd-fsck@.service.in \
	units/systemd-fsck-root.service.in \
	units/systemd-machine-id-commit.service.in \
	units/user@.service.m4.in \
	units/debug-shell.service.in \
	units/systemd-suspend.service.in \
	units/quotaon.service.in \
	units/initrd-parse-etc.service.in \
	units/initrd-cleanup.service.in \
	units/initrd-udevadm-cleanup-db.service.in \
	units/initrd-switch-root.service.in \
	units/systemd-nspawn@.service.in \
	units/systemd-update-done.service.in \
    units/tmp.mount.m4

if HAVE_SYSV_COMPAT
nodist_systemunit_DATA += \
	units/rc-local.service \
	units/halt-local.service

systemgenerator_PROGRAMS += \
	systemd-sysv-generator \
	systemd-rc-local-generator
endif

EXTRA_DIST += \
	src/systemctl/systemd-sysv-install.SKELETON \
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
	CODING_STYLE \
	LICENSE.LGPL2.1 \
	LICENSE.GPL2 \
	DISTRO_PORTING \
	src/libsystemd/sd-bus/PORTING-DBUS1 \
	src/libsystemd/sd-bus/DIFFERENCES \
	src/libsystemd/sd-bus/GVARIANT-SERIALIZATION

EXTRA_DIST += \
	README.md \
	autogen.sh \
	.dir-locals.el \
	.editorconfig \
	.vimrc \
	.ycm_extra_conf.py \
	.travis.yml \
	.mailmap

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
	$(HTML_ALIAS) \
	docs/html/man
endif

CLEANFILES += \
	$(man_MANS) \
	$(HTML_FILES) \
	$(HTML_ALIAS) \
	docs/html/man

docs/html/man:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_LN)$(LN_S) -f ../../man $@

man/index.html: man/systemd.index.html
	$(AM_V_LN)$(LN_S) -f systemd.index.html $@

if HAVE_PYTHON
noinst_DATA += \
	man/index.html
endif

CLEANFILES += \
	man/index.html

XML_GLOB = $(wildcard $(top_srcdir)/man/*.xml)
NON_INDEX_XML_FILES = $(filter-out man/systemd.index.xml,$(XML_FILES))
SOURCE_XML_FILES = ${patsubst %,$(top_srcdir)/%,$(filter-out man/systemd.directives.xml,$(NON_INDEX_XML_FILES))}

# This target should only be run manually. It recreates Makefile-man.am
# file in the source directory based on all man/*.xml files. Run it after
# adding, removing, or changing the conditional in a man page.
update-man-list: $(top_srcdir)/tools/make-man-rules.py $(XML_GLOB) man/custom-entities.ent
	$(AM_V_GEN)$(PYTHON) $< $(XML_GLOB) > $(top_srcdir)/Makefile-man.tmp
	$(AM_V_at)mv $(top_srcdir)/Makefile-man.tmp $(top_srcdir)/Makefile-man.am
	@echo "Makefile-man.am has been regenerated"

man/systemd.index.xml: $(top_srcdir)/tools/make-man-index.py $(NON_INDEX_XML_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $< $@ $(filter-out $<,$^)

man/systemd.directives.xml: $(top_srcdir)/tools/make-directive-index.py man/custom-entities.ent $(SOURCE_XML_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $< $@ $(SOURCE_XML_FILES)

CLEANFILES += \
	man/systemd.index.xml \
	man/systemd.directives.xml

EXTRA_DIST += \
	$(filter-out man/systemd.directives.xml man/systemd.index.xml,$(XML_FILES)) \
	tools/make-man-index.py \
	tools/make-man-rules.py \
	tools/make-directive-index.py \
	tools/xml_helper.py \
	man/glib-event-glue.c

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libbasic.la

libbasic_la_SOURCES = \
	src/basic/missing.h \
	src/basic/missing_syscall.h \
	src/basic/raw-clone.h \
	src/basic/capability-util.c \
	src/basic/capability-util.h \
	src/basic/conf-files.c \
	src/basic/conf-files.h \
	src/basic/stdio-util.h \
	src/basic/hostname-util.h \
	src/basic/hostname-util.c \
	src/basic/unit-name.c \
	src/basic/unit-name.h \
	src/basic/ioprio.h \
	src/basic/securebits.h \
	src/basic/special.h \
	src/basic/list.h \
	src/basic/unaligned.h \
	src/basic/macro.h \
	src/basic/def.h \
	src/basic/sparse-endian.h \
	src/basic/refcnt.h \
	src/basic/util.c \
	src/basic/util.h \
	src/basic/io-util.c \
	src/basic/io-util.h \
	src/basic/string-util.c \
	src/basic/string-util.h \
	src/basic/fd-util.c \
	src/basic/fd-util.h \
	src/basic/parse-util.c \
	src/basic/parse-util.h \
	src/basic/user-util.c \
	src/basic/user-util.h \
	src/basic/rlimit-util.c \
	src/basic/rlimit-util.h \
	src/basic/dirent-util.c \
	src/basic/dirent-util.h \
	src/basic/xattr-util.c \
	src/basic/xattr-util.h \
	src/basic/chattr-util.c \
	src/basic/chattr-util.h \
	src/basic/proc-cmdline.c \
	src/basic/proc-cmdline.h \
	src/basic/fs-util.c \
	src/basic/fs-util.h \
	src/basic/syslog-util.c \
	src/basic/syslog-util.h \
	src/basic/stat-util.c \
	src/basic/stat-util.h \
	src/basic/mount-util.c \
	src/basic/mount-util.h \
	src/basic/hexdecoct.c \
	src/basic/hexdecoct.h \
	src/basic/glob-util.h \
	src/basic/glob-util.c \
	src/basic/extract-word.c \
	src/basic/extract-word.h \
	src/basic/escape.c \
	src/basic/escape.h \
	src/basic/cpu-set-util.c \
	src/basic/cpu-set-util.h \
	src/basic/lockfile-util.c \
	src/basic/lockfile-util.h \
	src/basic/path-util.c \
	src/basic/path-util.h \
	src/basic/time-util.c \
	src/basic/time-util.h \
	src/basic/locale-util.c \
	src/basic/locale-util.h \
	src/basic/umask-util.h \
	src/basic/signal-util.c \
	src/basic/signal-util.h \
	src/basic/string-table.c \
	src/basic/string-table.h \
	src/basic/mempool.c \
	src/basic/mempool.h \
	src/basic/hashmap.c \
	src/basic/hashmap.h \
	src/basic/hash-funcs.c \
	src/basic/hash-funcs.h \
	src/basic/siphash24.c \
	src/basic/siphash24.h \
	src/basic/set.h \
	src/basic/ordered-set.h \
	src/basic/ordered-set.c \
	src/basic/bitmap.c \
	src/basic/bitmap.h \
	src/basic/prioq.c \
	src/basic/prioq.h \
	src/basic/web-util.c \
	src/basic/web-util.h \
	src/basic/strv.c \
	src/basic/strv.h \
	src/basic/env-util.c \
	src/basic/env-util.h \
	src/basic/strbuf.c \
	src/basic/strbuf.h \
	src/basic/strxcpyx.c \
	src/basic/strxcpyx.h \
	src/basic/log.c \
	src/basic/log.h \
	src/basic/bus-label.c \
	src/basic/bus-label.h \
	src/basic/ratelimit.h \
	src/basic/ratelimit.c \
	src/basic/exit-status.c \
	src/basic/exit-status.h \
	src/basic/virt.c \
	src/basic/virt.h \
	src/basic/architecture.c \
	src/basic/architecture.h \
	src/basic/smack-util.c \
	src/basic/smack-util.h \
	src/basic/device-nodes.c \
	src/basic/device-nodes.h \
	src/basic/utf8.c \
	src/basic/utf8.h \
	src/basic/gunicode.c \
	src/basic/gunicode.h \
	src/basic/socket-util.c \
	src/basic/socket-util.h \
	src/basic/in-addr-util.c \
	src/basic/in-addr-util.h \
	src/basic/ether-addr-util.h \
	src/basic/ether-addr-util.c \
	src/basic/replace-var.c \
	src/basic/replace-var.h \
	src/basic/clock-util.c \
	src/basic/clock-util.h \
	src/basic/calendarspec.c \
	src/basic/calendarspec.h \
	src/basic/fileio.c \
	src/basic/fileio.h \
	src/basic/MurmurHash2.c \
	src/basic/MurmurHash2.h \
	src/basic/mkdir.c \
	src/basic/mkdir.h \
	src/basic/cgroup-util.c \
	src/basic/cgroup-util.h \
	src/basic/errno-list.c \
	src/basic/errno-list.h \
	src/basic/af-list.c \
	src/basic/af-list.h \
	src/basic/arphrd-list.c \
	src/basic/arphrd-list.h \
	src/basic/terminal-util.c \
	src/basic/terminal-util.h \
	src/basic/login-util.h \
	src/basic/login-util.c \
	src/basic/cap-list.c \
	src/basic/cap-list.h \
	src/basic/audit-util.c \
	src/basic/audit-util.h \
	src/basic/xml.c \
	src/basic/xml.h \
	src/basic/barrier.c \
	src/basic/barrier.h \
	src/basic/async.c \
	src/basic/async.h \
	src/basic/memfd-util.c \
	src/basic/memfd-util.h \
	src/basic/process-util.c \
	src/basic/process-util.h \
	src/basic/random-util.c \
	src/basic/random-util.h \
	src/basic/verbs.c \
	src/basic/verbs.h \
	src/basic/sigbus.c \
	src/basic/sigbus.h \
	src/basic/build.h \
	src/basic/socket-label.c \
	src/basic/label.c \
	src/basic/label.h \
	src/basic/btrfs-util.c \
	src/basic/btrfs-util.h \
	src/basic/btrfs-ctree.h \
	src/basic/selinux-util.c \
	src/basic/selinux-util.h \
	src/basic/mkdir-label.c \
	src/basic/fileio-label.c \
	src/basic/fileio-label.h \
	src/basic/rm-rf.c \
	src/basic/rm-rf.h \
	src/basic/copy.c \
	src/basic/copy.h \
	src/basic/alloc-util.h \
	src/basic/alloc-util.c \
	src/basic/formats-util.h \
	src/basic/nss-util.h

nodist_libbasic_la_SOURCES = \
	src/basic/errno-from-name.h \
	src/basic/errno-to-name.h \
	src/basic/af-from-name.h \
	src/basic/af-to-name.h \
	src/basic/arphrd-from-name.h \
	src/basic/arphrd-to-name.h \
	src/basic/cap-from-name.h \
	src/basic/cap-to-name.h

libbasic_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SELINUX_CFLAGS) \
	$(CAP_CFLAGS) \
	-pthread

libbasic_la_LIBADD = \
	$(SELINUX_LIBS) \
	$(CAP_LIBS) \
	-lrt \
	-lm

# -----------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libshared.la

libshared_la_SOURCES = \
	src/shared/output-mode.h \
	src/shared/output-mode.c \
	src/shared/gpt.h \
	src/shared/udev-util.h \
	src/shared/linux/auto_dev-ioctl.h \
	src/shared/initreq.h \
	src/shared/dns-domain.c \
	src/shared/dns-domain.h \
	src/shared/efivars.c \
	src/shared/efivars.h \
	src/shared/fstab-util.c \
	src/shared/fstab-util.h \
	src/shared/sleep-config.c \
	src/shared/sleep-config.h \
	src/shared/conf-parser.c \
	src/shared/conf-parser.h \
	src/shared/pager.c \
	src/shared/pager.h \
	src/shared/spawn-polkit-agent.c \
	src/shared/spawn-polkit-agent.h \
	src/shared/apparmor-util.c \
	src/shared/apparmor-util.h \
	src/shared/ima-util.c \
	src/shared/ima-util.h \
	src/shared/ptyfwd.c \
	src/shared/ptyfwd.h \
	src/shared/base-filesystem.c \
	src/shared/base-filesystem.h \
	src/shared/uid-range.c \
	src/shared/uid-range.h \
	src/shared/install.c \
	src/shared/install.h \
	src/shared/install-printf.c \
	src/shared/install-printf.h \
	src/shared/path-lookup.c \
	src/shared/path-lookup.h \
	src/shared/specifier.c \
	src/shared/specifier.h \
	src/shared/dev-setup.c \
	src/shared/dev-setup.h \
	src/shared/dropin.c \
	src/shared/dropin.h \
	src/shared/condition.c \
	src/shared/condition.h \
	src/shared/clean-ipc.c \
	src/shared/clean-ipc.h \
	src/shared/generator.h \
	src/shared/generator.c \
	src/shared/acpi-fpdt.h \
	src/shared/acpi-fpdt.c \
	src/shared/boot-timestamps.h \
	src/shared/boot-timestamps.c \
	src/shared/cgroup-show.c \
	src/shared/cgroup-show.h \
	src/shared/utmp-wtmp.h \
	src/shared/watchdog.c \
	src/shared/watchdog.h \
	src/shared/spawn-ask-password-agent.c \
	src/shared/spawn-ask-password-agent.h \
	src/shared/ask-password-api.c \
	src/shared/ask-password-api.h \
	src/shared/switch-root.h \
	src/shared/switch-root.c \
	src/shared/import-util.c \
	src/shared/import-util.h \
	src/shared/sysctl-util.c \
	src/shared/sysctl-util.h \
	src/shared/bus-util.c \
	src/shared/bus-util.h \
	src/shared/logs-show.c \
	src/shared/logs-show.h \
	src/shared/machine-image.c \
	src/shared/machine-image.h \
	src/shared/machine-pool.c \
	src/shared/machine-pool.h \
	src/shared/resolve-util.c \
	src/shared/resolve-util.h \
	src/shared/bus-unit-util.c \
	src/shared/bus-unit-util.h \
	src/shared/vlan-util.h \
	src/shared/vlan-util.c \
	src/shared/tests.h \
	src/shared/tests.c \
	src/shared/fdset.c \
	src/shared/fdset.h

if HAVE_UTMP
libshared_la_SOURCES += \
	src/shared/utmp-wtmp.c
endif

if HAVE_SECCOMP
libshared_la_SOURCES += \
	src/shared/seccomp-util.h \
	src/shared/seccomp-util.c
endif

if HAVE_ACL
libshared_la_SOURCES += \
	src/shared/acl-util.c \
	src/shared/acl-util.h
endif

libshared_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(ACL_CFLAGS) \
	$(LIBIDN_CFLAGS) \
	$(SECCOMP_CFLAGS)

libshared_la_LIBADD = \
	libsystemd-internal.la \
	libbasic.la \
	libsystemd-journal-internal.la \
	libudev-internal.la \
	$(ACL_LIBS) \
	$(LIBIDN_LIBS) \
	$(SECCOMP_LIBS)

rootlibexec_LTLIBRARIES += \
	libsystemd-shared.la

libsystemd_shared_la_SOURCES = \
	$(libbasic_la_SOURCES) \
	$(libshared_la_SOURCES) \
	$(libsystemd_internal_la_SOURCES) \
	$(libsystemd_journal_internal_la_SOURCES) \
	$(libudev_internal_la_SOURCES)

libsystemd_shared_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(libbasic_la_CFLAGS) \
	$(libshared_la_CFLAGS) \
	$(libsystemd_internal_la_CFLAGS) \
	$(libsystemd_journal_internal_la_CFLAGS) \
	$(libudev_internal_la_CFLAGS) \
	$(ACL_CFLAGS) \
	$(LIBIDN_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	-fvisibility=default

# We can't use libshared_la_LIBADD here because it would
# pull in libsystemd*-internal.la
libsystemd_shared_la_LIBADD = \
	$(libbasic_la_LIBADD) \
	$(libsystemd_internal_la_LIBADD) \
	$(libsystemd_journal_internal_la_LIBADD) \
	$(libudev_internal_la_LIBADD) \
	$(ACL_LIBS) \
	$(LIBIDN_LIBS) \
	$(SECCOMP_LIBS)

libsystemd_shared_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-release $(PACKAGE_VERSION)


# -----------------------------------------------------------------------------
if HAVE_LIBIPTC
noinst_LTLIBRARIES += \
	libfirewall.la

libfirewall_la_SOURCES = \
	src/shared/firewall-util.h \
	src/shared/firewall-util.c

libfirewall_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBIPTC_CFLAGS)

libfirewall_la_LIBADD = \
	$(LIBIPTC_LIBS)
endif

# -----------------------------------------------------------------------------
if ENABLE_LDCONFIG
dist_systemunit_DATA += \
	units/ldconfig.service

SYSINIT_TARGET_WANTS += \
	ldconfig.service
endif

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libcore.la

libcore_la_SOURCES = \
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
	src/core/bus-policy.c \
	src/core/bus-policy.h \
	src/core/target.c \
	src/core/target.h \
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
	src/core/kmod-setup.c \
	src/core/kmod-setup.h \
	src/core/loopback-setup.h \
	src/core/loopback-setup.c \
	src/core/namespace.c \
	src/core/namespace.h \
	src/core/killall.h \
	src/core/killall.c \
	src/core/audit-fd.c \
	src/core/audit-fd.h \
	src/core/show-status.c \
	src/core/show-status.h \
	src/core/failure-action.c \
	src/core/failure-action.h

nodist_libcore_la_SOURCES = \
	src/core/load-fragment-gperf.c \
	src/core/load-fragment-gperf-nulstr.c

libcore_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PAM_CFLAGS) \
	$(AUDIT_CFLAGS) \
	$(KMOD_CFLAGS) \
	$(APPARMOR_CFLAGS) \
	$(MOUNT_CFLAGS) \
	$(SECCOMP_CFLAGS)

libcore_la_LIBADD = \
	libsystemd-shared.la \
	$(PAM_LIBS) \
	$(AUDIT_LIBS) \
	$(KMOD_LIBS) \
	$(APPARMOR_LIBS) \
	$(MOUNT_LIBS)

src/core/load-fragment-gperf-nulstr.c: src/core/load-fragment-gperf.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ keywords=0 ; FS="," ; print "extern const char load_fragment_gperf_nulstr[];" ; print "const char load_fragment_gperf_nulstr[] ="} ; keyword==1 { print "\"" $$1 "\\0\"" } ; /%%/ { keyword=1} ; END { print ";" }' < $< > $@

gperf_gperf_m4_sources = \
	src/core/load-fragment-gperf.gperf.m4

gperf_txt_sources = \
	src/basic/errno-list.txt \
	src/basic/af-list.txt \
	src/basic/arphrd-list.txt \
	src/basic/cap-list.txt

BUILT_SOURCES += \
	$(gperf_gperf_m4_sources:-gperf.gperf.m4=-gperf.c) \
	$(gperf_gperf_m4_sources:-gperf.gperf.m4=-gperf-nulstr.c) \
	$(gperf_gperf_sources:-gperf.gperf=-gperf.c) \
	$(gperf_txt_sources:-list.txt=-from-name.h) \
	$(filter-out %keyboard-keys-to-name.h,$(gperf_txt_sources:-list.txt=-to-name.h))

CLEANFILES += \
	$(gperf_txt_sources:-list.txt=-from-name.gperf)
DISTCLEANFILES = \
	$(gperf_txt_sources)

EXTRA_DIST += \
	$(gperf_gperf_m4_sources) \
	$(gperf_gperf_sources)

CLEANFILES += \
	$(gperf_txt_sources)

%-from-name.gperf: %-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct $(notdir $*)_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { printf "%s, %s\n", $$1, $$1 }' <$< >$@

%-from-name.h: %-from-name.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_$(notdir $*) -H hash_$(notdir $*)_name -p -C <$< >$@


src/basic/errno-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include errno.h - </dev/null | $(AWK) '/^#define[ \t]+E[^ _]+[ \t]+/ { print $$2; }' >$@

src/basic/errno-to-name.h: src/basic/errno-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "static const char* const errno_names[] = { "} !/EDEADLOCK/ && !/EWOULDBLOCK/ && !/ENOTSUP/ { printf "[%s] = \"%s\",\n", $$1, $$1 } END{print "};"}' <$< >$@


src/basic/af-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include sys/socket.h - </dev/null | grep -v AF_UNSPEC | grep -v AF_MAX | $(AWK) '/^#define[ \t]+AF_[^ \t]+[ \t]+PF_[^ \t]/ { print $$2; }' >$@

src/basic/af-to-name.h: src/basic/af-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "static const char* const af_names[] = { "} !/AF_FILE/ && !/AF_ROUTE/ && !/AF_LOCAL/ { printf "[%s] = \"%s\",\n", $$1, $$1 } END{print "};"}' <$< >$@


src/basic/arphrd-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include net/if_arp.h - </dev/null | $(AWK) '/^#define[ \t]+ARPHRD_[^ \t]+[ \t]+[^ \t]/ { print $$2; }' | sed -e 's/ARPHRD_//' >$@

src/basic/arphrd-to-name.h: src/basic/arphrd-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "static const char* const arphrd_names[] = { "} !/CISCO/ { printf "[ARPHRD_%s] = \"%s\",\n", $$1, $$1 } END{print "};"}' <$< >$@

src/basic/arphrd-from-name.gperf: src/basic/arphrd-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct arphrd_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { printf "%s, ARPHRD_%s\n", $$1, $$1 }' <$< >$@


src/basic/cap-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/capability.h -include missing.h - </dev/null | $(AWK) '/^#define[ \t]+CAP_[A-Z_]+[ \t]+/ { print $$2; }' | grep -v CAP_LAST_CAP >$@

src/basic/cap-to-name.h: src/basic/cap-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "static const char* const capability_names[] = { "} { printf "[%s] = \"%s\",\n", $$1, tolower($$1) } END{print "};"}' <$< >$@

src/basic/cap-from-name.gperf: src/basic/cap-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct capability_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { printf "%s, %s\n", $$1, $$1 }' <$< >$@

src/basic/cap-from-name.h: src/basic/cap-from-name.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_capability -H hash_capability_name -p -C <$< >$@

audit_list_includes = -include linux/audit.h -include missing.h
if HAVE_AUDIT
audit_list_includes += -include libaudit.h
endif

src/journal/audit_type-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM $(audit_list_includes) - </dev/null | grep -vE 'AUDIT_.*(FIRST|LAST)_' | $(SED) -r -n 's/^#define\s+AUDIT_(\w+)\s+([0-9]{4})\s*$$/\1\t\2/p' | sort -k2 >$@

src/journal/audit_type-to-name.h: src/journal/audit_type-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char *audit_type_to_string(int type) {\n\tswitch(type) {" } {printf "        case AUDIT_%s: return \"%s\";\n", $$1, $$1 } END{ print "        default: return NULL;\n\t}\n}\n" }' <$< >$@


src/resolve/dns_type-list.txt: src/resolve/dns-type.h
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(SED) -n -r 's/.* DNS_TYPE_(\w+).*/\1/p' <$< >$@

src/resolve/dns_type-to-name.h: src/resolve/dns_type-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char *dns_type_to_string(int type) {\n\tswitch(type) {" } {printf "        case DNS_TYPE_%s: return ", $$1; sub(/_/, "-"); printf "\"%s\";\n", $$1 } END{ print "        default: return NULL;\n\t}\n}\n" }' <$< >$@

src/resolve/dns_type-from-name.gperf: src/resolve/dns_type-list.txt
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct dns_type_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { s=$$1; sub(/_/, "-", s); printf "%s, ", $$s; printf "DNS_TYPE_%s\n", $$1 }' <$< >$@

# ------------------------------------------------------------------------------
systemd_SOURCES = \
	src/core/main.c

systemd_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(MOUNT_CFLAGS)

systemd_LDADD = \
	libcore.la

dist_pkgsysconf_DATA += \
	src/core/system.conf \
	src/core/user.conf

dist_dbuspolicy_DATA += \
	src/core/org.freedesktop.systemd1.conf

dist_dbussystemservice_DATA += \
	src/core/org.freedesktop.systemd1.service

polkitpolicy_in_in_files += \
	src/core/org.freedesktop.systemd1.policy.in.in

pkgconfigdata_DATA += \
	src/core/systemd.pc

nodist_rpmmacros_DATA = \
	src/core/macros.systemd

BUILT_SOURCES += \
	src/core/triggers.systemd

EXTRA_DIST += \
	src/core/systemd.pc.in \
	src/core/macros.systemd.in \
	src/core/triggers.systemd.in

# ------------------------------------------------------------------------------

manual_tests += \
	test-ns \
	test-cgroup \
	test-install \
	test-btrfs \
	test-acd \
	test-ipv4ll-manual \
	test-ask-password-api

unsafe_tests = \
	test-hostname \
	test-ipcrm

if HAVE_LIBIPTC
manual_tests += \
	test-firewall-util
endif

if HAVE_KMOD
manual_tests += \
	test-netlink-manual
endif

tests += \
	test-daemon \
	test-log \
	test-loopback \
	test-engine \
	test-watchdog \
	test-cgroup-mask \
	test-job-type \
	test-env-util \
	test-strbuf \
	test-strv \
	test-path \
	test-path-util \
	test-strxcpyx \
	test-siphash24 \
	test-unit-name \
	test-unit-file \
	test-utf8 \
	test-ellipsize \
	test-util \
	test-cpu-set-util \
	test-hexdecoct \
	test-escape \
	test-alloc-util \
	test-proc-cmdline \
	test-io-util \
	test-glob-util \
	test-xattr-util \
	test-fs-util \
	test-web-util \
	test-stat-util \
	test-fd-util \
	test-string-util \
	test-extract-word \
	test-parse-util \
	test-user-util \
	test-hostname-util \
	test-process-util \
	test-terminal-util \
	test-path-lookup \
	test-barrier \
	test-tmpfiles \
	test-namespace \
	test-date \
	test-sleep \
	test-replace-var \
	test-sched-prio \
	test-calendarspec \
	test-strip-tab-ansi \
	test-cgroup-util \
	test-fstab-util \
	test-prioq \
	test-fileio \
	test-time \
	test-clock \
	test-hashmap \
	test-set \
	test-bitmap \
	test-list \
	test-unaligned \
	test-tables \
	test-device-nodes \
	test-xml \
	test-architecture \
	test-socket-util \
	test-fdset \
	test-conf-files \
	test-conf-parser \
	test-capability \
	test-async \
	test-ratelimit \
	test-condition \
	test-uid-range \
	test-locale-util \
	test-execute \
	test-copy \
	test-cap-list \
	test-sigbus \
	test-verbs \
	test-af-list \
	test-arphrd-list \
	test-dns-domain \
	test-install-root \
	test-rlimit-util \
	test-signal-util \
	test-selinux \
	test-sizeof

if HAVE_ACL
tests += \
	test-acl-util
endif

EXTRA_DIST += \
	test/a.service \
	test/basic.target \
	test/b.service \
	test/c.service \
	test/daughter.service \
	test/d.service \
	test/end.service \
	test/e.service \
	test/f.service \
	test/grandchild.service \
	test/g.service \
	test/hello-after-sleep.target \
	test/hello.service \
	test/h.service \
	test/parent-deep.slice \
	test/parent.slice \
	test/sched_idle_bad.service \
	test/sched_idle_ok.service \
	test/sched_rr_bad.service \
	test/sched_rr_change.service \
	test/sched_rr_ok.service \
	test/shutdown.target \
	test/sleep.service \
	test/sockets.target \
	test/son.service \
	test/sysinit.target \
	test/testsuite.target \
	test/timers.target \
	test/unstoppable.service \
	test/test-path/paths.target \
	test/test-path/basic.target \
	test/test-path/sysinit.target \
	test/test-path/path-changed.service \
	test/test-path/path-directorynotempty.service \
	test/test-path/path-existsglob.service \
	test/test-path/path-exists.service \
	test/test-path/path-makedirectory.service \
	test/test-path/path-modified.service \
	test/test-path/path-mycustomunit.service \
	test/test-path/path-service.service \
	test/test-path/path-changed.path \
	test/test-path/path-directorynotempty.path \
	test/test-path/path-existsglob.path \
	test/test-path/path-exists.path \
	test/test-path/path-makedirectory.path \
	test/test-path/path-modified.path \
	test/test-path/path-unit.path \
	test/test-execute/exec-environment-empty.service \
	test/test-execute/exec-environment-multiple.service \
	test/test-execute/exec-environment.service \
	test/test-execute/exec-passenvironment-absent.service \
	test/test-execute/exec-passenvironment-empty.service \
	test/test-execute/exec-passenvironment-repeated.service \
	test/test-execute/exec-passenvironment.service \
	test/test-execute/exec-group.service \
	test/test-execute/exec-group-nfsnobody.service \
	test/test-execute/exec-ignoresigpipe-no.service \
	test/test-execute/exec-ignoresigpipe-yes.service \
	test/test-execute/exec-personality-x86-64.service \
	test/test-execute/exec-personality-x86.service \
	test/test-execute/exec-personality-s390.service \
	test/test-execute/exec-privatedevices-no.service \
	test/test-execute/exec-privatedevices-yes.service \
	test/test-execute/exec-privatetmp-no.service \
	test/test-execute/exec-privatetmp-yes.service \
	test/test-execute/exec-spec-interpolation.service \
	test/test-execute/exec-systemcallerrornumber.service \
	test/test-execute/exec-systemcallfilter-failing2.service \
	test/test-execute/exec-systemcallfilter-failing.service \
	test/test-execute/exec-systemcallfilter-not-failing2.service \
	test/test-execute/exec-systemcallfilter-not-failing.service \
	test/test-execute/exec-systemcallfilter-system-user.service \
	test/test-execute/exec-systemcallfilter-system-user-nfsnobody.service \
	test/test-execute/exec-user.service \
	test/test-execute/exec-user-nfsnobody.service \
	test/test-execute/exec-workingdirectory.service \
	test/test-execute/exec-umask-0177.service \
	test/test-execute/exec-umask-default.service \
	test/test-execute/exec-privatenetwork-yes.service \
	test/test-execute/exec-environmentfile.service \
	test/test-execute/exec-oomscoreadjust-positive.service \
	test/test-execute/exec-oomscoreadjust-negative.service \
	test/test-execute/exec-ioschedulingclass-best-effort.service \
	test/test-execute/exec-ioschedulingclass-idle.service \
	test/test-execute/exec-ioschedulingclass-none.service \
	test/test-execute/exec-ioschedulingclass-realtime.service \
	test/test-execute/exec-capabilityboundingset-invert.service \
	test/test-execute/exec-capabilityboundingset-merge.service \
	test/test-execute/exec-capabilityboundingset-reset.service \
	test/test-execute/exec-capabilityboundingset-simple.service \
	test/test-execute/exec-capabilityambientset.service \
	test/test-execute/exec-capabilityambientset-nfsnobody.service \
	test/test-execute/exec-capabilityambientset-merge.service \
	test/test-execute/exec-capabilityambientset-merge-nfsnobody.service \
	test/test-execute/exec-runtimedirectory.service \
	test/test-execute/exec-runtimedirectory-mode.service \
	test/test-execute/exec-runtimedirectory-owner.service \
	test/test-execute/exec-runtimedirectory-owner-nfsnobody.service \
	test/bus-policy/hello.conf \
	test/bus-policy/methods.conf \
	test/bus-policy/ownerships.conf \
	test/bus-policy/signals.conf \
	test/bus-policy/check-own-rules.conf \
	test/bus-policy/many-rules.conf \
	test/bus-policy/test.conf


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
	$(SECCOMP_CFLAGS) \
	$(MOUNT_CFLAGS)

test_engine_LDADD = \
	libcore.la

test_job_type_SOURCES = \
	src/test/test-job-type.c

test_job_type_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(MOUNT_CFLAGS)

test_job_type_LDADD = \
	libcore.la

test_ns_SOURCES = \
	src/test/test-ns.c

test_ns_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_ns_LDADD = \
	libcore.la

test_loopback_SOURCES = \
	src/test/test-loopback.c

test_loopback_LDADD = \
	libcore.la

test_hostname_SOURCES = \
	src/test/test-hostname.c

test_hostname_LDADD = \
	libcore.la

test_dns_domain_SOURCES = \
	src/test/test-dns-domain.c

test_dns_domain_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la


if ENABLE_EFI
tests += \
	test-boot-timestamps

test_boot_timestamps_SOURCES = \
	src/test/test-boot-timestamps.c

test_boot_timestamps_LDADD = \
	libsystemd-shared.la
endif

test_unit_name_SOURCES = \
	src/test/test-unit-name.c

test_unit_name_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(MOUNT_CFLAGS)

test_unit_name_LDADD = \
	libcore.la

test_unit_file_SOURCES = \
	src/test/test-unit-file.c

test_unit_file_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(MOUNT_CFLAGS)

test_unit_file_LDADD = \
	libcore.la

test_utf8_SOURCES = \
	src/test/test-utf8.c

test_utf8_LDADD = \
	libsystemd-shared.la

test_capability_SOURCES = \
	src/test/test-capability.c

test_capability_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS)

test_capability_LDADD = \
	libsystemd-shared.la \
	$(CAP_LIBS)

test_async_SOURCES = \
	src/test/test-async.c

test_async_LDADD = \
	libsystemd-shared.la

test_locale_util_SOURCES = \
	src/test/test-locale-util.c

test_locale_util_LDADD = \
	libsystemd-shared.la

test_copy_SOURCES = \
	src/test/test-copy.c

# Link statically to ensure file is large
test_copy_LDADD = \
	libshared.la

test_sigbus_SOURCES = \
	src/test/test-sigbus.c

test_sigbus_LDADD = \
	libsystemd-shared.la

test_condition_SOURCES = \
	src/test/test-condition.c

test_condition_LDADD = \
	libsystemd-shared.la

test_fdset_SOURCES = \
	src/test/test-fdset.c

test_fdset_LDADD = \
	libsystemd-shared.la

test_fstab_util_SOURCES = \
	src/test/test-fstab-util.c

test_fstab_util_LDADD = \
	libsystemd-shared.la

test_ratelimit_SOURCES = \
	src/test/test-ratelimit.c

test_ratelimit_LDADD = \
	libsystemd-shared.la

test_util_SOURCES = \
	src/test/test-util.c

test_util_LDADD = \
	libsystemd-shared.la

test_hexdecoct_SOURCES = \
	src/test/test-hexdecoct.c

test_hexdecoct_LDADD = \
	libsystemd-shared.la

test_alloc_util_SOURCES = \
	src/test/test-alloc-util.c

test_alloc_util_LDADD = \
	libsystemd-shared.la

test_xattr_util_SOURCES = \
	src/test/test-xattr-util.c

test_xattr_util_LDADD = \
	libsystemd-shared.la

test_io_util_SOURCES = \
	src/test/test-io-util.c

test_io_util_LDADD = \
	libsystemd-shared.la

test_glob_util_SOURCES = \
	src/test/test-glob-util.c

test_glob_util_LDADD = \
	libsystemd-shared.la

test_fs_util_SOURCES = \
	src/test/test-fs-util.c

test_fs_util_LDADD = \
	libsystemd-shared.la

test_proc_cmdline_SOURCES = \
	src/test/test-proc-cmdline.c

test_proc_cmdline_LDADD = \
	libsystemd-shared.la

test_fd_util_SOURCES = \
	src/test/test-fd-util.c

test_fd_util_LDADD = \
	libsystemd-shared.la

test_web_util_SOURCES = \
	src/test/test-web-util.c

test_web_util_LDADD = \
	libsystemd-shared.la

test_cpu_set_util_SOURCES = \
	src/test/test-cpu-set-util.c

test_cpu_set_util_LDADD = \
	libsystemd-shared.la

test_stat_util_SOURCES = \
	src/test/test-stat-util.c

test_stat_util_LDADD = \
	libsystemd-shared.la

test_escape_SOURCES = \
	src/test/test-escape.c

test_escape_LDADD = \
	libsystemd-shared.la

test_string_util_SOURCES = \
	src/test/test-string-util.c

test_string_util_LDADD = \
	libsystemd-shared.la

test_extract_word_SOURCES = \
	src/test/test-extract-word.c

test_extract_word_LDADD = \
	libsystemd-shared.la

test_parse_util_SOURCES = \
	src/test/test-parse-util.c

test_parse_util_LDADD = \
	libsystemd-shared.la

test_user_util_SOURCES = \
	src/test/test-user-util.c

test_user_util_LDADD = \
	libsystemd-shared.la

test_hostname_util_SOURCES = \
	src/test/test-hostname-util.c

test_hostname_util_LDADD = \
	libsystemd-shared.la

test_process_util_SOURCES = \
	src/test/test-process-util.c

test_process_util_LDADD = \
	libsystemd-shared.la

test_terminal_util_SOURCES = \
	src/test/test-terminal-util.c

test_terminal_util_LDADD = \
	libsystemd-shared.la

test_path_lookup_SOURCES = \
	src/test/test-path-lookup.c

test_path_lookup_LDADD = \
	libsystemd-shared.la

test_uid_range_SOURCES = \
	src/test/test-uid-range.c

test_uid_range_LDADD = \
	libsystemd-shared.la

test_cap_list_SOURCES = \
	src/test/test-cap-list.c

test_cap_list_CFLAGS = \
	$(AM_CFLAGS) \
	$(CAP_CFLAGS)

test_cap_list_LDADD = \
	libsystemd-shared.la \
	$(CAP_LIBS)

test_socket_util_SOURCES = \
	src/test/test-socket-util.c

test_socket_util_LDADD = \
	libsystemd-shared.la

test_barrier_SOURCES = \
	src/test/test-barrier.c

test_barrier_LDADD = \
	libsystemd-shared.la

test_tmpfiles_SOURCES = \
	src/test/test-tmpfiles.c

test_tmpfiles_LDADD = \
	libsystemd-shared.la

test_namespace_SOURCES = \
	src/test/test-namespace.c

test_verbs_SOURCES = \
	src/test/test-verbs.c

test_verbs_LDADD = \
	libsystemd-shared.la

test_install_root_SOURCES = \
	src/test/test-install-root.c

test_install_root_LDADD = \
	libsystemd-shared.la

test_acl_util_SOURCES = \
	src/test/test-acl-util.c

test_acl_util_LDADD = \
	libsystemd-shared.la

test_namespace_LDADD = \
	libcore.la

test_rlimit_util_SOURCES = \
	src/test/test-rlimit-util.c

test_rlimit_util_LDADD = \
	libsystemd-shared.la

test_ask_password_api_SOURCES = \
	src/test/test-ask-password-api.c

test_ask_password_api_LDADD = \
	libsystemd-shared.la

test_signal_util_SOURCES = \
	src/test/test-signal-util.c

test_signal_util_LDADD = \
	libsystemd-shared.la

test_selinux_SOURCES = \
	src/test/test-selinux.c

test_selinux_LDADD = \
	libsystemd-shared.la

test_sizeof_SOURCES = \
	src/test/test-sizeof.c

test_sizeof_LDADD = \
	libsystemd-shared.la

BUILT_SOURCES += \
	src/test/test-hashmap-ordered.c

src/test/test-hashmap-ordered.c: src/test/test-hashmap-plain.c
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN { print "/* GENERATED FILE */\n#define ORDERED" } \
	                   { if (!match($$0, "^#include"))          \
	                         gsub(/hashmap/, "ordered_hashmap"); \
	                     gsub(/HASHMAP/, "ORDERED_HASHMAP");     \
	                     gsub(/Hashmap/, "OrderedHashmap");      \
	                     print }' <$< >$@

nodist_test_hashmap_SOURCES = \
	src/test/test-hashmap-ordered.c

test_hashmap_SOURCES = \
	src/test/test-hashmap.c \
	src/test/test-hashmap-plain.c

test_hashmap_LDADD = \
	libsystemd-shared.la

test_set_SOURCES = \
	src/test/test-set.c

test_set_LDADD = \
	libsystemd-shared.la

test_bitmap_SOURCES = \
	src/test/test-bitmap.c

test_bitmap_LDADD = \
	libsystemd-shared.la

test_xml_SOURCES = \
	src/test/test-xml.c

test_xml_LDADD = \
	libsystemd-shared.la

test_list_SOURCES = \
	src/test/test-list.c

test_list_LDADD = \
	libsystemd-shared.la

test_unaligned_LDADD = \
	libsystemd-shared.la

test_unaligned_SOURCES = \
	src/test/test-unaligned.c

test_tables_SOURCES = \
	src/test/test-tables.c \
	src/shared/test-tables.h \
	src/journal/journald-server.c \
	src/journal/journald-server.h

test_tables_CPPFLAGS = \
	$(AM_CPPFLAGS)

test_tables_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(MOUNT_CFLAGS)

test_tables_LDADD = \
	libjournal-core.la \
	libcore.la \
	libudev-core.la

test_prioq_SOURCES = \
	src/test/test-prioq.c

test_prioq_LDADD = \
	libsystemd-shared.la

test_fileio_SOURCES = \
	src/test/test-fileio.c

test_fileio_LDADD = \
	libsystemd-shared.la

test_time_SOURCES = \
	src/test/test-time.c

test_time_LDADD = \
	libsystemd-shared.la

test_clock_SOURCES = \
	src/test/test-clock.c

test_clock_LDADD = \
	libsystemd-shared.la

test_architecture_SOURCES = \
	src/test/test-architecture.c

test_architecture_LDADD = \
	libsystemd-shared.la

test_log_SOURCES = \
	src/test/test-log.c

test_log_LDADD = \
	libsystemd-shared.la

test_ipcrm_SOURCES = \
	src/test/test-ipcrm.c

test_ipcrm_LDADD = \
	libsystemd-shared.la

test_btrfs_SOURCES = \
	src/test/test-btrfs.c

test_btrfs_LDADD = \
	libsystemd-shared.la

if HAVE_LIBIPTC
test_firewall_util_SOURCES = \
	src/test/test-firewall-util.c

test_firewall_util_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBIPTC_CFLAGS)

test_firewall_util_LDADD = \
	libfirewall.la \
	libsystemd-shared.la \
	$(LIBIPTC_LIBS)
endif

test_netlink_manual_SOURCES = \
	src/test/test-netlink-manual.c

test_netlink_manual_CFLAGS = \
	$(AM_CFLAGS) \
	$(KMOD_CFLAGS)

test_netlink_manual_LDADD = \
	libsystemd-shared.la \
	$(KMOD_LIBS)

test_ellipsize_SOURCES = \
	src/test/test-ellipsize.c

test_ellipsize_LDADD = \
	libsystemd-shared.la

test_date_SOURCES = \
	src/test/test-date.c

test_date_LDADD = \
	libsystemd-shared.la

test_sleep_SOURCES = \
	src/test/test-sleep.c

test_sleep_LDADD = \
	libcore.la

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
	libsystemd-shared.la

test_cgroup_SOURCES = \
	src/test/test-cgroup.c

test_cgroup_LDADD = \
	libsystemd-shared.la

test_cgroup_mask_SOURCES = \
	src/test/test-cgroup-mask.c

test_cgroup_mask_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(MOUNT_CFLAGS)

test_cgroup_mask_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_cgroup_mask_LDADD = \
	libcore.la

test_cgroup_util_SOURCES = \
	src/test/test-cgroup-util.c

test_cgroup_util_LDADD = \
	libsystemd-shared.la

test_env_util_SOURCES = \
	src/test/test-env-util.c

test_env_util_LDADD = \
	libsystemd-shared.la

test_strbuf_SOURCES = \
	src/test/test-strbuf.c

test_strbuf_LDADD = \
	libsystemd-shared.la

test_strv_SOURCES = \
	src/test/test-strv.c

test_strv_LDADD = \
	libsystemd-shared.la

test_path_util_SOURCES = \
	src/test/test-path-util.c

test_path_util_LDADD = \
	libsystemd-shared.la

test_path_SOURCES = \
	src/test/test-path.c

test_path_CFLAGS = \
	$(AM_CFLAGS) \
	$(MOUNT_CFLAGS)

test_path_LDADD = \
	libcore.la

test_execute_SOURCES = \
	src/test/test-execute.c

test_execute_CFLAGS = \
	$(AM_CFLAGS) \
	$(MOUNT_CFLAGS)

test_execute_LDADD = \
	libcore.la

test_siphash24_SOURCES = \
	src/test/test-siphash24.c

test_siphash24_LDADD = \
	libsystemd-shared.la

test_strxcpyx_SOURCES = \
	src/test/test-strxcpyx.c

test_strxcpyx_LDADD = \
	libsystemd-shared.la

test_install_SOURCES = \
	src/test/test-install.c

test_install_LDADD = \
	libsystemd-shared.la

test_watchdog_SOURCES = \
	src/test/test-watchdog.c

test_watchdog_LDADD = \
	libsystemd-shared.la

test_sched_prio_SOURCES = \
	src/test/test-sched-prio.c

test_sched_prio_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(MOUNT_CFLAGS)

test_sched_prio_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_sched_prio_LDADD = \
	libcore.la

test_conf_files_SOURCES = \
	src/test/test-conf-files.c

test_conf_files_LDADD = \
	libsystemd-shared.la

test_conf_parser_SOURCES = \
	src/test/test-conf-parser.c

test_conf_parser_LDADD = \
	libsystemd-shared.la

test_af_list_SOURCES = \
	src/test/test-af-list.c

test_af_list_LDADD = \
	libsystemd-shared.la

test_arphrd_list_SOURCES = \
	src/test/test-arphrd-list.c

test_arphrd_list_LDADD = \
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
	lcov --remove $(coverage_dir)/.lcov.info --output-file $(coverage_dir)/.lcov-clean.info 'test-*'
	genhtml -t "systemd test coverage" -o $(coverage_dir) $(coverage_dir)/.lcov-clean.info
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
	src/analyze/analyze.c \
	src/analyze/analyze-verify.c \
	src/analyze/analyze-verify.h

systemd_analyze_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(MOUNT_CFLAGS)

systemd_analyze_LDADD = \
	libcore.la

# ------------------------------------------------------------------------------
systemd_initctl_SOURCES = \
	src/initctl/initctl.c

systemd_initctl_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_update_utmp_SOURCES = \
	src/update-utmp/update-utmp.c

systemd_update_utmp_CFLAGS = \
	$(AM_CFLAGS) \
	$(AUDIT_CFLAGS)

systemd_update_utmp_LDADD = \
	libsystemd-shared.la \
	$(AUDIT_LIBS)

# ------------------------------------------------------------------------------
systemd_update_done_SOURCES = \
	src/update-done/update-done.c

systemd_update_done_LDADD = \
	libsystemd-shared.la

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

systemd_tmpfiles_CFLAGS = \
	$(AM_CFLAGS) \
	$(ACL_CFLAGS)

systemd_tmpfiles_LDADD = \
	libsystemd-shared.la \
	$(ACL_LIBS)

rootbin_PROGRAMS += \
	systemd-tmpfiles

dist_systemunit_DATA += \
	units/systemd-tmpfiles-clean.timer

nodist_systemunit_DATA += \
	units/systemd-tmpfiles-setup-dev.service \
	units/systemd-tmpfiles-setup.service \
	units/systemd-tmpfiles-clean.service

nodist_tmpfiles_DATA = \
	tmpfiles.d/systemd.conf \
	tmpfiles.d/etc.conf

dist_tmpfiles_DATA = \
	tmpfiles.d/systemd-nologin.conf \
	tmpfiles.d/tmp.conf \
	tmpfiles.d/x11.conf \
	tmpfiles.d/var.conf \
	tmpfiles.d/home.conf \
	tmpfiles.d/systemd-nspawn.conf \
	tmpfiles.d/journal-nocow.conf

if HAVE_SYSV_COMPAT
dist_tmpfiles_DATA += \
	tmpfiles.d/legacy.conf
endif

SYSINIT_TARGET_WANTS += \
	systemd-tmpfiles-setup-dev.service \
	systemd-tmpfiles-setup.service

dist_zshcompletion_data += \
	shell-completion/zsh/_systemd-tmpfiles

TIMERS_TARGET_WANTS += \
	systemd-tmpfiles-clean.timer

INSTALL_DIRS += \
	$(tmpfilesdir) \
	$(sysconfdir)/tmpfiles.d
endif

EXTRA_DIST += \
	tmpfiles.d/systemd.conf.m4 \
	tmpfiles.d/etc.conf.m4 \
	units/systemd-tmpfiles-setup-dev.service.in \
	units/systemd-tmpfiles-setup.service.in \
	units/systemd-tmpfiles-clean.service.in

# ------------------------------------------------------------------------------
if ENABLE_SYSUSERS
systemd_sysusers_SOURCES = \
	src/sysusers/sysusers.c

systemd_sysusers_LDADD = \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	systemd-sysusers

nodist_systemunit_DATA += \
	units/systemd-sysusers.service

SYSINIT_TARGET_WANTS += \
	systemd-sysusers.service

nodist_sysusers_DATA = \
	sysusers.d/systemd.conf \
	sysusers.d/basic.conf

if HAVE_REMOTE
nodist_sysusers_DATA += \
	sysusers.d/systemd-remote.conf
endif

INSTALL_DIRS += \
	$(sysusersdir)
endif

EXTRA_DIST += \
	units/systemd-sysusers.service.in \
	sysusers.d/systemd.conf.m4 \
	sysusers.d/systemd-remote.conf.m4 \
	sysusers.d/basic.conf.in

# ------------------------------------------------------------------------------
dist_factory_etc_DATA = \
	factory/etc/nsswitch.conf

if HAVE_PAM
dist_factory_pam_DATA = \
	factory/etc/pam.d/system-auth \
	factory/etc/pam.d/other
endif

# ------------------------------------------------------------------------------
if ENABLE_FIRSTBOOT
systemd_firstboot_SOURCES = \
	src/firstboot/firstboot.c

systemd_firstboot_LDADD = \
	libsystemd-shared.la \
	-lcrypt

rootbin_PROGRAMS += \
	systemd-firstboot

nodist_systemunit_DATA += \
	units/systemd-firstboot.service

SYSINIT_TARGET_WANTS += \
	systemd-firstboot.service
endif

EXTRA_DIST += \
	units/systemd-firstboot.service.in

# ------------------------------------------------------------------------------
systemd_machine_id_setup_SOURCES = \
	src/machine-id-setup/machine-id-setup-main.c \
	src/core/machine-id-setup.c \
	src/core/machine-id-setup.h

systemd_machine_id_setup_LDADD = \
	libsystemd-shared.la

SYSINIT_TARGET_WANTS += \
	systemd-machine-id-commit.service

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
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_ac_power_SOURCES = \
	src/ac-power/ac-power.c

systemd_ac_power_LDADD = \
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
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_debug_generator_SOURCES = \
	src/debug-generator/debug-generator.c

systemd_debug_generator_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_fstab_generator_SOURCES = \
	src/fstab-generator/fstab-generator.c \
	src/core/mount-setup.c

systemd_fstab_generator_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_system_update_generator_SOURCES = \
	src/system-update-generator/system-update-generator.c

systemd_system_update_generator_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
if ENABLE_HIBERNATE
systemgenerator_PROGRAMS += \
	systemd-hibernate-resume-generator

rootlibexec_PROGRAMS += \
	systemd-hibernate-resume

systemd_hibernate_resume_SOURCES = \
	src/hibernate-resume/hibernate-resume.c

systemd_hibernate_resume_LDADD = \
	libsystemd-shared.la

systemd_hibernate_resume_generator_SOURCES = \
	src/hibernate-resume/hibernate-resume-generator.c

systemd_hibernate_resume_generator_LDADD = \
	libsystemd-shared.la

dist_systemunit_DATA += \
	units/hibernate.target \
	units/hybrid-sleep.target

nodist_systemunit_DATA += \
	units/systemd-hibernate.service \
	units/systemd-hibernate-resume@.service \
	units/systemd-hybrid-sleep.service
endif

EXTRA_DIST += \
	units/systemd-hibernate.service.in \
	units/systemd-hibernate-resume@.service.in \
	units/systemd-hybrid-sleep.service.in

# ------------------------------------------------------------------------------
if ENABLE_EFI
if HAVE_BLKID
bootctl_SOURCES = \
	src/boot/bootctl.c

bootctl_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DEFI_MACHINE_TYPE_NAME=\"$(EFI_MACHINE_TYPE_NAME)\" \
	-DBOOTLIBDIR=\"$(bootlibdir)\"

bootctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS)

bootctl_LDADD = \
	libsystemd-shared.la \
	$(BLKID_LIBS)

bin_PROGRAMS += \
	bootctl

dist_bashcompletion_data += \
	shell-completion/bash/bootctl

dist_zshcompletion_data += \
	shell-completion/zsh/_bootctl
endif

# ------------------------------------------------------------------------------
if HAVE_GNUEFI
efi_cppflags = \
	$(EFI_CPPFLAGS) \
	-I$(top_builddir) -include config.h \
	-I$(EFI_INC_DIR)/efi \
	-I$(EFI_INC_DIR)/efi/$(EFI_ARCH) \
	-DEFI_MACHINE_TYPE_NAME=\"$(EFI_MACHINE_TYPE_NAME)\"

efi_cflags = \
	$(EFI_CFLAGS) \
	-Wall \
	-Wextra \
	-std=gnu90 \
	-nostdinc \
	-ggdb -O0 \
	-fpic \
	-fshort-wchar \
	-nostdinc \
	-ffreestanding \
	-fno-strict-aliasing \
	-fno-stack-protector \
	-Wsign-compare \
	-Wno-missing-field-initializers

if ARCH_X86_64
efi_cflags += \
	-mno-red-zone \
	-mno-sse \
	-mno-mmx \
	-DEFI_FUNCTION_WRAPPER \
	-DGNU_EFI_USE_MS_ABI
endif

if ARCH_IA32
efi_cflags += \
	-mno-sse \
	-mno-mmx
endif

efi_ldflags = \
	$(EFI_LDFLAGS) \
	-T $(EFI_LDS_DIR)/elf_$(EFI_ARCH)_efi.lds \
	-shared \
	-Bsymbolic \
	-nostdlib \
	-znocombreloc \
	-L $(EFI_LIB_DIR) \
	$(EFI_LDS_DIR)/crt0-efi-$(EFI_ARCH).o

# Aarch64 and ARM32 don't have an EFI capable objcopy. Use 'binary' instead,
# and add required symbols manually.
if ARCH_AARCH64
efi_ldflags += --defsym=EFI_SUBSYSTEM=0xa
EFI_FORMAT = -O binary
else
EFI_FORMAT = --target=efi-app-$(EFI_ARCH)
endif
endif
endif

# ------------------------------------------------------------------------------
systemd_boot_headers = \
	src/boot/efi/util.h \
	src/boot/efi/console.h \
	src/boot/efi/graphics.h \
	src/boot/efi/pefile.h \
	src/boot/efi/measure.h \
	src/boot/efi/disk.h

systemd_boot_sources = \
	src/boot/efi/util.c \
	src/boot/efi/console.c \
	src/boot/efi/graphics.c \
	src/boot/efi/pefile.c \
	src/boot/efi/disk.c \
	src/boot/efi/measure.c \
	src/boot/efi/boot.c

EXTRA_DIST += $(systemd_boot_sources) $(systemd_boot_headers)

systemd_boot_objects = $(addprefix $(top_builddir)/,$(systemd_boot_sources:.c=.o))
systemd_boot_solib = $(top_builddir)/src/boot/efi/systemd_boot.so
systemd_boot = systemd-boot$(EFI_MACHINE_TYPE_NAME).efi

if ENABLE_EFI
if HAVE_GNUEFI
bootlib_DATA = $(systemd_boot)

$(top_builddir)/src/boot/efi/%.o: $(top_srcdir)/src/boot/efi/%.c $(addprefix $(top_srcdir)/,$(systemd_boot_headers))
	@$(MKDIR_P) $(top_builddir)/src/boot/efi/
	$(AM_V_CC)$(EFI_CC) $(efi_cppflags) $(efi_cflags) -c $< -o $@

$(systemd_boot_solib): $(systemd_boot_objects)
	$(AM_V_CCLD)$(LD) $(efi_ldflags) $(systemd_boot_objects) \
		-o $@ -lefi -lgnuefi $(shell $(CC) -print-libgcc-file-name); \
	nm -D -u $@ | grep ' U ' && exit 1 || :

$(systemd_boot): $(systemd_boot_solib)
	$(AM_V_GEN)$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic \
	  -j .dynsym -j .rel -j .rela -j .reloc $(EFI_FORMAT) $< $@
endif
endif

CLEANFILES += $(systemd_boot_objects) $(systemd_boot_solib) $(systemd_boot)

# ------------------------------------------------------------------------------
stub_headers = \
	src/boot/efi/util.h \
	src/boot/efi/pefile.h \
	src/boot/efi/disk.h \
	src/boot/efi/graphics.h \
	src/boot/efi/splash.h \
	src/boot/efi/measure.h \
	src/boot/efi/linux.h

stub_sources = \
	src/boot/efi/util.c \
	src/boot/efi/pefile.c \
	src/boot/efi/disk.c \
	src/boot/efi/graphics.c \
	src/boot/efi/splash.c \
	src/boot/efi/linux.c \
	src/boot/efi/measure.c \
	src/boot/efi/stub.c

EXTRA_DIST += \
	$(stub_sources) \
	$(stub_headers) \
	test/splash.bmp

stub_objects = $(addprefix $(top_builddir)/,$(stub_sources:.c=.o))
stub_solib = $(top_builddir)/src/boot/efi/stub.so
stub = linux$(EFI_MACHINE_TYPE_NAME).efi.stub

if ENABLE_EFI
if HAVE_GNUEFI
bootlib_DATA += $(stub)

$(top_builddir)/src/boot/efi/%.o: $(top_srcdir)/src/boot/efi/%.c $(addprefix $(top_srcdir)/,$(stub_headers))
	@$(MKDIR_P) $(top_builddir)/src/boot/efi/
	$(AM_V_CC)$(EFI_CC) $(efi_cppflags) $(efi_cflags) -c $< -o $@

$(stub_solib): $(stub_objects)
	$(AM_V_CCLD)$(LD) $(efi_ldflags) $(stub_objects) \
		-o $@ -lefi -lgnuefi $(shell $(CC) -print-libgcc-file-name); \
	nm -D -u $@ | grep ' U ' && exit 1 || :

$(stub): $(stub_solib)
	$(AM_V_GEN)$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic \
	  -j .dynsym -j .rel -j .rela -j .reloc $(EFI_FORMAT) $< $@
endif
endif

CLEANFILES += $(stub_objects) $(stub_solib) $(stub)


# ------------------------------------------------------------------------------
CLEANFILES += test-efi-disk.img

test-efi-disk.img: $(systemd_boot) $(stub) test/test-efi-create-disk.sh
	$(AM_V_GEN)test/test-efi-create-disk.sh

test-efi: test-efi-disk.img
	$(QEMU) -machine accel=kvm -m 1024 -bios $(QEMU_BIOS) -snapshot test-efi-disk.img

EXTRA_DIST += test/test-efi-create-disk.sh

# ------------------------------------------------------------------------------
if HAVE_BLKID
systemgenerator_PROGRAMS +=  \
	systemd-gpt-auto-generator

systemd_gpt_auto_generator_SOURCES = \
	src/gpt-auto-generator/gpt-auto-generator.c \
	src/basic/blkid-util.h

systemd_gpt_auto_generator_LDADD = \
	libsystemd-shared.la \
	$(BLKID_LIBS)

systemd_gpt_auto_generator_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS)
endif

# ------------------------------------------------------------------------------
dist_xinitrc_SCRIPTS = \
	xorg/50-systemd-user.sh

# ------------------------------------------------------------------------------
systemd_sysv_generator_SOURCES = \
	src/sysv-generator/sysv-generator.c

systemd_sysv_generator_LDADD = \
	libcore.la

# ------------------------------------------------------------------------------
systemd_rc_local_generator_SOURCES = \
	src/rc-local-generator/rc-local-generator.c

systemd_rc_local_generator_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_remount_fs_SOURCES = \
	src/remount-fs/remount-fs.c \
	src/core/mount-setup.c \
	src/core/mount-setup.h

systemd_remount_fs_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_cgroups_agent_SOURCES = \
	src/cgroups-agent/cgroups-agent.c

systemd_cgroups_agent_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_escape_SOURCES = \
	src/escape/escape.c

systemd_escape_LDADD = \
	libsystemd-shared.la

# -----------------------------------------------------------------------------
systemctl_SOURCES = \
	src/systemctl/systemctl.c

systemctl_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_notify_SOURCES = \
	src/notify/notify.c

systemd_notify_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_path_SOURCES = \
	src/path/path.c

systemd_path_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_ask_password_SOURCES = \
	src/ask-password/ask-password.c

systemd_ask_password_LDADD = \
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
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_cgtop_SOURCES = \
	src/cgtop/cgtop.c

systemd_cgtop_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_nspawn_SOURCES = \
	src/nspawn/nspawn.c \
	src/nspawn/nspawn-settings.c \
	src/nspawn/nspawn-settings.h \
	src/nspawn/nspawn-mount.c \
	src/nspawn/nspawn-mount.h \
	src/nspawn/nspawn-network.c \
	src/nspawn/nspawn-network.h \
	src/nspawn/nspawn-expose-ports.c \
	src/nspawn/nspawn-expose-ports.h \
	src/nspawn/nspawn-cgroup.c \
	src/nspawn/nspawn-cgroup.h \
	src/nspawn/nspawn-seccomp.c \
	src/nspawn/nspawn-seccomp.h \
	src/nspawn/nspawn-register.c \
	src/nspawn/nspawn-register.h \
	src/nspawn/nspawn-setuid.c \
	src/nspawn/nspawn-setuid.h \
	src/nspawn/nspawn-stub-pid1.c \
	src/nspawn/nspawn-stub-pid1.h \
	src/nspawn/nspawn-patch-uid.c \
	src/nspawn/nspawn-patch-uid.h \
	src/core/mount-setup.c \
	src/core/mount-setup.h \
	src/core/loopback-setup.c \
	src/core/loopback-setup.h \
	src/core/machine-id-setup.c \
	src/core/machine-id-setup.h

nodist_systemd_nspawn_SOURCES = \
	src/nspawn/nspawn-gperf.c

gperf_gperf_sources += \
	src/nspawn/nspawn-gperf.gperf

systemd_nspawn_CFLAGS = \
	$(AM_CFLAGS) \
	$(ACL_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(SECCOMP_CFLAGS) \
	$(SELINUX_CFLAGS)

systemd_nspawn_LDADD = \
	libsystemd-shared.la \
	$(ACL_LIBS) \
	$(BLKID_LIBS) \
	$(SECCOMP_LIBS) \
	$(SELINUX_LIBS)

if HAVE_LIBIPTC
systemd_nspawn_LDADD += \
	libfirewall.la
endif

test_patch_uid_SOURCES = \
	src/nspawn/nspawn-patch-uid.c \
	src/nspawn/nspawn-patch-uid.h \
	src/nspawn/test-patch-uid.c

test_patch_uid_CFLAGS = \
	$(AM_CFLAGS) \
	$(ACL_CFLAGS)

test_patch_uid_LDADD = \
	libsystemd-shared.la \
	$(ACL_LIBS)

manual_tests += \
	test-patch-uid

# ------------------------------------------------------------------------------
systemd_run_SOURCES = \
	src/run/run.c

systemd_run_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_stdio_bridge_SOURCES = \
	src/stdio-bridge/stdio-bridge.c

systemd_stdio_bridge_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_tty_ask_password_agent_SOURCES = \
	src/tty-ask-password-agent/tty-ask-password-agent.c

systemd_tty_ask_password_agent_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
libsystemd_internal_la_SOURCES = \
	src/systemd/sd-bus.h \
	src/systemd/sd-bus-protocol.h \
	src/systemd/sd-bus-vtable.h \
	src/systemd/sd-utf8.h \
	src/systemd/sd-event.h \
	src/systemd/sd-netlink.h \
	src/systemd/sd-resolve.h \
	src/systemd/sd-login.h \
	src/systemd/sd-id128.h \
	src/systemd/sd-daemon.h \
	src/systemd/sd-path.h \
	src/systemd/sd-network.h \
	src/systemd/sd-hwdb.h \
	src/systemd/sd-device.h \
	src/libsystemd/libsystemd.sym \
	src/libsystemd/sd-bus/sd-bus.c \
	src/libsystemd/sd-bus/bus-control.c \
	src/libsystemd/sd-bus/bus-control.h \
	src/libsystemd/sd-bus/bus-error.c \
	src/libsystemd/sd-bus/bus-error.h \
	src/libsystemd/sd-bus/bus-common-errors.h \
	src/libsystemd/sd-bus/bus-common-errors.c \
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
	src/libsystemd/sd-bus/bus-slot.c \
	src/libsystemd/sd-bus/bus-slot.h \
	src/libsystemd/sd-bus/bus-protocol.h \
	src/libsystemd/sd-bus/kdbus.h \
	src/libsystemd/sd-bus/bus-dump.c \
	src/libsystemd/sd-bus/bus-dump.h \
	src/libsystemd/sd-utf8/sd-utf8.c \
	src/libsystemd/sd-event/sd-event.c \
	src/libsystemd/sd-netlink/sd-netlink.c \
	src/libsystemd/sd-netlink/netlink-internal.h \
	src/libsystemd/sd-netlink/netlink-message.c \
	src/libsystemd/sd-netlink/netlink-socket.c \
	src/libsystemd/sd-netlink/rtnl-message.c \
	src/libsystemd/sd-netlink/netlink-types.h \
	src/libsystemd/sd-netlink/netlink-types.c \
	src/libsystemd/sd-netlink/netlink-util.h \
	src/libsystemd/sd-netlink/netlink-util.c \
	src/libsystemd/sd-netlink/local-addresses.h \
	src/libsystemd/sd-netlink/local-addresses.c \
	src/libsystemd/sd-id128/sd-id128.c \
	src/libsystemd/sd-daemon/sd-daemon.c \
	src/libsystemd/sd-login/sd-login.c \
	src/libsystemd/sd-path/sd-path.c \
	src/libsystemd/sd-network/sd-network.c \
	src/libsystemd/sd-network/network-util.h \
	src/libsystemd/sd-network/network-util.c \
	src/libsystemd/sd-hwdb/sd-hwdb.c \
	src/libsystemd/sd-hwdb/hwdb-util.h \
	src/libsystemd/sd-hwdb/hwdb-internal.h \
	src/libsystemd/sd-device/device-internal.h \
	src/libsystemd/sd-device/device-util.h \
	src/libsystemd/sd-device/device-enumerator.c \
	src/libsystemd/sd-device/device-enumerator-private.h \
	src/libsystemd/sd-device/sd-device.c \
	src/libsystemd/sd-device/device-private.c \
	src/libsystemd/sd-device/device-private.h \
	src/libsystemd/sd-resolve/sd-resolve.c

libsystemd_internal_la_LIBADD = \
	-lresolv

noinst_LTLIBRARIES += \
	libsystemd-internal.la

EXTRA_DIST += \
	src/libsystemd/libsystemd.pc.in \
	src/libsystemd/sd-bus/DIFFERENCES \
	src/libsystemd/sd-bus/GVARIANT-SERIALIZATION

libsystemd_la_SOURCES =

libsystemd_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBSYSTEMD_CURRENT):$(LIBSYSTEMD_REVISION):$(LIBSYSTEMD_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libsystemd/libsystemd.sym

libsystemd_la_LIBADD = \
	libsystemd-internal.la \
	libbasic.la \
	libsystemd-journal-internal.la

libsystemd-install-hook:
	libname=libsystemd.so && $(move-to-rootlibdir)

libsystemd-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd.so*

INSTALL_EXEC_HOOKS += libsystemd-install-hook
UNINSTALL_EXEC_HOOKS += libsystemd-uninstall-hook

pkgconfiglib_DATA += \
	src/libsystemd/libsystemd.pc

pkginclude_HEADERS += \
	src/systemd/sd-bus.h \
	src/systemd/sd-bus-protocol.h \
	src/systemd/sd-bus-vtable.h \
	src/systemd/sd-event.h \
	src/systemd/sd-login.h \
	src/systemd/sd-id128.h \
	src/systemd/sd-daemon.h

lib_LTLIBRARIES += \
	libsystemd.la

tests += \
	test-bus-marshal \
	test-bus-signature \
	test-bus-benchmark \
	test-bus-chat \
	test-bus-cleanup \
	test-bus-server \
	test-bus-match \
	test-bus-kernel \
	test-bus-kernel-bloom \
	test-bus-zero-copy \
	test-bus-introspect \
	test-bus-objects \
	test-bus-error \
	test-bus-creds \
	test-bus-gvariant \
	test-event \
	test-netlink \
	test-local-addresses \
	test-resolve

bin_PROGRAMS += \
	busctl

test_bus_marshal_SOURCES = \
	src/libsystemd/sd-bus/test-bus-marshal.c

test_bus_marshal_LDADD = \
	libsystemd-shared.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

test_bus_marshal_CFLAGS = \
	$(AM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_bus_signature_SOURCES = \
	src/libsystemd/sd-bus/test-bus-signature.c

test_bus_signature_LDADD = \
	libsystemd-shared.la

test_bus_chat_SOURCES = \
	src/libsystemd/sd-bus/test-bus-chat.c

test_bus_chat_LDADD = \
	libsystemd-shared.la

test_bus_cleanup_SOURCES = \
	src/libsystemd/sd-bus/test-bus-cleanup.c

test_bus_cleanup_CFLAGS = \
	$(AM_CFLAGS) \
	$(SECCOMP_CFLAGS)

test_bus_cleanup_LDADD = \
	libsystemd-shared.la

test_bus_server_SOURCES = \
	src/libsystemd/sd-bus/test-bus-server.c

test_bus_server_LDADD = \
	libsystemd-shared.la

test_bus_objects_SOURCES = \
	src/libsystemd/sd-bus/test-bus-objects.c

test_bus_objects_LDADD = \
	libsystemd-shared.la

test_bus_error_SOURCES = \
	src/libsystemd/sd-bus/test-bus-error.c

# Link statically because this test uses BUS_ERROR_MAP_ELF_REGISTER
test_bus_error_LDADD = \
	libshared.la

test_bus_gvariant_SOURCES = \
	src/libsystemd/sd-bus/test-bus-gvariant.c

test_bus_gvariant_LDADD = \
	libsystemd-shared.la \
	$(GLIB_LIBS)

test_bus_gvariant_CFLAGS = \
	$(AM_CFLAGS) \
	$(GLIB_CFLAGS)

test_bus_creds_SOURCES = \
	src/libsystemd/sd-bus/test-bus-creds.c

test_bus_creds_LDADD = \
	libsystemd-shared.la

test_bus_match_SOURCES = \
	src/libsystemd/sd-bus/test-bus-match.c

test_bus_match_LDADD = \
	libsystemd-shared.la

test_bus_kernel_SOURCES = \
	src/libsystemd/sd-bus/test-bus-kernel.c

test_bus_kernel_LDADD = \
	libsystemd-shared.la

test_bus_kernel_bloom_SOURCES = \
	src/libsystemd/sd-bus/test-bus-kernel-bloom.c

test_bus_kernel_bloom_LDADD = \
	libsystemd-shared.la

test_bus_benchmark_SOURCES = \
	src/libsystemd/sd-bus/test-bus-benchmark.c

test_bus_benchmark_LDADD = \
	libsystemd-shared.la

test_bus_zero_copy_SOURCES = \
	src/libsystemd/sd-bus/test-bus-zero-copy.c

test_bus_zero_copy_LDADD = \
	libsystemd-shared.la

test_bus_introspect_SOURCES = \
	src/libsystemd/sd-bus/test-bus-introspect.c

test_bus_introspect_LDADD = \
	libsystemd-shared.la

test_event_SOURCES = \
	src/libsystemd/sd-event/test-event.c

test_event_LDADD = \
	libsystemd-shared.la

test_netlink_SOURCES = \
	src/libsystemd/sd-netlink/test-netlink.c

test_netlink_LDADD = \
	libsystemd-shared.la

test_local_addresses_SOURCES = \
	src/libsystemd/sd-netlink/test-local-addresses.c

test_local_addresses_LDADD = \
	libsystemd-shared.la

test_resolve_SOURCES = \
	src/libsystemd/sd-resolve/test-resolve.c

test_resolve_LDADD = \
	libsystemd-shared.la

busctl_SOURCES = \
	src/libsystemd/sd-bus/busctl.c \
	src/libsystemd/sd-bus/busctl-introspect.c \
	src/libsystemd/sd-bus/busctl-introspect.h

busctl_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-network.la

libsystemd_network_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(KMOD_CFLAGS)

libsystemd_network_la_SOURCES = \
	src/systemd/sd-dhcp-client.h \
	src/systemd/sd-dhcp-server.h \
	src/systemd/sd-dhcp-lease.h \
	src/systemd/sd-ipv4ll.h \
	src/systemd/sd-ipv4acd.h \
	src/systemd/sd-ndisc.h \
	src/systemd/sd-dhcp6-client.h \
	src/systemd/sd-dhcp6-lease.h \
	src/systemd/sd-lldp.h \
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
	src/libsystemd-network/sd-ipv4acd.c \
	src/libsystemd-network/arp-util.h \
	src/libsystemd-network/arp-util.c \
	src/libsystemd-network/network-internal.c \
	src/libsystemd-network/network-internal.h \
	src/libsystemd-network/sd-ndisc.c \
	src/libsystemd-network/ndisc-internal.h \
	src/libsystemd-network/ndisc-router.h \
	src/libsystemd-network/ndisc-router.c \
	src/libsystemd-network/icmp6-util.h \
	src/libsystemd-network/icmp6-util.c \
	src/libsystemd-network/sd-dhcp6-client.c \
	src/libsystemd-network/dhcp6-internal.h \
	src/libsystemd-network/dhcp6-protocol.h \
	src/libsystemd-network/dhcp6-network.c \
	src/libsystemd-network/dhcp6-option.c \
	src/libsystemd-network/dhcp6-lease-internal.h \
	src/libsystemd-network/sd-dhcp6-lease.c \
	src/libsystemd-network/dhcp-identifier.h \
	src/libsystemd-network/dhcp-identifier.c \
	src/libsystemd-network/lldp-internal.h \
	src/libsystemd-network/lldp-network.h \
	src/libsystemd-network/lldp-network.c \
	src/libsystemd-network/lldp-neighbor.h \
	src/libsystemd-network/lldp-neighbor.c \
	src/libsystemd-network/sd-lldp.c

libsystemd_network_la_LIBADD = \
	$(KMOD_LIBS)

test_dhcp_option_SOURCES = \
	src/libsystemd-network/dhcp-protocol.h \
	src/libsystemd-network/dhcp-internal.h \
	src/libsystemd-network/test-dhcp-option.c

test_dhcp_option_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

test_dhcp_client_SOURCES = \
	src/systemd/sd-dhcp-client.h \
	src/libsystemd-network/dhcp-protocol.h \
	src/libsystemd-network/dhcp-internal.h \
	src/libsystemd-network/test-dhcp-client.c

test_dhcp_client_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

test_dhcp_server_SOURCES = \
	src/libsystemd-network/test-dhcp-server.c

test_dhcp_server_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

test_ipv4ll_SOURCES = \
	src/systemd/sd-ipv4ll.h \
	src/libsystemd-network/arp-util.h \
	src/libsystemd-network/test-ipv4ll.c

test_ipv4ll_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

test_ipv4ll_manual_SOURCES = \
	src/systemd/sd-ipv4ll.h \
	src/libsystemd-network/test-ipv4ll-manual.c

test_ipv4ll_manual_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

test_acd_SOURCES = \
	src/systemd/sd-ipv4acd.h \
	src/libsystemd-network/test-acd.c

test_acd_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

test_ndisc_rs_SOURCES = \
	src/systemd/sd-dhcp6-client.h \
	src/systemd/sd-ndisc.h \
	src/libsystemd-network/icmp6-util.h \
	src/libsystemd-network/test-ndisc-rs.c \
	src/libsystemd-network/dhcp-identifier.h \
	src/libsystemd-network/dhcp-identifier.c

test_ndisc_rs_LDADD = \
	libsystemd-network.la \
	libudev.la \
	libsystemd-shared.la

test_dhcp6_client_SOURCES = \
	src/systemd/sd-dhcp6-client.h \
	src/libsystemd-network/dhcp6-internal.h \
	src/libsystemd-network/test-dhcp6-client.c \
	src/libsystemd-network/dhcp-identifier.h \
	src/libsystemd-network/dhcp-identifier.c

test_dhcp6_client_LDADD = \
	libsystemd-network.la \
	libudev.la \
	libsystemd-shared.la

test_lldp_SOURCES = \
	src/libsystemd-network/test-lldp.c

test_lldp_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

tests += \
	test-dhcp-option \
	test-dhcp-client \
	test-dhcp-server \
	test-ipv4ll \
	test-ndisc-rs \
	test-dhcp6-client \
	test-lldp

# ------------------------------------------------------------------------------
include_HEADERS += \
	src/libudev/libudev.h

lib_LTLIBRARIES += \
	libudev.la

libudev_la_SOURCES =\
	src/libudev/libudev.sym \
	src/libudev/libudev-private.h \
	src/libudev/libudev-device-internal.h \
	src/libudev/libudev.c \
	src/libudev/libudev-list.c \
	src/libudev/libudev-util.c \
	src/libudev/libudev-device.c \
	src/libudev/libudev-device-private.c \
	src/libudev/libudev-enumerate.c \
	src/libudev/libudev-monitor.c \
	src/libudev/libudev-queue.c \
	src/libudev/libudev-hwdb.c

libudev_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(LIBUDEV_CURRENT):$(LIBUDEV_REVISION):$(LIBUDEV_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libudev/libudev.sym

libudev_la_LIBADD = \
	libsystemd-internal.la \
	libbasic.la

pkgconfiglib_DATA += \
	src/libudev/libudev.pc

EXTRA_DIST += \
	src/libudev/libudev.pc.in

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
	$(libudev_la_SOURCES)

# ------------------------------------------------------------------------------
INSTALL_DIRS += \
	$(sysconfdir)/udev/rules.d

dist_network_DATA = \
	network/99-default.link \
	network/80-container-host0.network \
	network/80-container-ve.network \
	network/80-container-vz.network

dist_udevrules_DATA += \
	rules/50-udev-default.rules \
	rules/60-block.rules \
	rules/60-drm.rules \
	rules/60-evdev.rules \
	rules/60-persistent-storage-tape.rules \
	rules/60-persistent-input.rules \
	rules/60-persistent-alsa.rules \
	rules/60-persistent-storage.rules \
	rules/60-serial.rules \
	rules/64-btrfs.rules \
	rules/70-mouse.rules \
	rules/70-touchpad.rules \
	rules/75-net-description.rules \
	rules/78-sound-card.rules \
	rules/80-net-setup-link.rules

nodist_udevrules_DATA += \
	rules/99-systemd.rules

udevconfdir = $(sysconfdir)/udev
dist_udevconf_DATA = \
	src/udev/udev.conf

pkgconfigdata_DATA += \
	src/udev/udev.pc

EXTRA_DIST += \
	rules/99-systemd.rules.in \
	src/udev/udev.pc.in

EXTRA_DIST += \
	units/systemd-udevd.service.in \
	units/systemd-udev-trigger.service.in \
	units/systemd-udev-settle.service.in

SOCKETS_TARGET_WANTS += \
	systemd-udevd-control.socket \
	systemd-udevd-kernel.socket

SYSINIT_TARGET_WANTS += \
	systemd-udevd.service \
	systemd-udev-trigger.service

rootbin_PROGRAMS += \
	udevadm

rootlibexec_PROGRAMS += \
	systemd-udevd

noinst_LTLIBRARIES += \
	libudev-core.la

src/udev/keyboard-keys-list.txt:
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9K]/ { if ($$2 != "KEY_MAX") { print $$2 } }' > $@

src/udev/keyboard-keys-from-name.gperf: src/udev/keyboard-keys-list.txt
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print tolower(substr($$1 ,5)) ", " $$1 }' < $< > $@

src/udev/keyboard-keys-from-name.h: src/udev/keyboard-keys-from-name.gperf
	$(AM_V_GPERF)$(GPERF) -L ANSI-C -t -N keyboard_lookup_key -H hash_key_name -p -C < $< > $@

gperf_txt_sources += \
	src/udev/keyboard-keys-list.txt

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
	src/udev/net/link-config-gperf.c

gperf_gperf_sources += \
	src/udev/net/link-config-gperf.gperf

libudev_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(KMOD_CFLAGS)

libudev_core_la_LIBADD = \
	libsystemd-network.la \
	libshared.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS)

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
endif

systemd_udevd_SOURCES = \
	src/udev/udevd.c

systemd_udevd_LDADD = \
	libudev-core.la \
	libbasic.la

udevadm_SOURCES = \
	src/udev/udevadm.c \
	src/udev/udevadm-info.c \
	src/udev/udevadm-control.c \
	src/udev/udevadm-monitor.c \
	src/udev/udevadm-hwdb.c \
	src/udev/udevadm-settle.c \
	src/udev/udevadm-trigger.c \
	src/udev/udevadm-test.c \
	src/udev/udevadm-test-builtin.c \
	src/udev/udevadm-util.c \
	src/udev/udevadm-util.h

udevadm_LDADD = \
	libudev-core.la \
	libbasic.la

# ------------------------------------------------------------------------------
if ENABLE_HWDB
INSTALL_DIRS += \
	$(sysconfdir)/udev/hwdb.d

systemd_hwdb_SOURCES = \
	src/libsystemd/sd-hwdb/hwdb-internal.h \
	src/hwdb/hwdb.c

systemd_hwdb_LDADD = \
	libshared.la

rootbin_PROGRAMS += \
	systemd-hwdb

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
	hwdb/60-evdev.hwdb \
	hwdb/60-keyboard.hwdb \
	hwdb/70-mouse.hwdb \
	hwdb/70-pointingstick.hwdb \
	hwdb/70-touchpad.hwdb

SYSINIT_TARGET_WANTS += \
	systemd-hwdb-update.service

# Update hwdb on installation. Do not bother if installing
# in DESTDIR, since this is likely for packaging purposes.
hwdb-update-hook:
	-test -n "$(DESTDIR)" || $(rootbindir)/systemd-hwdb update

INSTALL_DATA_HOOKS += \
	hwdb-update-hook

hwdb-remove-hook:
	-test -n "$(DESTDIR)" || rm -f /etc/udev/hwdb.bin
endif

EXTRA_DIST += \
	units/systemd-hwdb-update.service.in \
	hwdb/ids-update.pl \
	hwdb/sdio.ids

# ------------------------------------------------------------------------------
if ENABLE_TESTS
TESTS += \
	test/udev-test.pl

if HAVE_PYTHON
TESTS += \
	test/rule-syntax-check.py

if HAVE_SYSV_COMPAT
TESTS += \
	test/sysv-generator-test.py
endif
endif
endif

tests += \
	test-libudev

manual_tests += \
	test-udev

test_libudev_SOURCES = \
	src/test/test-libudev.c

test_libudev_LDADD = \
	libsystemd-shared.la

test_udev_SOURCES = \
	src/test/test-udev.c

test_udev_LDADD = \
	libudev-core.la  \
	libsystemd-shared.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS) \
	-lrt

if ENABLE_TESTS
check_DATA += \
	test/sys
endif

# packed sysfs test tree
test/sys: test/sys.tar.xz
	-rm -rf test/sys
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)tar -C test/ -xJf $(top_srcdir)/test/sys.tar.xz
	-touch test/sys

test-sys-distclean:
	-rm -rf test/sys
DISTCLEAN_LOCAL_HOOKS += test-sys-distclean

EXTRA_DIST += \
	test/sys.tar.xz \
	test/udev-test.pl \
	test/rule-syntax-check.py \
	test/sysv-generator-test.py \
	test/mocks/fsck

# ------------------------------------------------------------------------------
ata_id_SOURCES = \
	src/udev/ata_id/ata_id.c

ata_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	ata_id

# ------------------------------------------------------------------------------
cdrom_id_SOURCES = \
	src/udev/cdrom_id/cdrom_id.c

cdrom_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	cdrom_id

dist_udevrules_DATA += \
	rules/60-cdrom_id.rules

# ------------------------------------------------------------------------------
collect_SOURCES = \
	src/udev/collect/collect.c

collect_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	collect

# ------------------------------------------------------------------------------
scsi_id_SOURCES =\
	src/udev/scsi_id/scsi_id.c \
	src/udev/scsi_id/scsi_serial.c \
	src/udev/scsi_id/scsi.h \
	src/udev/scsi_id/scsi_id.h

scsi_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	scsi_id

EXTRA_DIST += \
	src/udev/scsi_id/README

# ------------------------------------------------------------------------------
v4l_id_SOURCES = \
	src/udev/v4l_id/v4l_id.c

v4l_id_LDADD = \
	libshared.la

udevlibexec_PROGRAMS += \
	v4l_id

dist_udevrules_DATA += \
	rules/60-persistent-v4l.rules

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
	libsystemd-shared.la

tests += \
	test-id128

# ------------------------------------------------------------------------------

bin_PROGRAMS += \
	systemd-socket-activate

systemd_socket_activate_SOURCES = \
	src/activate/activate.c

systemd_socket_activate_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_journald_SOURCES = \
	src/journal/journald.c \
	src/journal/journald-server.h

systemd_journald_LDADD = \
	libjournal-core.la \
	libsystemd-shared.la

systemd_cat_SOURCES = \
	src/journal/cat.c

systemd_cat_LDADD = \
	libjournal-core.la

if HAVE_LIBCURL
rootlibexec_PROGRAMS += \
        systemd-journal-upload

systemd_journal_upload_SOURCES = \
        src/journal-remote/journal-upload.h \
        src/journal-remote/journal-upload.c \
        src/journal-remote/journal-upload-journal.c

systemd_journal_upload_CFLAGS = \
        $(AM_CFLAGS) \
        $(LIBCURL_CFLAGS)

systemd_journal_upload_LDADD = \
        libsystemd-shared.la \
        $(LIBCURL_LIBS)

nodist_systemunit_DATA += \
        units/systemd-journal-upload.service

nodist_pkgsysconf_DATA += \
        src/journal-remote/journal-upload.conf
endif

EXTRA_DIST += \
        units/systemd-journal-upload.service.in \
        src/journal-remote/journal-upload.conf.in

if HAVE_MICROHTTPD
rootlibexec_PROGRAMS += \
	systemd-journal-remote

systemd_journal_remote_SOURCES = \
	src/journal-remote/journal-remote-parse.h \
	src/journal-remote/journal-remote-parse.c \
	src/journal-remote/journal-remote-write.h \
	src/journal-remote/journal-remote-write.c \
	src/journal-remote/journal-remote.h \
	src/journal-remote/journal-remote.c

systemd_journal_remote_LDADD = \
	libjournal-core.la

systemd_journal_remote_SOURCES += \
	src/journal-remote/microhttpd-util.h \
	src/journal-remote/microhttpd-util.c

systemd_journal_remote_CFLAGS = \
	$(AM_CFLAGS) \
	$(MICROHTTPD_CFLAGS)

systemd_journal_remote_LDADD += \
	$(MICROHTTPD_LIBS)

if ENABLE_TMPFILES
dist_tmpfiles_DATA += \
	tmpfiles.d/systemd-remote.conf
endif

if HAVE_GNUTLS
systemd_journal_remote_LDADD += \
	$(GNUTLS_LIBS)
endif

# systemd-journal-remote make sense mostly with full crypto stack
dist_systemunit_DATA += \
	units/systemd-journal-remote.socket

nodist_systemunit_DATA += \
	units/systemd-journal-remote.service

journal-remote-install-hook: journal-install-hook
	-$(MKDIR_P) $(DESTDIR)/var/log/journal/remote
	-chown 0:0 $(DESTDIR)/var/log/journal/remote
	-chmod 755 $(DESTDIR)/var/log/journal/remote

INSTALL_EXEC_HOOKS += journal-remote-install-hook

nodist_pkgsysconf_DATA += \
	src/journal-remote/journal-remote.conf

EXTRA_DIST += \
	units/systemd-journal-remote.service.in \
	src/journal-remote/journal-remote.conf.in \
	src/journal-remote/log-generator.py
endif

# using _CFLAGS = in the conditional below would suppress AM_CFLAGS
journalctl_CFLAGS = \
	$(AM_CFLAGS)

journalctl_SOURCES = \
	src/journal/journalctl.c

journalctl_LDADD = \
	libsystemd-shared.la \
	libudev-core.la

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
	libjournal-core.la

test_journal_send_SOURCES = \
	src/journal/test-journal-send.c

test_journal_send_LDADD = \
	libjournal-core.la

test_journal_syslog_SOURCES = \
	src/journal/test-journal-syslog.c

test_journal_syslog_LDADD = \
	libjournal-core.la

test_journal_match_SOURCES = \
	src/journal/test-journal-match.c

test_journal_match_LDADD = \
	libjournal-core.la

test_journal_enum_SOURCES = \
	src/journal/test-journal-enum.c

test_journal_enum_LDADD = \
	libjournal-core.la

test_journal_stream_SOURCES = \
	src/journal/test-journal-stream.c

test_journal_stream_LDADD = \
	libjournal-core.la

test_journal_flush_SOURCES = \
	src/journal/test-journal-flush.c

test_journal_flush_LDADD = \
	libjournal-core.la

test_journal_init_SOURCES = \
	src/journal/test-journal-init.c

test_journal_init_LDADD = \
	libjournal-core.la

test_journal_verify_SOURCES = \
	src/journal/test-journal-verify.c

test_journal_verify_LDADD = \
	libjournal-core.la

test_journal_interleaving_SOURCES = \
	src/journal/test-journal-interleaving.c

test_journal_interleaving_LDADD = \
	libjournal-core.la

test_mmap_cache_SOURCES = \
	src/journal/test-mmap-cache.c

test_mmap_cache_LDADD = \
	libjournal-core.la

test_catalog_SOURCES = \
	src/journal/test-catalog.c

test_catalog_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DCATALOG_DIR=\"$(abs_top_builddir)/catalog\"

test_catalog_LDADD = \
	libjournal-core.la

test_compress_SOURCES = \
	src/journal/test-compress.c

test_compress_LDADD = \
	libsystemd-shared.la

if HAVE_LZ4
test_compress_LDADD += \
	-llz4
endif

test_compress_benchmark_SOURCES = \
	src/journal/test-compress-benchmark.c

test_compress_benchmark_LDADD = \
	libsystemd-shared.la

test_audit_type_SOURCES = \
	src/journal/test-audit-type.c

test_audit_type_LDADD = \
	libjournal-core.la

libjournal_core_la_SOURCES = \
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
	src/journal/journald-audit.c \
	src/journal/journald-audit.h \
	src/journal/journald-rate-limit.c \
	src/journal/journald-rate-limit.h \
	src/journal/journal-internal.h

nodist_libjournal_core_la_SOURCES = \
	src/journal/journald-gperf.c

libjournal_core_la_LIBADD = \
	libsystemd-shared.la

noinst_LTLIBRARIES += \
	libjournal-core.la

journal-install-hook:
	-$(MKDIR_P) $(DESTDIR)/var/log/journal
	-chown 0:0 $(DESTDIR)/var/log/journal
	-chmod 755 $(DESTDIR)/var/log/journal
	-setfacl -nm g:adm:rx,d:g:adm:rx $(DESTDIR)/var/log/journal/
	-setfacl -nm g:wheel:rx,d:g:wheel:rx $(DESTDIR)/var/log/journal/

journal-uninstall-hook:
	-rmdir $(DESTDIR)/var/log/journal/remote
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

tests += \
	test-journal \
	test-journal-enum \
	test-journal-send \
	test-journal-syslog \
	test-journal-match \
	test-journal-stream \
	test-journal-init \
	test-journal-verify \
	test-journal-interleaving \
	test-journal-flush \
	test-mmap-cache \
	test-catalog \
	test-audit-type

if HAVE_COMPRESSION
tests += \
	test-compress \
	test-compress-benchmark
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
	src/journal/mmap-cache.h \
	src/journal/compress.c \
	src/journal/audit-type.h \
	src/journal/audit-type.c \
	src/shared/gcrypt-util.h \
	src/shared/gcrypt-util.c

nodist_libsystemd_journal_internal_la_SOURCES = \
	src/journal/audit_type-to-name.h

gperf_txt_sources += \
	src/journal/audit_type-list.txt

# using _CFLAGS = in the conditional below would suppress AM_CFLAGS
libsystemd_journal_internal_la_CFLAGS = \
	$(AM_CFLAGS)

libsystemd_journal_internal_la_LIBADD =

if HAVE_XZ
libsystemd_journal_internal_la_CFLAGS += \
	$(XZ_CFLAGS)

libsystemd_journal_internal_la_LIBADD += \
	$(XZ_LIBS)
endif

if HAVE_LZ4
libsystemd_journal_internal_la_LIBADD += \
	-llz4
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
	units/systemd-journald-dev-log.socket \
	units/systemd-journald-audit.socket

nodist_systemunit_DATA += \
	units/systemd-journald.service \
	units/systemd-journal-flush.service \
	units/systemd-journal-catalog-update.service

dist_pkgsysconf_DATA += \
	src/journal/journald.conf

nodist_catalog_DATA = \
	catalog/systemd.bg.catalog \
	catalog/systemd.be.catalog \
	catalog/systemd.be@latin.catalog \
	catalog/systemd.fr.catalog \
	catalog/systemd.it.catalog \
	catalog/systemd.pl.catalog \
	catalog/systemd.pt_BR.catalog \
	catalog/systemd.ru.catalog \
	catalog/systemd.zh_CN.catalog \
	catalog/systemd.zh_TW.catalog \
	catalog/systemd.catalog

EXTRA_DIST += \
	$(nodist_catalog_DATA:.catalog=.catalog.in)

# Note that we don't use @@ for replacement markers here, but %%. This is
# because the catalog uses @@ already for its runtime replacement handling and
# we don't want to conflict with that.
catalog/%.catalog: catalog/%.catalog.in
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED) -e 's~%SUPPORT_URL%~$(SUPPORT_URL)~' < $< > $@

SOCKETS_TARGET_WANTS += \
	systemd-journald.socket \
	systemd-journald-dev-log.socket \
	systemd-journald-audit.socket

SYSINIT_TARGET_WANTS += \
	systemd-journald.service \
	systemd-journal-flush.service \
	systemd-journal-catalog-update.service

EXTRA_DIST += \
	units/systemd-journald.service.in \
	units/systemd-journal-flush.service.in \
	units/systemd-journal-catalog-update.service.in

gperf_gperf_sources += \
	src/journal/journald-gperf.gperf

# ------------------------------------------------------------------------------
if HAVE_MICROHTTPD
gatewayddocumentrootdir=$(pkgdatadir)/gatewayd

rootlibexec_PROGRAMS += \
	systemd-journal-gatewayd

systemd_journal_gatewayd_SOURCES = \
	src/journal-remote/journal-gatewayd.c \
	src/journal-remote/microhttpd-util.h \
	src/journal-remote/microhttpd-util.c

systemd_journal_gatewayd_LDADD = \
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
	src/journal-remote/browse.html

endif

EXTRA_DIST += \
	units/systemd-journal-gatewayd.service.in

# ------------------------------------------------------------------------------

systemd_socket_proxyd_SOURCES = \
	src/socket-proxy/socket-proxyd.c

systemd_socket_proxyd_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
if ENABLE_COREDUMP
systemd_coredump_SOURCES = \
	src/coredump/coredump.c \
	src/coredump/coredump-vacuum.c \
	src/coredump/coredump-vacuum.h

systemd_coredump_CFLAGS = \
	$(AM_CFLAGS) \
	$(ACL_CFLAGS)

systemd_coredump_LDADD = \
	libsystemd-shared.la \
	$(ACL_LIBS)

if HAVE_ELFUTILS
systemd_coredump_SOURCES += \
	src/coredump/stacktrace.c \
	src/coredump/stacktrace.h

systemd_coredump_LDADD += \
	$(ELFUTILS_LIBS)
endif

nodist_systemunit_DATA += \
	units/systemd-coredump@.service

dist_systemunit_DATA += \
	units/systemd-coredump.socket

SOCKETS_TARGET_WANTS += \
	systemd-coredump.socket

rootlibexec_PROGRAMS += \
	systemd-coredump

dist_pkgsysconf_DATA += \
	src/coredump/coredump.conf

coredumpctl_SOURCES = \
	src/coredump/coredumpctl.c

coredumpctl_LDADD = \
	libsystemd-shared.la

bin_PROGRAMS += \
	coredumpctl

manual_tests += \
	test-coredump-vacuum

test_coredump_vacuum_SOURCES = \
	src/coredump/test-coredump-vacuum.c  \
	src/coredump/coredump-vacuum.c \
	src/coredump/coredump-vacuum.h

test_coredump_vacuum_LDADD = \
	libsystemd-shared.la

dist_bashcompletion_data += \
	shell-completion/bash/coredumpctl

dist_zshcompletion_data += \
	shell-completion/zsh/_coredumpctl

nodist_sysctl_DATA = \
	sysctl.d/50-coredump.conf

CLEANFILES += \
	sysctl.d/50-coredump.conf
endif

EXTRA_DIST += \
	sysctl.d/50-coredump.conf.in \
	units/systemd-coredump@.service.in

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

nodist_udevrules_DATA += \
	src/vconsole/90-vconsole.rules

nodist_systemunit_DATA += \
	units/systemd-vconsole-setup.service

SYSINIT_TARGET_WANTS += \
	systemd-vconsole-setup.service
endif

EXTRA_DIST += \
	src/vconsole/90-vconsole.rules.in \
	units/systemd-vconsole-setup.service.in

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
	libsystemd-shared.la
endif

EXTRA_DIST += \
	units/systemd-backlight@.service.in

# ------------------------------------------------------------------------------
if ENABLE_RFKILL
rootlibexec_PROGRAMS += \
	systemd-rfkill

nodist_systemunit_DATA += \
	units/systemd-rfkill.service

dist_systemunit_DATA += \
	units/systemd-rfkill.socket

systemd_rfkill_SOURCES = \
	src/rfkill/rfkill.c

systemd_rfkill_LDADD = \
	libsystemd-shared.la
endif

EXTRA_DIST += \
	units/systemd-rfkill.service.in

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
	libsystemd-shared.la \
	$(LIBCRYPTSETUP_LIBS)

systemd_cryptsetup_generator_SOURCES = \
	src/cryptsetup/cryptsetup-generator.c

systemd_cryptsetup_generator_LDADD = \
	libsystemd-shared.la

SYSINIT_TARGET_WANTS += \
	cryptsetup.target

endif

# ------------------------------------------------------------------------------
if ENABLE_HOSTNAMED
systemd_hostnamed_SOURCES = \
	src/hostname/hostnamed.c

systemd_hostnamed_LDADD = \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-hostnamed

nodist_systemunit_DATA += \
	units/systemd-hostnamed.service

dist_systemunit_DATA_busnames += \
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
	libsystemd-shared.la

bin_PROGRAMS += \
	hostnamectl

dist_bashcompletion_data += \
	shell-completion/bash/hostnamectl

dist_zshcompletion_data += \
	shell-completion/zsh/_hostnamectl
endif

polkitpolicy_in_files += \
	src/hostname/org.freedesktop.hostname1.policy.in

EXTRA_DIST += \
	units/systemd-hostnamed.service.in

# ------------------------------------------------------------------------------
dist_systemunit_DATA_busnames += \
	units/org.freedesktop.systemd1.busname

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.systemd1.busname

# ------------------------------------------------------------------------------
if ENABLE_LOCALED
systemd_localed_SOURCES = \
	src/locale/localed.c \
	src/locale/keymap-util.c \
	src/locale/keymap-util.h

systemd_localed_LDADD = \
	libsystemd-shared.la \
	-ldl

systemd_localed_CFLAGS = \
	$(AM_CFLAGS) \
	$(XKBCOMMON_CFLAGS)

nodist_systemunit_DATA += \
	units/systemd-localed.service

dist_systemunit_DATA_busnames += \
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

dist_pkgdata_DATA = \
	src/locale/kbd-model-map \
	src/locale/language-fallback-map

test_keymap_util_SOURCES = \
	src/locale/test-keymap-util.c \
	src/locale/keymap-util.c \
	src/locale/keymap-util.h

test_keymap_util_LDADD = \
	libsystemd-shared.la \
	-ldl

tests += \
	test-keymap-util

localectl_SOURCES = \
	src/locale/localectl.c

localectl_LDADD = \
	libsystemd-shared.la

bin_PROGRAMS += \
	localectl

dist_bashcompletion_data += \
	shell-completion/bash/localectl

dist_zshcompletion_data += \
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
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-timedated

dist_dbussystemservice_DATA += \
	src/timedate/org.freedesktop.timedate1.service

dist_dbuspolicy_DATA += \
	src/timedate/org.freedesktop.timedate1.conf

nodist_systemunit_DATA += \
	units/systemd-timedated.service

dist_systemunit_DATA_busnames += \
	units/org.freedesktop.timedate1.busname

polkitpolicy_files += \
	src/timedate/org.freedesktop.timedate1.policy

SYSTEM_UNIT_ALIASES += \
	systemd-timedated.service dbus-org.freedesktop.timedate1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.timedate1.busname

timedatectl_SOURCES = \
	src/timedate/timedatectl.c

timedatectl_LDADD = \
	libsystemd-shared.la

bin_PROGRAMS += \
	timedatectl

dist_bashcompletion_data += \
	shell-completion/bash/timedatectl

dist_zshcompletion_data += \
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
	src/timesync/timesyncd-manager.c \
	src/timesync/timesyncd-manager.h \
	src/timesync/timesyncd-conf.c \
	src/timesync/timesyncd-conf.h \
	src/timesync/timesyncd-server.c \
	src/timesync/timesyncd-server.h

nodist_systemd_timesyncd_SOURCES = \
	src/timesync/timesyncd-gperf.c

systemd_timesyncd_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la \
	-lm

rootlibexec_PROGRAMS += \
	systemd-timesyncd

nodist_systemunit_DATA += \
	units/systemd-timesyncd.service

GENERAL_ALIASES += \
	$(systemunitdir)/systemd-timesyncd.service $(pkgsysconfdir)/system/sysinit.target.wants/systemd-timesyncd.service

nodist_pkgsysconf_DATA += \
	src/timesync/timesyncd.conf

endif

gperf_gperf_sources += \
	src/timesync/timesyncd-gperf.gperf

EXTRA_DIST += \
	units/systemd-timesyncd.service.in \
	src/timesync/timesyncd.conf.in

# ------------------------------------------------------------------------------
test_nss_SOURCES = \
	src/test/test-nss.c

test_nss_LDADD = \
	libsystemd-internal.la \
	libbasic.la \
	-ldl

manual_tests += \
	test-nss

# ------------------------------------------------------------------------------
if HAVE_MYHOSTNAME
libnss_myhostname_la_SOURCES = \
	src/nss-myhostname/nss-myhostname.sym \
	src/nss-myhostname/nss-myhostname.c

libnss_myhostname_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.2 \
	-Wl,--version-script=$(top_srcdir)/src/nss-myhostname/nss-myhostname.sym

libnss_myhostname_la_LIBADD = \
	libsystemd-internal.la \
	libbasic.la

lib_LTLIBRARIES += \
	libnss_myhostname.la
endif

# ------------------------------------------------------------------------------
if ENABLE_MACHINED
systemd_machined_SOURCES = \
	src/machine/machined.c \
	src/machine/machined.h

systemd_machined_LDADD = \
	libmachine-core.la

rootlibexec_PROGRAMS += \
	systemd-machined

libmachine_core_la_SOURCES = \
	src/machine/machine.c \
	src/machine/machine.h \
	src/machine/machined-dbus.c \
	src/machine/machine-dbus.c \
	src/machine/machine-dbus.h \
	src/machine/image-dbus.c \
	src/machine/image-dbus.h \
	src/machine/operation.c \
	src/machine/operation.h

libmachine_core_la_LIBADD = \
	libsystemd-shared.la

noinst_LTLIBRARIES += \
	libmachine-core.la

machinectl_SOURCES = \
	src/machine/machinectl.c

machinectl_LDADD = \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	machinectl

test_machine_tables_SOURCES = \
	src/machine/test-machine-tables.c

test_machine_tables_LDADD = \
	libmachine-core.la

tests += \
	test-machine-tables

nodist_systemunit_DATA += \
	units/systemd-machined.service

dist_systemunit_DATA += \
	units/machine.slice

dist_systemunit_DATA_busnames += \
	units/org.freedesktop.machine1.busname

dist_dbussystemservice_DATA += \
	src/machine/org.freedesktop.machine1.service

dist_dbuspolicy_DATA += \
	src/machine/org.freedesktop.machine1.conf

polkitpolicy_files += \
	src/machine/org.freedesktop.machine1.policy

dist_bashcompletion_data += \
	shell-completion/bash/machinectl

dist_zshcompletion_data += \
	shell-completion/zsh/_machinectl \
	shell-completion/zsh/_sd_machines

SYSTEM_UNIT_ALIASES += \
	systemd-machined.service dbus-org.freedesktop.machine1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.machine1.busname

libnss_mymachines_la_SOURCES = \
	src/nss-mymachines/nss-mymachines.sym \
	src/nss-mymachines/nss-mymachines.c

libnss_mymachines_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.2 \
	-Wl,--version-script=$(top_srcdir)/src/nss-mymachines/nss-mymachines.sym

libnss_mymachines_la_LIBADD = \
	libsystemd-internal.la \
	libbasic.la

lib_LTLIBRARIES += \
	libnss_mymachines.la

endif

polkitpolicy_in_files += \
	src/machine/org.freedesktop.machine1.policy.in

EXTRA_DIST += \
	units/systemd-machined.service.in

# ------------------------------------------------------------------------------
if ENABLE_IMPORTD

if HAVE_LIBCURL
if HAVE_XZ
if HAVE_ZLIB
if HAVE_BZIP2
if HAVE_GCRYPT

rootlibexec_PROGRAMS += \
	systemd-importd \
	systemd-pull \
	systemd-import \
	systemd-export

systemd_importd_SOURCES = \
	src/import/importd.c

systemd_importd_CFLAGS = \
	$(AM_CFLAGS) \
	-D SYSTEMD_PULL_PATH=\"$(rootlibexecdir)/systemd-pull\" \
	-D SYSTEMD_IMPORT_PATH=\"$(rootlibexecdir)/systemd-import\" \
	-D SYSTEMD_EXPORT_PATH=\"$(rootlibexecdir)/systemd-export\"

systemd_importd_LDADD = \
	libsystemd-shared.la

systemd_pull_SOURCES = \
	src/import/pull.c \
	src/import/pull-raw.c \
	src/import/pull-raw.h \
	src/import/pull-tar.c \
	src/import/pull-tar.h \
	src/import/pull-job.c \
	src/import/pull-job.h \
	src/import/pull-common.c \
	src/import/pull-common.h \
	src/import/import-common.c \
	src/import/import-common.h \
	src/import/import-compress.c \
	src/import/import-compress.h \
	src/import/curl-util.c \
	src/import/curl-util.h \
	src/import/qcow2-util.c \
	src/import/qcow2-util.h

systemd_pull_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBCURL_CFLAGS) \
	$(XZ_CFLAGS) \
	$(ZLIB_CFLAGS) \
	$(GCRYPT_CFLAGS) \
	-D VENDOR_KEYRING_PATH=\"$(rootlibexecdir)/import-pubring.gpg\" \
	-D USER_KEYRING_PATH=\"$(pkgsysconfdir)/import-pubring.gpg\"

systemd_pull_LDADD = \
	libsystemd-shared.la \
	$(LIBCURL_LIBS) \
	$(XZ_LIBS) \
	$(ZLIB_LIBS) \
	-lbz2 \
	$(GCRYPT_LIBS)

systemd_import_SOURCES = \
	src/import/import.c \
	src/import/import-raw.c \
	src/import/import-raw.h \
	src/import/import-tar.c \
	src/import/import-tar.h \
	src/import/import-common.c \
	src/import/import-common.h \
	src/import/import-compress.c \
	src/import/import-compress.h \
	src/import/qcow2-util.c \
	src/import/qcow2-util.h

systemd_import_CFLAGS = \
	$(AM_CFLAGS) \
	$(XZ_CFLAGS) \
	$(ZLIB_CFLAGS)

systemd_import_LDADD = \
	libsystemd-shared.la \
	$(XZ_LIBS) \
	$(ZLIB_LIBS) \
	-lbz2

systemd_export_SOURCES = \
	src/import/export.c \
	src/import/export-tar.c \
	src/import/export-tar.h \
	src/import/export-raw.c \
	src/import/export-raw.h \
	src/import/import-common.c \
	src/import/import-common.h \
	src/import/import-compress.c \
	src/import/import-compress.h

systemd_export_CFLAGS = \
	$(AM_CFLAGS) \
	$(XZ_CFLAGS) \
	$(ZLIB_CFLAGS)

systemd_export_LDADD = \
	libsystemd-shared.la \
	$(XZ_LIBS) \
	$(ZLIB_LIBS) \
	-lbz2

dist_rootlibexec_DATA += \
	src/import/import-pubring.gpg

nodist_systemunit_DATA += \
	units/systemd-importd.service

dist_systemunit_DATA_busnames += \
	units/org.freedesktop.import1.busname

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.import1.busname

SYSTEM_UNIT_ALIASES += \
	systemd-importd.service dbus-org.freedesktop.import1.service

dist_dbussystemservice_DATA += \
	src/import/org.freedesktop.import1.service

dist_dbuspolicy_DATA += \
	src/import/org.freedesktop.import1.conf

polkitpolicy_files += \
	src/import/org.freedesktop.import1.policy

manual_tests += \
	test-qcow2

test_qcow2_SOURCES = \
	src/import/test-qcow2.c \
	src/import/qcow2-util.c \
	src/import/qcow2-util.h

test_qcow2_CFLAGS = \
	$(AM_CFLAGS) \
	$(ZLIB_CFLAGS)

test_qcow2_LDADD = \
	libsystemd-shared.la \
	$(ZLIB_LIBS)

endif
endif
endif
endif
endif

endif

polkitpolicy_in_files += \
	src/import/org.freedesktop.import1.policy.in

EXTRA_DIST += \
	units/systemd-importd.service.in


# ------------------------------------------------------------------------------
if ENABLE_RESOLVED

basic_dns_sources = \
	src/resolve/resolved-dns-dnssec.c \
	src/resolve/resolved-dns-dnssec.h \
	src/resolve/resolved-dns-packet.c \
	src/resolve/resolved-dns-packet.h \
	src/resolve/resolved-dns-rr.c \
	src/resolve/resolved-dns-rr.h \
	src/resolve/resolved-dns-answer.c \
	src/resolve/resolved-dns-answer.h \
	src/resolve/resolved-dns-question.c \
	src/resolve/resolved-dns-question.h \
	src/resolve/dns-type.c \
	src/resolve/dns-type.h

systemd_resolved_SOURCES = \
	src/resolve/resolved.c \
	src/resolve/resolved-manager.c \
	src/resolve/resolved-manager.h \
	src/resolve/resolved-conf.c \
	src/resolve/resolved-conf.h \
	src/resolve/resolved-resolv-conf.c \
	src/resolve/resolved-resolv-conf.h \
	src/resolve/resolved-bus.c \
	src/resolve/resolved-bus.h \
	src/resolve/resolved-link.h \
	src/resolve/resolved-link.c \
	src/resolve/resolved-link-bus.c \
	src/resolve/resolved-link-bus.h \
	src/resolve/resolved-llmnr.h \
	src/resolve/resolved-llmnr.c \
	src/resolve/resolved-mdns.h \
	src/resolve/resolved-mdns.c \
	src/resolve/resolved-def.h \
	$(basic_dns_sources) \
	src/resolve/resolved-dns-query.h \
	src/resolve/resolved-dns-query.c \
	src/resolve/resolved-dns-synthesize.h \
	src/resolve/resolved-dns-synthesize.c \
	src/resolve/resolved-dns-transaction.h \
	src/resolve/resolved-dns-transaction.c \
	src/resolve/resolved-dns-scope.h \
	src/resolve/resolved-dns-scope.c \
	src/resolve/resolved-dns-server.h \
	src/resolve/resolved-dns-server.c \
	src/resolve/resolved-dns-search-domain.h \
	src/resolve/resolved-dns-search-domain.c \
	src/resolve/resolved-dns-cache.h \
	src/resolve/resolved-dns-cache.c \
	src/resolve/resolved-dns-zone.h \
	src/resolve/resolved-dns-zone.c \
	src/resolve/resolved-dns-stream.h \
	src/resolve/resolved-dns-stream.c \
	src/resolve/resolved-dns-trust-anchor.h \
	src/resolve/resolved-dns-trust-anchor.c \
	src/resolve/resolved-dns-stub.h \
	src/resolve/resolved-dns-stub.c \
	src/resolve/resolved-etc-hosts.h \
	src/resolve/resolved-etc-hosts.c \
	src/shared/gcrypt-util.c \
	src/shared/gcrypt-util.h

nodist_systemd_resolved_SOURCES = \
	src/resolve/dns_type-from-name.h \
	src/resolve/dns_type-to-name.h \
	src/resolve/resolved-gperf.c

systemd_resolved_CFLAGS = \
	$(AM_CFLAGS) \
	$(GCRYPT_CFLAGS)

systemd_resolved_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la \
	$(GCRYPT_LIBS) \
	-lm

rootlibexec_PROGRAMS += \
	systemd-resolved

nodist_systemunit_DATA += \
	units/systemd-resolved.service

dist_systemunit_DATA_busnames += \
	units/org.freedesktop.resolve1.busname

dist_dbuspolicy_DATA += \
	src/resolve/org.freedesktop.resolve1.conf

dist_dbussystemservice_DATA += \
	src/resolve/org.freedesktop.resolve1.service

SYSTEM_UNIT_ALIASES += \
	systemd-resolved.service dbus-org.freedesktop.resolve1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.resolve1.busname

GENERAL_ALIASES += \
	$(systemunitdir)/systemd-resolved.service $(pkgsysconfdir)/system/multi-user.target.wants/systemd-resolved.service

nodist_pkgsysconf_DATA += \
	src/resolve/resolved.conf

libnss_resolve_la_SOURCES = \
	src/nss-resolve/nss-resolve.sym \
	src/nss-resolve/nss-resolve.c

libnss_resolve_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.2 \
	-Wl,--version-script=$(top_srcdir)/src/nss-resolve/nss-resolve.sym

libnss_resolve_la_LIBADD = \
	libsystemd-internal.la \
	libbasic.la \
        -ldl

lib_LTLIBRARIES += \
	libnss_resolve.la

systemd_resolve_SOURCES = \
	src/resolve/resolve-tool.c \
	$(basic_dns_sources) \
	src/shared/gcrypt-util.c \
	src/shared/gcrypt-util.h

nodist_systemd_resolve_SOURCES = \
	src/resolve/dns_type-from-name.h \
	src/resolve/dns_type-to-name.h

systemd_resolve_CFLAGS = \
	$(AM_CFLAGS) \
	$(GCRYPT_CFLAGS)

systemd_resolve_LDADD = \
	libsystemd-shared.la \
	$(GCRYPT_LIBS) \
	-lm

bin_PROGRAMS += \
	systemd-resolve

dist_bashcompletion_data += \
	shell-completion/bash/systemd-resolve

dist_zshcompletion_data += \
	shell-completion/zsh/_systemd-resolve

tests += \
	test-dns-packet \
	test-resolve-tables \
	test-dnssec

manual_tests += \
	test-dnssec-complex

test_resolve_tables_SOURCES = \
	src/resolve/test-resolve-tables.c \
	src/resolve/dns_type-from-name.h \
	src/resolve/dns_type-to-name.h \
	$(basic_dns_sources) \
	src/shared/test-tables.h

test_resolve_tables_CFLAGS = \
	$(AM_CFLAGS) \
	$(GCRYPT_CFLAGS)

test_resolve_tables_LDADD = \
	libsystemd-shared.la \
	$(GCRYPT_LIBS) \
	-lm

test_dns_packet_SOURCES = \
	src/resolve/test-dns-packet.c \
	$(basic_dns_sources)

test_dns_packet_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DRESOLVE_TEST_DIR=\"$(abs_top_srcdir)/src/resolve/test-data\"

test_dns_packet_CFLAGS = \
	$(AM_CFLAGS) \
	$(GCRYPT_CFLAGS)

test_dns_packet_LDADD = \
	libsystemd-shared.la \
	$(GCRYPT_LIBS) \
	-lm

EXTRA_DIST += \
	src/resolve/test-data/_openpgpkey.fedoraproject.org.pkts \
	src/resolve/test-data/fedoraproject.org.pkts \
	src/resolve/test-data/gandi.net.pkts \
	src/resolve/test-data/google.com.pkts \
	src/resolve/test-data/root.pkts \
	src/resolve/test-data/sw1a1aa-sw1a2aa-sw1a2ab-sw1a2ac.find.me.uk.pkts \
	src/resolve/test-data/teamits.com.pkts \
	src/resolve/test-data/zbyszek@fedoraproject.org.pkts \
	src/resolve/test-data/_443._tcp.fedoraproject.org.pkts \
	src/resolve/test-data/kyhwana.org.pkts \
	src/resolve/test-data/fake-caa.pkts

test_dnssec_SOURCES = \
	src/resolve/test-dnssec.c \
	$(basic_dns_sources)

test_dnssec_CFLAGS = \
	$(AM_CFLAGS) \
	$(GCRYPT_CFLAGS)

test_dnssec_LDADD = \
	libsystemd-shared.la \
	$(GCRYPT_LIBS) \
	-lm

test_dnssec_complex_SOURCES = \
	src/resolve/test-dnssec-complex.c \
	src/resolve/dns-type.c \
	src/resolve/dns-type.h

test_dnssec_complex_LDADD = \
	libsystemd-shared.la

endif

gperf_txt_sources += \
	src/resolve/dns_type-list.txt

gperf_gperf_sources += \
	src/resolve/resolved-gperf.gperf

EXTRA_DIST += \
	units/systemd-resolved.service.m4.in \
	src/resolve/resolved.conf.in

dist_rootlibexec_DATA += \
	src/resolve/resolv.conf

# ------------------------------------------------------------------------------
if ENABLE_NETWORKD
rootlibexec_PROGRAMS += \
	systemd-networkd

systemd_networkd_SOURCES = \
	src/network/networkd.c

systemd_networkd_LDADD = \
	libnetworkd-core.la

if HAVE_LIBIPTC
systemd_networkd_LDADD += \
	libfirewall.la
endif

noinst_LTLIBRARIES += \
	libnetworkd-core.la

libnetworkd_core_la_CFLAGS = \
	$(AM_CFLAGS)

libnetworkd_core_la_SOURCES = \
	src/libsystemd-network/network-internal.h \
	src/network/networkd.h \
	src/network/networkd-conf.h \
	src/network/networkd-conf.c \
	src/network/networkd-link.h \
	src/network/networkd-link.c \
	src/network/networkd-netdev.h \
	src/network/networkd-netdev.c \
	src/network/networkd-netdev-vrf.h \
	src/network/networkd-netdev-vrf.c \
	src/network/networkd-netdev-tunnel.h \
	src/network/networkd-netdev-tunnel.c \
	src/network/networkd-netdev-veth.h \
	src/network/networkd-netdev-veth.c \
	src/network/networkd-netdev-vxlan.h \
	src/network/networkd-netdev-vxlan.c \
	src/network/networkd-netdev-vlan.h \
	src/network/networkd-netdev-vlan.c \
	src/network/networkd-netdev-macvlan.h \
	src/network/networkd-netdev-macvlan.c \
	src/network/networkd-netdev-ipvlan.h \
	src/network/networkd-netdev-ipvlan.c \
	src/network/networkd-netdev-dummy.h \
	src/network/networkd-netdev-dummy.c \
	src/network/networkd-netdev-tuntap.h \
	src/network/networkd-netdev-tuntap.c \
	src/network/networkd-netdev-bond.h \
	src/network/networkd-netdev-bond.c \
	src/network/networkd-netdev-bridge.h \
	src/network/networkd-netdev-bridge.c \
	src/network/networkd-link-bus.c \
	src/network/networkd-ipv4ll.c \
	src/network/networkd-dhcp4.c \
	src/network/networkd-dhcp6.c \
	src/network/networkd-ndisc.h \
	src/network/networkd-ndisc.c \
	src/network/networkd-network.h \
	src/network/networkd-network.c \
	src/network/networkd-network-bus.c \
	src/network/networkd-address.h \
	src/network/networkd-address.c \
	src/network/networkd-route.h \
	src/network/networkd-route.c \
	src/network/networkd-manager.c \
	src/network/networkd-manager-bus.c \
	src/network/networkd-fdb.h \
	src/network/networkd-fdb.c \
	src/network/networkd-brvlan.h \
	src/network/networkd-brvlan.c \
	src/network/networkd-address-pool.h \
	src/network/networkd-address-pool.c \
	src/network/networkd-util.h \
	src/network/networkd-util.c \
	src/network/networkd-lldp-tx.h \
	src/network/networkd-lldp-tx.c

nodist_libnetworkd_core_la_SOURCES = \
	src/network/networkd-gperf.c \
	src/network/networkd-network-gperf.c \
	src/network/networkd-netdev-gperf.c

libnetworkd_core_la_LIBADD = \
	libsystemd-network.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-networkd-wait-online

systemd_networkd_wait_online_CFLAGS = \
	$(AM_CFLAGS)

systemd_networkd_wait_online_SOURCES = \
	src/libsystemd-network/network-internal.h \
	src/network/networkd-wait-online.h \
	src/network/networkd-wait-online-link.h \
	src/network/networkd-wait-online.c \
	src/network/networkd-wait-online-manager.c \
	src/network/networkd-wait-online-link.c

systemd_networkd_wait_online_LDADD = \
	libsystemd-network.la \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	networkctl

networkctl_SOURCES = \
	src/network/networkctl.c

networkctl_LDADD = \
	libsystemd-shared.la \
	libsystemd-network.la

dist_bashcompletion_data += \
	shell-completion/bash/networkctl

test_networkd_conf_SOURCES = \
	src/network/test-networkd-conf.c

test_networkd_conf_LDADD = \
	libnetworkd-core.la

test_network_SOURCES = \
	src/network/test-network.c

test_network_LDADD = \
	libnetworkd-core.la

if HAVE_LIBIPTC
test_network_LDADD += \
	libfirewall.la
endif

test_network_tables_SOURCES = \
	src/network/test-network-tables.c \
	src/shared/test-tables.h

test_network_tables_LDADD = \
	libnetworkd-core.la \
	libudev-core.la

if HAVE_LIBIPTC
test_network_tables_LDADD += \
	libfirewall.la
endif

tests += \
	test-networkd-conf \
	test-network \
	test-network-tables

dist_systemunit_DATA += \
	units/systemd-networkd.socket

nodist_systemunit_DATA += \
	units/systemd-networkd.service \
	units/systemd-networkd-wait-online.service

dist_systemunit_DATA_busnames += \
	units/org.freedesktop.network1.busname

dist_dbussystemservice_DATA += \
	src/network/org.freedesktop.network1.service

dist_dbuspolicy_DATA += \
	src/network/org.freedesktop.network1.conf

GENERAL_ALIASES += \
	$(systemunitdir)/systemd-networkd.socket $(pkgsysconfdir)/system/sockets.target.wants/systemd-networkd.socket \
	$(systemunitdir)/systemd-networkd.service $(pkgsysconfdir)/system/multi-user.target.wants/systemd-networkd.service \
	$(systemunitdir)/systemd-networkd-wait-online.service $(pkgsysconfdir)/system/network-online.target.wants/systemd-networkd-wait-online.service

SYSTEM_UNIT_ALIASES += \
	systemd-networkd.service dbus-org.freedesktop.network1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.network1.busname

endif

gperf_gperf_sources += \
	src/network/networkd-gperf.gperf \
	src/network/networkd-network-gperf.gperf \
	src/network/networkd-netdev-gperf.gperf

EXTRA_DIST += \
	units/systemd-networkd.service.m4.in \
	units/systemd-networkd-wait-online.service.in \
	test/networkd-test.py

# ------------------------------------------------------------------------------
if ENABLE_LOGIND
systemd_logind_SOURCES = \
	src/login/logind.c \
	src/login/logind.h

nodist_systemd_logind_SOURCES = \
	src/login/logind-gperf.c

systemd_logind_LDADD = \
	liblogind-core.la

liblogind_core_la_SOURCES = \
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
	src/login/logind-utmp.c \
	src/login/logind-acl.h

liblogind_core_la_LIBADD = \
	libsystemd-shared.la

if HAVE_ACL
liblogind_core_la_SOURCES += \
	src/login/logind-acl.c
endif

noinst_LTLIBRARIES += \
	liblogind-core.la

rootlibexec_PROGRAMS += \
	systemd-logind

loginctl_SOURCES = \
	src/login/loginctl.c \
	src/login/sysfs-show.h \
	src/login/sysfs-show.c

loginctl_LDADD = \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	loginctl

dist_bashcompletion_data += \
	shell-completion/bash/loginctl

dist_zshcompletion_data += \
	shell-completion/zsh/_loginctl \
	shell-completion/zsh/_systemd-inhibit

systemd_inhibit_SOURCES = \
	src/login/inhibit.c

systemd_inhibit_LDADD = \
	libsystemd-shared.la

rootbin_PROGRAMS += \
	systemd-inhibit

test_login_SOURCES = \
	src/libsystemd/sd-login/test-login.c

test_login_LDADD = \
	libsystemd-shared.la

test_login_shared_SOURCES = \
	src/login/test-login-shared.c

test_login_shared_LDADD = \
	libsystemd-shared.la

test_inhibit_SOURCES = \
	src/login/test-inhibit.c

test_inhibit_LDADD = \
	libsystemd-shared.la

test_login_tables_SOURCES = \
	src/login/test-login-tables.c

test_login_tables_LDADD = \
	liblogind-core.la

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
	$(PAM_CFLAGS)

pam_systemd_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-Wl,--version-script=$(top_srcdir)/src/login/pam_systemd.sym

pam_systemd_la_LIBADD = \
	libshared.la \
	$(PAM_LIBS)

pamlib_LTLIBRARIES = \
	pam_systemd.la

dist_pamconf_DATA = \
	src/login/systemd-user

EXTRA_DIST += \
	src/login/systemd-user.m4
endif

nodist_systemunit_DATA += \
	units/systemd-logind.service

dist_systemunit_DATA += \
	units/user.slice

dist_systemunit_DATA_busnames += \
	units/org.freedesktop.login1.busname

dist_dbussystemservice_DATA += \
	src/login/org.freedesktop.login1.service

dist_dbuspolicy_DATA += \
	src/login/org.freedesktop.login1.conf

nodist_pkgsysconf_DATA += \
	src/login/logind.conf

polkitpolicy_files += \
	src/login/org.freedesktop.login1.policy

INSTALL_DIRS += \
	$(systemdstatedir)

MULTI_USER_TARGET_WANTS += \
	systemd-logind.service

SYSTEM_UNIT_ALIASES += \
	systemd-logind.service dbus-org.freedesktop.login1.service

BUSNAMES_TARGET_WANTS += \
	org.freedesktop.login1.busname

dist_udevrules_DATA += \
	src/login/70-uaccess.rules \
	src/login/70-power-switch.rules

nodist_udevrules_DATA += \
	src/login/71-seat.rules \
	src/login/73-seat-late.rules

endif

polkitpolicy_in_files += \
	src/login/org.freedesktop.login1.policy.in

gperf_gperf_sources += \
	src/login/logind-gperf.gperf

EXTRA_DIST += \
	src/login/71-seat.rules.in \
	src/login/73-seat-late.rules.in \
	units/systemd-logind.service.in \
	src/login/logind.conf.in

# ------------------------------------------------------------------------------
if HAVE_PAM

systemd_user_sessions_SOURCES = \
	src/user-sessions/user-sessions.c

systemd_user_sessions_LDADD = \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-user-sessions

nodist_systemunit_DATA += \
	units/systemd-user-sessions.service

MULTI_USER_TARGET_WANTS += \
	systemd-user-sessions.service

endif

EXTRA_DIST += \
	units/systemd-user-sessions.service.in

# ------------------------------------------------------------------------------
EXTRA_DIST += \
	test/Makefile \
	test/README.testsuite \
	test/TEST-01-BASIC \
	test/TEST-01-BASIC/Makefile \
	test/TEST-01-BASIC/test.sh \
	test/TEST-02-CRYPTSETUP \
	test/TEST-02-CRYPTSETUP/Makefile \
	test/TEST-02-CRYPTSETUP/test.sh \
	test/TEST-03-JOBS \
	test/TEST-03-JOBS/Makefile \
	test/TEST-03-JOBS/test-jobs.sh \
	test/TEST-03-JOBS/test.sh \
	test/TEST-04-JOURNAL/Makefile \
	test/TEST-04-JOURNAL/test-journal.sh \
	test/TEST-04-JOURNAL/test.sh \
	test/TEST-05-RLIMITS/Makefile \
	test/TEST-05-RLIMITS/test-rlimits.sh \
	test/TEST-05-RLIMITS/test.sh \
	test/TEST-06-SELINUX/Makefile \
	test/TEST-06-SELINUX/test-selinux-checks.sh \
	test/TEST-06-SELINUX/test.sh \
	test/TEST-06-SELINUX/systemd_test.te \
	test/TEST-06-SELINUX/systemd_test.if \
	test/TEST-07-ISSUE-1981/Makefile \
	test/TEST-07-ISSUE-1981/test-segfault.sh \
	test/TEST-07-ISSUE-1981/test.sh \
	test/TEST-08-ISSUE-2730/Makefile \
	test/TEST-08-ISSUE-2730/test.sh \
	test/TEST-09-ISSUE-2691/Makefile \
	test/TEST-09-ISSUE-2691/test.sh \
	test/TEST-10-ISSUE-2467/Makefile \
	test/TEST-10-ISSUE-2467/test.sh \
	test/TEST-11-ISSUE-3166/Makefile \
	test/TEST-11-ISSUE-3166/test.sh \
	test/TEST-12-ISSUE-3171/Makefile \
	test/TEST-12-ISSUE-3171/test.sh \
	test/test-functions

EXTRA_DIST += \
	test/loopy2.service \
	test/loopy3.service \
	test/loopy4.service \
	test/loopy.service \
	test/loopy.service.d \
	test/loopy.service.d/compat.conf

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
       '|CERTIFICATEROOT=$(CERTIFICATEROOT)|' \
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
       '|SULOGIN=$(SULOGIN)|' \
       '|DEBUGTTY=$(DEBUGTTY)|' \
       '|KILL=$(KILL)|' \
       '|KMOD=$(KMOD)|' \
       '|MOUNT_PATH=$(MOUNT_PATH)|' \
       '|UMOUNT_PATH=$(UMOUNT_PATH)|' \
       '|MKDIR_P=$(MKDIR_P)|' \
       '|QUOTAON=$(QUOTAON)|' \
       '|QUOTACHECK=$(QUOTACHECK)|' \
       '|SYSTEM_SYSVINIT_PATH=$(sysvinitdir)|' \
       '|VARLOGDIR=$(varlogdir)|' \
       '|RC_LOCAL_SCRIPT_PATH_START=$(RC_LOCAL_SCRIPT_PATH_START)|' \
       '|RC_LOCAL_SCRIPT_PATH_STOP=$(RC_LOCAL_SCRIPT_PATH_STOP)|' \
       '|PYTHON=$(PYTHON)|' \
       '|NTP_SERVERS=$(NTP_SERVERS)|' \
       '|DNS_SERVERS=$(DNS_SERVERS)|' \
       '|DEFAULT_DNSSEC_MODE=$(DEFAULT_DNSSEC_MODE)|' \
       '|KILL_USER_PROCESSES=$(KILL_USER_PROCESSES)|' \
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

%.conf: %.conf.in
	$(SED_PROCESS)

src/core/%.systemd: src/core/%.systemd.in
	$(SED_PROCESS)

src/%.policy.in: src/%.policy.in.in
	$(SED_PROCESS)

shell-completion/%: shell-completion/%.in
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

src/%: src/%.m4 $(top_builddir)/config.status
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) < $< > $@

sysusers.d/%: sysusers.d/%.m4 $(top_builddir)/config.status
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) < $< > $@

tmpfiles.d/%: tmpfiles.d/%.m4 $(top_builddir)/config.status
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) < $< > $@


units/%: units/%.m4 $(top_builddir)/config.status
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) -DFOR_SYSTEM=1 < $< > $@

units/user/%: units/user/%.m4 $(top_builddir)/config.status
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_M4)$(M4) -P $(M4_DEFINES) -DFOR_USER=1 < $< > $@

if ENABLE_POLKIT
nodist_polkitpolicy_DATA = \
	$(polkitpolicy_files) \
	$(polkitpolicy_in_in_files:.policy.in.in=.policy)
endif

EXTRA_DIST += \
	$(polkitpolicy_in_files) \
	$(polkitpolicy_in_in_files)

# ------------------------------------------------------------------------------
man/custom-entities.ent: configure.ac
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)(echo '<?xml version="1.0" encoding="utf-8" ?>' && \
	 printf '$(subst '|,<!ENTITY ,$(subst =, ",$(subst |',">\n,$(substitutions))))') \
	 > $@ # '

CLEANFILES += \
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

XSLT = $(if $(XSLTPROC), $(XSLTPROC), xsltproc)
XSLTPROC_PROCESS_MAN = \
	$(AM_V_XSLT)$(XSLT) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-man.xsl $<

XSLTPROC_PROCESS_HTML = \
	$(AM_V_XSLT)$(XSLT) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-html.xsl $<

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
	systemd-initctl.socket

if HAVE_UTMP
if HAVE_SYSV_COMPAT
MULTI_USER_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
GRAPHICAL_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
RESCUE_TARGET_WANTS += \
	systemd-update-utmp-runlevel.service
endif

SYSINIT_TARGET_WANTS += \
	systemd-update-utmp.service
endif

SYSINIT_TARGET_WANTS += \
	systemd-update-done.service

LOCAL_FS_TARGET_WANTS += \
	systemd-remount-fs.service \
	tmp.mount \
	var-lib-machines.mount

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
	$(systemunitdir)/timers.target timers.target \
	$(systemunitdir)/paths.target paths.target \
	$(systemunitdir)/bluetooth.target bluetooth.target \
	$(systemunitdir)/printer.target printer.target \
	$(systemunitdir)/sound.target sound.target \
	$(systemunitdir)/smartcard.target smartcard.target

USER_UNIT_ALIASES += \
	$(systemunitdir)/busnames.target busnames.target

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

if ENABLE_SPLIT_USR
DISTCHECK_CONFIGURE_FLAGS += \
	--enable-split-usr
else
DISTCHECK_CONFIGURE_FLAGS += \
	--disable-split-usr
endif

.PHONY: dist-check-help
dist-check-help: $(rootbin_PROGRAMS) $(bin_PROGRAMS)
	for i in $(abspath $^); do                                             \
            if $$i  --help | grep -v 'default:' | grep -E -q '.{80}.' ; then   \
		echo "$(basename $$i) --help output is too wide:";             \
	        $$i  --help | awk 'length > 80' | grep -E --color=yes '.{80}'; \
	        exit 1;                                                        \
            fi; done

include_compilers = "$(CC)" "$(CC) -ansi" "$(CC) -std=iso9899:1990"
public_headers = $(filter-out src/systemd/_sd-common.h, $(pkginclude_HEADERS) $(include_HEADERS))
.PHONY: dist-check-includes
dist-check-includes: $(public_headers)
	@res=0;                                                        	        \
	for i in $(abspath $^); do	                                        \
	    for cc in $(include_compilers); do                                  \
	        echo "$$cc -o/dev/null -c -x c -include "$$i" - </dev/null";    \
	        $$cc -o/dev/null -c -x c -include "$$i" - </dev/null || res=1;  \
	    done;                                                               \
	done; exit $$res

.PHONY: hwdb-update
hwdb-update:
	( cd $(top_srcdir)/hwdb && \
	wget -O usb.ids 'http://www.linux-usb.org/usb.ids' && \
	wget -O pci.ids 'http://pci-ids.ucw.cz/v2.2/pci.ids' && \
	wget -O ma-large.txt 'http://standards.ieee.org/develop/regauth/oui/oui.txt' && \
	wget -O ma-medium.txt 'http://standards.ieee.org/develop/regauth/oui28/mam.txt' && \
	wget -O ma-small.txt 'http://standards.ieee.org/develop/regauth/oui36/oui36.txt' && \
	wget -O pnp_id_registry.html 'http://www.uefi.org/uefi-pnp-export' && \
	wget -O acpi_id_registry.html 'http://www.uefi.org/uefi-acpi-export' && \
	./ids-update.pl && \
	./acpi-update.py > 20-acpi-vendor.hwdb.base && \
	patch -p0 -o- 20-acpi-vendor.hwdb.base < 20-acpi-vendor.hwdb.patch > 20-acpi-vendor.hwdb )

.PHONY: built-sources
built-sources: $(BUILT_SOURCES)

.PHONY: git-tag
git-tag:
	git tag -s "v$(VERSION)" -m "systemd $(VERSION)"

.PHONY: git-tar
git-tar:
	git archive --format=tar --prefix=systemd-$(VERSION)/ HEAD | gzip > systemd-$(VERSION).tar.gz

www_target = www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd

.PHONY: doc-sync
doc-sync: all
	rsync -rlv --delete-excluded --include="*.html" --exclude="*" --omit-dir-times man/ $(www_target)/man/

.PHONY: install-tree
install-tree: all
	rm -rf $(abs_srcdir)/install-tree
	$(MAKE) install DESTDIR=$(abs_srcdir)/install-tree
	tree $(abs_srcdir)/install-tree

# Let's run all tests of the test suite, but under valgrind. Let's
# exclude perl/python/shell scripts we have in there
.PHONY: valgrind-tests
valgrind-tests: $(TESTS)
	$(AM_V_GEN)for f in $(filter-out %.pl %.py, $^); do \
		if $(LIBTOOL) --mode=execute file $$f | grep -q shell; then \
		echo -e "$${x}Skipping non-binary $$f"; else \
		echo -e "$${x}Running $$f"; \
		$(LIBTOOL) --mode=execute valgrind -q --leak-check=full --max-stackframe=5242880 --error-exitcode=55 $(builddir)/$$f ; fi; \
		x="\n\n"; \
	done

exported-%: %
	$(AM_V_GEN)$(NM) -g --defined-only $(builddir)/.libs/$(<:.la=.so) 2>&1 /dev/null | grep " T " | cut -d" " -f3 > $@

exported: $(addprefix exported-, $(lib_LTLIBRARIES))
	$(AM_V_GEN)sort -u $^ > $@

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
		src/systemd/sd-resolve.h \
		src/systemd/sd-path.h \
		src/systemd/sd-event.h
	$(generate-sym-test)

test-libudev-sym.c: \
		src/libudev/libudev.sym \
		src/udev/udev.h
	$(generate-sym-test)

nodist_test_libsystemd_sym_SOURCES = \
	test-libsystemd-sym.c
test_libsystemd_sym_LDADD = \
	libsystemd.la

nodist_test_libudev_sym_SOURCES = \
	test-libudev-sym.c
test_libudev_sym_CFLAGS = \
	$(AM_CFLAGS) \
	-Wno-deprecated-declarations
test_libudev_sym_LDADD = \
	libudev.la

BUILT_SOURCES += \
	test-libsystemd-sym.c \
	test-libudev-sym.c

CLEANFILES += \
	test-libsystemd-sym.c \
	test-libudev-sym.c

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

EXTRA_DIST += \
        tools/gdb-sd_dump_hashmaps.py

list-keys:
	gpg --verbose --no-options --no-default-keyring --no-auto-key-locate --batch --trust-model=always --keyring=$(srcdir)/src/import/import-pubring.gpg --list-keys

add-key:
	gpg --verbose --no-options --no-default-keyring --no-auto-key-locate --batch --trust-model=always --keyring=$(srcdir)/src/import/import-pubring.gpg --import -
