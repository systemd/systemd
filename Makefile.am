#  -*- Mode: makefile; indent-tabs-mode: t -*- */
#
#  This file is part of systemd.
#
#  Copyright 2010-2012 Lennart Poettering
#  Copyright 2010-2012 Kay Sievers
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

SUBDIRS = . po

# remove targets if the command fails
.DELETE_ON_ERROR:

LIBUDEV_CURRENT=3
LIBUDEV_REVISION=0
LIBUDEV_AGE=2

LIBGUDEV_CURRENT=1
LIBGUDEV_REVISION=2
LIBGUDEV_AGE=1

LIBSYSTEMD_LOGIN_CURRENT=3
LIBSYSTEMD_LOGIN_REVISION=9
LIBSYSTEMD_LOGIN_AGE=3

LIBSYSTEMD_DAEMON_CURRENT=0
LIBSYSTEMD_DAEMON_REVISION=5
LIBSYSTEMD_DAEMON_AGE=0

LIBSYSTEMD_ID128_CURRENT=0
LIBSYSTEMD_ID128_REVISION=15
LIBSYSTEMD_ID128_AGE=0

LIBSYSTEMD_JOURNAL_CURRENT=6
LIBSYSTEMD_JOURNAL_REVISION=0
LIBSYSTEMD_JOURNAL_AGE=6

# Dirs of external packages
dbuspolicydir=@dbuspolicydir@
dbussessionservicedir=@dbussessionservicedir@
dbussystemservicedir=@dbussystemservicedir@
dbusinterfacedir=@dbusinterfacedir@
pamlibdir=@pamlibdir@
pkgconfigdatadir=$(datadir)/pkgconfig
pkgconfiglibdir=$(libdir)/pkgconfig
polkitpolicydir=$(datadir)/polkit-1/actions
bashcompletiondir=$(sysconfdir)/bash_completion.d
rpmmacrosdir=$(sysconfdir)/rpm
sysvinitdir=$(SYSTEM_SYSVINIT_PATH)
varlogdir=$(localstatedir)/log

# Our own, non-special dirs
pkgsysconfdir=$(sysconfdir)/systemd
userunitdir=$(prefix)/lib/systemd/user
userpresetdir=$(prefix)/lib/systemd/user-preset
tmpfilesdir=$(prefix)/lib/tmpfiles.d
sysctldir=$(prefix)/lib/sysctl.d
usergeneratordir=$(prefix)/lib/systemd/user-generators
pkgincludedir=$(includedir)/systemd
systemgeneratordir=$(rootlibexecdir)/system-generators
systemshutdowndir=$(rootlibexecdir)/system-shutdown
systemsleepdir=$(rootlibexecdir)/system-sleep
systemunitdir=$(rootprefix)/lib/systemd/system
systempresetdir=$(rootprefix)/lib/systemd/system-preset
udevlibexecdir=$(rootprefix)/lib/udev
udevhomedir = $(udevlibexecdir)
udevrulesdir = $(udevlibexecdir)/rules.d
udevhwdbdir = $(udevlibexecdir)/hwdb.d

# And these are the special ones for /
rootprefix=@rootprefix@
rootbindir=$(rootprefix)/bin
rootlibexecdir=$(rootprefix)/lib/systemd

CLEANFILES = $(BUILT_SOURCES)
EXTRA_DIST =
BUILT_SOURCES =
INSTALL_EXEC_HOOKS =
UNINSTALL_EXEC_HOOKS =
INSTALL_DATA_HOOKS =
DISTCLEAN_LOCAL_HOOKS =
pkginclude_HEADERS =
noinst_LTLIBRARIES =
lib_LTLIBRARIES =
include_HEADERS =
pkgconfiglib_DATA =
polkitpolicy_in_files =
polkitpolicy_files =
dist_udevrules_DATA =
nodist_udevrules_DATA =
dist_man_MANS =
dist_pkgsysconf_DATA =
dist_pkgdata_DATA =
dist_dbuspolicy_DATA =
dbusinterface_DATA =
dist_dbussystemservice_DATA =
check_PROGRAMS =
check_DATA =
noinst_PROGRAMS =
TESTS =
udevlibexec_PROGRAMS =

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSTEM_CONFIG_FILE=\"$(pkgsysconfdir)/system.conf\" \
	-DSYSTEM_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/system\" \
	-DSYSTEM_DATA_UNIT_PATH=\"$(systemunitdir)\" \
	-DSYSTEM_SYSVINIT_PATH=\"$(SYSTEM_SYSVINIT_PATH)\" \
	-DSYSTEM_SYSVRCND_PATH=\"$(SYSTEM_SYSVRCND_PATH)\" \
	-DUSER_CONFIG_FILE=\"$(pkgsysconfdir)/user.conf\" \
	-DUSER_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/user\" \
	-DUSER_DATA_UNIT_PATH=\"$(userunitdir)\" \
	-DSYSTEMD_CGROUP_AGENT_PATH=\"$(rootlibexecdir)/systemd-cgroups-agent\" \
	-DSYSTEMD_BINARY_PATH=\"$(rootlibexecdir)/systemd\" \
	-DSYSTEMD_SHUTDOWN_BINARY_PATH=\"$(rootlibexecdir)/systemd-shutdown\" \
	-DSYSTEMD_SLEEP_BINARY_PATH=\"$(rootlibexecdir)/systemd-sleep\" \
	-DSYSTEMCTL_BINARY_PATH=\"$(rootbindir)/systemctl\" \
	-DSYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH=\"$(rootbindir)/systemd-tty-ask-password-agent\" \
	-DSYSTEMD_STDIO_BRIDGE_BINARY_PATH=\"$(bindir)/systemd-stdio-bridge\" \
	-DROOTPREFIX=\"$(rootprefix)\" \
	-DRUNTIME_DIR=\"/run\" \
	-DRANDOM_SEED=\"$(localstatedir)/lib/random-seed\" \
	-DSYSTEMD_CRYPTSETUP_PATH=\"$(rootlibexecdir)/systemd-cryptsetup\" \
	-DSYSTEM_GENERATOR_PATH=\"$(systemgeneratordir)\" \
	-DUSER_GENERATOR_PATH=\"$(usergeneratordir)\" \
	-DSYSTEM_SHUTDOWN_PATH=\"$(systemshutdowndir)\" \
	-DSYSTEM_SLEEP_PATH=\"$(systemsleepdir)\" \
	-DSYSTEMD_KBD_MODEL_MAP=\"$(pkgdatadir)/kbd-model-map\" \
	-DX_SERVER=\"$(bindir)/X\" \
	-DUDEVLIBEXECDIR=\"$(udevlibexecdir)\" \
	-DPOLKIT_AGENT_BINARY_PATH=\"$(bindir)/pkttyagent\" \
	-I $(top_srcdir)/src \
	-I $(top_srcdir)/src/shared \
	-I $(top_srcdir)/src/login \
	-I $(top_srcdir)/src/journal \
	-I $(top_srcdir)/src/systemd \
	-I $(top_builddir)/src/core \
	-I $(top_srcdir)/src/core \
	-I $(top_srcdir)/src/libudev \
	-I $(top_srcdir)/src/udev \
	$(OUR_CPPFLAGS)

AM_CFLAGS = $(OUR_CFLAGS)
AM_LDFLAGS = $(OUR_LDFLAGS)

# ------------------------------------------------------------------------------
if TARGET_GENTOO
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\"
else
if TARGET_ARCH
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\"
else
if TARGET_FRUGALWARE
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\"
else
if TARGET_MANDRIVA
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\"
else
if TARGET_ANGSTROM
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\"
else
if TARGET_MAGEIA
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\"
else
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\"
endif
endif
endif
endif
endif
endif

# ------------------------------------------------------------------------------
rootbin_PROGRAMS = \
	systemctl \
	systemd-notify \
	systemd-ask-password \
	systemd-tty-ask-password-agent \
	systemd-tmpfiles \
	systemd-machine-id-setup

bin_PROGRAMS = \
	systemd-cgls \
	systemd-cgtop \
	systemd-stdio-bridge \
	systemd-nspawn \
	systemd-detect-virt \
	systemd-delta

dist_bin_SCRIPTS = \
	src/analyze/systemd-analyze

rootlibexec_PROGRAMS = \
	systemd \
	systemd-cgroups-agent \
	systemd-initctl \
	systemd-update-utmp \
	systemd-shutdownd \
	systemd-shutdown \
	systemd-modules-load \
	systemd-remount-fs \
	systemd-reply-password \
	systemd-fsck \
	systemd-timestamp \
	systemd-ac-power \
	systemd-sysctl \
	systemd-sleep

systemgenerator_PROGRAMS = \
	systemd-getty-generator \
	systemd-fstab-generator \
	systemd-system-update-generator

dist_bashcompletion_DATA = \
	shell-completion/systemd-bash-completion.sh

dist_tmpfiles_DATA = \
	tmpfiles.d/systemd.conf \
	tmpfiles.d/tmp.conf \
	tmpfiles.d/x11.conf

if HAVE_SYSV_COMPAT
dist_tmpfiles_DATA += \
	tmpfiles.d/legacy.conf
endif

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
	units/remote-fs.target \
	units/remote-fs-pre.target \
	units/network.target \
	units/nss-lookup.target \
	units/nss-user-lookup.target \
	units/mail-transfer-agent.target \
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
	units/suspend.target \
	units/swap.target \
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
	units/systemd-tmpfiles-clean.timer \
	units/quotaon.service \
	units/systemd-ask-password-wall.path \
	units/systemd-ask-password-console.path \
	units/syslog.target \
	units/systemd-udevd-control.socket \
	units/systemd-udevd-kernel.socket \
	units/system-update.target

nodist_systemunit_DATA = \
	units/getty@.service \
	units/serial-getty@.service \
	units/console-shell.service \
	units/console-getty.service \
	units/systemd-initctl.service \
	units/systemd-shutdownd.service \
	units/systemd-modules-load.service \
	units/systemd-remount-fs.service \
	units/systemd-update-utmp-runlevel.service \
	units/systemd-update-utmp-shutdown.service \
	units/systemd-tmpfiles-setup.service \
	units/systemd-tmpfiles-clean.service \
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
	units/debug-shell.service

dist_userunit_DATA = \
	units/user/default.target \
	units/user/exit.target

nodist_userunit_DATA = \
	units/user/systemd-exit.service

EXTRA_DIST += \
	units/getty@.service.m4 \
	units/serial-getty@.service.m4 \
	units/console-shell.service.m4.in \
	units/console-getty.service.m4.in \
	units/rescue.service.m4.in \
	units/systemd-initctl.service.in \
	units/systemd-shutdownd.service.in \
	units/systemd-modules-load.service.in \
	units/systemd-remount-fs.service.in \
	units/systemd-update-utmp-runlevel.service.in \
	units/systemd-update-utmp-shutdown.service.in \
	units/systemd-tmpfiles-setup.service.in \
	units/systemd-tmpfiles-clean.service.in \
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
	units/systemd-udevd.service \
	units/systemd-udev-trigger.service \
	units/systemd-udev-settle.service \
	units/debug-shell.service.in \
	units/systemd-hibernate.service.in \
	units/systemd-hybrid-sleep.service.in \
	units/systemd-suspend.service.in \
	units/quotaon.service.in \
	introspect.awk \
	man/custom-html.xsl

if TARGET_FEDORA
dist_systemunit_DATA += \
	units/fedora/rc-local.service \
	units/fedora/halt-local.service
systemgenerator_PROGRAMS += \
	systemd-rc-local-generator
endif

if TARGET_MANDRIVA
dist_systemunit_DATA += \
	units/fedora/rc-local.service \
	units/fedora/halt-local.service
systemgenerator_PROGRAMS += \
	systemd-rc-local-generator
endif

if TARGET_FRUGALWARE
dist_systemunit_DATA += \
	units/frugalware/display-manager.service
endif

if TARGET_SUSE
dist_systemunit_DATA += \
	units/suse/rc-local.service \
	units/suse/halt-local.service
systemgenerator_PROGRAMS += \
	systemd-rc-local-generator
endif

if TARGET_MAGEIA
dist_systemunit_DATA += \
	units/fedora/rc-local.service \
	units/fedora/halt-local.service
systemgenerator_PROGRAMS += \
	systemd-rc-local-generator
endif

dist_doc_DATA = \
	README \
	NEWS \
	LICENSE.LGPL2.1 \
	LICENSE.GPL2 \
	LICENSE.MIT \
	DISTRO_PORTING

@INTLTOOL_POLICY_RULE@

# ------------------------------------------------------------------------------
MANPAGES = \
	man/systemd.1 \
	man/systemctl.1 \
	man/systemd-cgls.1 \
	man/systemd-delta.1 \
	man/systemd-cgtop.1 \
	man/systemd-nspawn.1 \
	man/systemd-tmpfiles.8 \
	man/systemd-notify.1 \
	man/systemd.unit.5 \
	man/systemd.service.5 \
	man/systemd.socket.5 \
	man/systemd.mount.5 \
	man/systemd.automount.5 \
	man/systemd.swap.5 \
	man/systemd.timer.5 \
	man/systemd.path.5 \
	man/systemd.target.5 \
	man/systemd.device.5 \
	man/systemd.snapshot.5 \
	man/systemd.exec.5 \
	man/systemd.kill.5 \
	man/systemd.special.7 \
	man/systemd.journal-fields.7 \
	man/kernel-command-line.7 \
	man/daemon.7 \
	man/bootup.7 \
	man/runlevel.8 \
	man/telinit.8 \
	man/halt.8 \
	man/shutdown.8 \
	man/pam_systemd.8 \
	man/systemd.conf.5 \
	man/tmpfiles.d.5 \
	man/hostname.5 \
	man/localtime.5 \
	man/machine-id.5 \
	man/locale.conf.5 \
	man/os-release.5 \
	man/machine-info.5 \
	man/modules-load.d.5 \
	man/systemd-modules-load.service.8 \
	man/sysctl.d.5 \
	man/systemd-sysctl.service.8 \
	man/systemd-ask-password.1 \
	man/systemd-cat.1 \
	man/systemd-machine-id-setup.1 \
	man/systemd-detect-virt.1 \
	man/journald.conf.5 \
	man/systemd-journald.service.8 \
	man/journalctl.1 \
	man/systemd-coredumpctl.1 \
	man/systemd-inhibit.1 \
	man/systemd-remount-fs.service.8 \
	man/systemd-update-utmp-runlevel.service.8 \
	man/systemd-initctl.service.8 \
	man/systemd-shutdownd.service.8 \
	man/systemd-suspend.service.8 \
	man/systemd-halt.service.8 \
	man/systemd-fsck@.service.8 \
	man/systemd-ask-password-console.service.8 \
	man/systemd-analyze.1 \
	man/systemd-tty-ask-password-agent.1 \
	man/systemd-getty-generator.8 \
	man/systemd-system-update-generator.8 \
	man/systemd-fstab-generator.8 \
	man/systemd.preset.5 \
	man/sd-id128.3 \
	man/sd_id128_to_string.3 \
	man/sd_id128_randomize.3 \
	man/sd_id128_get_machine.3 \
	man/sd-journal.3 \
	man/sd_journal_print.3 \
	man/sd_journal_stream_fd.3 \
	man/sd_journal_open.3 \
	man/sd_journal_next.3 \
	man/sd_journal_get_data.3 \
	man/sd_journal_get_realtime_usec.3 \
	man/sd_journal_get_cutoff_realtime_usec.3 \
	man/sd_journal_get_cursor.3 \
	man/sd_journal_get_fd.3 \
	man/sd_journal_get_usage.3 \
	man/sd_journal_add_match.3 \
	man/sd_journal_seek_head.3 \
	man/sd_journal_query_unique.3

MANPAGES_ALIAS = \
	man/reboot.8 \
	man/poweroff.8 \
	man/init.1 \
	man/systemd-modules-load.8 \
	man/systemd-sysctl.8 \
	man/systemd-journald.socket.8 \
	man/systemd-journald.8 \
	man/systemd-remount-fs.8 \
	man/systemd-update-utmp-shutdown.service.8 \
	man/systemd-update-utmp.8 \
	man/systemd-initctl.socket.8 \
	man/systemd-initctl.8 \
	man/systemd-shutdownd.socket.8 \
	man/systemd-shutdownd.8 \
	man/systemd-hibernate.service.8 \
	man/systemd-hybrid-sleep.service.8 \
	man/systemd-sleep.8 \
	man/systemd-shutdown.8 \
	man/systemd-poweroff.service.8 \
	man/systemd-reboot.service.8 \
	man/systemd-kexec.service.8 \
	man/systemd-fsck.8 \
	man/systemd-fsck-root.service.8 \
	man/systemd-ask-password-console.path.8 \
	man/systemd-ask-password-wall.service.8 \
	man/systemd-ask-password-wall.path.8 \
	man/systemd-tmpfiles-setup.service.8 \
	man/systemd-tmpfiles-clean.service.8 \
	man/systemd-tmpfiles-clean.timer.8 \
	man/sd_id128_t.3 \
	man/SD_ID128_MAKE.3 \
	man/SD_ID128_CONST_STR.3 \
	man/SD_ID128_FORMAT_STR.3 \
	man/SD_ID128_FORMAT_VAL.3 \
	man/sd_id128_equal.3 \
	man/sd_id128_from_string.3 \
	man/sd_id128_get_boot.3 \
	man/sd_journal_printv.3 \
	man/sd_journal_send.3 \
	man/sd_journal_sendv.3 \
	man/sd_journal_perror.3 \
	man/SD_JOURNAL_SUPPRESS_LOCATION.3 \
	man/sd_journal_open_directory.3 \
	man/sd_journal_close.3 \
	man/sd_journal.3 \
	man/SD_JOURNAL_RUNTIME_ONLY.3 \
	man/SD_JOURNAL_SYSTEM_ONLY.3 \
	man/SD_JOURNAL_LOCAL_ONLY.3 \
	man/sd_journal_previous.3 \
	man/sd_journal_next_skip.3 \
	man/sd_journal_previous_skip.3 \
	man/SD_JOURNAL_FOREACH.3 \
	man/SD_JOURNAL_FOREACH_BACKWARDS.3 \
	man/sd_journal_enumerate_data.3 \
	man/sd_journal_restart_data.3 \
	man/SD_JOURNAL_FOREACH_DATA.3 \
	man/sd_journal_get_monotonic_usec.3 \
	man/sd_journal_get_cutoff_monotonic_usec.3 \
	man/sd_journal_reliable_fd.3 \
	man/sd_journal_process.3 \
	man/sd_journal_wait.3 \
	man/SD_JOURNAL_NOP.3 \
	man/SD_JOURNAL_APPEND.3 \
	man/SD_JOURNAL_INVALIDATE.3 \
	man/sd_journal_add_disjunction.3 \
	man/sd_journal_flush_matches.3 \
	man/sd_journal_seek_tail.3 \
	man/sd_journal_seek_monotonic_usec.3 \
	man/sd_journal_seek_realtime_usec.3 \
	man/sd_journal_seek_cursor.3 \
	man/sd_journal_test_cursor.3 \
	man/sd_journal_enumerate_unique.3 \
	man/sd_journal_restart_unique.3 \
	man/SD_JOURNAL_FOREACH_UNIQUE.3

man/reboot.8: man/halt.8
man/poweroff.8: man/halt.8
man/init.1: man/systemd.1
man/systemd-modules-load.8: man/systemd-modules-load.service.8
man/systemd-sysctl.8: man/systemd-sysctl.service.8
man/systemd-journald.socket.8: man/systemd-journald.service.8
man/systemd-journald.8: man/systemd-journald.service.8
man/systemd-remount-fs.8: man/systemd-remount-fs.service.8
man/systemd-update-utmp-shutdown.service.8: man/systemd-update-utmp-runlevel.service.8
man/systemd-update-utmp.8: man/systemd-update-utmp-runlevel.service.8
man/systemd-initctl.socket.8: man/systemd-initctl.service.8
man/systemd-initctl.8: man/systemd-initctl.service.8
man/systemd-shutdownd.socket.8: man/systemd-shutdownd.service.8
man/systemd-shutdownd.8: man/systemd-shutdownd.service.8
man/systemd-hibernate.service.8: man/systemd-suspend.service.8
man/systemd-hybrid-sleep.service.8: man/systemd-suspend.service.8
man/systemd-sleep.8: man/systemd-suspend.service.8
man/systemd-shutdown.8: man/systemd-halt.service.8
man/systemd-poweroff.service.8: man/systemd-halt.service.8
man/systemd-reboot.service.8: man/systemd-halt.service.8
man/systemd-kexec.service.8: man/systemd-halt.service.8
man/systemd-fsck.8: man/systemd-fsck@.service.8
man/systemd-fsck-root.service.8: man/systemd-fsck@.service.8
man/systemd-ask-password-console.path.8: man/systemd-ask-password-console.service.8
man/systemd-ask-password-wall.service.8: man/systemd-ask-password-console.service.8
man/systemd-ask-password-wall.path.8: man/systemd-ask-password-console.service.8
man/systemd-tmpfiles-setup.service.8: man/systemd-tmpfiles.8
man/systemd-tmpfiles-clean.service.8: man/systemd-tmpfiles.8
man/systemd-tmpfiles-clean.timer.8: man/systemd-tmpfiles.8
man/sd_id128_t.3: man/sd-id128.3
man/SD_ID128_MAKE.3: man/sd-id128.3
man/SD_ID128_CONST_STR.3: man/sd-id128.3
man/SD_ID128_FORMAT_STR.3: man/sd-id128.3
man/SD_ID128_FORMAT_VAL.3: man/sd-id128.3
man/sd_id128_equal.3: man/sd-id128.3
man/sd_id128_from_string.3: man/sd_id128_to_string.3
man/sd_id128_get_boot.3: man/sd_id128_get_machine.3
man/sd_journal_printv.3: man/sd_journal_print.3
man/sd_journal_send.3: man/sd_journal_print.3
man/sd_journal_sendv.3: man/sd_journal_print.3
man/sd_journal_perror.3: man/sd_journal_print.3
man/SD_JOURNAL_SUPPRESS_LOCATION.3: man/sd_journal_print.3
man/sd_journal_open_directory.3: man/sd_journal_open.3
man/sd_journal_close.3: man/sd_journal_open.3
man/sd_journal.3: man/sd_journal_open.3
man/SD_JOURNAL_RUNTIME_ONLY.3: man/sd_journal_open.3
man/SD_JOURNAL_SYSTEM_ONLY.3: man/sd_journal_open.3
man/SD_JOURNAL_LOCAL_ONLY.3: man/sd_journal_open.3
man/sd_journal_previous.3: man/sd_journal_next.3
man/sd_journal_next_skip.3: man/sd_journal_next.3
man/sd_journal_previous_skip.3: man/sd_journal_next.3
man/SD_JOURNAL_FOREACH.3: man/sd_journal_next.3
man/SD_JOURNAL_FOREACH_BACKWARDS.3: man/sd_journal_next.3
man/sd_journal_enumerate_data.3: man/sd_journal_get_data.3
man/sd_journal_restart_data.3: man/sd_journal_get_data.3
man/SD_JOURNAL_FOREACH_DATA.3: man/sd_journal_get_data.3
man/sd_journal_get_monotonic_usec.3: man/sd_journal_get_realtime_usec.3
man/sd_journal_get_cutoff_monotonic_usec.3: man/sd_journal_get_cutoff_realtime_usec.3
man/sd_journal_reliable_fd.3: man/sd_journal_get_fd.3
man/sd_journal_process.3: man/sd_journal_get_fd.3
man/sd_journal_wait.3: man/sd_journal_get_fd.3
man/SD_JOURNAL_NOP.3: man/sd_journal_get_fd.3
man/SD_JOURNAL_APPEND.3: man/sd_journal_get_fd.3
man/SD_JOURNAL_INVALIDATE.3: man/sd_journal_get_fd.3
man/sd_journal_add_disjunction.3: man/sd_journal_add_match.3
man/sd_journal_flush_matches.3: man/sd_journal_add_match.3
man/sd_journal_seek_tail.3: man/sd_journal_seek_head.3
man/sd_journal_seek_monotonic_usec.3: man/sd_journal_seek_head.3
man/sd_journal_seek_realtime_usec.3: man/sd_journal_seek_head.3
man/sd_journal_seek_cursor.3: man/sd_journal_seek_head.3
man/sd_journal_test_cursor.3: man/sd_journal_get_cursor.3
man/sd_journal_enumerate_unique.3: man/sd_journal_query_unique.3
man/sd_journal_restart_unique.3: man/sd_journal_query_unique.3
man/SD_JOURNAL_FOREACH_UNIQUE.3: man/sd_journal_query_unique.3

XML_FILES = \
	${patsubst %.1,%.xml,${patsubst %.3,%.xml,${patsubst %.5,%.xml,${patsubst %.7,%.xml,${patsubst %.8,%.xml,$(MANPAGES)}}}}}

if ENABLE_MANPAGES
man_MANS = \
	$(MANPAGES) \
	$(MANPAGES_ALIAS)

noinst_DATA = \
	${XML_FILES:.xml=.html}

CLEANFILES += \
	$(MANPAGES) \
	$(MANPAGES_ALIAS) \
	${XML_FILES:.xml=.html}

if HAVE_PYTHON
noinst_DATA += \
	man/index.html

CLEANFILES += \
	man/index.html

man/index.html: make-man-index.py $(XML_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $^ > $@

MANPAGES += \
	man/systemd.directives.5

EXTRA_DIST += \
	man/index.html

XML_DIRECTIVE_FILES = \
	man/systemd.unit.xml \
	man/systemd.service.xml \
	man/systemd.socket.xml \
	man/systemd.mount.xml \
	man/systemd.automount.xml \
	man/systemd.swap.xml \
	man/systemd.target.xml \
	man/systemd.path.xml \
	man/systemd.timer.xml \
	man/systemd.snapshot.xml \
	man/systemd.exec.xml \
	man/systemd.kill.xml \
	man/systemd.device.xml \
	man/systemd.conf.xml \
	man/systemd.journal-fields.xml

man/systemd.directives.xml: make-directive-index.py $(XML_DIRECTIVE_FILES)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(PYTHON) $^ > $@

EXTRA_DIST += \
	man/systemd.directives.xml

endif

endif

EXTRA_DIST += \
	$(XML_FILES) \
	${XML_FILES:.xml=.html} \
	$(MANPAGES) \
	$(MANPAGES_ALIAS) \
	make-man-index.py \
	make-directive-index.py

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-shared.la

libsystemd_shared_la_SOURCES = \
	src/shared/linux/auto_dev-ioctl.h \
	src/shared/linux/fanotify.h \
	src/shared/linux/seccomp.h \
	src/shared/linux/seccomp-bpf.h \
	src/shared/missing.h \
	src/shared/list.h \
	src/shared/macro.h \
	src/shared/def.h \
	src/shared/sparse-endian.h \
	src/shared/util.c \
	src/shared/util.h \
	src/shared/virt.c \
	src/shared/virt.h \
	src/shared/path-util.c \
	src/shared/path-util.h \
	src/shared/hashmap.c \
	src/shared/hashmap.h \
	src/shared/set.c \
	src/shared/set.h \
	src/shared/strv.c \
	src/shared/strv.h \
	src/shared/strbuf.c \
	src/shared/strbuf.h \
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
	src/shared/pager.c \
	src/shared/pager.h \
	src/shared/ioprio.h \
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
	src/shared/specifier.c \
	src/shared/specifier.h \
	src/shared/spawn-polkit-agent.c \
	src/shared/spawn-polkit-agent.h \
	src/shared/hwclock.c \
	src/shared/hwclock.h \
	src/shared/time-dst.c \
	src/shared/time-dst.h

#-------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-dbus.la

libsystemd_dbus_la_SOURCES = \
	src/shared/dbus-common.c \
	src/shared/dbus-common.h \
	src/shared/dbus-loop.c \
	src/shared/dbus-loop.h \
	src/shared/polkit.c \
	src/shared/polkit.h

libsystemd_dbus_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

libsystemd_dbus_la_LIBADD = \
	$(DBUS_LIBS)

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-units.la

libsystemd_units_la_SOURCES = \
	src/shared/install.c \
	src/shared/install.h \
	src/shared/path-lookup.c \
	src/shared/path-lookup.h

libsystemd_units_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-label.la

libsystemd_label_la_SOURCES = \
	src/shared/cgroup-label.c \
	src/shared/socket-label.c \
	src/shared/label.c \
	src/shared/label.h \
	src/shared/selinux-util.c \
	src/shared/selinux-util.h \
	src/shared/mkdir.c \
	src/shared/mkdir.h \
	src/shared/ask-password-api.c \
	src/shared/ask-password-api.h \
	src/shared/dev-setup.c \
	src/shared/dev-setup.h

libsystemd_label_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SELINUX_CFLAGS)

libsystemd_label_la_LIBADD = \
	$(SELINUX_LIBS)

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libsystemd-logs.la

libsystemd_logs_la_SOURCES = \
	src/shared/logs-show.c \
	src/shared/logs-show.h

libsystemd_logs_la_CFLAGS = \
	$(AM_CFLAGS)

libsystemd_logs_la_LIBADD = \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la \
	libsystemd-shared.la

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
noinst_LTLIBRARIES += \
	libsystemd-audit.la

libsystemd_audit_la_SOURCES = \
	src/shared/audit.c \
	src/shared/audit.h

libsystemd_audit_la_LIBADD = \
	libsystemd-capability.la

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
	src/core/automount.c \
	src/core/automount.h \
	src/core/mount.c \
	src/core/mount.h \
	src/core/swap.c \
	src/core/swap.h \
	src/core/device.c \
	src/core/device.h \
	src/core/target.c \
	src/core/target.h \
	src/core/snapshot.c \
	src/core/snapshot.h \
	src/core/socket.c \
	src/core/socket.h \
	src/core/timer.c \
	src/core/timer.h \
	src/core/path.c \
	src/core/path.h \
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
	src/core/dbus-timer.c \
	src/core/dbus-timer.h \
	src/core/dbus-target.c \
	src/core/dbus-target.h \
	src/core/dbus-mount.c \
	src/core/dbus-mount.h \
	src/core/dbus-automount.c \
	src/core/dbus-automount.h \
	src/core/dbus-swap.c \
	src/core/dbus-swap.h \
	src/core/dbus-snapshot.c \
	src/core/dbus-snapshot.h \
	src/core/dbus-device.c \
	src/core/dbus-device.h \
	src/core/dbus-execute.c \
	src/core/dbus-execute.h \
	src/core/dbus-kill.c \
	src/core/dbus-kill.h \
	src/core/dbus-path.c \
	src/core/dbus-path.h \
	src/core/cgroup.c \
	src/core/cgroup.h \
	src/core/selinux-access.c \
	src/core/selinux-access.h \
	src/core/selinux-setup.c \
	src/core/selinux-setup.h \
	src/core/ima-setup.c \
	src/core/ima-setup.h \
	src/core/kmod-setup.c \
	src/core/kmod-setup.h \
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
	src/core/fdset.c \
	src/core/fdset.h \
	src/core/condition.c \
	src/core/condition.h \
	src/core/namespace.c \
	src/core/namespace.h \
	src/core/tcpwrap.c \
	src/core/tcpwrap.h \
	src/core/cgroup-attr.c \
	src/core/cgroup-attr.h \
	src/core/securebits.h \
	src/core/initreq.h \
	src/core/special.h \
	src/core/bus-errors.h \
	src/core/build.h \
	src/core/sysfs-show.h \
	src/core/switch-root.h \
	src/core/switch-root.c \
	src/core/killall.h \
	src/core/killall.c \
	src/core/syscall-list.c \
	src/core/syscall-list.h \
	src/core/audit-fd.c \
	src/core/audit-fd.h

nodist_libsystemd_core_la_SOURCES = \
	src/core/load-fragment-gperf.c \
	src/core/load-fragment-gperf-nulstr.c \
	src/core/syscall-from-name.h \
	src/core/syscall-to-name.h

libsystemd_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(LIBWRAP_CFLAGS) \
	$(PAM_CFLAGS) \
	$(AUDIT_CFLAGS) \
	$(KMOD_CFLAGS)

libsystemd_core_la_LIBADD = \
	libsystemd-capability.la \
	libsystemd-units.la \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-dbus.la \
	libsystemd-audit.la \
	libsystemd-id128-internal.la \
	libudev.la \
	$(LIBWRAP_LIBS) \
	$(PAM_LIBS) \
	$(AUDIT_LIBS) \
	$(CAP_LIBS) \
	$(KMOD_LIBS)

src/core/load-fragment-gperf-nulstr.c: src/core/load-fragment-gperf.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ keywords=0 ; FS="," ; print "extern const char load_fragment_gperf_nulstr[];" ; print "const char load_fragment_gperf_nulstr[] ="} ; keyword==1 { print "\"" $$1 "\\0\"" } ; /%%/ { keyword=1} ; END { print ";" }' < $< > $@

EXTRA_DIST += \
	src/core/load-fragment-gperf.gperf.m4

CLEANFILES += \
	src/core/load-fragment-gperf.gperf \
	src/core/load-fragment-gperf.c \
	src/core/load-fragment-gperf-nulstr.c \
	src/core/syscall-list.txt \
	src/core/syscall-from-name.gperf

BUILT_SOURCES += \
	src/core/syscall-from-name.h \
	src/core/syscall-to-name.h

src/core/syscall-list.txt: Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include sys/syscall.h - < /dev/null | $(AWK) '/^#define[ \t]+__NR_[^ ]+[ \t]+\(?.*[0-9]+.*\)?/ { sub(/__NR_/, "", $$2); print $$2; }' > $@

src/core/syscall-from-name.gperf: src/core/syscall-list.txt Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct syscall_name { const char* name; int id; };"; print "%null-strings"; print "%%";} { printf "%s, __NR_%s\n", $$1, $$1 }' < $< > $@

src/core/syscall-from-name.h: src/core/syscall-from-name.gperf Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_syscall -H hash_syscall_name -p -C < $< > $@

src/core/syscall-to-name.h: src/core/syscall-list.txt Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const syscall_names[] = { "} { printf "[__NR_%s] = \"%s\",\n", $$1, $$1 } END{print "};"}' < $< > $@

# ------------------------------------------------------------------------------
systemd_SOURCES = \
	src/core/main.c

systemd_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_LDADD = \
	libsystemd-core.la \
	libsystemd-daemon.la \
	libsystemd-id128-internal.la \
	libsystemd-dbus.la

dist_pkgsysconf_DATA += \
	src/core/system.conf \
	src/core/user.conf

dist_dbuspolicy_DATA += \
	src/core/org.freedesktop.systemd1.conf

dist_dbussystemservice_DATA += \
	src/core/org.freedesktop.systemd1.service

dbusinterface_DATA += \
	org.freedesktop.systemd1.Manager.xml \
	org.freedesktop.systemd1.Job.xml \
	org.freedesktop.systemd1.Unit.xml \
	org.freedesktop.systemd1.Service.xml \
	org.freedesktop.systemd1.Socket.xml \
	org.freedesktop.systemd1.Timer.xml \
	org.freedesktop.systemd1.Target.xml \
	org.freedesktop.systemd1.Device.xml \
	org.freedesktop.systemd1.Mount.xml \
	org.freedesktop.systemd1.Automount.xml \
	org.freedesktop.systemd1.Snapshot.xml \
	org.freedesktop.systemd1.Swap.xml \
	org.freedesktop.systemd1.Path.xml

polkitpolicy_in_in_files = \
	src/core/org.freedesktop.systemd1.policy.in.in

org.freedesktop.systemd1.%.xml: systemd
	$(AM_V_GEN)$(LIBTOOL) --mode=execute $(OBJCOPY) -O binary -j introspect.$* $< $@.tmp && \
		$(STRINGS) $@.tmp | $(AWK) -f $(srcdir)/introspect.awk | \
		$(DBUS_PREPROCESS) -o $@ - && rm $@.tmp

pkgconfigdata_DATA = \
	src/core/systemd.pc

nodist_rpmmacros_DATA = \
	src/core/macros.systemd

EXTRA_DIST += \
	src/core/systemd.pc.in \
	src/core/macros.systemd.in

CLEANFILES += \
	src/core/macros.systemd

# ------------------------------------------------------------------------------
noinst_PROGRAMS += \
	test-engine \
	test-job-type \
	test-ns \
	test-loopback \
	test-hostname \
	test-daemon \
	test-cgroup \
	test-env-replace \
	test-strv \
	test-install \
	test-watchdog \
	test-unit-name \
	test-log \
	test-unit-file \
	test-date \
	test-sleep

TESTS += \
	test-job-type \
	test-env-replace \
	test-strv \
	test-unit-name \
	test-unit-file \
	test-date \
	test-sleep

test_engine_SOURCES = \
	src/test/test-engine.c

test_engine_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

test_engine_LDADD = \
	libsystemd-core.la \
	libsystemd-daemon.la \
	libsystemd-dbus.la

test_job_type_SOURCES = \
	src/test/test-job-type.c

test_job_type_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

test_job_type_LDADD = \
	libsystemd-core.la \
	libsystemd-daemon.la

test_ns_SOURCES = \
	src/test/test-ns.c

test_ns_LDADD = \
	libsystemd-core.la

test_loopback_SOURCES = \
	src/test/test-loopback.c

test_loopback_LDADD = \
	libsystemd-shared.la \
	libsystemd-core.la

test_hostname_SOURCES = \
	src/test/test-hostname.c

test_hostname_LDADD = \
	libsystemd-core.la

test_unit_name_SOURCES = \
	src/test/test-unit-name.c

test_unit_name_LDADD = \
	libsystemd-core.la

test_unit_file_SOURCES = \
	src/test/test-unit-file.c

test_unit_file_LDADD = \
	libsystemd-core.la

test_log_SOURCES = \
	src/test/test-log.c

test_log_LDADD = \
	libsystemd-core.la

test_date_SOURCES = \
	src/test/test-date.c

test_date_LDADD = \
	libsystemd-core.la

test_sleep_SOURCES = \
	src/test/test-sleep.c

test_sleep_LDADD = \
	libsystemd-core.la

test_daemon_SOURCES = \
	src/test/test-daemon.c

test_daemon_LDADD = \
	libsystemd-shared.la \
	libsystemd-daemon.la

test_cgroup_SOURCES = \
	src/test/test-cgroup.c

test_cgroup_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

test_env_replace_SOURCES = \
	src/test/test-env-replace.c

test_env_replace_LDADD = \
	libsystemd-shared.la

test_strv_SOURCES = \
	src/test/test-strv.c

test_strv_LDADD = \
	libsystemd-shared.la

test_install_SOURCES = \
	src/test/test-install.c

test_install_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

test_install_LDADD = \
	libsystemd-units.la \
	libsystemd-label.la \
	libsystemd-shared.la

test_watchdog_SOURCES = \
	src/test/test-watchdog.c

test_watchdog_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_initctl_SOURCES = \
	src/initctl/initctl.c

systemd_initctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_initctl_LDADD = \
	libsystemd-shared.la \
	libsystemd-daemon.la \
	libsystemd-dbus.la

# ------------------------------------------------------------------------------
systemd_update_utmp_SOURCES = \
	src/update-utmp/update-utmp.c

systemd_update_utmp_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(AUDIT_CFLAGS)

systemd_update_utmp_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la \
	$(AUDIT_LIBS)

# ------------------------------------------------------------------------------
systemd_shutdownd_SOURCES = \
	src/shutdownd/shutdownd.c

systemd_shutdownd_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-daemon.la

pkginclude_HEADERS += \
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
	libsystemd-shared.la \
	libudev.la

# ------------------------------------------------------------------------------
systemd_modules_load_SOURCES = \
	src/modules-load/modules-load.c

systemd_modules_load_CFLAGS = \
	$(AM_CFLAGS) \
	$(KMOD_CFLAGS)

systemd_modules_load_LDADD = \
	libsystemd-shared.la \
	$(KMOD_LIBS)

# ------------------------------------------------------------------------------
systemd_tmpfiles_SOURCES = \
	src/tmpfiles/tmpfiles.c

systemd_tmpfiles_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-capability.la

# ------------------------------------------------------------------------------
systemd_machine_id_setup_SOURCES = \
	src/machine-id-setup/machine-id-setup-main.c \
	src/core/machine-id-setup.c \
	src/core/machine-id-setup.h

systemd_machine_id_setup_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-id128-internal.la

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

systemd_fsck_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_fsck_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la \
	libudev.la

# ------------------------------------------------------------------------------
systemd_timestamp_SOURCES = \
	src/timestamp/timestamp.c

systemd_timestamp_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_ac_power_SOURCES = \
	src/ac-power/ac-power.c

systemd_ac_power_LDADD = \
	libsystemd-shared.la \
	libudev.la

# ------------------------------------------------------------------------------
systemd_detect_virt_SOURCES = \
	src/detect-virt/detect-virt.c

systemd_detect_virt_LDADD = \
	libsystemd-shared.la

systemd-detect-virt-install-hook:
	$(SETCAP) cap_dac_override,cap_sys_ptrace=ep $(DESTDIR)$(bindir)/systemd-detect-virt ||:

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

systemd_cgroups_agent_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_cgroups_agent_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la

# ------------------------------------------------------------------------------
systemctl_SOURCES = \
	src/systemctl/systemctl.c

systemctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemctl_LDADD = \
	libsystemd-units.la \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-daemon.la \
	libsystemd-dbus.la \
	libsystemd-logs.la

# ------------------------------------------------------------------------------
systemd_notify_SOURCES = \
	src/notify/notify.c \
	src/readahead/sd-readahead.c

systemd_notify_LDADD = \
	libsystemd-shared.la \
	libsystemd-daemon.la

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

systemd_nspawn_LDADD = \
	libsystemd-label.la \
	libsystemd-capability.la \
	libsystemd-shared.la \
	libsystemd-daemon.la \
	libsystemd-id128-internal.la

# ------------------------------------------------------------------------------
systemd_stdio_bridge_SOURCES = \
	src/stdio-bridge/stdio-bridge.c

systemd_stdio_bridge_LDADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
systemd_tty_ask_password_agent_SOURCES = \
	src/tty-ask-password-agent/tty-ask-password-agent.c

systemd_tty_ask_password_agent_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
libsystemd_daemon_la_SOURCES = \
	src/libsystemd-daemon/sd-daemon.c

libsystemd_daemon_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden \
	-DSD_EXPORT_SYMBOLS

libsystemd_daemon_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-version-info $(LIBSYSTEMD_DAEMON_CURRENT):$(LIBSYSTEMD_DAEMON_REVISION):$(LIBSYSTEMD_DAEMON_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libsystemd-daemon/libsystemd-daemon.sym

pkginclude_HEADERS += \
	src/systemd/sd-daemon.h

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-daemon-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libsystemd-daemon.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libsystemd-daemon.so && \
		mv $(DESTDIR)$(libdir)/libsystemd-daemon.so.* $(DESTDIR)$(rootlibdir); \
	fi

INSTALL_EXEC_HOOKS += \
	libsystemd-daemon-install-hook

libsystemd-daemon-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-daemon.so*

UNINSTALL_EXEC_HOOKS += \
	libsystemd-daemon-uninstall-hook

lib_LTLIBRARIES += \
	libsystemd-daemon.la

pkgconfiglib_DATA += \
	src/libsystemd-daemon/libsystemd-daemon.pc

MANPAGES += \
	man/sd-daemon.3 \
	man/sd_notify.3 \
	man/sd_listen_fds.3 \
	man/sd_is_fifo.3 \
	man/sd_booted.3

MANPAGES_ALIAS += \
	man/sd_is_socket.3 \
	man/sd_is_socket_unix.3 \
	man/sd_is_socket_inet.3 \
	man/sd_is_mq.3 \
	man/sd_notifyf.3 \
	man/SD_LISTEN_FDS_START.3 \
	man/SD_EMERG.3 \
	man/SD_ALERT.3 \
	man/SD_CRIT.3 \
	man/SD_ERR.3 \
	man/SD_WARNING.3 \
	man/SD_NOTICE.3 \
	man/SD_INFO.3 \
	man/SD_DEBUG.3

man/sd_is_socket.3: man/sd_is_fifo.3
man/sd_is_socket_unix.3: man/sd_is_fifo.3
man/sd_is_socket_inet.3: man/sd_is_fifo.3
man/sd_is_mq.3: man/sd_is_fifo.3
man/sd_notifyf.3: man/sd_notify.3
man/SD_LISTEN_FDS_START.3: man/sd_listen_fds.3
man/SD_EMERG.3: man/sd-daemon.3
man/SD_ALERT.3: man/sd-daemon.3
man/SD_CRIT.3: man/sd-daemon.3
man/SD_ERR.3: man/sd-daemon.3
man/SD_WARNING.3: man/sd-daemon.3
man/SD_NOTICE.3: man/sd-daemon.3
man/SD_INFO.3: man/sd-daemon.3
man/SD_DEBUG.3: man/sd-daemon.3

EXTRA_DIST += \
	src/libsystemd-daemon/libsystemd-daemon.pc.in \
	src/libsystemd-daemon/libsystemd-daemon.sym

# ------------------------------------------------------------------------------
if ENABLE_GTK_DOC
SUBDIRS += \
	docs/libudev
endif

include_HEADERS += \
	src/libudev/libudev.h

lib_LTLIBRARIES += \
	libudev.la

libudev_la_SOURCES =\
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
	libsystemd-shared.la

pkgconfiglib_DATA += \
	src/libudev/libudev.pc

EXTRA_DIST += \
	src/libudev/libudev.pc.in \
	src/libudev/libudev.sym

CLEANFILES += \
	src/libudev/libudev.pc

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libudev-install-move-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libudev.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libudev.so && \
		mv $(DESTDIR)$(libdir)/libudev.so.* $(DESTDIR)$(rootlibdir); \
	fi

libudev-uninstall-move-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libudev.so*

INSTALL_EXEC_HOOKS += libudev-install-move-hook
UNINSTALL_EXEC_HOOKS += libudev-uninstall-move-hook

# ------------------------------------------------------------------------------
noinst_LTLIBRARIES += \
	libudev-private.la

libudev_private_la_SOURCES =\
	$(libudev_la_SOURCES) \
	src/libudev/libudev-device-private.c \
	src/libudev/libudev-queue-private.c

libudev_private_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=default

libudev_private_la_LIBADD = \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
MANPAGES += \
	man/udev.7 \
	man/udevadm.8 \
	man/systemd-udevd.service.8

MANPAGES_ALIAS += \
	man/systemd-udevd.8 \
	man/systemd-udevd-control.socket.8 \
	man/systemd-udevd-kernel.socket.8

man/systemd-udevd.8: man/systemd-udevd.service.8
man/systemd-udevd-control.socket.8: man/systemd-udevd.service.8
man/systemd-udevd-kernel.socket.8: man/systemd-udevd.service.8

udev-confdirs:
	-$(MKDIR_P) $(DESTDIR)$(sysconfdir)/udev/rules.d
	-$(MKDIR_P) $(DESTDIR)$(sysconfdir)/udev/hwdb.d

INSTALL_DATA_HOOKS += udev-confdirs

dist_udevrules_DATA += \
	rules/99-systemd.rules \
	rules/42-usb-hid-pm.rules \
	rules/50-udev-default.rules \
	rules/60-persistent-storage-tape.rules \
	rules/60-persistent-serial.rules \
	rules/60-persistent-input.rules \
	rules/60-persistent-alsa.rules \
	rules/60-persistent-storage.rules \
	rules/64-btrfs.rules \
	rules/75-net-description.rules \
	rules/75-tty-description.rules \
	rules/78-sound-card.rules \
	rules/80-drivers.rules \
	rules/95-udev-late.rules

dist_udevhwdb_DATA = \
	hwdb/20-pci-vendor-product.hwdb \
	hwdb/20-usb-vendor-product.hwdb \
	hwdb/20-acpi-vendor.hwdb \
	hwdb/20-OUI.hwdb

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
	units/systemd-udev-settle.service.in

CLEANFILES += \
	units/systemd-udevd.service \
	units/systemd-udev-trigger.service \
	units/systemd-udev-settle.service

systemd-install-hook:
	$(MKDIR_P) $(DESTDIR)$(systemunitdir)/sockets.target.wants
	ln -sf ../systemd-udevd-control.socket $(DESTDIR)$(systemunitdir)/sockets.target.wants/systemd-udevd-control.socket
	ln -sf ../systemd-udevd-kernel.socket $(DESTDIR)$(systemunitdir)/sockets.target.wants/systemd-udevd-kernel.socket
	$(MKDIR_P) $(DESTDIR)$(systemunitdir)/sysinit.target.wants
	ln -sf ../systemd-udevd.service $(DESTDIR)$(systemunitdir)/sysinit.target.wants/systemd-udevd.service
	ln -sf ../systemd-udev-trigger.service $(DESTDIR)$(systemunitdir)/sysinit.target.wants/systemd-udev-trigger.service

INSTALL_DATA_HOOKS += systemd-install-hook

bin_PROGRAMS += \
	udevadm

rootlibexec_PROGRAMS += \
	systemd-udevd

noinst_LTLIBRARIES += \
	libudev-core.la

libudev_core_la_SOURCES = \
	src/udev/udev.h \
	src/udev/udev-event.c \
	src/udev/udev-watch.c \
	src/udev/udev-node.c \
	src/udev/udev-rules.c \
	src/udev/udev-ctrl.c \
	src/udev/udev-builtin.c \
	src/udev/udev-builtin-blkid.c \
	src/udev/udev-builtin-btrfs.c \
	src/udev/udev-builtin-firmware.c \
	src/udev/udev-builtin-hwdb.c \
	src/udev/udev-builtin-input_id.c \
	src/udev/udev-builtin-kmod.c \
	src/udev/udev-builtin-path_id.c \
	src/udev/udev-builtin-usb_id.c \
	src/libsystemd-daemon/sd-daemon.c

libudev_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(KMOD_CFLAGS)

libudev_core_la_LIBADD = \
	libudev-private.la \
	libsystemd-label.la \
	libsystemd-shared.la \
	$(BLKID_LIBS) \
	$(KMOD_LIBS)

libudev_core_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DFIRMWARE_PATH="$(FIRMWARE_PATH)"

if HAVE_ACL
libudev_core_la_SOURCES += \
	src/udev/udev-builtin-uaccess.c \
	src/login/logind-acl.c \
	src/login/sd-login.c

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
	libudev-core.la \
	libsystemd-shared.la

# ------------------------------------------------------------------------------
TESTS += \
	test/udev-test.pl \
	test/rules-test.sh

noinst_PROGRAMS += \
	test-libudev \
	test-udev

test_libudev_SOURCES = \
	src/test/test-libudev.c

test_libudev_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libudev.la

test_udev_SOURCES = \
	src/test/test-udev.c

test_udev_LDADD = \
	libudev-core.la \
	libsystemd-shared.la \
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
	libudev-private.la \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	ata_id

# ------------------------------------------------------------------------------
cdrom_id_SOURCES = \
	src/udev/cdrom_id/cdrom_id.c

cdrom_id_LDADD = \
	libudev.la \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	cdrom_id

dist_udevrules_DATA += \
	rules/60-cdrom_id.rules

# ------------------------------------------------------------------------------
collect_SOURCES = \
	src/udev/collect/collect.c

collect_LDADD = \
	libudev-private.la

udevlibexec_PROGRAMS += \
	collect

# ------------------------------------------------------------------------------
scsi_id_SOURCES =\
	src/udev/scsi_id/scsi_id.c \
	src/udev/scsi_id/scsi_serial.c \
	src/udev/scsi_id/scsi.h \
	src/udev/scsi_id/scsi_id.h

scsi_id_LDADD = \
	libudev-private.la \
	libsystemd-shared.la

udevlibexec_PROGRAMS += \
	scsi_id

EXTRA_DIST += \
	src/udev/scsi_id/README

# ------------------------------------------------------------------------------
v4l_id_SOURCES = \
	src/udev/v4l_id/v4l_id.c

v4l_id_LDADD = \
	libudev.la

udevlibexec_PROGRAMS += \
	v4l_id

dist_udevrules_DATA += \
	rules/60-persistent-v4l.rules

# ------------------------------------------------------------------------------
accelerometer_SOURCES = \
	src/udev/accelerometer/accelerometer.c

accelerometer_LDADD = \
	libudev.la -lm \
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
	-export-dynamic -no-undefined \
	-export-symbols-regex '^g_udev_.*'

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
	$(INCLUDES) \
	-D_GUDEV_COMPILATION \
	-D_GUDEV_WORK_AROUND_DEV_T_BUG \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src/gdev \
	-I$(top_builddir)/src/gdev

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
libgudev-install-move-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libgudev-1.0.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libgudev-1.0.so && \
		mv $(DESTDIR)$(libdir)/libgudev-1.0.so.* $(DESTDIR)$(rootlibdir); \
	fi

libgudev-uninstall-move-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libgudev-1.0.so*

INSTALL_EXEC_HOOKS += libgudev-install-move-hook
UNINSTALL_EXEC_HOOKS += libgudev-uninstall-move-hook
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
if ENABLE_KEYMAP
keymap_SOURCES = \
	src/udev/keymap/keymap.c

keymap_CPPFLAGS = \
	$(AM_CPPFLAGS) -I src/udev/keymap

keymap_LDADD = \
	libsystemd-shared.la

nodist_keymap_SOURCES = \
	src/udev/keymap/keys-from-name.h \
	src/udev/keymap/keys-to-name.h

BUILT_SOURCES += \
	$(nodist_keymap_SOURCES)

udevlibexec_PROGRAMS += \
	keymap

dist_doc_DATA += \
	src/udev/keymap/README.keymap.txt

dist_udevrules_DATA += \
	src/udev/keymap/95-keymap.rules \
	src/udev/keymap/95-keyboard-force-release.rules

dist_udevhome_SCRIPTS = \
	src/udev/keymap/findkeyboards \
	src/udev/keymap/keyboard-force-release.sh

TESTS += \
	src/udev/keymap/check-keymaps.sh

CLEANFILES += \
	src/udev/keymap/keys.txt \
	src/udev/keymap/keys-from-name.gperf \
	src/udev/keymap/keyboard-force-release.sh

udevkeymapdir = $(udevlibexecdir)/keymaps
dist_udevkeymap_DATA = \
	keymaps/acer \
	keymaps/acer-aspire_5720 \
	keymaps/acer-aspire_8930 \
	keymaps/acer-aspire_5920g \
	keymaps/acer-aspire_6920 \
	keymaps/acer-travelmate_c300 \
	keymaps/asus \
	keymaps/compaq-e_evo \
	keymaps/dell \
	keymaps/dell-latitude-xt2 \
	keymaps/everex-xt5000 \
	keymaps/fujitsu-amilo_li_2732 \
	keymaps/fujitsu-amilo_pa_2548 \
	keymaps/fujitsu-amilo_pro_edition_v3505 \
	keymaps/fujitsu-amilo_pro_v3205 \
	keymaps/fujitsu-amilo_si_1520 \
	keymaps/fujitsu-esprimo_mobile_v5 \
	keymaps/fujitsu-esprimo_mobile_v6 \
	keymaps/genius-slimstar-320 \
	keymaps/hewlett-packard \
	keymaps/hewlett-packard-2510p_2530p \
	keymaps/hewlett-packard-compaq_elitebook \
	keymaps/hewlett-packard-pavilion \
	keymaps/hewlett-packard-presario-2100 \
	keymaps/hewlett-packard-tablet \
	keymaps/hewlett-packard-tx2 \
	keymaps/hewlett-packard_elitebook-8440p \
	keymaps/ibm-thinkpad-usb-keyboard-trackpoint \
	keymaps/inventec-symphony_6.0_7.0 \
	keymaps/lenovo-3000 \
	keymaps/lenovo-ideapad \
	keymaps/lenovo-thinkpad-usb-keyboard-trackpoint \
	keymaps/lenovo-thinkpad_x6_tablet \
	keymaps/lenovo-thinkpad_x200_tablet \
	keymaps/lg-x110 \
	keymaps/logitech-wave \
	keymaps/logitech-wave-cordless \
	keymaps/logitech-wave-pro-cordless \
	keymaps/maxdata-pro_7000 \
	keymaps/medion-fid2060 \
	keymaps/medionnb-a555 \
	keymaps/micro-star \
	keymaps/module-asus-w3j \
	keymaps/module-ibm \
	keymaps/module-lenovo \
	keymaps/module-sony \
	keymaps/module-sony-old \
	keymaps/module-sony-vgn \
	keymaps/module-sony-vpc \
	keymaps/olpc-xo \
	keymaps/onkyo \
	keymaps/oqo-model2 \
	keymaps/samsung-other \
	keymaps/samsung-90x3a \
	keymaps/samsung-sq1us \
	keymaps/samsung-sx20s \
	keymaps/toshiba-satellite_a100 \
	keymaps/toshiba-satellite_a110 \
	keymaps/toshiba-satellite_m30x \
	keymaps/zepto-znote

udevkeymapforcereldir = $(udevlibexecdir)/keymaps/force-release
dist_udevkeymapforcerel_DATA = \
	keymaps-force-release/dell-touchpad \
	keymaps-force-release/dell-xps \
	keymaps-force-release/hp-other \
	keymaps-force-release/samsung-other \
	keymaps-force-release/samsung-90x3a \
	keymaps-force-release/common-volume-keys

src/udev/keymap/keys.txt: Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(CPP) $(CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -dM -include linux/input.h - < /dev/null | $(AWK) '/^#define[ \t]+KEY_[^ ]+[ \t]+[0-9]/ { if ($$2 != "KEY_MAX") { print $$2 } }' | sed 's/^KEY_COFFEE$$/KEY_SCREENLOCK/' > $@

src/udev/keymap/keys-from-name.gperf: src/udev/keymap/keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

src/udev/keymap/keys-from-name.h: src/udev/keymap/keys-from-name.gperf Makefile
	$(AM_V_GEN)$(GPERF) -L ANSI-C -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

src/udev/keymap/keys-to-name.h: src/udev/keymap/keys.txt Makefile
	$(AM_V_GEN)$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@
endif

EXTRA_DIST += \
	src/udev/keymap/check-keymaps.sh \
	src/udev/keymap/keyboard-force-release.sh.in

# ------------------------------------------------------------------------------
mtd_probe_SOURCES =  \
	src/udev/mtd_probe/mtd_probe.c \
	src/udev/mtd_probe/mtd_probe.h \
	src/udev/mtd_probe/probe_smartmedia.c

mtd_probe_CPPFLAGS = \
	$(AM_CPPFLAGS)

dist_udevrules_DATA += \
	rules/75-probe_mtd.rules

udevlibexec_PROGRAMS += \
	mtd_probe

# ------------------------------------------------------------------------------
libsystemd_id128_la_SOURCES = \
	src/libsystemd-id128/sd-id128.c

libsystemd_id128_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libsystemd_id128_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-version-info $(LIBSYSTEMD_ID128_CURRENT):$(LIBSYSTEMD_ID128_REVISION):$(LIBSYSTEMD_ID128_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libsystemd-id128/libsystemd-id128.sym

libsystemd_id128_la_LIBADD = \
	libsystemd-shared.la

libsystemd_id128_internal_la_SOURCES = \
	$(libsystemd_id128_la_SOURCES)

test_id128_SOURCES = \
	src/test/test-id128.c

test_id128_LDADD = \
	libsystemd-shared.la \
	libsystemd-id128-internal.la

noinst_PROGRAMS += \
	test-id128

TESTS += \
	test-id128

pkginclude_HEADERS += \
	src/systemd/sd-id128.h

lib_LTLIBRARIES += \
	libsystemd-id128.la

noinst_LTLIBRARIES += \
	libsystemd-id128-internal.la

pkgconfiglib_DATA += \
	src/libsystemd-id128/libsystemd-id128.pc

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-id128-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libsystemd-id128.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libsystemd-id128.so && \
		mv $(DESTDIR)$(libdir)/libsystemd-id128.so.* $(DESTDIR)$(rootlibdir); \
	fi

INSTALL_EXEC_HOOKS += \
	libsystemd-id128-install-hook

libsystemd-id128-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-id128.so*

UNINSTALL_EXEC_HOOKS += \
	libsystemd-id128-uninstall-hook

EXTRA_DIST += \
	src/libsystemd-id128/libsystemd-id128.pc.in \
	src/libsystemd-id128/libsystemd-id128.sym

# ------------------------------------------------------------------------------
systemd_journald_SOURCES = \
	src/journal/journald.c \
	src/journal/journald.h \
	src/journal/journald-kmsg.c \
	src/journal/journald-kmsg.h \
	src/journal/journald-syslog.c \
	src/journal/journald-syslog.h \
	src/journal/journald-stream.c \
	src/journal/journald-stream.h \
	src/journal/journald-console.c \
	src/journal/journald-console.h \
	src/journal/journald-native.c \
	src/journal/journald-native.h \
	src/journal/journald-rate-limit.c \
	src/journal/journald-rate-limit.h \
	src/journal/journal-internal.h

nodist_systemd_journald_SOURCES = \
	src/journal/journald-gperf.c

systemd_journald_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-audit.la \
	libsystemd-daemon.la \
	libsystemd-id128-internal.la \
	libsystemd-journal-internal.la \
	libudev.la

if ENABLE_LOGIND
systemd_journald_LDADD += \
	libsystemd-login-internal.la
endif

if HAVE_ACL
systemd_journald_LDADD += \
	libsystemd-acl.la
endif

systemd_cat_SOURCES = \
	src/journal/cat.c

systemd_cat_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la

journalctl_SOURCES = \
	src/journal/journalctl.c

journalctl_CFLAGS = \
	$(AM_CFLAGS)

journalctl_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la \
	libsystemd-logs.la

if HAVE_QRENCODE
journalctl_SOURCES += \
	src/journal/journal-qrcode.c \
	src/journal/journal-qrcode.h

journalctl_CFLAGS += \
	$(QRENCODE_CFLAGS)

journalctl_LDADD += \
	$(QRENCODE_LIBS)
endif

systemd_coredumpctl_SOURCES = \
	src/journal/coredumpctl.c

systemd_coredumpctl_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal.la

test_journal_SOURCES = \
	src/journal/test-journal.c

test_journal_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la

test_journal_send_SOURCES = \
	src/journal/test-journal-send.c

test_journal_send_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la

test_journal_syslog_SOURCES = \
	src/journal/test-journal-syslog.c \
	src/journal/journald-syslog.c

test_journal_syslog_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la

test_journal_match_SOURCES = \
	src/journal/test-journal-match.c

test_journal_match_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la

test_journal_enum_SOURCES = \
	src/journal/test-journal-enum.c

test_journal_enum_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la

test_journal_stream_SOURCES = \
	src/journal/test-journal-stream.c

test_journal_stream_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la

test_journal_verify_SOURCES = \
	src/journal/test-journal-verify.c

test_journal_verify_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la

test_mmap_cache_SOURCES = \
	src/journal/test-mmap-cache.c

test_mmap_cache_LDADD = \
	libsystemd-shared.la \
	libsystemd-journal-internal.la

libsystemd_journal_la_SOURCES = \
	src/journal/sd-journal.c \
	src/systemd/sd-journal.h \
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
	src/journal/mmap-cache.c \
	src/journal/mmap-cache.h

libsystemd_journal_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libsystemd_journal_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-version-info $(LIBSYSTEMD_JOURNAL_CURRENT):$(LIBSYSTEMD_JOURNAL_REVISION):$(LIBSYSTEMD_JOURNAL_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/journal/libsystemd-journal.sym

libsystemd_journal_la_LIBADD = \
	libsystemd-shared.la \
	libsystemd-id128-internal.la

libsystemd_journal_internal_la_SOURCES = \
	$(libsystemd_journal_la_SOURCES)

libsystemd_journal_internal_la_CFLAGS = \
	$(AM_CFLAGS)

libsystemd_journal_internal_la_LIBADD =

if HAVE_XZ
libsystemd_journal_la_SOURCES += \
	src/journal/compress.c

libsystemd_journal_la_CFLAGS += \
	$(XZ_CFLAGS)

libsystemd_journal_la_LIBADD += \
	$(XZ_LIBS)

libsystemd_journal_internal_la_CFLAGS += \
	$(XZ_CFLAGS)

libsystemd_journal_internal_la_LIBADD += \
	$(XZ_LIBS)

endif

if HAVE_GCRYPT
libsystemd_journal_la_SOURCES += \
	src/journal/journal-authenticate.c \
	src/journal/journal-authenticate.h \
	src/journal/fsprg.c \
	src/journal/fsprg.h

libsystemd_journal_la_CFLAGS += \
	$(GCRYPT_CFLAGS) \
	-Wno-pointer-arith

libsystemd_journal_la_LIBADD += \
	$(GCRYPT_LIBS)

libsystemd_journal_internal_la_CFLAGS += \
	$(GCRYPT_CFLAGS) \
	-Wno-pointer-arith

libsystemd_journal_internal_la_LIBADD += \
	$(GCRYPT_LIBS)
endif

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-journal-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libsystemd-journal.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libsystemd-journal.so && \
		mv $(DESTDIR)$(libdir)/libsystemd-journal.so.* $(DESTDIR)$(rootlibdir); \
	fi

INSTALL_EXEC_HOOKS += \
	libsystemd-journal-install-hook

libsystemd-journal-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-journal.so*

UNINSTALL_EXEC_HOOKS += \
	libsystemd-journal-uninstall-hook

noinst_PROGRAMS += \
	test-journal \
	test-journal-send \
	test-journal-syslog \
	test-journal-match \
	test-journal-enum \
	test-journal-stream \
	test-journal-verify \
	test-mmap-cache

TESTS += \
	test-journal \
	test-journal-send \
	test-journal-syslog \
	test-journal-match \
	test-journal-stream \
	test-journal-verify \
	test-mmap-cache

pkginclude_HEADERS += \
	src/systemd/sd-journal.h \
	src/systemd/sd-messages.h

lib_LTLIBRARIES += \
	libsystemd-journal.la

noinst_LTLIBRARIES += \
	libsystemd-journal-internal.la

rootlibexec_PROGRAMS += \
	systemd-journald

rootbin_PROGRAMS += \
	journalctl

bin_PROGRAMS += \
	systemd-coredumpctl \
	systemd-cat

dist_systemunit_DATA += \
	units/systemd-journald.socket

nodist_systemunit_DATA += \
	units/systemd-journald.service \
	units/systemd-journal-flush.service

dist_pkgsysconf_DATA += \
	src/journal/journald.conf

pkgconfiglib_DATA += \
	src/journal/libsystemd-journal.pc

journal-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir)/sockets.target.wants \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants
	( cd $(DESTDIR)$(systemunitdir)/sockets.target.wants && \
		rm -f systemd-journald.socket && \
		$(LN_S) ../systemd-journald.socket )
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f systemd-journald.service systemd-journal-flush.service && \
		$(LN_S) ../systemd-journald.service && \
		$(LN_S) ../systemd-journal-flush.service )

INSTALL_DATA_HOOKS += \
	journal-install-data-hook

EXTRA_DIST += \
	src/journal/libsystemd-journal.pc.in \
	src/journal/libsystemd-journal.sym \
	units/systemd-journald.service.in \
	units/systemd-journal-flush.service.in \
	src/journal/journald-gperf.gperf

CLEANFILES += \
	src/journal/journald-gperf.c

if HAVE_MICROHTTPD

gatewayddocumentrootdir=$(pkgdatadir)/gatewayd

rootlibexec_PROGRAMS += \
	systemd-journal-gatewayd

systemd_journal_gatewayd_SOURCES = \
	src/journal/journal-gatewayd.c

systemd_journal_gatewayd_LDADD = \
	libsystemd-shared.la \
	libsystemd-logs.la \
	libsystemd-journal-internal.la \
	libsystemd-id128-internal.la \
	libsystemd-daemon.la \
	$(MICROHTTPD_LIBS)

systemd_journal_gatewayd_CFLAGS = \
	-DDOCUMENT_ROOT=\"$(gatewayddocumentrootdir)\" \
	$(AM_CFLAGS) \
	$(MICROHTTPD_CFLAGS)

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
if ENABLE_COREDUMP
systemd_coredump_SOURCES = \
	src/journal/coredump.c

systemd_coredump_LDADD = \
	libsystemd-journal-internal.la \
	libsystemd-label.la \
	libsystemd-shared.la

if ENABLE_LOGIND
systemd_coredump_LDADD += \
	libsystemd-login-internal.la
endif

rootlibexec_PROGRAMS += \
	systemd-coredump

sysctl_DATA = \
	sysctl.d/coredump.conf

CLEANFILES += \
	sysctl.d/coredump.conf
endif

EXTRA_DIST += \
	sysctl.d/coredump.conf.in

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

binfmt-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(prefix)/lib/binfmt.d \
		$(DESTDIR)$(sysconfdir)/binfmt.d \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f systemd-binfmt.service \
			proc-sys-fs-binfmt_misc.automount && \
		$(LN_S) ../systemd-binfmt.service systemd-binfmt.service && \
		$(LN_S) ../proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.automount )

INSTALL_DATA_HOOKS += \
	binfmt-install-data-hook

MANPAGES += \
	man/binfmt.d.5 \
	man/systemd-binfmt.service.8

MANPAGES_ALIAS +=  \
	man/systemd-binfmt.8

man/systemd-binfmt.8: man/systemd-binfmt.service.8
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

vconsole-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f systemd-vconsole-setup.service && \
		$(LN_S) ../systemd-vconsole-setup.service systemd-vconsole-setup.service )

INSTALL_DATA_HOOKS += \
	vconsole-install-data-hook

MANPAGES += \
	man/vconsole.conf.5 \
	man/systemd-vconsole-setup.service.8

MANPAGES_ALIAS += \
	man/systemd-vconsole-setup.8

man/systemd-vconsole-setup.8: man/systemd-vconsole-setup.service.8
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
	libsystemd-shared.la \
	libsystemd-daemon.la \
	libudev.la

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

MANPAGES += \
	man/sd_readahead.3 \
	man/sd-readahead.3 \
	man/systemd-readahead-replay.service.8

MANPAGES_ALIAS += \
	man/systemd-readahead-collect.service.8 \
	man/systemd-readahead-done.service.8 \
	man/systemd-readahead-done.timer.8 \
	man/systemd-readahead.8

man/systemd-readahead-collect.service.8: man/systemd-readahead-replay.service.8
man/systemd-readahead-done.service.8: man/systemd-readahead-replay.service.8
man/systemd-readahead-done.timer.8: man/systemd-readahead-replay.service.8
man/systemd-readahead.8: man/systemd-readahead-replay.service.8

endif

EXTRA_DIST += \
	units/systemd-readahead-collect.service.in \
	units/systemd-readahead-replay.service.in \
	units/systemd-readahead-done.service.in

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

MANPAGES += \
	man/systemd-quotacheck.service.8

MANPAGES_ALIAS += \
	man/systemd-quotacheck.8

man/systemd-quotacheck.8: man/systemd-quotacheck.service.8

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
	units/systemd-random-seed-save.service \
	units/systemd-random-seed-load.service

systemd_random_seed_SOURCES = \
	src/random-seed/random-seed.c

systemd_random_seed_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

randomseed-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir)/shutdown.target.wants \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants
	( cd $(DESTDIR)$(systemunitdir)/shutdown.target.wants && \
		rm -f systemd-random-seed-save.service && \
		$(LN_S) ../systemd-random-seed-save.service systemd-random-seed-save.service )
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f systemd-random-seed-load.service && \
		$(LN_S) ../systemd-random-seed-load.service systemd-random-seed-load.service )

INSTALL_DATA_HOOKS += \
	randomseed-install-data-hook

MANPAGES += \
	man/systemd-random-seed-load.service.8

MANPAGES_ALIAS +=  \
	man/systemd-random-seed-save.service.8 \
	man/systemd-random-seed.8

man/systemd-random-seed-save.service.8: man/systemd-random-seed-load.service.8
man/systemd-random-seed.8: man/systemd-random-seed-load.service.8

endif

EXTRA_DIST += \
	units/systemd-random-seed-save.service.in \
	units/systemd-random-seed-load.service.in

# ------------------------------------------------------------------------------
if HAVE_LIBCRYPTSETUP
rootlibexec_PROGRAMS += \
	systemd-cryptsetup

systemgenerator_PROGRAMS += \
	systemd-cryptsetup-generator

dist_systemunit_DATA += \
	units/cryptsetup.target

systemd_cryptsetup_SOURCES = \
	src/cryptsetup/cryptsetup.c

systemd_cryptsetup_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBCRYPTSETUP_CFLAGS)

systemd_cryptsetup_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libudev.la \
	$(LIBCRYPTSETUP_LIBS)

systemd_cryptsetup_generator_SOURCES = \
	src/cryptsetup/cryptsetup-generator.c

systemd_cryptsetup_generator_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

cryptsetup-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f cryptsetup.target && \
		$(LN_S) ../cryptsetup.target cryptsetup.target )

INSTALL_DATA_HOOKS += \
	cryptsetup-install-data-hook

MANPAGES += \
	man/systemd-cryptsetup@.service.8 \
	man/systemd-cryptsetup-generator.8 \
	man/crypttab.5

MANPAGES_ALIAS += \
	man/systemd-cryptsetup.8

man/systemd-cryptsetup.8: man/systemd-cryptsetup@.service.8

endif

# ------------------------------------------------------------------------------
if ENABLE_HOSTNAMED
systemd_hostnamed_SOURCES = \
	src/hostname/hostnamed.c

systemd_hostnamed_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_hostnamed_LDADD = \
	libsystemd-shared.la \
	libsystemd-daemon.la \
	libsystemd-dbus.la

rootlibexec_PROGRAMS += \
	systemd-hostnamed

nodist_systemunit_DATA += \
	units/systemd-hostnamed.service

dist_dbuspolicy_DATA += \
	src/hostname/org.freedesktop.hostname1.conf

dist_dbussystemservice_DATA += \
	src/hostname/org.freedesktop.hostname1.service

polkitpolicy_files += \
	src/hostname/org.freedesktop.hostname1.policy

dbusinterface_DATA += \
	org.freedesktop.hostname1.xml

org.freedesktop.hostname1.xml: systemd-hostnamed
	$(AM_V_GEN)$(LIBTOOL) --mode=execute $(OBJCOPY) -O binary -j introspect.hostname1 $< $@.tmp && \
		$(STRINGS) $@.tmp | $(AWK) -f $(srcdir)/introspect.awk | \
		$(DBUS_PREPROCESS) -o $@ - && rm $@.tmp

hostnamed-install-data-hook:
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f dbus-org.freedesktop.hostname1.service && \
		$(LN_S) systemd-hostnamed.service dbus-org.freedesktop.hostname1.service )

INSTALL_DATA_HOOKS += \
	hostnamed-install-data-hook

MANPAGES += \
	man/systemd-hostnamed.service.8

MANPAGES_ALIAS += \
	man/systemd-hostnamed.8

man/systemd-hostnamed.8: man/systemd-hostnamed.service.8

hostnamectl_SOURCES = \
	src/hostname/hostnamectl.c

hostnamectl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

hostnamectl_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la \
	libsystemd-id128-internal.la

bin_PROGRAMS += \
	hostnamectl

MANPAGES += \
	man/hostnamectl.1

endif

polkitpolicy_in_files += \
	src/hostname/org.freedesktop.hostname1.policy.in

EXTRA_DIST += \
	units/systemd-hostnamed.service.in

# ------------------------------------------------------------------------------
if ENABLE_LOCALED
systemd_localed_SOURCES = \
	src/locale/localed.c

systemd_localed_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_localed_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-daemon.la \
	libsystemd-dbus.la

nodist_systemunit_DATA += \
	units/systemd-localed.service

rootlibexec_PROGRAMS += \
	systemd-localed

dist_dbuspolicy_DATA += \
	src/locale/org.freedesktop.locale1.conf

dist_dbussystemservice_DATA += \
	src/locale/org.freedesktop.locale1.service

polkitpolicy_files += \
	src/locale/org.freedesktop.locale1.policy

dbusinterface_DATA += \
	org.freedesktop.locale1.xml

org.freedesktop.locale1.xml: systemd-localed
	$(AM_V_GEN)$(LIBTOOL) --mode=execute $(OBJCOPY) -O binary -j introspect.locale1 $< $@.tmp && \
		$(STRINGS) $@.tmp | $(AWK) -f $(srcdir)/introspect.awk | \
		$(DBUS_PREPROCESS) -o $@ - && rm $@.tmp

localed-install-data-hook:
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f dbus-org.freedesktop.locale1.service && \
		$(LN_S) systemd-localed.service dbus-org.freedesktop.locale1.service )

INSTALL_DATA_HOOKS += \
	localed-install-data-hook

MANPAGES += \
	man/systemd-localed.service.8

MANPAGES_ALIAS += \
	man/systemd-localed.8

man/systemd-localed.8: man/systemd-localed.service.8

dist_pkgdata_DATA += \
	src/locale/kbd-model-map

dist_noinst_SCRIPT = \
	src/locale/generate-kbd-model-map

update-kbd-model-map:
	src/locale/generate-kbd-model-map > src/locale/kbd-model-map

localectl_SOURCES = \
	src/locale/localectl.c

localectl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

localectl_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la \
	libsystemd-id128-internal.la

bin_PROGRAMS += \
	localectl

MANPAGES += \
	man/localectl.1

endif

polkitpolicy_in_files += \
	src/locale/org.freedesktop.locale1.policy.in

EXTRA_DIST += \
	units/systemd-localed.service.in

# ------------------------------------------------------------------------------
if ENABLE_TIMEDATED
systemd_timedated_SOURCES = \
	src/timedate/timedated.c

systemd_timedated_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_timedated_LDADD = \
	libsystemd-shared.la \
	libsystemd-daemon.la \
	libsystemd-dbus.la

rootlibexec_PROGRAMS += \
	systemd-timedated

dist_dbussystemservice_DATA += \
	src/timedate/org.freedesktop.timedate1.service

dist_dbuspolicy_DATA += \
	src/timedate/org.freedesktop.timedate1.conf

nodist_systemunit_DATA += \
	units/systemd-timedated.service

polkitpolicy_files += \
	src/timedate/org.freedesktop.timedate1.policy

org.freedesktop.timedate1.xml: systemd-timedated
	$(AM_V_GEN)$(LIBTOOL) --mode=execute $(OBJCOPY) -O binary -j introspect.timedate1 $< $@.tmp && \
		$(STRINGS) $@.tmp | $(AWK) -f $(srcdir)/introspect.awk | \
		$(DBUS_PREPROCESS) -o $@ - && rm $@.tmp

dbusinterface_DATA += \
	org.freedesktop.timedate1.xml

timedated-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(prefix)/lib/systemd/ntp-units.d \
		$(DESTDIR)$(sysconfdir)/systemd/ntp-units.d
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f dbus-org.freedesktop.timedate1.service  && \
		$(LN_S) systemd-timedated.service dbus-org.freedesktop.timedate1.service )

INSTALL_DATA_HOOKS += \
	timedated-install-data-hook

MANPAGES += \
	man/systemd-timedated.service.8

MANPAGES_ALIAS += \
	man/systemd-timedated.8

man/systemd-timedated.8: man/systemd-timedated.service.8

timedatectl_SOURCES = \
	src/timedate/timedatectl.c

timedatectl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

timedatectl_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la

bin_PROGRAMS += \
	timedatectl

MANPAGES += \
	man/timedatectl.1

endif

polkitpolicy_in_files += \
	src/timedate/org.freedesktop.timedate1.policy.in

EXTRA_DIST += \
	units/systemd-timedated.service.in

# ------------------------------------------------------------------------------
if ENABLE_LOGIND
systemd_logind_SOURCES = \
	src/login/logind.c \
	src/login/logind.h \
	src/login/logind-dbus.c \
	src/login/logind-device.c \
	src/login/logind-device.h \
	src/login/logind-button.c \
	src/login/logind-button.h \
	src/login/logind-seat.c \
	src/login/logind-seat.h \
	src/login/logind-session.c \
	src/login/logind-session.h \
	src/login/logind-user.c \
	src/login/logind-user.h \
	src/login/logind-inhibit.c \
	src/login/logind-inhibit.h \
	src/login/logind-session-dbus.c \
	src/login/logind-seat-dbus.c \
	src/login/logind-user-dbus.c \
	src/login/logind-acl.h

nodist_systemd_logind_SOURCES = \
	src/login/logind-gperf.c

systemd_logind_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_logind_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la \
	libsystemd-audit.la \
	libsystemd-daemon.la \
	libsystemd-dbus.la \
	libudev.la

if HAVE_ACL
systemd_logind_SOURCES += \
	src/login/logind-acl.c

systemd_logind_LDADD += \
	libsystemd-acl.la
endif

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

loginctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

loginctl_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la \
	libudev.la

rootbin_PROGRAMS += \
	loginctl

systemd_inhibit_SOURCES = \
	src/login/inhibit.c

systemd_inhibit_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_inhibit_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la

rootbin_PROGRAMS += \
	systemd-inhibit

test_login_SOURCES = \
	src/login/test-login.c

test_login_LDADD = \
	libsystemd-login-internal.la \
	libsystemd-shared.la

test_inhibit_SOURCES = \
	src/login/test-inhibit.c

test_inhibit_LDADD = \
	libsystemd-shared.la \
	libsystemd-dbus.la

test_inhibit_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS += \
	test-login \
	test-inhibit

libsystemd_login_la_SOURCES = \
	src/login/sd-login.c

libsystemd_login_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libsystemd_login_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-version-info $(LIBSYSTEMD_LOGIN_CURRENT):$(LIBSYSTEMD_LOGIN_REVISION):$(LIBSYSTEMD_LOGIN_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/login/libsystemd-login.sym

libsystemd_login_la_LIBADD = \
	libsystemd-shared.la

libsystemd_login_internal_la_SOURCES = \
	$(libsystemd_login_la_SOURCES)

if HAVE_PAM
pam_systemd_la_SOURCES = \
	src/login/pam-module.c

pam_systemd_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PAM_CFLAGS) \
	$(DBUS_CFLAGS) \
	-fvisibility=hidden

pam_systemd_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-export-symbols-regex '^pam_sm_.*'

pam_systemd_la_LIBADD = \
	libsystemd-daemon.la \
	libsystemd-audit.la \
	libsystemd-dbus.la \
	libsystemd-shared.la \
	$(PAM_LIBS)

pamlib_LTLIBRARIES = \
	pam_systemd.la
endif

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-login-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		$(MKDIR_P) $(DESTDIR)$(rootlibdir) && \
		so_img_name=$$(readlink $(DESTDIR)$(libdir)/libsystemd-login.so) && \
		so_img_rel_target_prefix=$$(echo $(libdir) | sed 's,\(^/\|\)[^/][^/]*,..,g') && \
		ln -sf $$so_img_rel_target_prefix$(rootlibdir)/$$so_img_name $(DESTDIR)$(libdir)/libsystemd-login.so && \
		mv $(DESTDIR)$(libdir)/libsystemd-login.so.* $(DESTDIR)$(rootlibdir); \
	fi

INSTALL_EXEC_HOOKS += \
	libsystemd-login-install-hook

libsystemd-login-uninstall-hook:
	rm -f $(DESTDIR)$(rootlibdir)/libsystemd-login.so*

UNINSTALL_EXEC_HOOKS += \
	libsystemd-login-uninstall-hook

nodist_systemunit_DATA += \
	units/systemd-logind.service \
	units/systemd-user-sessions.service

dist_dbussystemservice_DATA += \
	src/login/org.freedesktop.login1.service

dist_dbuspolicy_DATA += \
	src/login/org.freedesktop.login1.conf

dist_pkgsysconf_DATA += \
	src/login/logind.conf

pkginclude_HEADERS += \
	src/systemd/sd-login.h

lib_LTLIBRARIES += \
	libsystemd-login.la

noinst_LTLIBRARIES += \
	libsystemd-login-internal.la

pkgconfiglib_DATA += \
	src/login/libsystemd-login.pc

polkitpolicy_files += \
	src/login/org.freedesktop.login1.policy

logind-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir)/multi-user.target.wants \
		$(DESTDIR)$(localstatedir)/lib/systemd
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f dbus-org.freedesktop.login1.service && \
		$(LN_S) systemd-logind.service dbus-org.freedesktop.login1.service)
	( cd $(DESTDIR)$(systemunitdir)/multi-user.target.wants && \
		rm -f systemd-logind.service systemd-user-sessions.service && \
		$(LN_S) ../systemd-logind.service systemd-logind.service && \
		$(LN_S) ../systemd-user-sessions.service systemd-user-sessions.service )

INSTALL_DATA_HOOKS += \
	logind-install-data-hook

systemd_multi_seat_x_SOURCES = \
	src/login/multi-seat-x.c

systemd_multi_seat_x_LDADD = \
	libsystemd-label.la \
	libsystemd-shared.la

rootlibexec_PROGRAMS += \
	systemd-multi-seat-x

dist_udevrules_DATA += \
	src/login/70-uaccess.rules \
	src/login/70-power-switch.rules

nodist_udevrules_DATA += \
	src/login/71-seat.rules \
	src/login/73-seat-late.rules

MANPAGES += \
	man/systemd-logind.service.8 \
	man/logind.conf.5 \
	man/sd-login.3 \
	man/loginctl.1 \
	man/sd_login_monitor_new.3 \
	man/sd_pid_get_session.3 \
	man/sd_uid_get_state.3 \
	man/sd_session_is_active.3 \
	man/sd_seat_get_active.3 \
	man/sd_get_seats.3 \
	man/systemd-user-sessions.service.8

MANPAGES_ALIAS += \
	man/sd_login_monitor_unref.3 \
	man/sd_login_monitor_flush.3 \
	man/sd_login_monitor_get_fd.3 \
	man/sd_login_monitor.3 \
	man/sd_session_get_uid.3 \
	man/sd_session_get_seat.3 \
	man/sd_session_get_service.3 \
	man/sd_session_get_state.3 \
	man/sd_session_get_type.3 \
	man/sd_session_get_class.3 \
	man/sd_session_get_display.3 \
	man/sd_pid_get_owner_uid.3 \
	man/sd_pid_get_unit.3 \
	man/sd_uid_is_on_seat.3 \
	man/sd_uid_get_sessions.3 \
	man/sd_uid_get_seats.3 \
	man/sd_seat_get_sessions.3 \
	man/sd_seat_can_multi_session.3 \
	man/sd_get_sessions.3 \
	man/sd_get_uids.3 \
	man/systemd-logind.8 \
	man/systemd-user-sessions.8

man/systemd-logind.8: man/systemd-logind.service.8
man/sd_login_monitor_unref.3: man/sd_login_monitor_new.3
man/sd_login_monitor_flush.3: man/sd_login_monitor_new.3
man/sd_login_monitor_get_fd.3: man/sd_login_monitor_new.3
man/sd_login_monitor.3: man/sd_login_monitor_new.3
man/sd_session_get_uid.3: man/sd_session_is_active.3
man/sd_session_get_seat.3: man/sd_session_is_active.3
man/sd_session_get_service.3: man/sd_session_is_active.3
man/sd_session_get_state.3: man/sd_session_is_active.3
man/sd_session_get_type.3: man/sd_session_is_active.3
man/sd_session_get_class.3: man/sd_session_is_active.3
man/sd_session_get_display.3: man/sd_session_is_active.3
man/sd_pid_get_owner_uid.3: man/sd_pid_get_session.3
man/sd_pid_get_unit.3: man/sd_pid_get_session.3
man/sd_uid_is_on_seat.3: man/sd_uid_get_state.3
man/sd_uid_get_sessions.3: man/sd_uid_get_state.3
man/sd_uid_get_seats.3: man/sd_uid_get_state.3
man/sd_seat_get_sessions.3: man/sd_seat_get_active.3
man/sd_seat_can_multi_session.3: man/sd_seat_get_active.3
man/sd_get_sessions.3: man/sd_get_seats.3
man/sd_get_uids.3: man/sd_get_seats.3
man/systemd-user-sessions.8: man/systemd-user-sessions.service.8

CLEANFILES += \
	src/login/logind-gperf.c \
	src/login/71-seat.rules \
	src/login/73-seat-late.rules
endif

polkitpolicy_in_files += \
	src/login/org.freedesktop.login1.policy.in

EXTRA_DIST += \
	src/login/logind-gperf.gperf \
	src/login/libsystemd-login.pc.in \
	src/login/libsystemd-login.sym \
	src/login/71-seat.rules.in \
	src/login/73-seat-late.rules.in \
	units/systemd-logind.service.in \
	units/systemd-user-sessions.service.in

# ------------------------------------------------------------------------------

if HAVE_PYTHON_DEVEL

pkgpyexec_LTLIBRARIES = \
	_journal.la

_journal_la_SOURCES = \
	src/python-systemd/_journal.c

_journal_la_CFLAGS = \
	$(AM_CFLAGS) \
        -fvisibility=default \
	$(PYTHON_CFLAGS)

_journal_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-module \
	-avoid-version

_journal_la_LIBADD = \
	$(PYTHON_LIBS) \
	libsystemd-journal.la

dist_pkgpyexec_PYTHON = \
	src/python-systemd/journal.py \
	src/python-systemd/__init__.py

endif

# ------------------------------------------------------------------------------

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED)	-e 's,@rootlibexecdir\@,$(rootlibexecdir),g' \
		-e 's,@rootbindir\@,$(rootbindir),g' \
		-e 's,@bindir\@,$(bindir),g' \
		-e 's,@SYSTEMCTL\@,$(rootbindir)/systemctl,g' \
		-e 's,@SYSTEMD_NOTIFY\@,$(rootbindir)/systemd-notify,g' \
		-e 's,@pkgsysconfdir\@,$(pkgsysconfdir),g' \
		-e 's,@pkgdatadir\@,$(pkgdatadir),g' \
		-e 's,@systemunitdir\@,$(systemunitdir),g' \
		-e 's,@userunitdir\@,$(userunitdir),g' \
		-e 's,@systempresetdir\@,$(systempresetdir),g' \
		-e 's,@userpresetdir\@,$(userpresetdir),g' \
		-e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' \
		-e 's,@PACKAGE_NAME\@,$(PACKAGE_NAME),g' \
		-e 's,@PACKAGE_URL\@,$(PACKAGE_URL),g' \
		-e 's,@RANDOM_SEED\@,$(localstatedir)/lib/random-seed,g' \
		-e 's,@prefix\@,$(prefix),g' \
		-e 's,@exec_prefix\@,$(exec_prefix),g' \
		-e 's,@libdir\@,$(libdir),g' \
		-e 's,@includedir\@,$(includedir),g' \
		-e 's,@VERSION\@,$(VERSION),g' \
		-e 's,@rootprefix\@,$(rootprefix),g' \
		-e 's,@udevlibexecdir\@,$(udevlibexecdir),g' \
		-e 's,@sushell\@,$(sushell),g' \
		-e 's,@KILL\@,$(KILL),g' \
		-e 's,@QUOTAON\@,$(QUOTAON),g' \
		-e 's,@QUOTACHECK\@,$(QUOTACHECK),g' \
		-e 's,@SYSTEM_SYSVINIT_PATH\@,$(sysvinitdir),g' \
		-e 's,@VARLOGDIR\@,$(varlogdir),g' \
		< $< > $@

units/%: units/%.in Makefile
	$(SED_PROCESS)

man/%: man/%.in Makefile
	$(SED_PROCESS)

sysctl.d/%: sysctl.d/%.in Makefile
	$(SED_PROCESS)

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

src/core/macros.%: src/core/macros.%.in Makefile
	$(SED_PROCESS)

src/%.policy.in: src/%.policy.in.in Makefile
	$(SED_PROCESS)

%.rules: %.rules.in Makefile
	$(SED_PROCESS)

%.sh: %.sh.in Makefile
	$(SED_PROCESS)
	$(AM_V_GEN)chmod +x $@

src/%.c: src/%.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(GPERF) < $< > $@

src/%: src/%.m4
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(M4) -P $(M4_DEFINES) < $< > $@

M4_PROCESS_SYSTEM = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DEFINES) -DFOR_SYSTEM=1 < $< > $@

M4_PROCESS_USER = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DEFINES) -DFOR_USER=1 < $< > $@

units/%: units/%.m4 Makefile
	$(M4_PROCESS_SYSTEM)

units/user/%: units/%.m4 Makefile
	$(M4_PROCESS_USER)

nodist_polkitpolicy_DATA = \
	$(polkitpolicy_files) \
	$(polkitpolicy_in_in_files:.policy.in.in=.policy)

EXTRA_DIST += \
	$(polkitpolicy_in_files) \
	$(polkitpolicy_in_in_files)

CLEANFILES += \
	$(nodist_systemunit_DATA) \
	$(nodist_userunit_DATA) \
	$(nodist_man_MANS) \
	$(pkgconfigdata_DATA) \
	$(pkgconfiglib_DATA) \
	$(nodist_polkitpolicy_DATA)

if ENABLE_MANPAGES
XSLTPROC_FLAGS = \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0

XSLTPROC_PROCESS_MAN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

XSLTPROC_PROCESS_HTML = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-html.xsl $<

man/%.1: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.3: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.5: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.7: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.8: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.html: man/%.xml man/custom-html.xsl
	$(XSLTPROC_PROCESS_HTML)

CLEANFILES += \
	$(dist_man_MANS) \
	${XML_FILES:.xml=.html}
endif

DBUS_PREPROCESS = $(CPP) -P $(CFLAGS) $(DBUS_CFLAGS) -imacros dbus/dbus-protocol.h

CLEANFILES += \
	$(dbusinterface_DATA)

if HAVE_SYSV_COMPAT
sysvinit_DATA = \
	docs/sysvinit/README

varlog_DATA = \
	docs/var-log/README

docs/sysvinit/README: docs/sysvinit/README.in
	$(SED_PROCESS)

docs/var-log/README: docs/var-log/README.in
	$(SED_PROCESS)

EXTRA_DIST += \
	docs/sysvinit/README.in \
	docs/var-log/README.in

CLEANFILES += \
	docs/sysvinit/README \
	docs/var-log/README

endif


systemd-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(tmpfilesdir) \
		$(DESTDIR)$(sysconfdir)/tmpfiles.d \
		$(DESTDIR)$(prefix)/lib/modules-load.d \
		$(DESTDIR)$(sysconfdir)/modules-load.d \
		$(DESTDIR)$(prefix)/lib/sysctl.d \
		$(DESTDIR)$(sysconfdir)/sysctl.d \
		$(DESTDIR)$(systemshutdowndir) \
		$(DESTDIR)$(systemsleepdir) \
		$(DESTDIR)$(systemgeneratordir) \
		$(DESTDIR)$(usergeneratordir)
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir) \
		$(DESTDIR)$(userunitdir) \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants \
		$(DESTDIR)$(systemunitdir)/sockets.target.wants \
		$(DESTDIR)$(systemunitdir)/basic.target.wants \
		$(DESTDIR)$(systemunitdir)/shutdown.target.wants \
		$(DESTDIR)$(systemunitdir)/local-fs.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel1.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel2.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel3.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel4.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel5.target.wants \
		$(DESTDIR)$(systemunitdir)/multi-user.target.wants \
		$(DESTDIR)$(systemunitdir)/graphical.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system \
		$(DESTDIR)$(pkgsysconfdir)/system/sysinit.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/local-fs.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/getty.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/user \
		$(DESTDIR)$(dbussessionservicedir) \
		$(DESTDIR)$(sysconfdir)/xdg/systemd
	( cd $(DESTDIR)$(sysconfdir)/xdg/systemd/ && \
		rm -f user && \
		$(LN_S) $(pkgsysconfdir)/user user )
	( cd $(DESTDIR)$(systemunitdir)/sockets.target.wants && \
		rm -f systemd-initctl.socket systemd-shutdownd.socket && \
		$(LN_S) ../systemd-initctl.socket systemd-initctl.socket && \
		$(LN_S) ../systemd-shutdownd.socket systemd-shutdownd.socket )
	( cd $(DESTDIR)$(systemunitdir)/runlevel1.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel2.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel3.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel4.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel5.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/shutdown.target.wants && \
		rm -f systemd-update-utmp-shutdown.service && \
		$(LN_S) ../systemd-update-utmp-shutdown.service systemd-update-utmp-shutdown.service )
	( cd $(DESTDIR)$(systemunitdir)/local-fs.target.wants && \
		rm -f systemd-remount-fs.service \
			systemd-fsck-root.service \
			tmp.mount && \
		$(LN_S) ../systemd-remount-fs.service systemd-remount-fs.service && \
		$(LN_S) ../systemd-fsck-root.service systemd-fsck-root.service && \
		$(LN_S) ../tmp.mount tmp.mount )
	( cd $(DESTDIR)$(userunitdir) && \
		rm -f shutdown.target sockets.target bluetooth.target printer.target sound.target && \
		$(LN_S) $(systemunitdir)/shutdown.target shutdown.target && \
		$(LN_S) $(systemunitdir)/sockets.target sockets.target && \
		$(LN_S) $(systemunitdir)/bluetooth.target bluetooth.target && \
		$(LN_S) $(systemunitdir)/printer.target printer.target && \
		$(LN_S) $(systemunitdir)/sound.target sound.target )
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f runlevel0.target runlevel1.target runlevel2.target runlevel3.target runlevel4.target runlevel5.target runlevel6.target && \
		$(LN_S) poweroff.target runlevel0.target && \
		$(LN_S) rescue.target runlevel1.target && \
		$(LN_S) multi-user.target runlevel2.target && \
		$(LN_S) multi-user.target runlevel3.target && \
		$(LN_S) multi-user.target runlevel4.target && \
		$(LN_S) graphical.target runlevel5.target && \
		$(LN_S) reboot.target runlevel6.target )
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f default.target ctrl-alt-del.target autovt@.service && \
		$(LN_S) graphical.target default.target && \
		$(LN_S) reboot.target ctrl-alt-del.target && \
		$(LN_S) getty@.service autovt@.service )
	( cd $(DESTDIR)$(systemunitdir)/multi-user.target.wants && \
		rm -f getty.target systemd-ask-password-wall.path && \
		$(LN_S) ../getty.target getty.target && \
		$(LN_S) ../systemd-ask-password-wall.path systemd-ask-password-wall.path)
	( cd $(DESTDIR)$(pkgsysconfdir)/system/getty.target.wants && \
		rm -f getty@tty1.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty1.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants && \
		rm -f remote-fs.target && \
		$(LN_S) $(systemunitdir)/remote-fs.target remote-fs.target )
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f dev-hugepages.mount \
			dev-mqueue.mount \
			sys-kernel-config.mount \
			sys-kernel-debug.mount \
			sys-fs-fuse-connections.mount \
			systemd-modules-load.service \
			systemd-tmpfiles-setup.service \
			systemd-sysctl.service \
			systemd-ask-password-console.path && \
		$(LN_S) ../dev-hugepages.mount dev-hugepages.mount && \
		$(LN_S) ../dev-mqueue.mount dev-mqueue.mount && \
		$(LN_S) ../sys-kernel-config.mount sys-kernel-config.mount && \
		$(LN_S) ../sys-kernel-debug.mount sys-kernel-debug.mount && \
		$(LN_S) ../sys-fs-fuse-connections.mount sys-fs-fuse-connections.mount && \
		$(LN_S) ../systemd-modules-load.service systemd-modules-load.service && \
		$(LN_S) ../systemd-tmpfiles-setup.service systemd-tmpfiles-setup.service && \
		$(LN_S) ../systemd-sysctl.service systemd-sysctl.service && \
		$(LN_S) ../systemd-ask-password-console.path systemd-ask-password-console.path )
	( cd $(DESTDIR)$(systemunitdir)/basic.target.wants && \
		rm -f systemd-tmpfiles-clean.timer && \
		$(LN_S) ../systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.timer )
	( cd $(DESTDIR)$(dbussessionservicedir) && \
		rm -f org.freedesktop.systemd1.service && \
		$(LN_S) ../system-services/org.freedesktop.systemd1.service org.freedesktop.systemd1.service )

if TARGET_FEDORA
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f display-manager.service single.service && \
		$(LN_S) rescue.service single.service )
endif

if TARGET_MANDRIVA
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f display-manager.service dm.service single.service && \
		$(LN_S) rescue.service single.service )
endif

if TARGET_DEBIAN_OR_UBUNTU
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f runlevel5.target && \
		$(LN_S) multi-user.target runlevel5.target )
endif

if TARGET_SUSE
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f local.service && \
		$(LN_S) rc-local.service local.service )
endif

if TARGET_MAGEIA
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f display-manager.service )
endif

install-exec-hook: $(INSTALL_EXEC_HOOKS)

uninstall-hook: $(UNINSTALL_EXEC_HOOKS)

install-data-hook: systemd-install-data-hook $(INSTALL_DATA_HOOKS)

distclean-local: $(DISTCLEAN_LOCAL_HOOKS)

clean-local:
	rm -rf $(abs_srcdir)/install-tree
	rm -f $(abs_srcdir)/hwdb/usb.ids $(abs_srcdir)/hwdb/pci.ids $(abs_srcdir)/hwdb/oui.txt

DISTCHECK_CONFIGURE_FLAGS = \
	--with-sysvinit-path=$$dc_install_base/$(sysvinitdir) \
	--with-dbuspolicydir=$$dc_install_base/$(dbuspolicydir) \
	--with-dbussessionservicedir=$$dc_install_base/$(dbussessionservicedir) \
	--with-dbussystemservicedir=$$dc_install_base/$(dbussystemservicedir) \
	--with-dbusinterfacedir=$$dc_install_base/$(dbusinterfacedir) \
	--with-pamlibdir=$$dc_install_base/$(pamlibdir) \
	--with-rootprefix=$$dc_install_base \
	--disable-split-usr

if ENABLE_GTK_DOC
DISTCHECK_CONFIGURE_FLAGS += \
	--enable-gtk-doc
endif

hwdb-update:
	( cd hwdb && \
	wget -N http://www.linux-usb.org/usb.ids && \
	wget -N http://pciids.sourceforge.net/v2.2/pci.ids && \
	wget -N http://standards.ieee.org/develop/regauth/oui/oui.txt && \
	./ids-update.pl )

upload: all distcheck
	cp -v systemd-$(VERSION).tar.xz /home/lennart/git.fedora/systemd/
	scp systemd-$(VERSION).tar.xz fdo:/srv/www.freedesktop.org/www/software/systemd/
	scp man/*.html tango:public/systemd-man/

doc-sync: all
	gtkdoc-rebase --html-dir=docs/libudev/html --online
	rsync -av --delete docs/libudev/html/ --omit-dir-times www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd/libudev/
	gtkdoc-rebase --html-dir=docs/gudev/html --online
	rsync -av --delete docs/gudev/html/ --omit-dir-times www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd/gudev/
	rsync -av --delete-excluded --include="*.html" --exclude="*" --omit-dir-times man/ www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd/man/

git-tag:
	git tag "v$(VERSION)" -m "systemd $(VERSION)"

install-tree: all
	rm -rf $(abs_srcdir)/install-tree
	make install DESTDIR=$(abs_srcdir)/install-tree
	tree $(abs_srcdir)/install-tree
