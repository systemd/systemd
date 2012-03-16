#  This file is part of systemd.
#
#  Copyright 2011 Lennart Poettering
#  Copyright 2011 Kay Sievers
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = po

LIBSYSTEMD_LOGIN_CURRENT=2
LIBSYSTEMD_LOGIN_REVISION=1
LIBSYSTEMD_LOGIN_AGE=2

LIBSYSTEMD_DAEMON_CURRENT=0
LIBSYSTEMD_DAEMON_REVISION=1
LIBSYSTEMD_DAEMON_AGE=0

LIBSYSTEMD_ID128_CURRENT=0
LIBSYSTEMD_ID128_REVISION=3
LIBSYSTEMD_ID128_AGE=0

LIBSYSTEMD_JOURNAL_CURRENT=0
LIBSYSTEMD_JOURNAL_REVISION=3
LIBSYSTEMD_JOURNAL_AGE=0

# Dirs of external packages
dbuspolicydir=@dbuspolicydir@
dbussessionservicedir=@dbussessionservicedir@
dbussystemservicedir=@dbussystemservicedir@
dbusinterfacedir=@dbusinterfacedir@
udevrulesdir=@udevrulesdir@
pamlibdir=@pamlibdir@
pkgconfigdatadir=$(datadir)/pkgconfig
pkgconfiglibdir=$(libdir)/pkgconfig
polkitpolicydir=$(datadir)/polkit-1/actions
bashcompletiondir=$(sysconfdir)/bash_completion.d

# Our own, non-special dirs
pkgsysconfdir=$(sysconfdir)/systemd
userunitdir=$(prefix)/lib/systemd/user
tmpfilesdir=$(prefix)/lib/tmpfiles.d
sysctldir=$(prefix)/lib/sysctl.d
usergeneratordir=$(pkglibexecdir)/user-generators
pkgincludedir=$(includedir)/systemd

# And these are the special ones for /
rootprefix=@rootprefix@
rootbindir=$(rootprefix)/bin
rootlibexecdir=$(rootprefix)/lib/systemd
systemgeneratordir=$(rootlibexecdir)/system-generators
systemshutdowndir=$(rootlibexecdir)/system-shutdown
systemunitdir=$(rootprefix)/lib/systemd/system

CLEANFILES =
EXTRA_DIST =
INSTALL_EXEC_HOOKS =
UNINSTALL_EXEC_HOOKS =
INSTALL_DATA_HOOKS =
pkginclude_HEADERS =
lib_LTLIBRARIES =
pkgconfiglib_DATA =
polkitpolicy_in_files =
dist_udevrules_DATA =

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
	-DSYSTEMD_KBD_MODEL_MAP=\"$(pkgdatadir)/kbd-model-map\" \
        -DX_SERVER=\"$(bindir)/X\" \
	-I $(top_srcdir)/src \
	-I $(top_srcdir)/src/readahead \
	-I $(top_srcdir)/src/login \
	-I $(top_srcdir)/src/journal \
	-I $(top_srcdir)/src/systemd

if TARGET_GENTOO
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\" \
	-DDEFAULT_FONT=\"LatArCyrHeb-16\"
else
if TARGET_ARCH
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\" \
	-DDEFAULT_FONT=\"LatArCyrHeb-16\"
else
if TARGET_FRUGALWARE
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\" \
	-DDEFAULT_FONT=\"LatArCyrHeb-16\"
else
if TARGET_MANDRIVA
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\" \
	-DDEFAULT_FONT=\"LatArCyrHeb-16\"
else
if TARGET_MEEGO
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\" \
	-DDEFAULT_FONT=\"LatArCyrHeb-16\"
else
if TARGET_ANGSTROM
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/usr/bin/loadkeys\" \
	-DKBD_SETFONT=\"/usr/bin/setfont\" \
	-DDEFAULT_FONT=\"LatArCyrHeb-16\"
else
if TARGET_MAGEIA
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\" \
	-DDEFAULT_FONT=\"LatArCyrHeb-16\"
else
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\" \
	-DDEFAULT_FONT=\"latarcyrheb-sun16\"
endif
endif
endif
endif
endif
endif
endif

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
	systemd-nspawn

dist_bin_SCRIPTS = \
	src/systemd-analyze

if HAVE_GTK
bin_PROGRAMS += \
	systemadm \
	systemd-gnome-ask-password-agent
endif

rootlibexec_PROGRAMS = \
	systemd \
	systemd-cgroups-agent \
	systemd-initctl \
	systemd-update-utmp \
	systemd-shutdownd \
	systemd-shutdown \
	systemd-modules-load \
	systemd-remount-api-vfs \
	systemd-reply-password \
	systemd-fsck \
	systemd-timestamp \
	systemd-ac-power \
	systemd-detect-virt \
	systemd-sysctl

systemgenerator_PROGRAMS = \
	systemd-getty-generator

noinst_PROGRAMS = \
	test-engine \
	test-job-type \
	test-ns \
	test-loopback \
	test-hostname \
	test-daemon \
	test-cgroup \
	test-env-replace \
	test-strv \
	test-install

dist_pkgsysconf_DATA = \
	src/system.conf \
	src/user.conf

dist_dbuspolicy_DATA = \
	src/org.freedesktop.systemd1.conf

dist_dbussystemservice_DATA = \
	src/org.freedesktop.systemd1.service

nodist_udevrules_DATA = \
	src/99-systemd.rules

dbusinterface_DATA = \
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

dist_bashcompletion_DATA = \
	src/systemd-bash-completion.sh

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
	units/mail-transfer-agent.target \
	units/http-daemon.target \
	units/poweroff.target \
	units/reboot.target \
	units/rescue.target \
	units/rpcbind.target \
	units/time-sync.target \
	units/shutdown.target \
	units/final.target \
	units/umount.target \
	units/sigpwr.target \
	units/sockets.target \
	units/swap.target \
	units/systemd-initctl.socket \
	units/systemd-shutdownd.socket \
	units/syslog.socket \
	units/dev-hugepages.mount \
	units/dev-mqueue.mount \
	units/sys-kernel-config.mount \
	units/sys-kernel-debug.mount \
	units/sys-kernel-security.mount \
	units/sys-fs-fuse-connections.mount \
	units/var-run.mount \
	units/media.mount \
	units/remount-rootfs.service \
	units/printer.target \
	units/sound.target \
	units/bluetooth.target \
	units/smartcard.target \
	units/systemd-tmpfiles-clean.timer \
	units/quotaon.service \
	units/systemd-ask-password-wall.path \
	units/systemd-ask-password-console.path \
	units/syslog.target

if HAVE_SYSV_COMPAT
dist_systemunit_DATA += \
	units/var-lock.mount
endif

nodist_systemunit_DATA = \
	units/getty@.service \
	units/serial-getty@.service \
	units/console-shell.service \
	units/systemd-initctl.service \
	units/systemd-shutdownd.service \
	units/systemd-modules-load.service \
	units/systemd-remount-api-vfs.service \
	units/systemd-update-utmp-runlevel.service \
	units/systemd-update-utmp-shutdown.service \
	units/systemd-tmpfiles-setup.service \
	units/systemd-tmpfiles-clean.service \
	units/systemd-ask-password-wall.service \
	units/systemd-ask-password-console.service \
	units/systemd-sysctl.service \
	units/halt.service \
	units/poweroff.service \
	units/reboot.service \
	units/kexec.service \
	units/fsck@.service \
	units/fsck-root.service \
	units/rescue.service \
	units/user@.service

dist_userunit_DATA = \
	units/user/default.target \
	units/user/exit.target

nodist_userunit_DATA = \
	units/user/exit.service

EXTRA_DIST += \
	units/getty@.service.m4 \
	units/serial-getty@.service.m4 \
	units/console-shell.service.m4 \
	units/rescue.service.m4 \
	units/systemd-initctl.service.in \
	units/systemd-shutdownd.service.in \
	units/systemd-modules-load.service.in \
	units/systemd-remount-api-vfs.service.in \
	units/systemd-update-utmp-runlevel.service.in \
	units/systemd-update-utmp-shutdown.service.in \
	units/systemd-tmpfiles-setup.service.in \
	units/systemd-tmpfiles-clean.service.in \
	units/systemd-ask-password-wall.service.in \
	units/systemd-ask-password-console.service.in \
	units/systemd-sysctl.service.in \
	units/halt.service.in \
	units/poweroff.service.in \
	units/reboot.service.in \
	units/kexec.service.in \
	units/user/exit.service.in \
	units/fsck@.service.in \
	units/fsck-root.service.in \
	units/user@.service.in \
	src/systemd.pc.in \
	introspect.awk \
	src/99-systemd.rules.in \
	man/custom-html.xsl

if TARGET_FEDORA
dist_systemunit_DATA += \
	units/fedora/prefdm.service \
	units/fedora/rc-local.service \
	units/fedora/halt-local.service
systemgenerator_PROGRAMS += \
	systemd-rc-local-generator
endif

if TARGET_MANDRIVA
dist_systemunit_DATA += \
	units/mandriva/prefdm.service \
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
	units/mageia/prefdm.service \
	units/fedora/rc-local.service \
	units/fedora/halt-local.service
systemgenerator_PROGRAMS += \
	systemd-rc-local-generator
endif

if HAVE_PLYMOUTH
dist_systemunit_DATA += \
	units/plymouth-start.service \
	units/plymouth-read-write.service \
	units/plymouth-quit.service \
	units/plymouth-quit-wait.service \
	units/plymouth-reboot.service \
	units/plymouth-kexec.service \
	units/plymouth-poweroff.service \
	units/plymouth-halt.service \
	units/systemd-ask-password-plymouth.path

nodist_systemunit_DATA += \
	units/systemd-ask-password-plymouth.service

EXTRA_DIST += \
	units/systemd-ask-password-plymouth.service.in
endif

dist_doc_DATA = \
	README \
        NEWS \
	LICENSE \
	DISTRO_PORTING

pkgconfigdata_DATA = \
	src/systemd.pc

# First passed through sed, followed by intltool
polkitpolicy_in_in_files = \
	src/org.freedesktop.systemd1.policy.in.in

nodist_polkitpolicy_DATA = \
	$(polkitpolicy_in_files:.policy.in=.policy) \
	$(polkitpolicy_in_in_files:.policy.in.in=.policy)

EXTRA_DIST += \
	$(polkitpolicy_in_files) \
	$(polkitpolicy_in_in_files)

@INTLTOOL_POLICY_RULE@

noinst_LTLIBRARIES = \
	libsystemd-basic.la \
	libsystemd-core.la

libsystemd_basic_la_SOURCES = \
	src/util.c \
	src/virt.c \
	src/label.c \
	src/hashmap.c \
	src/set.c \
	src/strv.c \
	src/conf-parser.c \
	src/socket-util.c \
	src/log.c \
	src/ratelimit.c \
	src/exit-status.c \
        src/utf8.c

libsystemd_basic_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SELINUX_CFLAGS)

libsystemd_basic_la_LIBADD = \
	$(SELINUX_LIBS) \
	$(CAP_LIBS)

libsystemd_core_la_SOURCES = \
	src/unit.c \
	src/job.c \
	src/manager.c \
	src/path-lookup.c \
	src/load-fragment.c \
	src/service.c \
	src/automount.c \
	src/mount.c \
	src/swap.c \
	src/device.c \
	src/target.c \
	src/snapshot.c \
	src/socket.c \
	src/timer.c \
	src/path.c \
	src/load-dropin.c \
	src/execute.c \
	src/utmp-wtmp.c \
	src/dbus.c \
	src/dbus-manager.c \
	src/dbus-unit.c \
	src/dbus-job.c \
	src/dbus-service.c \
	src/dbus-socket.c \
	src/dbus-timer.c \
	src/dbus-target.c \
	src/dbus-mount.c \
	src/dbus-automount.c \
	src/dbus-swap.c \
	src/dbus-snapshot.c \
	src/dbus-device.c \
	src/dbus-execute.c \
	src/dbus-path.c \
	src/cgroup.c \
	src/mount-setup.c \
	src/hostname-setup.c \
	src/selinux-setup.c \
	src/loopback-setup.c \
	src/kmod-setup.c \
	src/locale-setup.c \
	src/machine-id-setup.c \
	src/specifier.c \
	src/unit-name.c \
	src/fdset.c \
	src/namespace.c \
	src/tcpwrap.c \
	src/cgroup-util.c \
	src/condition.c \
	src/dbus-common.c \
	src/sd-daemon.c \
	src/install.c \
	src/cgroup-attr.c \
	src/sd-id128.c

nodist_libsystemd_core_la_SOURCES = \
	src/load-fragment-gperf.c \
	src/load-fragment-gperf-nulstr.c

EXTRA_DIST += \
	src/load-fragment-gperf.gperf.m4

libsystemd_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(LIBWRAP_CFLAGS) \
	$(PAM_CFLAGS) \
	$(AUDIT_CFLAGS) \
	$(KMOD_CFLAGS)

libsystemd_core_la_LIBADD = \
	libsystemd-basic.la \
	$(DBUS_LIBS) \
	$(UDEV_LIBS) \
	$(LIBWRAP_LIBS) \
	$(PAM_LIBS) \
	$(AUDIT_LIBS) \
	$(CAP_LIBS) \
	$(KMOD_LIBS)

# This is needed because automake is buggy in how it generates the
# rules for C programs, but not Vala programs.	We therefore can't
# list the .h files as dependencies if we want make dist to work.

EXTRA_DIST += \
	src/util.h \
	src/virt.h \
	src/label.h \
	src/hashmap.h \
	src/set.h \
	src/strv.h \
	src/conf-parser.h \
	src/socket-util.h \
	src/log.h \
	src/ratelimit.h \
	src/exit-status.h \
	src/unit.h \
	src/job.h \
	src/manager.h \
	src/path-lookup.h \
	src/load-fragment.h \
	src/service.h \
	src/automount.h \
	src/mount.h \
	src/swap.h \
	src/device.h \
	src/target.h \
	src/snapshot.h \
	src/socket.h \
	src/timer.h \
	src/path.h \
	src/load-dropin.h \
	src/execute.h \
	src/utmp-wtmp.h \
	src/dbus.h \
	src/dbus-manager.h \
	src/dbus-unit.h \
	src/dbus-job.h \
	src/dbus-service.h \
	src/dbus-socket.h \
	src/dbus-timer.h \
	src/dbus-target.h \
	src/dbus-mount.h \
	src/dbus-automount.h \
	src/dbus-swap.h \
	src/dbus-snapshot.h \
	src/dbus-device.h \
	src/dbus-execute.h \
	src/dbus-path.h \
	src/cgroup.h \
	src/mount-setup.h \
	src/hostname-setup.h \
	src/selinux-setup.h \
	src/loopback-setup.h \
	src/kmod-setup.h \
	src/locale-setup.h \
	src/machine-id-setup.h \
	src/specifier.h \
	src/unit-name.h \
	src/fdset.h \
	src/namespace.h \
	src/tcpwrap.h \
	src/cgroup-util.h \
	src/condition.h \
	src/dbus-common.h \
	src/install.h \
	src/cgroup-attr.h \
	src/macro.h \
	src/def.h \
	src/ioprio.h \
	src/missing.h \
	src/list.h \
	src/securebits.h \
	src/linux/auto_dev-ioctl.h \
	src/linux/fanotify.h \
	src/initreq.h \
	src/special.h \
	src/dbus-common.h \
	src/bus-errors.h \
	src/cgroup-show.h \
	src/build.h \
	src/shutdownd.h \
	src/umount.h \
	src/ask-password-api.h \
	src/pager.h \
	src/sysfs-show.h \
	src/polkit.h \
	src/dbus-loop.h \
	src/spawn-agent.h \
	src/acl-util.h \
	src/logs-show.h \
        src/utf8.h

MANPAGES = \
	man/systemd.1 \
	man/systemctl.1 \
	man/systemadm.1 \
	man/systemd-cgls.1 \
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
	man/systemd.special.7 \
	man/daemon.7 \
	man/runlevel.8 \
	man/telinit.8 \
	man/halt.8 \
	man/shutdown.8 \
	man/pam_systemd.8 \
	man/systemd.conf.5 \
	man/tmpfiles.d.5 \
	man/hostname.5 \
	man/timezone.5 \
	man/machine-id.5 \
	man/locale.conf.5 \
	man/os-release.5 \
	man/machine-info.5 \
	man/modules-load.d.5 \
	man/sysctl.d.5 \
	man/systemd-ask-password.1 \
	man/systemd-cat.1 \
        man/systemd-machine-id-setup.1 \
        man/systemd-journald.conf.5 \
        man/systemd-journalctl.1

MANPAGES_ALIAS = \
	man/reboot.8 \
	man/poweroff.8 \
	man/init.1

man/reboot.8: man/halt.8
man/poweroff.8: man/halt.8
man/init.1: man/systemd.1

XML_FILES = \
	${patsubst %.1,%.xml,${patsubst %.3,%.xml,${patsubst %.5,%.xml,${patsubst %.7,%.xml,${patsubst %.8,%.xml,$(MANPAGES)}}}}}

if ENABLE_MANPAGES
man_MANS = \
	$(MANPAGES) \
	$(MANPAGES_ALIAS)

noinst_DATA = \
	${XML_FILES:.xml=.html}
endif

EXTRA_DIST += \
	$(XML_FILES) \
	${XML_FILES:.xml=.html} \
	$(MANPAGES) \
	$(MANPAGES_ALIAS)

systemd_SOURCES = \
	src/main.c

systemd_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_LDADD = \
	libsystemd-core.la

test_engine_SOURCES = \
	src/test-engine.c

test_engine_CFLAGS = $(systemd_CFLAGS)
test_engine_LDADD = $(systemd_LDADD)

test_job_type_SOURCES = \
	src/test-job-type.c

test_job_type_CFLAGS = $(systemd_CFLAGS)
test_job_type_LDADD = $(systemd_LDADD)

test_ns_SOURCES = \
	src/test-ns.c

test_ns_CFLAGS = $(systemd_CFLAGS)
test_ns_LDADD = $(systemd_LDADD)

test_loopback_SOURCES = \
	src/test-loopback.c \
	src/loopback-setup.c

test_loopback_LDADD = \
	libsystemd-basic.la

test_hostname_SOURCES = \
	src/test-hostname.c \
	src/hostname-setup.c

test_hostname_LDADD = \
	libsystemd-basic.la

test_daemon_SOURCES = \
	src/test-daemon.c

test_daemon_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la

test_cgroup_SOURCES = \
	src/test-cgroup.c \
	src/cgroup-util.c

test_cgroup_LDADD = \
	libsystemd-basic.la

test_env_replace_SOURCES = \
	src/test-env-replace.c

test_env_replace_LDADD = \
	libsystemd-basic.la

test_strv_SOURCES = \
	src/test-strv.c \
	src/specifier.c

test_strv_LDADD = \
	libsystemd-basic.la

test_install_SOURCES = \
	src/test-install.c \
	src/install.c \
	src/path-lookup.c \
	src/unit-name.c

test_install_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

test_install_LDADD = \
	libsystemd-basic.la

systemd_initctl_SOURCES = \
	src/initctl.c \
	src/dbus-common.c

systemd_initctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_initctl_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(DBUS_LIBS)

systemd_update_utmp_SOURCES = \
	src/update-utmp.c \
	src/dbus-common.c \
	src/utmp-wtmp.c

systemd_update_utmp_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(AUDIT_CFLAGS)

systemd_update_utmp_LDADD = \
	libsystemd-basic.la \
	$(DBUS_LIBS) \
	$(AUDIT_LIBS)

systemd_shutdownd_SOURCES = \
	src/utmp-wtmp.c \
	src/shutdownd.c

systemd_shutdownd_CFLAGS = \
	$(AM_CFLAGS)

systemd_shutdownd_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la

systemd_shutdown_SOURCES = \
	src/mount-setup.c \
	src/umount.c \
	src/shutdown.c

systemd_shutdown_CFLAGS = \
	$(AM_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_shutdown_LDADD = \
	libsystemd-basic.la \
	$(UDEV_LIBS)

systemd_modules_load_SOURCES = \
	src/modules-load.c

systemd_modules_load_CFLAGS = \
	$(KMOD_CFLAGS)

systemd_modules_load_LDADD = \
	libsystemd-basic.la \
	$(KMOD_LIBS)

systemd_tmpfiles_SOURCES = \
	src/tmpfiles.c

systemd_tmpfiles_LDADD = \
	libsystemd-basic.la

systemd_machine_id_setup_SOURCES = \
	src/machine-id-setup.c \
	src/machine-id-main.c \
	src/sd-id128.c

systemd_machine_id_setup_LDADD = \
	libsystemd-basic.la

systemd_sysctl_SOURCES = \
	src/sysctl.c

systemd_sysctl_LDADD = \
	libsystemd-basic.la

systemd_fsck_SOURCES = \
	src/fsck.c \
	src/dbus-common.c

systemd_fsck_CFLAGS = \
	$(AM_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_fsck_LDADD = \
	libsystemd-basic.la \
	$(UDEV_LIBS) \
	$(DBUS_LIBS)

systemd_timestamp_SOURCES = \
	src/timestamp.c

systemd_timestamp_LDADD = \
	libsystemd-basic.la

systemd_ac_power_SOURCES = \
	src/ac-power.c

systemd_ac_power_CFLAGS = \
	$(AM_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_ac_power_LDADD = \
	libsystemd-basic.la \
	$(UDEV_LIBS)

systemd_detect_virt_SOURCES = \
	src/detect-virt.c

systemd_detect_virt_LDADD = \
	libsystemd-basic.la

systemd_getty_generator_SOURCES = \
	src/getty-generator.c \
	src/unit-name.c

systemd_getty_generator_LDADD = \
	libsystemd-basic.la

systemd_rc_local_generator_SOURCES = \
	src/rc-local-generator.c

systemd_rc_local_generator_LDADD = \
	libsystemd-basic.la

systemd_remount_api_vfs_SOURCES = \
	src/remount-api-vfs.c \
	src/mount-setup.c \
	src/exit-status.c

systemd_remount_api_vfs_LDADD = \
	libsystemd-basic.la

systemd_cgroups_agent_SOURCES = \
	src/cgroups-agent.c \
	src/dbus-common.c

systemd_cgroups_agent_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_cgroups_agent_LDADD = \
	libsystemd-basic.la \
	$(DBUS_LIBS)

systemctl_SOURCES = \
	src/systemctl.c \
	src/utmp-wtmp.c \
	src/dbus-common.c \
	src/path-lookup.c \
	src/cgroup-show.c \
	src/cgroup-util.c \
	src/exit-status.c \
	src/unit-name.c \
	src/pager.c \
	src/install.c \
	src/spawn-agent.c \
	src/logs-show.c

systemctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemctl_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	libsystemd-journal.la \
	libsystemd-id128.la \
	$(DBUS_LIBS)

systemd_notify_SOURCES = \
	src/notify.c \
	src/readahead/sd-readahead.c

systemd_notify_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la

systemd_ask_password_SOURCES = \
	src/ask-password.c \
	src/ask-password-api.c

systemd_ask_password_LDADD = \
	libsystemd-basic.la

systemd_reply_password_SOURCES = \
	src/reply-password.c

systemd_reply_password_LDADD = \
	libsystemd-basic.la

systemd_cgls_SOURCES = \
	src/cgls.c \
	src/cgroup-show.c \
	src/cgroup-util.c \
	src/pager.c

systemd_cgls_LDADD = \
	libsystemd-basic.la

systemd_cgtop_SOURCES = \
	src/cgtop.c \
        src/cgroup-util.c

systemd_cgtop_LDADD = \
	libsystemd-basic.la

systemd_nspawn_SOURCES = \
	src/nspawn.c \
	src/cgroup-util.c \
	src/loopback-setup.c

systemd_nspawn_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la

systemd_stdio_bridge_SOURCES = \
	src/bridge.c

systemd_stdio_bridge_LDADD = \
	libsystemd-basic.la

systemadm_SOURCES = \
	src/systemadm.vala \
	src/systemd-interfaces.vala \
	src/wraplabel.vala

systemadm_CFLAGS = \
	$(AM_CFLAGS) \
	$(GTK_CFLAGS) \
	-Wno-unused-variable \
	-Wno-unused-function \
	-Wno-shadow \
	-Wno-format-nonliteral

systemadm_VALAFLAGS = \
	--pkg=posix \
	--pkg=gtk+-2.0 \
	--pkg=gee-1.0 \
	-g

systemadm_LDADD = \
	$(GTK_LIBS)

systemd_gnome_ask_password_agent_SOURCES = \
	src/gnome-ask-password-agent.vala

systemd_gnome_ask_password_agent_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBNOTIFY_CFLAGS) \
	$(GTK_CFLAGS) \
	-Wno-unused-variable \
	-Wno-unused-function \
	-Wno-shadow \
	-Wno-format-nonliteral

systemd_gnome_ask_password_agent_VALAFLAGS = \
	--pkg=posix \
	--pkg=gtk+-2.0 \
	--pkg=linux \
	--pkg=gio-unix-2.0 \
	--pkg=libnotify \
	-g

systemd_gnome_ask_password_agent_LDADD = \
	$(LIBNOTIFY_LIBS) \
	$(GTK_LIBS)

systemd_tty_ask_password_agent_SOURCES = \
	src/tty-ask-password-agent.c \
	src/ask-password-api.c \
	src/utmp-wtmp.c

systemd_tty_ask_password_agent_LDADD = \
	libsystemd-basic.la

# ------------------------------------------------------------------------------
libsystemd_daemon_la_SOURCES = \
	src/sd-daemon.c

libsystemd_daemon_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden \
	-DSD_EXPORT_SYMBOLS

libsystemd_daemon_la_LDFLAGS = \
	-shared \
	-version-info $(LIBSYSTEMD_DAEMON_CURRENT):$(LIBSYSTEMD_DAEMON_REVISION):$(LIBSYSTEMD_DAEMON_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libsystemd-daemon.sym

pkginclude_HEADERS += \
	src/systemd/sd-daemon.h

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-daemon-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		mkdir -p $(DESTDIR)$(rootlibdir) && \
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
	src/libsystemd-daemon.pc

MANPAGES += \
	man/sd-daemon.7 \
	man/sd_notify.3 \
	man/sd_listen_fds.3 \
	man/sd_is_fifo.3 \
	man/sd_booted.3

MANPAGES_ALIAS += \
	man/sd_is_socket.3 \
	man/sd_is_socket_unix.3 \
	man/sd_is_socket_inet.3 \
	man/sd_is_mq.3 \
	man/sd_notifyf.3

man/sd_is_socket.3: man/sd_is_fifo.3
man/sd_is_socket_unix.3: man/sd_is_fifo.3
man/sd_is_socket_inet.3: man/sd_is_fifo.3
man/sd_is_mq.3: man/sd_is_fifo.3
man/sd_notifyf.3: man/sd_notify.3

EXTRA_DIST += \
	src/libsystemd-daemon.pc.in \
	src/libsystemd-daemon.sym

# ------------------------------------------------------------------------------
libsystemd_id128_la_SOURCES = \
	src/sd-id128.c

libsystemd_id128_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libsystemd_id128_la_LDFLAGS = \
	-shared \
	-version-info $(LIBSYSTEMD_ID128_CURRENT):$(LIBSYSTEMD_ID128_REVISION):$(LIBSYSTEMD_ID128_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libsystemd-id128.sym

libsystemd_id128_la_LIBADD = \
	libsystemd-basic.la

test_id128_SOURCES = \
	src/test-id128.c \
	src/sd-id128.c

test_id128_LDADD = \
	libsystemd-basic.la

noinst_PROGRAMS += \
	test-id128

pkginclude_HEADERS += \
	src/systemd/sd-id128.h

lib_LTLIBRARIES += \
	libsystemd-id128.la

pkgconfiglib_DATA += \
	src/libsystemd-id128.pc

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-id128-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		mkdir -p $(DESTDIR)$(rootlibdir) && \
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
	src/libsystemd-id128.pc.in \
	src/libsystemd-id128.sym

# ------------------------------------------------------------------------------
systemd_journald_SOURCES = \
	src/journal/journald.c \
	src/journal/sd-journal.c \
	src/journal/journal-file.c \
	src/journal/lookup3.c \
	src/journal/journal-rate-limit.c \
	src/sd-id128.c \
	src/cgroup-util.c

if HAVE_ACL
systemd_journald_SOURCES += \
	src/acl-util.c
endif

nodist_systemd_journald_SOURCES = \
	src/journal/journald-gperf.c

systemd_journald_CFLAGS = \
	$(AM_CFLAGS) \
	$(ACL_CFLAGS)

systemd_journald_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	libsystemd-login.la \
	$(ACL_LIBS)

if HAVE_XZ
systemd_journald_SOURCES += \
	src/journal/compress.c
systemd_journald_CFLAGS += \
	$(XZ_CFLAGS)
systemd_journald_LDADD += \
	$(XZ_LIBS)
endif

systemd_cat_SOURCES = \
	src/journal/cat.c

systemd_cat_LDADD = \
	libsystemd-basic.la \
	libsystemd-journal.la

systemd_journalctl_SOURCES = \
	src/journal/journalctl.c \
	src/pager.c \
	src/logs-show.c

systemd_journalctl_LDADD = \
	libsystemd-basic.la \
	libsystemd-journal.la \
	libsystemd-id128.la

if HAVE_XZ
systemd_journalctl_SOURCES += \
	src/journal/compress.c
systemd_journalctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(XZ_CFLAGS)
systemd_journalctl_LDADD += \
	$(XZ_LIBS)
endif

test_journal_SOURCES = \
	src/journal/test-journal.c \
	src/journal/sd-journal.c \
	src/journal/journal-file.c \
	src/journal/lookup3.c \
	src/journal/journal-send.c \
	src/sd-id128.c

test_journal_LDADD = \
	libsystemd-basic.la

if HAVE_XZ
test_journal_SOURCES += \
	src/journal/compress.c

test_journal_CFLAGS = \
	$(AM_CFLAGS) \
	$(XZ_CFLAGS)

test_journal_LDADD += \
	$(XZ_LIBS)
endif

libsystemd_journal_la_SOURCES = \
	src/journal/sd-journal.c \
	src/journal/journal-file.c \
	src/journal/lookup3.c \
	src/journal/journal-send.c

libsystemd_journal_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libsystemd_journal_la_LDFLAGS = \
	-shared \
	-version-info $(LIBSYSTEMD_JOURNAL_CURRENT):$(LIBSYSTEMD_JOURNAL_REVISION):$(LIBSYSTEMD_JOURNAL_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/journal/libsystemd-journal.sym

libsystemd_journal_la_LIBADD = \
	libsystemd-basic.la \
	libsystemd-id128.la

if HAVE_XZ
libsystemd_journal_la_SOURCES += \
	src/journal/compress.c

libsystemd_journal_la_CFLAGS += \
	$(XZ_CFLAGS)

libsystemd_journal_la_LIBADD += \
	$(XZ_LIBS)
endif

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-journal-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		mkdir -p $(DESTDIR)$(rootlibdir) && \
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
	test-journal

pkginclude_HEADERS += \
	src/systemd/sd-journal.h \
	src/systemd/sd-messages.h

lib_LTLIBRARIES += \
	libsystemd-journal.la

rootlibexec_PROGRAMS += \
	systemd-journald

rootbin_PROGRAMS += \
	systemd-journalctl

bin_PROGRAMS += \
	systemd-cat

dist_systemunit_DATA += \
	units/systemd-journald.socket

nodist_systemunit_DATA += \
	units/systemd-journald.service

dist_pkgsysconf_DATA += \
	src/journal/systemd-journald.conf

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
		rm -f systemd-journald.service && \
		$(LN_S) ../systemd-journald.service )

INSTALL_DATA_HOOKS += \
	journal-install-data-hook

EXTRA_DIST += \
	src/journal/journald.h \
	src/journal/journal-def.h \
	src/journal/journal-internal.h \
	src/journal/journal-file.h \
	src/journal/lookup3.h \
	src/journal/compress.h \
	src/journal/journal-rate-limit.h \
	src/journal/libsystemd-journal.pc.in \
	src/journal/libsystemd-journal.sym \
	units/systemd-journald.service.in \
	src/journal/journald-gperf.gperf

CLEANFILES += \
	src/journal/journald-gperf.c

# ------------------------------------------------------------------------------
if ENABLE_COREDUMP
systemd_coredump_SOURCES = \
	src/journal/coredump.c

systemd_coredump_LDADD = \
	libsystemd-basic.la \
	libsystemd-journal.la \
	libsystemd-login.la

rootlibexec_PROGRAMS += \
	systemd-coredump

sysctl_DATA = \
	sysctl.d/coredump.conf

EXTRA_DIST += \
	sysctl.d/coredump.conf.in

CLEANFILES += \
	sysctl.d/coredump.conf
endif

# ------------------------------------------------------------------------------
if ENABLE_BINFMT
systemd_binfmt_SOURCES = \
	src/binfmt/binfmt.c

systemd_binfmt_LDADD = \
	libsystemd-basic.la

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
	man/binfmt.d.5

EXTRA_DIST += \
	units/systemd-binfmt.service.in
endif

# ------------------------------------------------------------------------------
if ENABLE_VCONSOLE
systemd_vconsole_setup_SOURCES = \
	src/vconsole/vconsole-setup.c

systemd_vconsole_setup_LDADD = \
	libsystemd-basic.la

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
	man/vconsole.conf.5

EXTRA_DIST += \
	units/systemd-vconsole-setup.service.in
endif

# ------------------------------------------------------------------------------
if ENABLE_READAHEAD
systemd_readahead_collect_SOURCES = \
	src/readahead/readahead-collect.c \
	src/readahead/readahead-common.c

systemd_readahead_collect_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(UDEV_LIBS)

systemd_readahead_collect_CFLAGS = \
	$(AM_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_readahead_replay_SOURCES = \
	src/readahead/readahead-replay.c \
	src/readahead/readahead-common.c

systemd_readahead_replay_CFLAGS = \
	$(AM_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_readahead_replay_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(UDEV_LIBS)

rootlibexec_PROGRAMS += \
	systemd-readahead-collect \
	systemd-readahead-replay

dist_systemunit_DATA += \
	units/systemd-readahead-done.timer

nodist_systemunit_DATA += \
	units/systemd-readahead-collect.service \
	units/systemd-readahead-replay.service \
	units/systemd-readahead-done.service

EXTRA_DIST += \
	src/systemd/sd-readahead.h \
	src/readahead/readahead-common.h \
	units/systemd-readahead-collect.service.in \
	units/systemd-readahead-replay.service.in \
	units/systemd-readahead-done.service.in

MANPAGES += \
	man/sd_readahead.3 \
	man/sd-readahead.7
endif

# ------------------------------------------------------------------------------
if ENABLE_QUOTACHECK
rootlibexec_PROGRAMS += \
	systemd-quotacheck

nodist_systemunit_DATA += \
	units/quotacheck.service

EXTRA_DIST += \
	units/quotacheck.service.in

systemd_quotacheck_SOURCES = \
	src/quotacheck.c

systemd_quotacheck_LDADD = \
	libsystemd-basic.la
endif

# ------------------------------------------------------------------------------
if ENABLE_RANDOMSEED
rootlibexec_PROGRAMS += \
	systemd-random-seed

nodist_systemunit_DATA += \
	units/systemd-random-seed-save.service \
	units/systemd-random-seed-load.service

EXTRA_DIST += \
	units/systemd-random-seed-save.service.in \
	units/systemd-random-seed-load.service.in

systemd_random_seed_SOURCES = \
	src/random-seed.c

systemd_random_seed_LDADD = \
	libsystemd-basic.la

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
endif

# ------------------------------------------------------------------------------
if HAVE_LIBCRYPTSETUP
rootlibexec_PROGRAMS += \
	systemd-cryptsetup

systemgenerator_PROGRAMS += \
	systemd-cryptsetup-generator

dist_systemunit_DATA += \
	units/cryptsetup.target

systemd_cryptsetup_SOURCES = \
	src/cryptsetup/cryptsetup.c \
	src/ask-password-api.c

systemd_cryptsetup_CFLAGS = \
	$(AM_CFLAGS) \
	$(LIBCRYPTSETUP_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_cryptsetup_LDADD = \
	$(LIBCRYPTSETUP_LIBS) \
	$(UDEV_LIBS) \
	libsystemd-basic.la

systemd_cryptsetup_generator_SOURCES = \
	src/cryptsetup/cryptsetup-generator.c \
	src/unit-name.c

systemd_cryptsetup_generator_LDADD = \
	libsystemd-basic.la

cryptsetup-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f cryptsetup.target && \
		$(LN_S) ../cryptsetup.target cryptsetup.target )

INSTALL_DATA_HOOKS += \
	cryptsetup-install-data-hook
endif

# ------------------------------------------------------------------------------
if ENABLE_HOSTNAMED
systemd_hostnamed_SOURCES = \
	src/hostname/hostnamed.c \
	src/dbus-common.c \
	src/polkit.c

systemd_hostnamed_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_hostnamed_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(DBUS_LIBS)

rootlibexec_PROGRAMS += \
	systemd-hostnamed

nodist_systemunit_DATA += \
	units/systemd-hostnamed.service

dist_dbuspolicy_DATA += \
	src/hostname/org.freedesktop.hostname1.conf

dist_dbussystemservice_DATA += \
	src/hostname/org.freedesktop.hostname1.service

polkitpolicy_in_files += \
	src/hostname/org.freedesktop.hostname1.policy.in

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

EXTRA_DIST += \
	units/systemd-hostnamed.service.in
endif

# ------------------------------------------------------------------------------
if ENABLE_LOCALED
systemd_localed_SOURCES = \
	src/locale/localed.c \
	src/dbus-common.c \
	src/polkit.c

systemd_localed_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_localed_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(DBUS_LIBS)

nodist_systemunit_DATA += \
	units/systemd-localed.service

rootlibexec_PROGRAMS += \
	systemd-localed

dist_dbuspolicy_DATA += \
	src/locale/org.freedesktop.locale1.conf

dist_dbussystemservice_DATA += \
	src/locale/org.freedesktop.locale1.service

polkitpolicy_in_files += \
	src/locale/org.freedesktop.locale1.policy.in

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

EXTRA_DIST += \
	units/systemd-localed.service.in

dist_pkgdata_DATA = \
	src/locale/kbd-model-map

dist_noinst_SCRIPT = \
	src/locale/generate-kbd-model-map

update-kbd-model-map:
	src/locale/generate-kbd-model-map > src/locale/kbd-model-map

endif

# ------------------------------------------------------------------------------
if ENABLE_TIMEDATED
systemd_timedated_SOURCES = \
	src/timedate/timedated.c \
	src/dbus-common.c \
	src/polkit.c

systemd_timedated_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_timedated_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(DBUS_LIBS)

rootlibexec_PROGRAMS += \
	systemd-timedated

dist_dbussystemservice_DATA += \
	src/timedate/org.freedesktop.timedate1.service

dist_dbuspolicy_DATA += \
	src/timedate/org.freedesktop.timedate1.conf

nodist_systemunit_DATA += \
	units/systemd-timedated.service

polkitpolicy_in_files += \
	src/timedate/org.freedesktop.timedate1.policy.in

org.freedesktop.timedate1.xml: systemd-timedated
	$(AM_V_GEN)$(LIBTOOL) --mode=execute $(OBJCOPY) -O binary -j introspect.timedate1 $< $@.tmp && \
		$(STRINGS) $@.tmp | $(AWK) -f $(srcdir)/introspect.awk | \
		$(DBUS_PREPROCESS) -o $@ - && rm $@.tmp

dbusinterface_DATA += \
	org.freedesktop.timedate1.xml

timedated-install-data-hook:
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f dbus-org.freedesktop.timedate1.service  && \
		$(LN_S) systemd-timedated.service dbus-org.freedesktop.timedate1.service )

INSTALL_DATA_HOOKS += \
	timedated-install-data-hook

EXTRA_DIST += \
	units/systemd-timedated.service.in
endif

# ------------------------------------------------------------------------------
if ENABLE_LOGIND
systemd_logind_SOURCES = \
	src/login/logind.c \
	src/login/logind-dbus.c \
	src/login/logind-device.c \
	src/login/logind-seat.c \
	src/login/logind-seat-dbus.c \
	src/login/logind-session.c \
	src/login/logind-session-dbus.c \
	src/login/logind-user.c \
	src/login/logind-user-dbus.c \
	src/dbus-common.c \
	src/dbus-loop.c \
	src/cgroup-util.c \
	src/polkit.c

nodist_systemd_logind_SOURCES = \
	src/login/logind-gperf.c

if HAVE_ACL
systemd_logind_SOURCES += \
	src/login/logind-acl.c \
	src/acl-util.c
endif

systemd_logind_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(ACL_CFLAGS)

systemd_logind_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(DBUS_LIBS) \
	$(UDEV_LIBS) \
	$(ACL_LIBS)

systemd_user_sessions_SOURCES = \
	src/login/user-sessions.c \
	src/cgroup-util.c

systemd_user_sessions_LDADD = \
	libsystemd-basic.la

rootlibexec_PROGRAMS += \
	systemd-logind \
	systemd-user-sessions

systemd_loginctl_SOURCES = \
	src/login/loginctl.c \
	src/login/sysfs-show.c \
	src/dbus-common.c \
	src/cgroup-show.c \
	src/cgroup-util.c \
	src/pager.c

systemd_loginctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_loginctl_LDADD = \
	libsystemd-basic.la \
	$(DBUS_LIBS) \
	$(UDEV_LIBS)

rootbin_PROGRAMS += \
	systemd-loginctl

test_login_SOURCES = \
	src/login/test-login.c

test_login_LDADD = \
	libsystemd-basic.la \
	libsystemd-login.la

noinst_PROGRAMS += \
	test-login

libsystemd_login_la_SOURCES = \
	src/login/sd-login.c \
	src/cgroup-util.c

libsystemd_login_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libsystemd_login_la_LDFLAGS = \
	-shared \
	-version-info $(LIBSYSTEMD_LOGIN_CURRENT):$(LIBSYSTEMD_LOGIN_REVISION):$(LIBSYSTEMD_LOGIN_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/login/libsystemd-login.sym

libsystemd_login_la_LIBADD = \
	libsystemd-basic.la

if HAVE_PAM
pam_systemd_la_SOURCES = \
	src/login/pam-module.c \
	src/dbus-common.c

pam_systemd_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PAM_CFLAGS) \
	$(DBUS_CFLAGS) \
	-fvisibility=hidden

pam_systemd_la_LDFLAGS = \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-export-symbols-regex '^pam_sm_.*'

pam_systemd_la_LIBADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	$(PAM_LIBS) \
	$(DBUS_LIBS)

pamlib_LTLIBRARIES = \
	pam_systemd.la
endif

# move lib from $(libdir) to $(rootlibdir) and update devel link, if needed
libsystemd-login-install-hook:
	if test "$(libdir)" != "$(rootlibdir)"; then \
		mkdir -p $(DESTDIR)$(rootlibdir) && \
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
	src/login/systemd-logind.conf

pkginclude_HEADERS += \
	src/systemd/sd-login.h

lib_LTLIBRARIES += \
	libsystemd-login.la

pkgconfiglib_DATA += \
	src/login/libsystemd-login.pc

polkitpolicy_in_files += \
	src/login/org.freedesktop.login1.policy.in

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

systemd_multi_seat_x_CFLAGS = \
	$(AM_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_multi_seat_x_LDADD = \
	libsystemd-basic.la \
	$(UDEV_LIBS)

rootlibexec_PROGRAMS += \
	systemd-multi-seat-x

systemd_uaccess_SOURCES = \
	src/login/uaccess.c

if HAVE_ACL
systemd_uaccess_SOURCES += \
	src/login/logind-acl.c \
	src/acl-util.c
endif

systemd_uaccess_CFLAGS = \
	$(AM_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(ACL_CFLAGS)

systemd_uaccess_LDADD = \
	libsystemd-basic.la \
	libsystemd-daemon.la \
	libsystemd-login.la \
	$(UDEV_LIBS) \
	$(ACL_LIBS)

rootlibexec_PROGRAMS += \
	systemd-uaccess

dist_udevrules_DATA += \
	src/login/70-uaccess.rules

dist_udevrules_DATA += \
	src/login/71-seat.rules

nodist_udevrules_DATA += \
	src/login/73-seat-late.rules

MANPAGES += \
	man/systemd-logind.conf.5 \
	man/sd-login.7 \
	man/systemd-loginctl.1 \
	man/sd_login_monitor_new.3 \
	man/sd_pid_get_session.3 \
	man/sd_uid_get_state.3 \
	man/sd_session_is_active.3 \
	man/sd_seat_get_active.3 \
	man/sd_get_seats.3

MANPAGES_ALIAS += \
	man/sd_login_monitor_unref.3 \
	man/sd_login_monitor_flush.3 \
	man/sd_login_monitor_get_fd.3 \
	man/sd_session_get_uid.3 \
	man/sd_session_get_seat.3 \
	man/sd_session_get_service.3 \
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
	man/sd_get_uids.3

man/sd_login_monitor_unref.3: man/sd_login_monitor_new.3
man/sd_login_monitor_flush.3: man/sd_login_monitor_new.3
man/sd_login_monitor_get_fd.3: man/sd_login_monitor_new.3
man/sd_session_get_uid.3: man/sd_session_is_active.3
man/sd_session_get_seat.3: man/sd_session_is_active.3
man/sd_session_get_service.3: man/sd_session_is_active.3
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

EXTRA_DIST += \
	src/login/logind-gperf.gperf \
	src/login/libsystemd-login.pc.in \
	src/login/libsystemd-login.sym \
	src/login/logind.h \
	src/login/logind-device.h \
	src/login/logind-seat.h \
	src/login/logind-session.h \
	src/login/logind-user.h \
	src/login/logind-acl.h \
	src/login/73-seat-late.rules.in \
	units/systemd-logind.service.in \
	units/systemd-user-sessions.service.in

CLEANFILES += \
	src/login/logind-gperf.c \
	src/login/73-seat-late.rules
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
		-e 's,@pkglibexecdir\@,$(pkglibexecdir),g' \
		-e 's,@systemunitdir\@,$(systemunitdir),g' \
		-e 's,@userunitdir\@,$(userunitdir),g' \
		-e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' \
		-e 's,@PACKAGE_NAME\@,$(PACKAGE_NAME),g' \
		-e 's,@PACKAGE_URL\@,$(PACKAGE_URL),g' \
		-e 's,@prefix\@,$(prefix),g' \
		-e 's,@exec_prefix\@,$(exec_prefix),g' \
		-e 's,@libdir\@,$(libdir),g' \
		-e 's,@includedir\@,$(includedir),g' \
		< $< > $@ || rm $@

units/%: units/%.in Makefile
	$(SED_PROCESS)

man/%: man/%.in Makefile
	$(SED_PROCESS)

sysctl.d/%: sysctl.d/%.in Makefile
	$(SED_PROCESS)

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

src/%.policy.in: src/%.policy.in.in Makefile
	$(SED_PROCESS)

src/%.rules: src/%.rules.in Makefile
	$(SED_PROCESS)

src/%.c: src/%.gperf
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(GPERF) < $< > $@

src/%: src/%.m4
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DEFINES) < $< > $@ || rm $@

src/load-fragment-gperf-nulstr.c: src/load-fragment-gperf.gperf
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(AWK) 'BEGIN{ keywords=0 ; FS="," ; print "extern const char load_fragment_gperf_nulstr[];" ; print "const char load_fragment_gperf_nulstr[] ="} ; keyword==1 { print "\"" $$1 "\\0\"" } ; /%%/ { keyword=1} ; END { print ";" }' < $< > $@ || rm $@

M4_PROCESS_SYSTEM = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DEFINES) -DFOR_SYSTEM=1 < $< > $@ || rm $@

M4_PROCESS_USER = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DEFINES) -DFOR_USER=1 < $< > $@ || rm $@

units/%: units/%.m4 Makefile
	$(M4_PROCESS_SYSTEM)

units/user/%: units/%.m4 Makefile
	$(M4_PROCESS_USER)

CLEANFILES += \
	$(nodist_systemunit_DATA) \
	$(nodist_userunit_DATA) \
	$(nodist_man_MANS) \
	$(pkgconfigdata_DATA) \
	$(pkgconfiglib_DATA) \
	$(nodist_polkitpolicy_DATA) \
	src/load-fragment-gperf.gperf \
	src/load-fragment-gperf.c \
	src/load-fragment-gperf-nulstr.c \
	src/99-systemd.rules

if HAVE_VALAC
CLEANFILES += \
	${systemadm_SOURCES:.vala=.c}
endif

if HAVE_XSLTPROC
XSLTPROC_FLAGS = \
	--nonet \
	--stringparam funcsynopsis.style ansi

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

man/%.html: man/%.xml
	$(XSLTPROC_PROCESS_HTML)

CLEANFILES += \
	$(dist_man_MANS) \
	${XML_FILES:.xml=.html}
endif

DBUS_PREPROCESS = $(CPP) -P $(DBUS_CFLAGS) -imacros dbus/dbus-protocol.h

org.freedesktop.systemd1.%.xml: systemd
	$(AM_V_GEN)$(LIBTOOL) --mode=execute $(OBJCOPY) -O binary -j introspect.$* $< $@.tmp && \
		$(STRINGS) $@.tmp | $(AWK) -f $(srcdir)/introspect.awk | \
		$(DBUS_PREPROCESS) -o $@ - && rm $@.tmp

CLEANFILES += \
	$(dbusinterface_DATA)

systemd-install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(tmpfilesdir) \
		$(DESTDIR)$(sysconfdir)/tmpfiles.d \
		$(DESTDIR)$(prefix)/lib/modules-load.d \
		$(DESTDIR)$(sysconfdir)/modules-load.d \
		$(DESTDIR)$(prefix)/lib/sysctl.d \
		$(DESTDIR)$(sysconfdir)/sysctl.d \
		$(DESTDIR)$(systemshutdowndir) \
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
		rm -f systemd-remount-api-vfs.service \
			fsck-root.service \
			remount-rootfs.service \
			var-run.mount \
			media.mount && \
		$(LN_S) ../systemd-remount-api-vfs.service systemd-remount-api-vfs.service && \
		$(LN_S) ../fsck-root.service fsck-root.service && \
		$(LN_S) ../remount-rootfs.service remount-rootfs.service && \
		$(LN_S) ../var-run.mount var-run.mount && \
		$(LN_S) ../media.mount media.mount )
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
			sys-kernel-security.mount \
			sys-fs-fuse-connections.mount \
			systemd-modules-load.service \
			systemd-tmpfiles-setup.service \
			systemd-sysctl.service \
			systemd-ask-password-console.path && \
		$(LN_S) ../dev-hugepages.mount dev-hugepages.mount && \
		$(LN_S) ../dev-mqueue.mount dev-mqueue.mount && \
		$(LN_S) ../sys-kernel-config.mount sys-kernel-config.mount && \
		$(LN_S) ../sys-kernel-debug.mount sys-kernel-debug.mount && \
		$(LN_S) ../sys-kernel-security.mount sys-kernel-security.mount && \
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
if HAVE_PLYMOUTH
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(SYSTEM_SYSVINIT_PATH) \
		$(DESTDIR)$(systemunitdir)/reboot.target.wants \
		$(DESTDIR)$(systemunitdir)/kexec.target.wants \
		$(DESTDIR)$(systemunitdir)/poweroff.target.wants \
		$(DESTDIR)$(systemunitdir)/halt.target.wants
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f plymouth-start.service plymouth-read-write.service && \
		$(LN_S) ../plymouth-start.service plymouth-start.service && \
		$(LN_S) ../plymouth-read-write.service plymouth-read-write.service )
	( cd $(DESTDIR)$(systemunitdir)/multi-user.target.wants && \
		rm -f plymouth-quit.service plymouth-quit-wait.service && \
		$(LN_S) ../plymouth-quit.service plymouth-quit.service && \
		$(LN_S) ../plymouth-quit-wait.service plymouth-quit-wait.service )
	( cd $(DESTDIR)$(systemunitdir)/reboot.target.wants && \
		rm -f plymouth-reboot.service && \
		$(LN_S) ../plymouth-reboot.service plymouth-reboot.service )
	( cd $(DESTDIR)$(systemunitdir)/kexec.target.wants && \
		rm -f plymouth-kexec.service && \
		$(LN_S) ../plymouth-kexec.service plymouth-kexec.service )
	( cd $(DESTDIR)$(systemunitdir)/poweroff.target.wants && \
		rm -f plymouth-poweroff.service && \
		$(LN_S) ../plymouth-poweroff.service plymouth-poweroff.service )
	( cd $(DESTDIR)$(systemunitdir)/halt.target.wants && \
		rm -f plymouth-halt.service && \
		$(LN_S) ../plymouth-halt.service plymouth-halt.service )
endif
if TARGET_MEEGO
	$(MKDIR_P) -m 0755 $(DESTDIR)$(systemunitdir)/final.target.wants
	( cd $(DESTDIR)$(systemunitdir)/multi-user.target.wants && \
		rm -f network.target && \
		$(LN_S) $(systemunitdir)/network.target network.target )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/sysinit.target.wants && \
		rm -f * )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/local-fs.target.wants && \
		rm -f * )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants && \
		rm -f * )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/getty.target.wants && \
		rm -f * )
endif

if TARGET_FEDORA
	$(MKDIR_P) -m 0755 $(DESTDIR)$(systemunitdir)/final.target.wants
	( cd $(DESTDIR)$(systemunitdir)/final.target.wants && \
		rm -f halt-local.service && \
		$(LN_S) $(systemunitdir)/halt-local.service halt-local.service )
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f display-manager.service single.service && \
		$(LN_S) prefdm.service display-manager.service && \
		$(LN_S) rescue.service single.service )
	( cd $(DESTDIR)$(systemunitdir)/graphical.target.wants && \
		rm -f display-manager.service && \
		$(LN_S) $(systemunitdir)/display-manager.service display-manager.service )
endif

if TARGET_MANDRIVA
	$(MKDIR_P) -m 0755 $(DESTDIR)$(systemunitdir)/final.target.wants
	( cd $(DESTDIR)$(systemunitdir)/final.target.wants && \
		rm -f halt-local.service && \
		$(LN_S) $(systemunitdir)/halt-local.service halt-local.service )
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f display-manager.service dm.service single.service && \
		$(LN_S) prefdm.service display-manager.service && \
		$(LN_S) prefdm.service dm.service && \
		$(LN_S) rescue.service single.service )
	( cd $(DESTDIR)$(systemunitdir)/graphical.target.wants && \
		rm -f display-manager.service && \
		$(LN_S) $(systemunitdir)/display-manager.service display-manager.service )
endif

if TARGET_DEBIAN_OR_UBUNTU
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f runlevel5.target && \
		$(LN_S) multi-user.target runlevel5.target )
endif

if TARGET_SUSE
	$(MKDIR_P) -m 0755 $(DESTDIR)$(systemunitdir)/final.target.wants
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f local.service && \
		$(LN_S) rc-local.service local.service )
	( cd $(DESTDIR)$(systemunitdir)/final.target.wants && \
		rm -f halt-local.service && \
		$(LN_S) $(systemunitdir)/halt-local.service halt-local.service )
endif

if TARGET_MAGEIA
	$(MKDIR_P) -m 0755 $(DESTDIR)$(systemunitdir)/final.target.wants
	( cd $(DESTDIR)$(systemunitdir)/final.target.wants && \
		rm -f halt-local.service && \
		$(LN_S) $(systemunitdir)/halt-local.service halt-local.service )
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f display-manager.service && \
		$(LN_S) prefdm.service display-manager.service && \
		$(LN_S) prefdm.service dm.service )
	( cd $(DESTDIR)$(systemunitdir)/graphical.target.wants && \
		rm -f display-manager.service && \
		$(LN_S) $(systemunitdir)/display-manager.service display-manager.service )
endif

if HAVE_SYSV_COMPAT
	( cd $(DESTDIR)$(systemunitdir)/local-fs.target.wants && \
		rm -f var-lock.mount && \
		$(LN_S) ../var-lock.mount var-lock.mount )
endif

install-exec-hook: $(INSTALL_EXEC_HOOKS)

uninstall-hook: $(UNINSTALL_EXEC_HOOKS)

install-data-hook: systemd-install-data-hook $(INSTALL_DATA_HOOKS)

DISTCHECK_CONFIGURE_FLAGS = \
	--with-dbuspolicydir=$$dc_install_base/$(dbuspolicydir) \
	--with-dbussessionservicedir=$$dc_install_base/$(dbussessionservicedir) \
	--with-dbussystemservicedir=$$dc_install_base/$(dbussystemservicedir) \
	--with-dbusinterfacedir=$$dc_install_base/$(dbusinterfacedir) \
	--with-udevrulesdir=$$dc_install_base/$(udevrulesdir) \
	--with-pamlibdir=$$dc_install_base/$(pamlibdir) \
        --with-rootprefix=$$dc_install_base \
        --disable-split-usr

upload: all distcheck
	cp -v systemd-$(VERSION).tar.xz /home/lennart/git.fedora/systemd/
	scp systemd-$(VERSION).tar.xz fdo:/srv/www.freedesktop.org/www/software/systemd/
	scp man/*.html fdo:/srv/www.freedesktop.org/www/software/systemd/man/
	scp man/*.html tango:public/systemd-man/

git-tag:
	git tag "v$(VERSION)" -m "systemd $(VERSION)"
