#  This file is part of systemd.
#
#  Copyright 2010 Lennart Poettering
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

# Dirs of external packages
dbuspolicydir=@dbuspolicydir@
dbussessionservicedir=@dbussessionservicedir@
dbussystemservicedir=@dbussystemservicedir@
dbusinterfacedir=@dbusinterfacedir@
udevrulesdir=@udevrulesdir@
pamlibdir=@pamlibdir@
pkgconfigdatadir=$(datadir)/pkgconfig
polkitpolicydir=$(datadir)/polkit-1/actions
bashcompletiondir=$(sysconfdir)/bash_completion.d

# Our own, non-special dirs
pkgsysconfdir=$(sysconfdir)/systemd
userunitdir=$(pkgdatadir)/user
tmpfilesdir=$(sysconfdir)/tmpfiles.d
usergeneratordir=$(pkglibexecdir)/user-generators

# And these are the special ones for /
rootdir=@rootdir@
rootbindir=$(rootdir)/bin
rootsbindir=$(rootdir)/sbin
rootlibexecdir=$(rootdir)/lib/systemd
systemunitdir=$(rootdir)/lib/systemd/system
systemgeneratordir=$(rootdir)/lib/systemd/system-generators

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
	-DSYSTEMD_BINARY_PATH=\"$(rootbindir)/systemd\" \
	-DSYSTEMD_SHUTDOWN_BINARY_PATH=\"$(rootlibexecdir)/systemd-shutdown\" \
	-DSYSTEMCTL_BINARY_PATH=\"$(rootbindir)/systemctl\" \
	-DSYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH=\"$(rootbindir)/systemd-tty-ask-password-agent\" \
	-DRUNTIME_DIR=\"$(localstatedir)/run\" \
	-DRANDOM_SEED=\"$(localstatedir)/lib/random-seed\" \
	-DSYSTEMD_CRYPTSETUP_PATH=\"$(rootlibexecdir)/systemd-cryptsetup\" \
	-DSYSTEM_GENERATOR_PATH=\"$(systemgeneratordir)\" \
	-DUSER_GENERATOR_PATH=\"$(usergeneratordir)\" \
	-I $(top_srcdir)/src

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
AM_CPPFLAGS += \
	-DKBD_LOADKEYS=\"/bin/loadkeys\" \
	-DKBD_SETFONT=\"/bin/setfont\" \
	-DDEFAULT_FONT=\"latarcyrheb-sun16\"
endif
endif

rootbin_PROGRAMS = \
	systemd \
	systemctl \
	systemd-notify \
	systemd-ask-password \
	systemd-tty-ask-password-agent

bin_PROGRAMS = \
	systemd-cgls

if HAVE_GTK
bin_PROGRAMS += \
	systemadm \
	systemd-gnome-ask-password-agent
endif

rootlibexec_PROGRAMS = \
	systemd-logger \
	systemd-cgroups-agent \
	systemd-initctl \
	systemd-update-utmp \
	systemd-random-seed \
	systemd-shutdownd \
	systemd-shutdown \
	systemd-modules-load \
	systemd-remount-api-vfs \
	systemd-kmsg-syslogd \
	systemd-vconsole-setup \
	systemd-reply-password \
	systemd-readahead-collect \
	systemd-readahead-replay \
	systemd-tmpfiles \
	systemd-user-sessions \
	systemd-fsck \
	systemd-quotacheck \
	systemd-timestamp \
	systemd-ac-power \
	systemd-sysctl

if HAVE_LIBCRYPTSETUP
rootlibexec_PROGRAMS += \
	systemd-cryptsetup

systemgenerator_PROGRAMS = \
	systemd-cryptsetup-generator
endif

noinst_PROGRAMS = \
	test-engine \
	test-job-type \
	test-ns \
	test-loopback \
	test-hostname \
	test-daemon \
	test-cgroup \
	test-env-replace \
	test-strv

if HAVE_PAM
pamlib_LTLIBRARIES = \
	pam_systemd.la
endif

dist_pkgsysconf_DATA = \
	src/system.conf

dist_dbuspolicy_DATA = \
	src/org.freedesktop.systemd1.conf

dist_dbussystemservice_DATA = \
	src/org.freedesktop.systemd1.service

dist_udevrules_DATA = \
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
        src/systemctl-bash-completion.sh

dist_tmpfiles_DATA = \
	tmpfiles.d/systemd.conf \
	tmpfiles.d/x11.conf

dist_systemunit_DATA = \
	units/emergency.service \
	units/emergency.target \
	units/sysinit.target \
	units/basic.target \
	units/getty.target \
	units/halt.target \
	units/kexec.target \
	units/local-fs.target \
	units/cryptsetup.target \
	units/network.target \
	units/nss-lookup.target \
	units/mail-transfer-agent.target \
	units/http-daemon.target \
	units/poweroff.target \
	units/reboot.target \
	units/rescue.target \
	units/rpcbind.target \
	units/rtc-set.target \
	units/shutdown.target \
	units/final.target \
	units/umount.target \
	units/sigpwr.target \
	units/sockets.target \
	units/swap.target \
	units/dbus.target \
	units/systemd-initctl.socket \
	units/systemd-logger.socket \
	units/systemd-shutdownd.socket \
	units/syslog.socket \
	units/dev-hugepages.automount \
	units/dev-hugepages.mount \
	units/dev-mqueue.automount \
	units/dev-mqueue.mount \
	units/proc-sys-fs-binfmt_misc.automount \
	units/proc-sys-fs-binfmt_misc.mount \
	units/sys-kernel-debug.automount \
	units/sys-kernel-debug.mount \
	units/sys-kernel-security.automount \
	units/sys-kernel-security.mount \
	units/var-lock.mount \
	units/var-run.mount \
	units/hwclock-load.service \
	units/hwclock-save.service \
	units/remount-rootfs.service \
	units/printer.target \
	units/bluetooth.target \
	units/smartcard.target \
	units/systemd-readahead-done.timer \
	units/systemd-tmpfiles-clean.timer \
	units/quotaon.service \
	units/systemd-ask-password-wall.path \
	units/systemd-ask-password-plymouth.path \
	units/systemd-ask-password-console.path

nodist_systemunit_DATA = \
	units/getty@.service \
	units/serial-getty@.service \
	units/graphical.target \
	units/remote-fs.target \
	units/multi-user.target \
	units/systemd-initctl.service \
	units/systemd-logger.service \
	units/systemd-shutdownd.service \
	units/systemd-kmsg-syslogd.service \
	units/systemd-modules-load.service \
	units/systemd-vconsole-setup.service \
	units/systemd-remount-api-vfs.service \
	units/systemd-update-utmp-runlevel.service \
	units/systemd-update-utmp-shutdown.service \
	units/systemd-random-seed-save.service \
	units/systemd-random-seed-load.service \
	units/systemd-readahead-collect.service \
	units/systemd-readahead-replay.service \
	units/systemd-readahead-done.service \
	units/systemd-tmpfiles-setup.service \
	units/systemd-tmpfiles-clean.service \
	units/systemd-user-sessions.service \
	units/systemd-ask-password-wall.service \
	units/systemd-ask-password-plymouth.service \
	units/systemd-ask-password-console.service \
	units/systemd-sysctl.service \
	units/syslog.target \
	units/halt.service \
	units/poweroff.service \
	units/reboot.service \
	units/kexec.service \
	units/fsck@.service \
	units/fsck-root.service \
	units/quotacheck.service \
	units/rescue.service

dist_userunit_DATA = \
	units/user/default.target \
	units/user/exit.target

nodist_userunit_DATA = \
	units/user/remote-fs.target \
	units/user/exit.service

EXTRA_DIST = \
	units/getty@.service.m4 \
	units/serial-getty@.service.m4 \
	units/graphical.target.m4 \
	units/multi-user.target.m4 \
	units/remote-fs.target.m4 \
	units/rescue.service.m4 \
	units/systemd-initctl.service.in \
	units/systemd-logger.service.in \
	units/systemd-shutdownd.service.in \
	units/systemd-kmsg-syslogd.service.in \
	units/systemd-modules-load.service.in \
	units/systemd-vconsole-setup.service.in \
	units/systemd-remount-api-vfs.service.in \
	units/systemd-update-utmp-runlevel.service.in \
	units/systemd-update-utmp-shutdown.service.in \
	units/systemd-random-seed-save.service.in \
	units/systemd-random-seed-load.service.in \
	units/systemd-readahead-collect.service.in \
	units/systemd-readahead-replay.service.in \
	units/systemd-readahead-done.service.in \
	units/systemd-tmpfiles-setup.service.in \
	units/systemd-tmpfiles-clean.service.in \
	units/systemd-user-sessions.service.in \
	units/systemd-ask-password-wall.service.in \
	units/systemd-ask-password-plymouth.service.in \
	units/systemd-ask-password-console.service.in \
	units/systemd-sysctl.service.in \
	units/syslog.target.in \
	units/halt.service.in \
	units/poweroff.service.in \
	units/reboot.service.in \
	units/kexec.service.in \
	units/user/exit.service.in \
	units/fsck@.service.in \
	units/fsck-root.service.in \
	units/quotacheck.service.in \
	systemd.pc.in \
	introspect.awk

if TARGET_FEDORA
dist_systemunit_DATA += \
	units/fedora/prefdm.service \
	units/fedora/rc-local.service \
	units/fedora/halt-local.service \
	units/fedora/plymouth-start.service \
	units/fedora/plymouth-read-write.service \
	units/fedora/plymouth-quit.service \
	units/fedora/plymouth-reboot.service \
	units/fedora/plymouth-kexec.service \
	units/fedora/plymouth-poweroff.service \
	units/fedora/plymouth-halt.service
endif


if TARGET_ARCH
dist_systemunit_DATA += \
	units/arch/rc-local.service
endif

dist_doc_DATA = \
	README \
	LICENSE \
	DISTRO_PORTING \
	src/sd-daemon.h \
	src/sd-daemon.c \
	src/sd-readahead.h \
	src/sd-readahead.c

pkgconfigdata_DATA = \
	systemd.pc

dist_polkitpolicy_DATA = \
	src/org.freedesktop.systemd1.policy

noinst_LTLIBRARIES = \
	libsystemd-basic.la \
	libsystemd-core.la

libsystemd_basic_la_SOURCES = \
	src/util.c \
	src/label.c \
	src/hashmap.c \
	src/set.c \
	src/strv.c \
	src/conf-parser.c \
	src/socket-util.c \
	src/log.c \
	src/ratelimit.c

libsystemd_basic_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(SELINUX_CFLAGS)

libsystemd_basic_la_LIBADD = \
	$(SELINUX_LIBS)

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
	src/exit-status.c \
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
	src/specifier.c \
	src/unit-name.c \
	src/fdset.c \
	src/namespace.c \
	src/tcpwrap.c \
	src/cgroup-util.c \
	src/condition.c

libsystemd_core_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(LIBWRAP_CFLAGS) \
	$(PAM_CFLAGS) \
	$(AUDIT_CFLAGS)

libsystemd_core_la_LIBADD = \
	libsystemd-basic.la \
	$(DBUS_LIBS) \
	$(UDEV_LIBS) \
	$(LIBWRAP_LIBS) \
	$(PAM_LIBS) \
	$(AUDIT_LIBS)

# This is needed because automake is buggy in how it generates the
# rules for C programs, but not Vala programs.  We therefore can't
# list the .h files as dependencies if we want make dist to work.

EXTRA_DIST += \
	${libsystemd_basic_la_SOURCES:.c=.h} \
	${libsystemd_core_la_SOURCES:.c=.h} \
	src/macro.h \
	src/ioprio.h \
	src/missing.h \
	src/list.h \
	src/securebits.h \
	src/linux/auto_dev-ioctl.h \
	src/linux/fanotify.h \
	src/initreq.h \
	src/sd-daemon.h \
	src/sd-readahead.h \
	src/special.h \
	src/dbus-common.h \
	src/bus-errors.h \
	src/cgroup-show.h \
	src/build.h \
	src/shutdownd.h \
	src/umount.h \
	src/readahead-common.h \
	src/ask-password-api.h

MANPAGES = \
	man/systemd.1 \
	man/systemctl.1 \
	man/systemadm.1 \
	man/systemd-cgls.1 \
	man/systemd-notify.1 \
	man/sd_notify.3 \
	man/sd_readahead.3 \
	man/sd_booted.3 \
	man/sd_listen_fds.3 \
	man/sd_is_fifo.3 \
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
	man/daemon.7 \
	man/sd-daemon.7 \
	man/sd-readahead.7 \
	man/runlevel.8 \
	man/telinit.8 \
	man/halt.8 \
	man/shutdown.8 \
	man/pam_systemd.8 \
	man/systemd.conf.5 \
	man/tmpfiles.d.5 \
	man/hostname.5 \
	man/vconsole.conf.5 \
	man/locale.conf.5 \
	man/os-release.5 \
	man/modules-load.d.5

MANPAGES_ALIAS = \
	man/reboot.8 \
	man/poweroff.8 \
	man/sd_is_socket.3 \
	man/sd_is_socket_unix.3 \
	man/sd_is_socket_inet.3 \
	man/sd_notifyf.3 \
	man/init.1

man/reboot.8: man/halt.8
man/poweroff.8: man/halt.8
man/sd_is_socket.3: man/sd_is_fifo.3
man/sd_is_socket_unix.3: man/sd_is_fifo.3
man/sd_is_socket_inet.3: man/sd_is_fifo.3
man/sd_notifyf.3: man/sd_notify.3
man/init.1: man/systemd.1

dist_man_MANS = \
	$(MANPAGES) \
	$(MANPAGES_ALIAS)

nodist_man_MANS = \
	man/systemd.special.7

XML_FILES = \
	${patsubst %.1,%.xml,${patsubst %.3,%.xml,${patsubst %.5,%.xml,${patsubst %.7,%.xml,${patsubst %.8,%.xml,$(MANPAGES)}}}}}

XML_IN_FILES = \
	${patsubst %.1,%.xml.in,${patsubst %.3,%.xml.in,${patsubst %.5,%.xml.in,${patsubst %.7,%.xml.in,${patsubst %.8,%.xml.in,$(nodist_man_MANS)}}}}}

dist_noinst_DATA = \
	${XML_FILES:.xml=.html}

nodist_noinst_DATA = \
	${XML_IN_FILES:.xml.in=.html}

EXTRA_DIST += \
	$(XML_FILES) \
	$(XML_IN_FILES) \
	${nodist_man_MANS:=.in} \
	${XML_IN_FILES:.xml.in=.html.in}

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
	src/test-daemon.c \
	src/sd-daemon.c

test_daemon_LDADD = \
	libsystemd-basic.la

test_cgroup_SOURCES = \
	src/test-cgroup.c \
	src/cgroup-util.c

test_cgroup_CFLAGS = \
	$(AM_CFLAGS)

test_cgroup_LDADD = \
	libsystemd-basic.la

test_env_replace_SOURCES = \
	src/test-env-replace.c

test_env_replace_CFLAGS = \
	$(AM_CFLAGS)

test_env_replace_LDADD = \
	libsystemd-basic.la

test_strv_SOURCES = \
	src/test-strv.c

test_strv_CFLAGS = \
	$(AM_CFLAGS)

test_strv_LDADD = \
	libsystemd-basic.la

systemd_logger_SOURCES = \
	src/logger.c \
	src/sd-daemon.c \
	src/tcpwrap.c

systemd_logger_LDADD = \
	libsystemd-basic.la \
	$(LIBWRAP_LIBS)

systemd_initctl_SOURCES = \
	src/initctl.c \
	src/sd-daemon.c \
	src/dbus-common.c

systemd_initctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemd_initctl_LDADD = \
	libsystemd-basic.la \
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

systemd_random_seed_SOURCES = \
	src/random-seed.c

systemd_random_seed_CFLAGS = \
	$(AM_CFLAGS)

systemd_random_seed_LDADD = \
	libsystemd-basic.la

systemd_shutdownd_SOURCES = \
	src/utmp-wtmp.c \
	src/sd-daemon.c \
	src/shutdownd.c

systemd_shutdownd_CFLAGS = \
	$(AM_CFLAGS)

systemd_shutdownd_LDADD = \
	libsystemd-basic.la

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
	$(AM_CFLAGS)

systemd_modules_load_LDADD = \
	libsystemd-basic.la

systemd_tmpfiles_SOURCES = \
	src/tmpfiles.c

systemd_tmpfiles_CFLAGS = \
	$(AM_CFLAGS)

systemd_tmpfiles_LDADD = \
	libsystemd-basic.la

systemd_sysctl_SOURCES = \
	src/sysctl.c

systemd_sysctl_CFLAGS = \
	$(AM_CFLAGS)

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

systemd_quotacheck_SOURCES = \
	src/quotacheck.c

systemd_quotacheck_CFLAGS = \
	$(AM_CFLAGS)

systemd_quotacheck_LDADD = \
	libsystemd-basic.la

systemd_timestamp_SOURCES = \
	src/timestamp.c

systemd_timestamp_CFLAGS = \
	$(AM_CFLAGS)

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

systemd_cryptsetup_SOURCES = \
	src/cryptsetup.c \
	src/ask-password-api.c

systemd_cryptsetup_CFLAGS = \
	$(LIBCRYPTSETUP_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(AM_CFLAGS)

systemd_cryptsetup_LDADD = \
	$(LIBCRYPTSETUP_LIBS) \
	$(UDEV_LIBS) \
	libsystemd-basic.la

systemd_cryptsetup_generator_SOURCES = \
	src/cryptsetup-generator.c \
	src/unit-name.c

systemd_cryptsetup_generator_CFLAGS = \
	$(AM_CFLAGS)

systemd_cryptsetup_generator_LDADD = \
	libsystemd-basic.la

systemd_user_sessions_SOURCES = \
	src/user-sessions.c \
	src/cgroup-util.c

systemd_user_sessions_CFLAGS = \
	$(AM_CFLAGS)

systemd_user_sessions_LDADD = \
	libsystemd-basic.la

systemd_vconsole_setup_SOURCES = \
	src/vconsole-setup.c

systemd_vconsole_setup_CFLAGS = \
	$(AM_CFLAGS)

systemd_vconsole_setup_LDADD = \
	libsystemd-basic.la

systemd_remount_api_vfs_SOURCES = \
	src/remount-api-vfs.c \
	src/mount-setup.c

systemd_remount_api_vfs_CFLAGS = \
	$(AM_CFLAGS)

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

systemd_kmsg_syslogd_SOURCES = \
	src/kmsg-syslogd.c \
	src/sd-daemon.c \
	src/fdset.c

systemd_kmsg_syslogd_CFLAGS = \
	$(AM_CFLAGS)

systemd_kmsg_syslogd_LDADD = \
	libsystemd-basic.la

systemctl_SOURCES = \
	src/systemctl.c \
	src/utmp-wtmp.c \
	src/dbus-common.c \
	src/path-lookup.c \
	src/sd-daemon.c \
	src/cgroup-show.c \
	src/cgroup-util.c \
	src/exit-status.c \
	src/unit-name.c

systemctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemctl_LDADD = \
	libsystemd-basic.la \
	$(DBUS_LIBS)

systemd_notify_SOURCES = \
	src/notify.c \
	src/sd-daemon.c \
	src/sd-readahead.c

systemd_notify_LDADD = \
	libsystemd-basic.la

systemd_ask_password_SOURCES = \
	src/ask-password.c \
	src/ask-password-api.c

systemd_ask_password_LDADD = \
	libsystemd-basic.la

systemd_reply_password_SOURCES = \
	src/reply-password.c

systemd_reply_password_LDADD = \
	libsystemd-basic.la

systemd_readahead_collect_SOURCES = \
	src/readahead-collect.c \
	src/sd-daemon.c \
	src/readahead-common.c

systemd_readahead_collect_CFLAGS = \
	$(UDEV_CFLAGS)

systemd_readahead_collect_LDADD = \
	libsystemd-basic.la \
	$(UDEV_LIBS)

systemd_readahead_replay_SOURCES = \
	src/readahead-replay.c \
	src/sd-daemon.c \
	src/readahead-common.c

systemd_readahead_replay_CFLAGS = \
	$(UDEV_CFLAGS)

systemd_readahead_replay_LDADD = \
	libsystemd-basic.la \
	$(UDEV_LIBS)

systemd_cgls_SOURCES = \
	src/cgls.c \
	src/cgroup-show.c \
	src/cgroup-util.c

systemd_cgls_CFLAGS = \
	$(AM_CFLAGS)

systemd_cgls_LDADD = \
	libsystemd-basic.la

systemadm_SOURCES = \
	src/systemadm.vala \
	src/systemd-interfaces.vala

systemadm_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUSGLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	-Wno-unused-variable \
	-Wno-unused-function \
	-Wno-shadow \
	-Wno-format-nonliteral

systemadm_VALAFLAGS = \
	--pkg=dbus-glib-1 \
	--pkg=posix \
	--pkg=gtk+-2.0 \
	-g

systemadm_LDADD = \
	$(DBUSGLIB_LIBS) \
	$(GTK_LIBS)

systemd_gnome_ask_password_agent_SOURCES = \
	src/gnome-ask-password-agent.vala

systemd_gnome_ask_password_agent_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUSGLIB_CFLAGS) \
	$(LIBNOTIFY_CFLAGS) \
	$(GTK_CFLAGS) \
	-Wno-unused-variable \
	-Wno-unused-function \
	-Wno-shadow \
	-Wno-format-nonliteral

systemd_gnome_ask_password_agent_VALAFLAGS = \
	--pkg=dbus-glib-1 \
	--pkg=posix \
	--pkg=gtk+-2.0 \
	--pkg=linux \
	--pkg=gio-unix-2.0 \
	--pkg=libnotify \
	-g

systemd_gnome_ask_password_agent_LDADD = \
	$(DBUSGLIB_LIBS) \
	$(LIBNOTIFY_LIBS) \
	$(GTK_LIBS)

systemd_tty_ask_password_agent_SOURCES = \
	src/tty-ask-password-agent.c \
	src/ask-password-api.c \
	src/utmp-wtmp.c

systemd_tty_ask_password_agent_LDADD = \
	libsystemd-basic.la

pam_systemd_la_SOURCES = \
	src/pam-module.c \
	src/cgroup-util.c \
	src/sd-daemon.c

pam_systemd_la_CFLAGS = \
	$(AM_CFLAGS)
	-fvisibility=hidden

pam_systemd_la_LDFLAGS = \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-export-symbols-regex '^pam_sm_.*'

pam_systemd_la_LIBADD = \
	libsystemd-basic.la \
	$(PAM_LIBS)

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED)  -e 's,@rootlibexecdir\@,$(rootlibexecdir),g' \
                -e 's,@rootbindir\@,$(rootbindir),g' \
		-e 's,@SPECIAL_SYSLOG_SERVICE\@,$(SPECIAL_SYSLOG_SERVICE),g' \
		-e 's,@SYSTEMCTL\@,$(rootbindir)/systemctl,g' \
		-e 's,@SYSTEMD_NOTIFY\@,$(rootbindir)/systemd-notify,g' \
		-e 's,@pkgsysconfdir\@,$(pkgsysconfdir),g' \
		-e 's,@pkgdatadir\@,$(pkgdatadir),g' \
		-e 's,@systemunitdir\@,$(systemunitdir),g' \
		-e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' \
		-e 's,@PACKAGE_NAME\@,$(PACKAGE_NAME),g' \
		-e 's,@PACKAGE_URL\@,$(PACKAGE_URL),g' \
		-e 's,@prefix\@,$(prefix),g' \
		< $< > $@ || rm $@

units/%: units/%.in Makefile
	$(SED_PROCESS)

man/%: man/%.in Makefile
	$(SED_PROCESS)

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

M4_PROCESS_SYSTEM = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DISTRO_FLAG) -DFOR_SYSTEM=1 < $< > $@ || rm $@

M4_PROCESS_USER = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DISTRO_FLAG) -DFOR_USER=1 < $< > $@ || rm $@

units/%: units/%.m4 Makefile
	$(M4_PROCESS_SYSTEM)

units/user/%: units/%.m4 Makefile
	$(M4_PROCESS_USER)

CLEANFILES = \
	$(nodist_systemunit_DATA) \
	$(nodist_userunit_DATA) \
	$(nodist_man_MANS) \
	${XML_IN_FILES:.xml.in=.html} \
	$(pkgconfigdata_DATA)

if HAVE_VALAC
CLEANFILES += \
	${systemadm_SOURCES:.vala=.c}
endif

if HAVE_XSLTPROC
XSLTPROC_FLAGS = \
	--nonet \
	--param funcsynopsis.style "'ansi'"

XSLTPROC_PROCESS_MAN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

XSLTPROC_PROCESS_MAN_IN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o ${@:.in=} $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $< && \
	mv ${@:.in=} $@

XSLTPROC_PROCESS_HTML = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

XSLTPROC_PROCESS_HTML_IN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o ${@:.in=} $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $< && \
	mv ${@:.in=} $@

man/%.1: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.1.in: man/%.xml.in
	$(XSLTPROC_PROCESS_MAN)

man/%.3: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.3.in: man/%.xml.in
	$(XSLTPROC_PROCESS_MAN)

man/%.5: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.5.in: man/%.xml.in
	$(XSLTPROC_PROCESS_MAN)

man/%.7: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.7.in: man/%.xml.in
	$(XSLTPROC_PROCESS_MAN_IN)

man/%.8: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.8.in: man/%.xml.in
	$(XSLTPROC_PROCESS_MAN_IN)

man/%.html: man/%.xml
	$(XSLTPROC_PROCESS_HTML)

man/%.html.in: man/%.xml.in
	$(XSLTPROC_PROCESS_HTML_IN)

CLEANFILES += \
	$(dist_man_MANS) \
	${nodist_man_MANS:=.in} \
	${XML_FILES:.xml=.html} \
	${XML_IN_FILES:.xml.in=.html.in}
endif

DBUS_PREPROCESS = $(CPP) -P $(DBUS_CFLAGS) -imacros dbus/dbus-protocol.h

org.freedesktop.systemd1.%.xml: systemd
	$(AM_V_GEN)$(OBJCOPY) -O binary -j introspect.$* $< $@.tmp && \
		$(STRINGS) $@.tmp | $(AWK) -f $(srcdir)/introspect.awk | \
		$(DBUS_PREPROCESS) -o $@ - && rm $@.tmp

CLEANFILES += \
	$(dbusinterface_DATA)

install-data-hook:
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
		$(DESTDIR)$(sysconfdir)/xdg/systemd
	( cd $(DESTDIR)$(sysconfdir)/xdg/systemd/ && \
		rm -f user && \
		$(LN_S) $(pkgsysconfdir)/user user )
	( cd $(DESTDIR)$(systemunitdir)/sockets.target.wants && \
		rm -f systemd-initctl.socket systemd-logger.socket systemd-shutdownd.socket syslog.socket && \
		$(LN_S) ../systemd-logger.socket systemd-logger.socket && \
		$(LN_S) ../systemd-initctl.socket systemd-initctl.socket && \
		$(LN_S) ../systemd-shutdownd.socket systemd-shutdownd.socket && \
		$(LN_S) ../syslog.socket syslog.socket )
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
		rm -f systemd-update-utmp-shutdown.service \
			hwclock-save.service \
			systemd-random-seed-save.service && \
		$(LN_S) ../systemd-update-utmp-shutdown.service systemd-update-utmp-shutdown.service && \
		$(LN_S) ../hwclock-save.service hwclock-save.service && \
		$(LN_S) ../systemd-random-seed-save.service systemd-random-seed-save.service )
	( cd $(DESTDIR)$(systemunitdir)/local-fs.target.wants && \
		rm -f systemd-remount-api-vfs.service \
			fsck-root.service \
			remount-rootfs.service \
			var-run.mount \
			var-lock.mount \
			cryptsetup.target && \
		$(LN_S) ../systemd-remount-api-vfs.service systemd-remount-api-vfs.service && \
		$(LN_S) ../fsck-root.service fsck-root.service && \
		$(LN_S) ../remount-rootfs.service remount-rootfs.service && \
		$(LN_S) ../var-run.mount var-run.mount && \
		$(LN_S) ../var-lock.mount var-lock.mount && \
		$(LN_S) ../cryptsetup.target )
	( cd $(DESTDIR)$(userunitdir) && \
		rm -f shutdown.target sockets.target local-fs.target swap.target bluetooth.target printer.target && \
		$(LN_S) $(systemunitdir)/shutdown.target shutdown.target && \
		$(LN_S) $(systemunitdir)/sockets.target sockets.target && \
		$(LN_S) $(systemunitdir)/local-fs.target local-fs.target && \
		$(LN_S) $(systemunitdir)/swap.target swap.target && \
		$(LN_S) $(systemunitdir)/bluetooth.target bluetooth.target && \
		$(LN_S) $(systemunitdir)/printer.target printer.target)
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
		rm -f default.target ctrl-alt-del.target && \
		$(LN_S) graphical.target default.target && \
		$(LN_S) reboot.target ctrl-alt-del.target )
	( cd $(DESTDIR)$(systemunitdir)/multi-user.target.wants && \
		rm -f getty.target systemd-user-sessions.service systemd-ask-password-wall.path && \
		$(LN_S) ../getty.target getty.target && \
		$(LN_S) ../systemd-user-sessions.service systemd-user-sessions.service && \
		$(LN_S) ../systemd-ask-password-wall.path systemd-ask-password-wall.path )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/getty.target.wants && \
		rm -f getty@tty1.service getty@tty2.service getty@tty3.service getty@tty4.service getty@tty5.service getty@tty6.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty1.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty2.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty3.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty4.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty5.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty6.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/local-fs.target.wants && \
		rm -f quotaon.service quotacheck.service && \
		$(LN_S) $(systemunitdir)/quotacheck.service quotacheck.service && \
		$(LN_S) $(systemunitdir)/quotaon.service quotaon.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants && \
		rm -f remote-fs.target && \
		$(LN_S) $(systemunitdir)/remote-fs.target remote-fs.target )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/sysinit.target.wants && \
		rm -f hwclock-load.service && \
		$(LN_S) $(systemunitdir)/hwclock-load.service hwclock-load.service )
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f dev-hugepages.automount \
			dev-mqueue.automount \
			proc-sys-fs-binfmt_misc.automount \
			sys-kernel-debug.automount \
			sys-kernel-security.automount \
			systemd-vconsole-setup.service \
			systemd-modules-load.service \
			systemd-random-seed-load.service \
			systemd-tmpfiles-setup.service \
			systemd-sysctl.service \
			systemd-ask-password-console.path && \
		$(LN_S) ../dev-hugepages.automount dev-hugepages.automount && \
		$(LN_S) ../dev-mqueue.automount dev-mqueue.automount && \
		$(LN_S) ../proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.automount && \
		$(LN_S) ../sys-kernel-debug.automount sys-kernel-debug.automount && \
		$(LN_S) ../sys-kernel-security.automount sys-kernel-security.automount && \
		$(LN_S) ../systemd-vconsole-setup.service systemd-vconsole-setup.service && \
		$(LN_S) ../systemd-modules-load.service systemd-modules-load.service && \
		$(LN_S) ../systemd-random-seed-load.service systemd-random-seed-load.service && \
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
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(SYSTEM_SYSVINIT_PATH) \
		$(DESTDIR)$(systemunitdir)/reboot.target.wants \
		$(DESTDIR)$(systemunitdir)/kexec.target.wants \
		$(DESTDIR)$(systemunitdir)/poweroff.target.wants \
		$(DESTDIR)$(systemunitdir)/halt.target.wants \
		$(DESTDIR)$(systemunitdir)/final.target.wants
	( cd $(DESTDIR)$(systemunitdir)/multi-user.target.wants && \
		rm -f rc-local.service && \
		$(LN_S) $(systemunitdir)/rc-local.service rc-local.service )
	( cd $(DESTDIR)$(systemunitdir)/final.target.wants && \
		rm -f halt-local.service && \
		$(LN_S) $(systemunitdir)/halt-local.service halt-local.service )
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f plymouth-start.service plymouth-read-write.service && \
		$(LN_S) ../plymouth-start.service plymouth-start.service && \
		$(LN_S) ../plymouth-read-write.service plymouth-read-write.service )
	( cd $(DESTDIR)$(systemunitdir)/multi-user.target.wants && \
		rm -f plymouth-quit.service  && \
		$(LN_S) ../plymouth-quit.service plymouth-quit.service )
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
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f display-manager.service && \
		$(LN_S) prefdm.service display-manager.service )
	( cd $(DESTDIR)$(systemunitdir)/graphical.target.wants && \
		rm -f display-manager.service && \
		$(LN_S) $(systemunitdir)/display-manager.service display-manager.service )
endif
if TARGET_DEBIAN_OR_UBUNTU
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f runlevel5.target && \
		$(LN_S) multi-user.target runlevel5.target )
endif

DISTCHECK_CONFIGURE_FLAGS = \
	--with-dbuspolicydir=$$dc_install_base/$(dbuspolicydir) \
	--with-dbussessionservicedir=$$dc_install_base/$(dbussessionservicedir) \
	--with-dbussystemservicedir=$$dc_install_base/$(dbussystemservicedir) \
	--with-dbusinterfacedir=$$dc_install_base/$(dbusinterfacedir) \
	--with-udevrulesdir=$$dc_install_base/$(udevrulesdir) \
	--with-pamlibdir=$$dc_install_base/$(pamlibdir) \
	--with-rootdir=$$dc_install_base/$(rootdir)

upload: all distcheck
	cp -v systemd-$(VERSION).tar.bz2 /home/lennart/git.fedora/systemd/
	scp systemd-$(VERSION).tar.bz2 fdo:/srv/www.freedesktop.org/www/software/systemd/
	scp man/*.html tango:public/systemd-man/

git-tag:
	git tag "v$(VERSION)" -m "systemd $(VERSION)"
