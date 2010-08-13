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

# Our own, non-special dirs
pkgsysconfdir=$(sysconfdir)/systemd
sessionunitdir=$(pkgdatadir)/session

# And these are the special ones for /
rootdir=@rootdir@
rootbindir=$(rootdir)/bin
rootlibexecdir=$(rootdir)/lib/systemd
systemunitdir=$(rootdir)/lib/systemd/system

AM_CPPFLAGS = \
        -include $(top_builddir)/config.h \
	-DSYSTEM_CONFIG_FILE=\"$(pkgsysconfdir)/system.conf\" \
	-DSYSTEM_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/system\" \
	-DSYSTEM_DATA_UNIT_PATH=\"$(systemunitdir)\" \
	-DSYSTEM_SYSVINIT_PATH=\"$(SYSTEM_SYSVINIT_PATH)\" \
	-DSYSTEM_SYSVRCND_PATH=\"$(SYSTEM_SYSVRCND_PATH)\" \
	-DSESSION_CONFIG_FILE=\"$(pkgsysconfdir)/session.conf\" \
	-DSESSION_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/session\" \
	-DSESSION_DATA_UNIT_PATH=\"$(sessionunitdir)\" \
	-DCGROUP_AGENT_PATH=\"$(rootlibexecdir)/systemd-cgroups-agent\" \
	-DSYSTEMD_BINARY_PATH=\"$(rootbindir)/systemd\" \
	-DSYSTEMCTL_BINARY_PATH=\"$(rootbindir)/systemctl\" \
	-DRUNTIME_DIR=\"$(localstatedir)/run\" \
	-I $(top_srcdir)/src

rootbin_PROGRAMS = \
	systemd \
	systemctl \
	systemd-notify

bin_PROGRAMS = \
	systemd-cgls

if HAVE_GTK
bin_PROGRAMS += \
	systemadm
endif

rootlibexec_PROGRAMS = \
	systemd-logger \
	systemd-cgroups-agent \
	systemd-initctl \
	systemd-update-utmp

noinst_PROGRAMS = \
	test-engine \
	test-job-type \
	test-ns \
	test-loopback \
	test-daemon \
	test-cgroup \
	test-env-replace

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

dist_systemunit_DATA = \
	units/emergency.service \
	units/emergency.target \
	units/basic.target \
	units/getty.target \
	units/halt.target \
	units/local-fs.target \
	units/network.target \
	units/nss-lookup.target \
	units/mail-transfer-agent.target \
	units/poweroff.target \
	units/reboot.target \
	units/rescue.target \
	units/rpcbind.target \
	units/rtc-set.target \
	units/shutdown.target \
	units/umount.target \
	units/sigpwr.target \
	units/sockets.target \
	units/swap.target \
	units/dbus.target \
	units/systemd-initctl.socket \
	units/systemd-logger.socket \
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
	units/printer.target \
	units/bluetooth.target \
	units/smartcard.target

nodist_systemunit_DATA = \
	units/sysinit.target \
	units/getty@.service \
	units/graphical.target \
	units/remote-fs.target \
	units/multi-user.target \
	units/systemd-initctl.service \
	units/systemd-logger.service \
	units/systemd-update-utmp-runlevel.service \
	units/systemd-update-utmp-shutdown.service \
	units/syslog.target

dist_sessionunit_DATA = \
	units/session/default.target

nodist_sessionunit_DATA = \
	units/session/remote-fs.target \
	units/session/exit.service

EXTRA_DIST = \
	units/sysinit.target.m4 \
	units/getty@.service.m4 \
	units/graphical.target.m4 \
	units/multi-user.target.m4 \
	units/remote-fs.target.m4 \
	units/systemd-initctl.service.in \
	units/systemd-logger.service.in \
	units/systemd-update-utmp-runlevel.service.in \
	units/systemd-update-utmp-shutdown.service.in \
	units/syslog.target.in \
	units/session/exit.service.in \
	systemd.pc.in

if TARGET_FEDORA
dist_systemunit_DATA += \
	units/fedora/halt.service \
	units/fedora/killall.service \
	units/fedora/poweroff.service \
	units/fedora/prefdm.service \
	units/fedora/rc-local.service \
	units/fedora/reboot.service \
	units/fedora/sysinit.service \
	units/fedora/single.service \
	units/fedora/plymouth-quit.service \
	units/fedora/plymouth-reboot.service \
	units/fedora/plymouth-poweroff.service \
	units/fedora/plymouth-halt.service
endif

if TARGET_SUSE
dist_systemunit_DATA += \
	units/suse/halt.service \
	units/suse/poweroff.service \
	units/suse/reboot.service \
	units/suse/fsck.target
endif

if TARGET_GENTOO
dist_systemunit_DATA += \
	units/gentoo/halt.service \
	units/gentoo/killall.service \
	units/gentoo/poweroff.service \
	units/gentoo/reboot.service \
	units/gentoo/xdm.service
endif

if TARGET_ARCH
dist_systemunit_DATA += \
	units/arch/sysinit.service \
	units/arch/rc-local.service \
	units/arch/halt.service \
	units/arch/poweroff.service \
	units/arch/reboot.service
endif

dist_doc_DATA = \
	README \
	LICENSE \
	DISTRO_PORTING \
	src/sd-daemon.h \
	src/sd-daemon.c

pkgconfigdata_DATA = \
	systemd.pc

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
	src/loopback-setup.c \
	src/kmod-setup.c \
	src/modprobe-setup.c \
	src/specifier.c \
	src/unit-name.c \
	src/fdset.c \
	src/namespace.c \
	src/tcpwrap.c \
	src/cgroup-util.c

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
	src/initreq.h \
	src/sd-daemon.h \
	src/special.h \
	src/dbus-common.h \
	src/bus-errors.h \
	src/cgroup-show.h \
	src/utmp-wtmp.h \
	src/build.h

MANPAGES = \
	man/systemd.1 \
	man/systemctl.1 \
	man/systemadm.1 \
	man/systemd-cgls.1 \
	man/systemd-notify.1 \
	man/sd_notify.3 \
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
	man/runlevel.8 \
	man/telinit.8 \
	man/halt.8 \
	man/shutdown.8 \
	man/pam_systemd.8 \
	man/systemd.conf.5

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
	src/sd-daemon.c \
	src/cgroup-show.c \
	src/cgroup-util.c

systemctl_CFLAGS = \
	$(AM_CFLAGS) \
	$(DBUS_CFLAGS)

systemctl_LDADD = \
	libsystemd-basic.la \
	$(DBUS_LIBS)

systemd_notify_SOURCES = \
	src/notify.c \
	src/sd-daemon.c

systemd_notify_LDADD = \
	libsystemd-basic.la

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
		-e 's,@SPECIAL_SYSLOG_SERVICE\@,$(SPECIAL_SYSLOG_SERVICE),g' \
		-e 's,@SYSTEMCTL\@,$(rootbindir)/systemctl,g' \
		-e 's,@pkgsysconfdir\@,$(pkgsysconfdir),g' \
		-e 's,@pkgdatadir\@,$(pkgdatadir),g' \
		-e 's,@systemunitdir\@,$(systemunitdir),g' \
		-e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' \
		-e 's,@PACKAGE_NAME\@,$(PACKAGE_NAME),g' \
		-e 's,@PACKAGE_URL\@,$(PACKAGE_URL),g' \
		-e 's,@prefix\@,$(prefix),g' \
		< $< > $@

units/%: units/%.in Makefile
	$(SED_PROCESS)

man/%: man/%.in Makefile
	$(SED_PROCESS)

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

M4_PROCESS_SYSTEM = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DISTRO_FLAG) -DFOR_SYSTEM=1 < $< > $@

M4_PROCESS_SESSION = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(M4) -P $(M4_DISTRO_FLAG) -DFOR_SESSION=1 < $< > $@

units/%: units/%.m4 Makefile
	$(M4_PROCESS_SYSTEM)

units/session/%: units/%.m4 Makefile
	$(M4_PROCESS_SESSION)

CLEANFILES = \
	$(nodist_systemunit_DATA) \
	$(nodist_sessionunit_DATA) \
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

org.freedesktop.systemd1.%.xml: systemd
	$(AM_V_GEN)SYSTEMD_SKIP_API_MOUNTS=1 ./systemd --introspect=${@:.xml=} > $@

CLEANFILES += \
	$(dbusinterface_DATA)

install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir) \
		$(DESTDIR)$(sessionunitdir) \
		$(DESTDIR)$(systemunitdir)/sockets.target.wants \
		$(DESTDIR)$(systemunitdir)/sysinit.target.wants \
		$(DESTDIR)$(systemunitdir)/shutdown.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel1.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel2.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel3.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel4.target.wants \
		$(DESTDIR)$(systemunitdir)/runlevel5.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system \
		$(DESTDIR)$(pkgsysconfdir)/system/getty.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/graphical.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/session \
		$(DESTDIR)$(sysconfdir)/xdg/systemd
	$(MKDIR_P) -m 0755 $(DESTDIR)/cgroup || \
		echo "Don't forget to create /cgroup! Couldn't create it for you, continuing anyway."
	( cd $(DESTDIR)$(sysconfdir)/xdg/systemd/ && \
		rm -f session && \
		$(LN_S) $(pkgsysconfdir)/session session )
	( cd $(DESTDIR)$(systemunitdir)/sockets.target.wants && \
		rm -f systemd-initctl.socket systemd-logger.socket && \
		$(LN_S) ../systemd-logger.socket systemd-logger.socket && \
		$(LN_S) ../systemd-initctl.socket systemd-initctl.socket )
	( cd $(DESTDIR)$(systemunitdir)/runlevel1.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel2.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel3.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel4.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/runlevel5.target.wants && \
		rm -f systemd-update-utmp-runlevel.service && \
		$(LN_S) ../systemd-update-utmp-runlevel.service )
	( cd $(DESTDIR)$(systemunitdir)/shutdown.target.wants && \
		rm -f systemd-update-utmp-shutdown.service && \
		$(LN_S) ../systemd-update-utmp-shutdown.service )
	( cd $(DESTDIR)$(sessionunitdir) && \
		rm -f shutdown.target sockets.target local-fs.target swap.target bluetooth.target printer.target && \
		$(LN_S) $(systemunitdir)/shutdown.target shutdown.target && \
		$(LN_S) $(systemunitdir)/sockets.target sockets.target && \
		$(LN_S) $(systemunitdir)/local-fs.target local-fs.target && \
		$(LN_S) $(systemunitdir)/swap.target swap.target && \
		$(LN_S) $(systemunitdir)/bluetooth.target bluetooth.target && \
		$(LN_S) $(systemunitdir)/printer.target printer.target)
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f runlevel0.target runlevel1.target runlevel6.target && \
		$(LN_S) poweroff.target runlevel0.target && \
		$(LN_S) rescue.target runlevel1.target && \
		$(LN_S) reboot.target runlevel6.target )
	( cd $(DESTDIR)$(pkgsysconfdir)/system && \
		rm -f default.target ctrl-alt-del.target kbrequest.target && \
		$(LN_S) $(systemunitdir)/graphical.target default.target && \
		$(LN_S) $(systemunitdir)/reboot.target ctrl-alt-del.target && \
		$(LN_S) $(systemunitdir)/rescue.target kbrequest.target && \
		rm -f runlevel2.target runlevel3.target runlevel4.target runlevel5.target && \
		$(LN_S) $(systemunitdir)/multi-user.target runlevel2.target && \
		$(LN_S) $(systemunitdir)/multi-user.target runlevel3.target && \
		$(LN_S) $(systemunitdir)/multi-user.target runlevel4.target && \
		$(LN_S) $(systemunitdir)/graphical.target runlevel5.target )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/getty.target.wants && \
		rm -f getty@tty1.service getty@tty2.service getty@tty3.service getty@tty4.service getty@tty5.service getty@tty6.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty1.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty2.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty3.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty4.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty5.service && \
		$(LN_S) $(systemunitdir)/getty@.service getty@tty6.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants && \
		rm -f getty.target remote-fs.target && \
		$(LN_S) $(systemunitdir)/getty.target getty.target && \
		$(LN_S) $(systemunitdir)/remote-fs.target remote-fs.target )
	( cd $(DESTDIR)$(systemunitdir)/sysinit.target.wants && \
		rm -f dev-hugepages.automount \
			dev-mqueue.automount \
			proc-sys-fs-binfmt_misc.automount \
			sys-kernel-debug.automount \
			sys-kernel-security.automount && \
		$(LN_S) ../dev-hugepages.automount dev-hugepages.automount && \
		$(LN_S) ../dev-mqueue.automount dev-mqueue.automount && \
		$(LN_S) ../proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.automount && \
		$(LN_S) ../sys-kernel-debug.automount sys-kernel-debug.automount && \
		$(LN_S) ../sys-kernel-security.automount sys-kernel-security.automount )
	( cd $(DESTDIR)$(dbussessionservicedir) && \
		rm -f org.freedesktop.systemd1.service && \
		$(LN_S) ../system-services/org.freedesktop.systemd1.service org.freedesktop.systemd1.service )
if TARGET_FEDORA
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(SYSTEM_SYSVINIT_PATH) \
		$(DESTDIR)$(pkgsysconfdir)/system/reboot.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/poweroff.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/halt.target.wants \
		$(DESTDIR)$(systemunitdir)/rescue.target.wants
	( cd $(DESTDIR)$(pkgsysconfdir)/system && \
		rm -f display-manager.service && \
		$(LN_S) $(systemunitdir)/prefdm.service display-manager.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/graphical.target.wants && \
		rm -f prefdm.service && \
		$(LN_S) $(systemunitdir)/prefdm.service prefdm.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants && \
		rm -f rc-local.service plymouth-quit.service && \
		$(LN_S) $(systemunitdir)/rc-local.service rc-local.service && \
		$(LN_S) $(systemunitdir)/plymouth-quit.service plymouth-quit.service )
	( cd $(DESTDIR)$(systemunitdir)/rescue.target.wants && \
		rm -f single.service && \
		$(LN_S) $(systemunitdir)/single.service single.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/reboot.target.wants && \
		rm -f plymouth-reboot.service && \
		$(LN_S) $(systemunitdir)/plymouth-reboot.service plymouth-reboot.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/poweroff.target.wants && \
		rm -f plymouth-poweroff.service && \
		$(LN_S) $(systemunitdir)/plymouth-poweroff.service plymouth-poweroff.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/halt.target.wants && \
		rm -f plymouth-halt.service && \
		$(LN_S) $(systemunitdir)/plymouth-halt.service plymouth-halt.service )
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f local.service && \
		$(LN_S) rc-local.service local.service )
	( cd $(DESTDIR)$(SYSTEM_SYSVINIT_PATH) && \
		$(LN_S) halt reboot > /dev/null 2>&1 || true )
endif
if TARGET_GENTOO
	( cd $(DESTDIR)$(pkgsysconfdir)/system && \
		rm -f display-manager.service && \
		$(LN_S) $(systemunitdir)/xdm.service display-manager.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/graphical.target.wants && \
		rm -f xdm.service && \
		$(LN_S) $(systemunitdir)/xdm.service xdm.service )
endif
if !TARGET_SUSE
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f fsck.target && \
		$(LN_S) sysinit.target fsck.target )
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
	cp -v systemd-$(VERSION).tar.bz2 /home/lennart/cvs.fedora/systemd/devel/
	scp systemd-$(VERSION).tar.bz2 fdo:/srv/www.freedesktop.org/www/software/systemd/
	scp man/*.html tango:public/systemd-man/

git-tag:
	git tag "v$(VERSION)" -m "systemd $(VERSION)"
