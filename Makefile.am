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

dbuspolicydir=$(sysconfdir)/dbus-1/system.d
udevrulesdir=@udevrulesdir@

pkgsysconfdir=$(sysconfdir)/systemd
systemunitdir=$(pkgdatadir)/system
sessionunitdir=$(pkgdatadir)/session

AM_CPPFLAGS = \
        -include $(top_builddir)/config.h \
	-DSYSTEM_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/system\" \
	-DSYSTEM_DATA_UNIT_PATH=\"$(systemunitdir)\" \
	-DSYSTEM_SYSVINIT_PATH=\"$(SYSTEM_SYSVINIT_PATH)\" \
	-DSYSTEM_SYSVRCND_PATH=\"$(SYSTEM_SYSVRCND_PATH)\" \
	-DSESSION_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/session\" \
	-DSESSION_DATA_UNIT_PATH=\"$(sessionunitdir)\" \
	-DCGROUP_AGENT_PATH=\"$(pkglibexecdir)/systemd-cgroups-agent\" \
	-DSYSTEMD_BINARY_PATH=\"$(sbindir)/systemd\" \
	-I $(top_srcdir)/src

sbin_PROGRAMS = \
	systemd

bin_PROGRAMS = \
	systemctl

if HAVE_GTK
bin_PROGRAMS += \
	systemadm
endif

pkglibexec_PROGRAMS = \
	systemd-logger \
	systemd-cgroups-agent \
	systemd-initctl

noinst_PROGRAMS = \
	test-engine \
	test-job-type \
	test-ns \
	test-loopback

dist_dbuspolicy_DATA = \
	src/org.freedesktop.systemd1.conf

dist_udevrules_DATA = \
	src/99-systemd.rules

dist_systemunit_DATA = \
	units/emergency.service \
	units/getty.target \
	units/halt.target \
	units/local-fs.target \
	units/network.target \
	units/nss-lookup.target \
	units/poweroff.target \
	units/reboot.target \
	units/remote-fs.target \
	units/rescue.target \
	units/rpcbind.target \
	units/rtc-set.target \
	units/shutdown.target \
	units/sigpwr.target \
	units/sockets.target \
	units/swap.target \
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
	units/var-run.mount

systemunit_DATA = \
	units/basic.target \
	units/getty@.service \
	units/graphical.target \
	units/multi-user.target \
	units/systemd-initctl.service \
	units/systemd-logger.service \
	units/syslog.target

sessionunit_DATA = \
	units/session/remote-fs.target

EXTRA_DIST = \
	units/basic.target.m4 \
	units/getty@.service.m4 \
	units/graphical.target.m4 \
	units/multi-user.target.m4 \
	units/remote-fs.target.m4 \
	units/systemd-initctl.service.in \
	units/systemd-logger.service.in \
	units/syslog.target.in \
	LICENSE \
	README \
	DISTRO_PORTING

if TARGET_FEDORA
dist_systemunit_DATA += \
	units/fedora/halt.service \
	units/fedora/killall.service \
	units/fedora/poweroff.service \
	units/fedora/prefdm.service \
	units/fedora/rc-local.service \
	units/fedora/reboot.service \
	units/fedora/sysinit.service
endif

# This is needed because automake is buggy in how it generates the
# rules for C programs, but not Vala programs.  We therefore can't
# list the .h files as dependencies if we want make dist to work.
BASIC_SOURCES = \
        src/util.c \
        src/hashmap.c \
        src/set.c \
        src/strv.c \
        src/conf-parser.c \
        src/socket-util.c \
        src/log.c \
        src/ratelimit.c

COMMON_SOURCES = \
	$(BASIC_SOURCES) \
	src/unit.c \
        src/job.c \
        src/manager.c \
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
        src/load-dropin.c \
        src/execute.c \
        src/dbus.c \
        src/dbus-manager.c \
        src/dbus-unit.c \
        src/dbus-job.c \
	src/dbus-service.c \
	src/dbus-socket.c \
	src/dbus-target.c \
	src/dbus-mount.c \
	src/dbus-automount.c \
	src/dbus-swap.c \
	src/dbus-snapshot.c \
	src/dbus-device.c \
	src/dbus-execute.c \
	src/cgroup.c \
	src/mount-setup.c \
	src/hostname-setup.c \
	src/loopback-setup.c \
	src/utmp-wtmp.c \
	src/specifier.c \
	src/unit-name.c \
	src/fdset.c \
	src/namespace.c

EXTRA_DIST += \
	${COMMON_SOURCES:.c=.h} \
	src/macro.h \
	src/ioprio.h \
	src/missing.h \
	src/list.h \
	src/securebits.h \
	src/linux/auto_dev-ioctl.h \
	src/initreq.h \
	src/sd-daemon.h

dist_man_MANS = \
	man/systemd.unit.5 \
	man/systemd.service.5

nodist_man_MANS = \
	man/systemd.special.7

dist_noinst_DATA = \
	man/systemd.unit.html \
	man/systemd.service.html

nodist_noinst_DATA = \
	man/systemd.special.html

EXTRA_DIST += \
	man/systemd.unit.xml \
	man/systemd.service.xml \
	man/systemd.special.xml.in \
	man/systemd.special.7.in \
	man/systemd.special.html.in

systemd_SOURCES = \
	$(COMMON_SOURCES) \
	src/main.c

systemd_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS) \
	$(CGROUP_CFLAGS)

systemd_LDADD = \
	$(DBUS_LIBS) \
	$(UDEV_LIBS) \
	$(CGROUP_LIBS)

test_engine_SOURCES = \
	$(COMMON_SOURCES) \
	src/test-engine.c

test_engine_CPPFLAGS = $(systemd_CPPFLAGS)
test_engine_LDADD = $(systemd_LDADD)

test_job_type_SOURCES = \
	$(COMMON_SOURCES) \
	src/test-engine.c

test_job_type_CPPFLAGS = $(systemd_CPPFLAGS)
test_job_type_LDADD = $(systemd_LDADD)

test_ns_SOURCES = \
	$(BASIC_SOURCES) \
	src/test-ns.c \
	src/namespace.c

test_ns_CPPFLAGS = $(systemd_CPPFLAGS)
test_ns_LDADD = $(systemd_LDADD)

test_loopback_SOURCES = \
	$(BASIC_SOURCES) \
	src/test-loopback.c \
	src/loopback-setup.c

test_loopback_CPPFLAGS = $(systemd_CPPFLAGS)
test_loopback_LDADD = $(systemd_LDADD)

systemd_logger_SOURCES = \
	$(BASIC_SOURCES) \
	src/logger.c \
	src/sd-daemon.c

systemd_initctl_SOURCES = \
	$(BASIC_SOURCES) \
	src/initctl.c \
	src/sd-daemon.c

systemd_initctl_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(DBUS_CFLAGS)

systemd_initctl_LDADD = \
	$(DBUS_LIBS)

systemd_cgroups_agent_SOURCES = \
	$(BASIC_SOURCES) \
	src/cgroups-agent.c

systemd_cgroups_agent_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(DBUS_CFLAGS)

systemd_cgroups_agent_LDADD = \
	$(DBUS_LIBS)

VALAFLAGS = \
	-g \
	--save-temps \
	--pkg=dbus-glib-1 \
	--pkg=posix

if HAVE_GTK
VALAFLAGS += \
	--pkg=gtk+-2.0
endif

VALA_CFLAGS = \
	-Wno-unused-variable \
	-Wno-unused-function

systemctl_SOURCES = \
	src/systemctl.vala \
	src/systemd-interfaces.vala

systemctl_CPPFLAGS = $(AM_CPPFLAGS) $(DBUSGLIB_CFLAGS) $(VALA_CFLAGS)
systemctl_LDADD = $(DBUSGLIB_LIBS)

systemadm_SOURCES = \
	src/systemadm.vala \
	src/systemd-interfaces.vala

systemadm_CPPFLAGS = $(AM_CPPFLAGS) $(DBUSGLIB_CFLAGS) $(GTK_CFLAGS) $(VALA_CFLAGS)
systemadm_LDADD = $(DBUSGLIB_LIBS) $(GTK_LIBS)

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED)  -e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@pkglibexecdir\@,$(pkglibexecdir),g' \
		-e 's,@SPECIAL_SYSLOG_SERVICE\@,$(SPECIAL_SYSLOG_SERVICE),g' \
		< $< > $@

units/%: units/%.in Makefile
	$(SED_PROCESS)

man/%: man/%.in Makefile
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
	units/systemd-initctl.service \
	units/systemd-logger.service \
	units/syslog.target \
	units/basic.target \
	units/getty@.service \
	units/graphical.target \
	units/multi-user.target \
	units/remote-fs.target \
	units/session/remote-fs.target \
	man/systemd.special.7 \
	man/systemd.special.html

if HAVE_VALAC
CLEANFILES += \
	src/systemd-interfaces.c \
	src/systemctl.c \
	src/systemadm.c
endif

if HAVE_XSLTPROC
XSLTPROC_PROCESS_MAN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

XSLTPROC_PROCESS_MAN_IN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o ${@:.in=} -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $< && \
	mv ${@:.in=} $@

XSLTPROC_PROCESS_HTML = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

XSLTPROC_PROCESS_HTML_IN = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(XSLTPROC) -o ${@:.in=} -nonet http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $< && \
	mv ${@:.in=} $@

man/%.5: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.5.in: man/%.xml.in
	$(XSLTPROC_PROCESS_MAN)

man/%.7: man/%.xml
	$(XSLTPROC_PROCESS_MAN)

man/%.7.in: man/%.xml.in
	$(XSLTPROC_PROCESS_MAN_IN)

man/%.html: man/%.xml
	$(XSLTPROC_PROCESS_HTML)

man/%.html.in: man/%.xml.in
	$(XSLTPROC_PROCESS_HTML_IN)

CLEANFILES += \
	$(dist_man_MANS) \
	man/systemd.special.7.in \
	man/systemd.unit.html \
	man/systemd.service.html \
	man/systemd.special.html.in
endif

install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir) \
		$(DESTDIR)$(sessionunitdir) \
		$(DESTDIR)$(systemunitdir)/sockets.target.wants \
		$(DESTDIR)$(systemunitdir)/basic.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system \
		$(DESTDIR)$(pkgsysconfdir)/system/getty.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/system/graphical.target.wants \
		$(DESTDIR)$(pkgsysconfdir)/session \
		$(DESTDIR)$(sysconfdir)/xdg/systemd
	$(MKDIR_P) -m 0755 $(DESTDIR)/cgroup/systemd || \
		echo "Don't forget to create /cgroup/systemd! Couldn't create it for you, continuing anyway."
	( cd $(DESTDIR)$(sysconfdir)/xdg/systemd/ && \
		rm -f session && \
		$(LN_S) $(pkgsysconfdir)/session session )
	( cd $(DESTDIR)$(systemunitdir)/sockets.target.wants && \
		rm -f systemd-initctl.socket systemd-logger.socket && \
		$(LN_S) ../systemd-logger.socket systemd-logger.socket && \
		$(LN_S) ../systemd-initctl.socket systemd-initctl.socket )
	( cd $(DESTDIR)$(sessionunitdir) && \
		rm -f shutdown.target sockets.target local-fs.target swap.target && \
		$(LN_S) ../system/shutdown.target shutdown.target && \
		$(LN_S) ../system/sockets.target sockets.target && \
		$(LN_S) ../system/local-fs.target local-fs.target && \
		$(LN_S) ../system/swap.target swap.target )
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
		rm -f getty.target && \
		$(LN_S) $(systemunitdir)/getty.target getty.target )
	( cd $(DESTDIR)$(systemunitdir)/basic.target.wants && \
		rm -f dev-hugepages.automount dev-mqueue.automount proc-sys-fs-binfmt_misc.automount sys-kernel-debug.automount && \
		$(LN_S) ../dev-hugepages.automount dev-hugepages.automount && \
		$(LN_S) ../dev-mqueue.automount dev-mqueue.automount && \
		$(LN_S) ../proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.automount && \
		$(LN_S) ../sys-kernel-debug.automount sys-kernel-debug.automount )
if TARGET_FEDORA
	( cd $(DESTDIR)$(pkgsysconfdir)/system/graphical.target.wants && \
		rm -f prefdm.service && \
		$(LN_S) $(systemunitdir)/prefdm.service prefdm.service )
	( cd $(DESTDIR)$(pkgsysconfdir)/system/multi-user.target.wants && \
		rm -f rc-local.service && \
		$(LN_S) $(systemunitdir)/rc-local.service rc-local.service )
	( cd $(DESTDIR)$(systemunitdir) && \
		rm -f local.service && \
		$(LN_S) rc-local.service local.service )
endif

DISTCHECK_CONFIGURE_FLAGS = \
	--with-udevrulesdir=$$dc_install_base/$(udevrulesdir)
