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
	units/systemd-initctl.socket \
	units/systemd-logger.socket

systemunit_DATA = \
	units/systemd-initctl.service \
	units/systemd-logger.service

EXTRA_DIST = \
	units/systemd-initctl.service.in \
	units/systemd-logger.service.in \
	LICENSE \
	README

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

HTMLMANS = \
	man/systemd.unit.html \
	man/systemd.service.html

dist_noinst_DATA = \
	$(HTMLMANS)

EXTRA_DIST += \
	man/systemd.unit.xml \
	man/systemd.service.xml

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

units/systemd-initctl.service: units/systemd-initctl.service.in Makefile
	$(MKDIR_P) units
	$(SED) -e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@pkglibexecdir\@,$(pkglibexecdir),g' \
		< $< > $@

units/systemd-logger.service: units/systemd-logger.service.in Makefile
	$(MKDIR_P) units
	$(SED) -e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@pkglibexecdir\@,$(pkglibexecdir),g' \
		< $< > $@

CLEANFILES = \
	src/systemd-interfaces.c \
	src/systemctl.c \
	src/systemadm.c \
	units/systemd-initctl.service \
	units/systemd-logger.service

if HAVE_XSLTPROC
man/%.5: man/%.xml
	$(MKDIR_P) man
	$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

man/%.html: man/%.xml
	$(MKDIR_P) man
	$(XSLTPROC) -o $@ -nonet http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

CLEANFILES += \
	$(dist_man_MANS) \
	$(HTMLMANS)
endif

install-data-hook:
	$(MKDIR_P) -m 0755 \
		$(DESTDIR)$(systemunitdir) \
		$(DESTDIR)$(sessionunitdir) \
		$(DESTDIR)$(pkgsysconfdir)/system \
		$(DESTDIR)$(pkgsysconfdir)/session \
		$(DESTDIR)$(sysconfdir)/xdg/systemd \
		$(DESTDIR)/cgroup/debug
	( cd $(DESTDIR)$(sysconfdir)/xdg/systemd/ && \
		rm -f session && \
		$(LN_S) $(DESTDIR)$(pkgsysconfdir)/session session )

DISTCHECK_CONFIGURE_FLAGS = \
	--with-udevrulesdir=$$dc_install_base/$(udevrulesdir)
