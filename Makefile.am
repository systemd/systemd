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

pkgsysconfdir=$(sysconfdir)/systemd
dbuspolicydir=$(sysconfdir)/dbus-1/system.d
udevrulesdir=/lib/udev/rules.d

systemunitdir=$(pkgdatadir)/system
sessionunitdir=$(pkgdatadir)/system

AM_CPPFLAGS = \
        -include $(top_builddir)/config.h \
	-DSYSTEM_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/system\" \
	-DSYSTEM_DATA_UNIT_PATH=\"$(systemunitdir)\" \
	-DSYSTEM_SYSVINIT_PATH=\"$(SYSTEM_SYSVINIT_PATH)\" \
	-DSYSTEM_SYSVRCND_PATH=\"$(SYSTEM_SYSVRCND_PATH)\" \
	-DSESSION_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/session\" \
	-DSESSION_DATA_UNIT_PATH=\"$(sessionunitdir)\" \
	-DCGROUP_AGENT_PATH=\"$(pkglibexecdir)/systemd-cgroups-agent\" \
	-DSYSTEMD_BINARY_PATH=\"$(sbindir)/systemd\"

#	-DSYSTEMD_BINARY_PATH=\"/home/lennart/projects/systemd/systemd\"


sbin_PROGRAMS = \
	systemd

bin_PROGRAMS = \
	systemctl \
	systemadm

pkglibexec_PROGRAMS = \
	systemd-logger \
	systemd-cgroups-agent \
	systemd-initctl

noinst_PROGRAMS = \
	test-engine \
	test-job-type \
	test-ns

dbuspolicy_DATA = \
	org.freedesktop.systemd1.conf

udevrules_DATA = \
	99-systemd.rules

systemunit_DATA = \
	units/emergency.service \
	systemd-initctl.service \
	units/systemd-initctl.socket \
	systemd-logger.service \
	units/systemd-logger.socket

EXTRA_DIST = \
	org.freedesktop.systemd1.conf \
	99-systemd.rules \
	units/emergency.service \
	units/systemd-initctl.service.in \
	units/systemd-initctl.socket \
	units/systemd-logger.service.in \
	units/systemd-logger.socket

BASIC_SOURCES= \
        util.c \
        util.h \
        hashmap.c \
        hashmap.h \
        set.c \
        set.h \
        strv.c \
        strv.h \
        conf-parser.c \
        conf-parser.h \
        socket-util.c \
        socket-util.h \
        log.c \
        log.h \
        ratelimit.c \
        ratelimit.h

COMMON_SOURCES= \
	$(BASIC_SOURCES) \
	unit.c \
	unit.h \
        job.c \
	job.h \
        manager.c \
        manager.h \
        load-fragment.c \
        load-fragment.h \
        service.c \
        service.h \
        automount.c \
        automount.h \
        mount.c \
        mount.h \
        device.c \
        device.h \
        target.c \
        target.h \
        snapshot.c \
        snapshot.h \
        socket.c \
        socket.h \
        timer.c \
        timer.h \
        load-dropin.c \
        load-dropin.h \
        execute.c \
        execute.h \
        dbus.c \
        dbus.h \
        dbus-manager.c \
        dbus-manager.h \
        dbus-unit.c \
        dbus-unit.h \
        dbus-job.c \
        dbus-job.h \
	dbus-service.c \
	dbus-service.h \
	dbus-socket.c \
	dbus-socket.h \
	dbus-target.c \
	dbus-target.h \
	dbus-mount.c \
	dbus-mount.h \
	dbus-automount.c \
	dbus-autpmount.h \
	dbus-snapshot.c \
	dbus-snapshot.h \
	dbus-device.c \
	dbus-device.h \
	dbus-execute.c \
	dbus-execute.h \
	cgroup.c \
	cgroup.h \
	mount-setup.c \
	mount-setup.h \
	hostname-setup.c \
	hostname-setup.h \
	utmp-wtmp.c \
	utmp-wtmp.h \
	specifier.c \
	specifier.h \
	unit-name.c \
	unit-name.h \
	fdset.c \
	fdset.h \
	namespace.h \
	namespace.c

systemd_SOURCES = \
	$(COMMON_SOURCES) \
	main.c

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
	test-engine.c

test_engine_CPPFLAGS = $(systemd_CPPFLAGS)
test_engine_LDADD = $(systemd_LDADD)

test_job_type_SOURCES = \
	$(COMMON_SOURCES) \
	test-engine.c

test_job_type_CPPFLAGS = $(systemd_CPPFLAGS)
test_job_type_LDADD = $(systemd_LDADD)

test_ns_SOURCES = \
	$(BASIC_SOURCES) \
	test-ns.c \
	namespace.c

test_ns_CPPFLAGS = $(systemd_CPPFLAGS)
test_ns_LDADD = $(systemd_LDADD)

systemd_logger_SOURCES = \
	$(BASIC_SOURCES) \
	logger.c

systemd_initctl_SOURCES = \
	$(BASIC_SOURCES) \
	initctl.c

systemd_initctl_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(DBUS_CFLAGS)

systemd_initctl_LDADD = \
	$(DBUS_LIBS)

systemd_cgroups_agent_SOURCES = \
	$(BASIC_SOURCES) \
	cgroups-agent.c

systemd_cgroups_agent_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(DBUS_CFLAGS)

systemd_cgroups_agent_LDADD = \
	$(DBUS_LIBS)

VALAFLAGS = -g --save-temps --pkg=dbus-glib-1 --pkg=posix --pkg gee-1.0 --pkg gtk+-2.0

systemctl_SOURCES = \
	systemctl.vala \
	systemd-interfaces.vala

systemctl_CPPFLAGS = $(AM_CPPFLAGS) $(DBUSGLIB_CFLAGS)
systemctl_LDADD = $(DBUSGLIB_LIBS)

systemadm_SOURCES = \
	systemadm.vala \
	systemd-interfaces.vala

systemadm_CPPFLAGS = $(AM_CPPFLAGS) $(DBUSGLIB_CFLAGS) $(GTK_CFLAGS)
systemadm_LDADD = $(DBUSGLIB_LIBS) $(GTK_LIBS)

systemd-initctl.service: units/systemd-initctl.service.in Makefile
	sed -e 's,@libexecdir\@,$(libexecdir),g' < $< > $@

systemd-logger.service: units/systemd-logger.service.in Makefile
	sed -e 's,@libexecdir\@,$(libexecdir),g' < $< > $@

CLEANFILES = \
	systemd-interfaces.c \
	systemctl.c \
	systemadm.c \
	systemd-initctl.service \
	systemd-logger.service
