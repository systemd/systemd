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
	test-ns \
	test-loopback

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

# This is needed because automake is buggy in how it generates the
# rules for C programs, but not Vala programs.  We therefore can't
# list the .h files as dependencies if we want make dist to work.
BASIC_SOURCES = \
        util.c \
        hashmap.c \
        set.c \
        strv.c \
        conf-parser.c \
        socket-util.c \
        log.c \
        ratelimit.c

COMMON_SOURCES = \
	$(BASIC_SOURCES) \
	unit.c \
        job.c \
        manager.c \
        load-fragment.c \
        service.c \
        automount.c \
        mount.c \
        swap.c \
        device.c \
        target.c \
        snapshot.c \
        socket.c \
        timer.c \
        load-dropin.c \
        execute.c \
        dbus.c \
        dbus-manager.c \
        dbus-unit.c \
        dbus-job.c \
	dbus-service.c \
	dbus-socket.c \
	dbus-target.c \
	dbus-mount.c \
	dbus-automount.c \
	dbus-swap.c \
	dbus-snapshot.c \
	dbus-device.c \
	dbus-execute.c \
	cgroup.c \
	mount-setup.c \
	hostname-setup.c \
	loopback-setup.c \
	utmp-wtmp.c \
	specifier.c \
	unit-name.c \
	fdset.c \
	namespace.c

EXTRA_DIST += \
	${COMMON_SOURCES:.c=.h} \
	macro.h \
	ioprio.h \
	missing.h \
	list.h \
	securebits.h \
	linux/auto_dev-ioctl.h \
	initreq.h

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

test_loopback_SOURCES = \
	$(BASIC_SOURCES) \
	test-loopback.c \
	loopback-setup.c

test_loopback_CPPFLAGS = $(systemd_CPPFLAGS)
test_loopback_LDADD = $(systemd_LDADD)

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

VALAFLAGS = -g --save-temps --pkg=dbus-glib-1 --pkg=posix --pkg gtk+-2.0

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
	sed -e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@pkglibexecdir\@,$(pkglibexecdir),g' \
		< $< > $@

systemd-logger.service: units/systemd-logger.service.in Makefile
	sed -e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@pkglibexecdir\@,$(pkglibexecdir),g' \
		< $< > $@

CLEANFILES = \
	systemd-interfaces.c \
	systemctl.c \
	systemadm.c \
	systemd-initctl.service \
	systemd-logger.service
