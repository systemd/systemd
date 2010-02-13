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

AM_CPPFLAGS = \
        -include $(top_builddir)/config.h \
	-DSYSTEM_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/system\" \
	-DSYSTEM_DATA_UNIT_PATH=\"$(pkgdatadir)/system\" \
	-DSYSTEM_SYSVINIT_PATH=\"$(sysconfdir)/init.d\" \
	-DSESSION_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/session\" \
	-DSESSION_DATA_UNIT_PATH=\"$(pkgdatadir)/session\"

sbin_PROGRAMS = \
	systemd

bin_PROGRAMS = \
	systemctl \
	systemadm \
	systemd-logger

noinst_PROGRAMS = \
	test-engine \
	test-job-type

BASIC_SOURCES= \
        util.c \
        hashmap.c \
        set.c \
        strv.c \
        conf-parser.c \
        socket-util.c \
        log.c \
        ratelimit.c

COMMON_SOURCES= \
	$(BASIC_SOURCES) \
	unit.c \
        job.c \
        manager.c \
        load-fragment.c \
        service.c \
        automount.c \
        mount.c \
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
        dbus-job.c

systemd_SOURCES = \
	$(COMMON_SOURCES) \
	main.c

systemd_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(DBUS_CFLAGS) \
	$(UDEV_CFLAGS)

systemd_LDADD = \
	$(DBUS_LIBS) \
	$(UDEV_LIBS)

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

systemd_logger_SOURCES = \
	$(BASIC_SOURCES) \
	logger.c

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

CLEANFILES = \
	systemd-interfaces.c \
	systemctl.c \
	systemadm.c
