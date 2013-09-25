/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include <systemd/sd-daemon.h>

#include "machined.h"
#include "dbus-common.h"
#include "dbus-loop.h"
#include "strv.h"
#include "conf-parser.h"
#include "mkdir.h"

Manager *manager_new(void) {
        Manager *m;

        m = new0(Manager, 1);
        if (!m)
                return NULL;

        m->bus_fd = -1;
        m->epoll_fd = -1;

        m->machines = hashmap_new(string_hash_func, string_compare_func);
        m->machine_units = hashmap_new(string_hash_func, string_compare_func);

        if (!m->machines || !m->machine_units) {
                manager_free(m);
                return NULL;
        }

        return m;
}

void manager_free(Manager *m) {
        Machine *machine;

        assert(m);

        while ((machine = hashmap_first(m->machines)))
                machine_free(machine);

        hashmap_free(m->machines);
        hashmap_free(m->machine_units);

        if (m->bus) {
                dbus_connection_flush(m->bus);
                dbus_connection_close(m->bus);
                dbus_connection_unref(m->bus);
        }

        if (m->bus_fd >= 0)
                close_nointr_nofail(m->bus_fd);

        if (m->epoll_fd >= 0)
                close_nointr_nofail(m->epoll_fd);

        free(m);
}

int manager_enumerate_machines(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(m);

        /* Read in machine data stored on disk */
        d = opendir("/run/systemd/machines");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open /run/systemd/machines: %m");
                return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                struct Machine *machine;
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_machine(m, de->d_name, &machine);
                if (k < 0) {
                        log_error("Failed to add machine by file name %s: %s", de->d_name, strerror(-k));

                        r = k;
                        continue;
                }

                machine_add_to_gc_queue(machine);

                k = machine_load(machine);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int manager_connect_bus(Manager *m) {
        DBusError error;
        int r;
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.u32 = FD_BUS,
        };

        assert(m);
        assert(!m->bus);
        assert(m->bus_fd < 0);

        dbus_error_init(&error);

        m->bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!m->bus) {
                log_error("Failed to get system D-Bus connection: %s", bus_error_message(&error));
                r = -ECONNREFUSED;
                goto fail;
        }

        if (!dbus_connection_register_object_path(m->bus, "/org/freedesktop/machine1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/machine1/machine", &bus_machine_vtable, m) ||
            !dbus_connection_add_filter(m->bus, bus_message_filter, m, NULL)) {
                r = log_oom();
                goto fail;
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Manager',"
                           "member='JobRemoved',"
                           "path='/org/freedesktop/systemd1'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for JobRemoved: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Manager',"
                           "member='UnitRemoved',"
                           "path='/org/freedesktop/systemd1'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for UnitRemoved: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.DBus.Properties',"
                           "member='PropertiesChanged'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for PropertiesChanged: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Manager',"
                           "member='Reloading',"
                           "path='/org/freedesktop/systemd1'",
                           &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match for Reloading: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        r = bus_method_call_with_reply(
                        m->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Subscribe",
                        NULL,
                        &error,
                        DBUS_TYPE_INVALID);
        if (r < 0) {
                log_error("Failed to enable subscription: %s", bus_error(&error, r));
                dbus_error_free(&error);
        }

        r = dbus_bus_request_name(m->bus, "org.freedesktop.machine1", DBUS_NAME_FLAG_DO_NOT_QUEUE, &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to register name on bus: %s", bus_error_message(&error));
                r = -EIO;
                goto fail;
        }

        if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)  {
                log_error("Failed to acquire name.");
                r = -EEXIST;
                goto fail;
        }

        m->bus_fd = bus_loop_open(m->bus);
        if (m->bus_fd < 0) {
                r = m->bus_fd;
                goto fail;
        }

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->bus_fd, &ev) < 0)
                goto fail;

        return 0;

fail:
        dbus_error_free(&error);

        return r;
}

void manager_gc(Manager *m, bool drop_not_started) {
        Machine *machine;

        assert(m);

        while ((machine = m->machine_gc_queue)) {
                LIST_REMOVE(Machine, gc_queue, m->machine_gc_queue, machine);
                machine->in_gc_queue = false;

                if (machine_check_gc(machine, drop_not_started) == 0) {
                        machine_stop(machine);
                        machine_free(machine);
                }
        }
}

int manager_startup(Manager *m) {
        int r;
        Machine *machine;
        Iterator i;

        assert(m);
        assert(m->epoll_fd <= 0);

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0)
                return -errno;

        /* Connect to the bus */
        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        /* Deserialize state */
        manager_enumerate_machines(m);

        /* Remove stale objects before we start them */
        manager_gc(m, false);

        /* And start everything */
        HASHMAP_FOREACH(machine, m->machines, i)
                machine_start(machine, NULL);

        return 0;
}

int manager_run(Manager *m) {
        assert(m);

        for (;;) {
                struct epoll_event event;
                int n;

                manager_gc(m, true);

                if (dbus_connection_dispatch(m->bus) != DBUS_DISPATCH_COMPLETE)
                        continue;

                manager_gc(m, true);

                n = epoll_wait(m->epoll_fd, &event, 1, -1);
                if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("epoll() failed: %m");
                        return -errno;
                }

                if (n == 0)
                        continue;

                switch (event.data.u32) {

                case FD_BUS:
                        bus_loop_dispatch(m->bus_fd);
                        break;

                default:
                        assert_not_reached("Unknown fd");
                }
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_set_facility(LOG_AUTH);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        /* Always create the directories people can create inotify
         * watches in. Note that some applications might check for the
         * existence of /run/systemd/seats/ to determine whether
         * machined is available, so please always make sure this check
         * stays in. */
        mkdir_label("/run/systemd/machines", 0755);

        m = manager_new();
        if (!m) {
                r = log_oom();
                goto finish;
        }

        r = manager_startup(m);
        if (r < 0) {
                log_error("Failed to fully start up daemon: %s", strerror(-r));
                goto finish;
        }

        log_debug("systemd-machined running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        r = manager_run(m);

        log_debug("systemd-machined stopped as pid %lu", (unsigned long) getpid());

finish:
        sd_notify(false,
                  "STATUS=Shutting down...");

        if (m)
                manager_free(m);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
