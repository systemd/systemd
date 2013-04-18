/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <stdbool.h>
#include <assert.h>
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "dbus-loop.h"
#include "dbus-common.h"
#include "util.h"

/* Minimal implementation of the dbus loop which integrates all dbus
 * events into a single epoll fd which we can triviall integrate with
 * other loops. Note that this is not used in the main systemd daemon
 * since we run a more elaborate mainloop there. */

typedef struct EpollData {
        int fd;
        void *object;
        bool is_timeout:1;
        bool fd_is_dupped:1;
} EpollData;

static dbus_bool_t add_watch(DBusWatch *watch, void *data) {
        _cleanup_free_ EpollData *e = NULL;
        struct epoll_event ev = {};

        assert(watch);

        e = new0(EpollData, 1);
        if (!e)
                return FALSE;

        e->fd = dbus_watch_get_unix_fd(watch);
        e->object = watch;
        e->is_timeout = false;

        ev.events = bus_flags_to_events(watch);
        ev.data.ptr = e;

        if (epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_ADD, e->fd, &ev) < 0) {

                if (errno != EEXIST)
                        return FALSE;

                /* Hmm, bloody D-Bus creates multiple watches on the
                 * same fd. epoll() does not like that. As a dirty
                 * hack we simply dup() the fd and hence get a second
                 * one we can safely add to the epoll(). */

                e->fd = dup(e->fd);
                if (e->fd < 0)
                        return FALSE;

                if (epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_ADD, e->fd, &ev) < 0) {
                        close_nointr_nofail(e->fd);
                        return FALSE;
                }

                e->fd_is_dupped = true;
        }

        dbus_watch_set_data(watch, e, NULL);
        e = NULL; /* prevent freeing */

        return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data) {
        _cleanup_free_ EpollData *e = NULL;

        assert(watch);

        e = dbus_watch_get_data(watch);
        if (!e)
                return;

        assert_se(epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_DEL, e->fd, NULL) >= 0);

        if (e->fd_is_dupped)
                close_nointr_nofail(e->fd);
}

static void toggle_watch(DBusWatch *watch, void *data) {
        EpollData *e;
        struct epoll_event ev = {};

        assert(watch);

        e = dbus_watch_get_data(watch);
        if (!e)
                return;

        ev.data.ptr = e;
        ev.events = bus_flags_to_events(watch);

        assert_se(epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_MOD, e->fd, &ev) == 0);
}

static int timeout_arm(EpollData *e) {
        struct itimerspec its = {};

        assert(e);
        assert(e->is_timeout);

        if (dbus_timeout_get_enabled(e->object)) {
                timespec_store(&its.it_value, dbus_timeout_get_interval(e->object) * USEC_PER_MSEC);
                its.it_interval = its.it_value;
        }

        if (timerfd_settime(e->fd, 0, &its, NULL) < 0)
                return -errno;

        return 0;
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data) {
        EpollData *e;
        struct epoll_event ev = {};

        assert(timeout);

        e = new0(EpollData, 1);
        if (!e)
                return FALSE;

        e->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
        if (e->fd < 0)
                goto fail;

        e->object = timeout;
        e->is_timeout = true;

        if (timeout_arm(e) < 0)
                goto fail;

        ev.events = EPOLLIN;
        ev.data.ptr = e;

        if (epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_ADD, e->fd, &ev) < 0)
                goto fail;

        dbus_timeout_set_data(timeout, e, NULL);

        return TRUE;

fail:
        if (e->fd >= 0)
                close_nointr_nofail(e->fd);

        free(e);
        return FALSE;
}

static void remove_timeout(DBusTimeout *timeout, void *data) {
        _cleanup_free_ EpollData *e = NULL;

        assert(timeout);

        e = dbus_timeout_get_data(timeout);
        if (!e)
                return;

        assert_se(epoll_ctl(PTR_TO_INT(data), EPOLL_CTL_DEL, e->fd, NULL) >= 0);
        close_nointr_nofail(e->fd);
}

static void toggle_timeout(DBusTimeout *timeout, void *data) {
        EpollData *e;
        int r;

        assert(timeout);

        e = dbus_timeout_get_data(timeout);
        if (!e)
                return;

        r = timeout_arm(e);
        if (r < 0)
                log_error("Failed to rearm timer: %s", strerror(-r));
}

int bus_loop_open(DBusConnection *c) {
        int fd;

        assert(c);

        fd = epoll_create1(EPOLL_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!dbus_connection_set_watch_functions(c, add_watch, remove_watch, toggle_watch, INT_TO_PTR(fd), NULL) ||
            !dbus_connection_set_timeout_functions(c, add_timeout, remove_timeout, toggle_timeout, INT_TO_PTR(fd), NULL)) {
                close_nointr_nofail(fd);
                return -ENOMEM;
        }

        return fd;
}

int bus_loop_dispatch(int fd) {
        int n;
        struct epoll_event event = {};
        EpollData *d;

        assert(fd >= 0);

        n = epoll_wait(fd, &event, 1, 0);
        if (n < 0)
                return errno == EAGAIN || errno == EINTR ? 0 : -errno;

        assert_se(d = event.data.ptr);

        if (d->is_timeout) {
                DBusTimeout *t = d->object;

                if (dbus_timeout_get_enabled(t))
                        dbus_timeout_handle(t);
        } else {
                DBusWatch *w = d->object;

                if (dbus_watch_get_enabled(w))
                        dbus_watch_handle(w, bus_events_to_flags(event.events));
        }

        return 0;
}
