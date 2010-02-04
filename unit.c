/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/poll.h>
#include <stdlib.h>
#include <unistd.h>

#include "set.h"
#include "unit.h"
#include "macro.h"
#include "strv.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"

const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = &service_vtable,
        [UNIT_TIMER] = &timer_vtable,
        [UNIT_SOCKET] = &socket_vtable,
        [UNIT_TARGET] = &target_vtable,
        [UNIT_DEVICE] = &device_vtable,
        [UNIT_MOUNT] = &mount_vtable,
        [UNIT_AUTOMOUNT] = &automount_vtable,
        [UNIT_SNAPSHOT] = &snapshot_vtable
};

UnitType unit_name_to_type(const char *n) {
        UnitType t;

        assert(n);

        for (t = 0; t < _UNIT_TYPE_MAX; t++)
                if (endswith(n, unit_vtable[t]->suffix))
                        return t;

        return _UNIT_TYPE_INVALID;
}

#define VALID_CHARS                             \
        "0123456789"                            \
        "abcdefghijklmnopqrstuvwxyz"            \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"            \
        "-_.\\"

bool unit_name_is_valid(const char *n) {
        UnitType t;
        const char *e, *i;

        assert(n);

        if (strlen(n) >= UNIT_NAME_MAX)
                return false;

        t = unit_name_to_type(n);
        if (t < 0 || t >= _UNIT_TYPE_MAX)
                return false;

        if (!(e = strrchr(n, '.')))
                return false;

        if (e == n)
                return false;

        for (i = n; i < e; i++)
                if (!strchr(VALID_CHARS, *i))
                        return false;

        return true;
}

char *unit_name_change_suffix(const char *n, const char *suffix) {
        char *e, *r;
        size_t a, b;

        assert(n);
        assert(unit_name_is_valid(n));
        assert(suffix);

        assert_se(e = strrchr(n, '.'));
        a = e - n;
        b = strlen(suffix);

        if (!(r = new(char, a + b + 1)))
                return NULL;

        memcpy(r, n, a);
        memcpy(r+a, suffix, b+1);

        return r;
}

Unit *unit_new(Manager *m) {
        Unit *u;

        assert(m);

        if (!(u = new0(Unit, 1)))
                return NULL;

        if (!(u->meta.names = set_new(string_hash_func, string_compare_func))) {
                free(u);
                return NULL;
        }

        u->meta.manager = m;
        u->meta.type = _UNIT_TYPE_INVALID;

        return u;
}

int unit_add_name(Unit *u, const char *text) {
        UnitType t;
        char *s;
        int r;

        assert(u);
        assert(text);

        if (!unit_name_is_valid(text))
                return -EINVAL;

        if ((t = unit_name_to_type(text)) == _UNIT_TYPE_INVALID)
                return -EINVAL;

        if (u->meta.type != _UNIT_TYPE_INVALID && t != u->meta.type)
                return -EINVAL;

        if (!(s = strdup(text)))
                return -ENOMEM;

        if ((r = set_put(u->meta.names, s)) < 0) {
                free(s);

                if (r == -EEXIST)
                        return 0;

                return r;
        }

        if ((r = hashmap_put(u->meta.manager->units, s, u)) < 0) {
                set_remove(u->meta.names, s);
                free(s);
                return r;
        }

        if (u->meta.type == _UNIT_TYPE_INVALID)
                LIST_PREPEND(Meta, units_per_type, u->meta.manager->units_per_type[t], &u->meta);

        u->meta.type = t;

        if (!u->meta.id)
                u->meta.id = s;

        unit_add_to_dbus_queue(u);
        return 0;
}

int unit_choose_id(Unit *u, const char *name) {
        char *s;

        assert(u);
        assert(name);

        /* Selects one of the names of this unit as the id */

        if (!(s = set_get(u->meta.names, (char*) name)))
                return -ENOENT;

        u->meta.id = s;

        unit_add_to_dbus_queue(u);
        return 0;
}

int unit_set_description(Unit *u, const char *description) {
        char *s;

        assert(u);

        if (!(s = strdup(description)))
                return -ENOMEM;

        free(u->meta.description);
        u->meta.description = s;

        unit_add_to_dbus_queue(u);
        return 0;
}

void unit_add_to_load_queue(Unit *u) {
        assert(u);

        if (u->meta.load_state != UNIT_STUB || u->meta.in_load_queue)
                return;

        LIST_PREPEND(Meta, load_queue, u->meta.manager->load_queue, &u->meta);
        u->meta.in_load_queue = true;
}

void unit_add_to_dbus_queue(Unit *u) {
        assert(u);

        if (u->meta.load_state == UNIT_STUB || u->meta.in_dbus_queue || set_isempty(u->meta.manager->subscribed))
                return;

        LIST_PREPEND(Meta, dbus_queue, u->meta.manager->dbus_unit_queue, &u->meta);
        u->meta.in_dbus_queue = true;
}

static void bidi_set_free(Unit *u, Set *s) {
        Iterator i;
        Unit *other;

        assert(u);

        /* Frees the set and makes sure we are dropped from the
         * inverse pointers */

        SET_FOREACH(other, s, i) {
                UnitDependency d;

                for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                        set_remove(other->meta.dependencies[d], u);
        }

        set_free(s);
}

void unit_free(Unit *u) {
        UnitDependency d;
        Iterator i;
        char *t;

        assert(u);

        bus_unit_send_removed_signal(u);

        /* Detach from next 'bigger' objects */

        SET_FOREACH(t, u->meta.names, i)
                hashmap_remove_value(u->meta.manager->units, t, u);

        if (u->meta.type != _UNIT_TYPE_INVALID)
                LIST_REMOVE(Meta, units_per_type, u->meta.manager->units_per_type[u->meta.type], &u->meta);

        if (u->meta.in_load_queue)
                LIST_REMOVE(Meta, load_queue, u->meta.manager->load_queue, &u->meta);

        if (u->meta.in_dbus_queue)
                LIST_REMOVE(Meta, dbus_queue, u->meta.manager->dbus_unit_queue, &u->meta);

        if (u->meta.load_state == UNIT_LOADED)
                if (UNIT_VTABLE(u)->done)
                        UNIT_VTABLE(u)->done(u);

        /* Free data and next 'smaller' objects */
        if (u->meta.job)
                job_free(u->meta.job);

        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                bidi_set_free(u, u->meta.dependencies[d]);

        free(u->meta.description);
        free(u->meta.load_path);

        while ((t = set_steal_first(u->meta.names)))
                free(t);
        set_free(u->meta.names);

        free(u);
}

UnitActiveState unit_active_state(Unit *u) {
        assert(u);

        if (u->meta.load_state != UNIT_LOADED)
                return UNIT_INACTIVE;

        return UNIT_VTABLE(u)->active_state(u);
}

static int ensure_merge(Set **s, Set *other) {

        if (!other)
                return 0;

        if (*s)
                return set_merge(*s, other);

        if (!(*s = set_copy(other)))
                return -ENOMEM;

        return 0;
}

/* FIXME: Does not rollback on failure! Needs to fix special unit
 * pointers. Needs to merge names and dependencies properly.*/
int unit_merge(Unit *u, Unit *other) {
        int r;
        UnitDependency d;

        assert(u);
        assert(other);
        assert(u->meta.manager == other->meta.manager);

        /* This merges 'other' into 'unit'. FIXME: This does not
         * rollback on failure. */

        if (u->meta.type != u->meta.type)
                return -EINVAL;

        if (u->meta.load_state != UNIT_STUB)
                return -EINVAL;

        /* Merge names */
        if ((r = ensure_merge(&u->meta.names, other->meta.names)) < 0)
                return r;

        /* Merge dependencies */
        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                /* fixme, the inverse mapping is missing */
                if ((r = ensure_merge(&u->meta.dependencies[d], other->meta.dependencies[d])) < 0)
                        return r;

        unit_add_to_dbus_queue(u);

        return 0;
}

const char* unit_id(Unit *u) {
        assert(u);

        if (u->meta.id)
                return u->meta.id;

        return set_first(u->meta.names);
}

const char *unit_description(Unit *u) {
        assert(u);

        if (u->meta.description)
                return u->meta.description;

        return unit_id(u);
}

void unit_dump(Unit *u, FILE *f, const char *prefix) {

        char *t;
        UnitDependency d;
        Iterator i;
        char *p2;
        const char *prefix2;

        assert(u);

        if (!prefix)
                prefix = "";
        p2 = strappend(prefix, "\t");
        prefix2 = p2 ? p2 : prefix;

        fprintf(f,
                "%s→ Unit %s:\n"
                "%s\tDescription: %s\n"
                "%s\tUnit Load State: %s\n"
                "%s\tUnit Active State: %s\n"
                "%s\tRecursive Stop: %s\n"
                "%s\tStop When Unneeded: %s\n",
                prefix, unit_id(u),
                prefix, unit_description(u),
                prefix, unit_load_state_to_string(u->meta.load_state),
                prefix, unit_active_state_to_string(unit_active_state(u)),
                prefix, yes_no(u->meta.recursive_stop),
                prefix, yes_no(u->meta.stop_when_unneeded));

        if (u->meta.load_path)
                fprintf(f, "%s\tLoad Path: %s\n", prefix, u->meta.load_path);

        SET_FOREACH(t, u->meta.names, i)
                fprintf(f, "%s\tName: %s\n", prefix, t);

        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
                Unit *other;

                if (set_isempty(u->meta.dependencies[d]))
                        continue;

                SET_FOREACH(other, u->meta.dependencies[d], i)
                        fprintf(f, "%s\t%s: %s\n", prefix, unit_dependency_to_string(d), unit_id(other));
        }

        if (UNIT_VTABLE(u)->dump)
                UNIT_VTABLE(u)->dump(u, f, prefix2);

        if (u->meta.job)
                job_dump(u->meta.job, f, prefix2);

        free(p2);
}

/* Common implementation for multiple backends */
int unit_load_fragment_and_dropin(Unit *u) {
        int r, ret;

        assert(u);

        /* Load a .socket file */
        if ((r = unit_load_fragment(u)) < 0)
                return r;

        ret = r > 0;

        /* Load drop-in directory data */
        if ((r = unit_load_dropin(u)) < 0)
                return r;

        return ret;
}

int unit_load(Unit *u) {
        int r;

        assert(u);

        if (u->meta.in_load_queue) {
                LIST_REMOVE(Meta, load_queue, u->meta.manager->load_queue, &u->meta);
                u->meta.in_load_queue = false;
        }

        if (u->meta.load_state != UNIT_STUB)
                return 0;

        if (UNIT_VTABLE(u)->init)
                if ((r = UNIT_VTABLE(u)->init(u)) < 0)
                        goto fail;

        u->meta.load_state = UNIT_LOADED;
        unit_add_to_dbus_queue(u);
        return 0;

fail:
        u->meta.load_state = UNIT_FAILED;
        unit_add_to_dbus_queue(u);
        return r;
}

/* Errors:
 *         -EBADR:    This unit type does not support starting.
 *         -EALREADY: Unit is already started.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int unit_start(Unit *u) {
        UnitActiveState state;

        assert(u);

        if (!UNIT_VTABLE(u)->start)
                return -EBADR;

        state = unit_active_state(u);
        if (UNIT_IS_ACTIVE_OR_RELOADING(state))
                return -EALREADY;

        /* We don't suppress calls to ->start() here when we are
         * already starting, to allow this request to be used as a
         * "hurry up" call, for example when the unit is in some "auto
         * restart" state where it waits for a holdoff timer to elapse
         * before it will start again. */

        unit_add_to_dbus_queue(u);
        return UNIT_VTABLE(u)->start(u);
}

bool unit_can_start(Unit *u) {
        assert(u);

        return !!UNIT_VTABLE(u)->start;
}

/* Errors:
 *         -EBADR:    This unit type does not support stopping.
 *         -EALREADY: Unit is already stopped.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int unit_stop(Unit *u) {
        UnitActiveState state;

        assert(u);

        if (!UNIT_VTABLE(u)->stop)
                return -EBADR;

        state = unit_active_state(u);
        if (state == UNIT_INACTIVE)
                return -EALREADY;

        if (state == UNIT_DEACTIVATING)
                return 0;

        unit_add_to_dbus_queue(u);
        return UNIT_VTABLE(u)->stop(u);
}

/* Errors:
 *         -EBADR:    This unit type does not support reloading.
 *         -ENOEXEC:  Unit is not started.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int unit_reload(Unit *u) {
        UnitActiveState state;

        assert(u);

        if (!unit_can_reload(u))
                return -EBADR;

        state = unit_active_state(u);
        if (unit_active_state(u) == UNIT_ACTIVE_RELOADING)
                return -EALREADY;

        if (unit_active_state(u) != UNIT_ACTIVE)
                return -ENOEXEC;

        unit_add_to_dbus_queue(u);
        return UNIT_VTABLE(u)->reload(u);
}

bool unit_can_reload(Unit *u) {
        assert(u);

        if (!UNIT_VTABLE(u)->reload)
                return false;

        if (!UNIT_VTABLE(u)->can_reload)
                return true;

        return UNIT_VTABLE(u)->can_reload(u);
}

static void unit_check_uneeded(Unit *u) {
        Iterator i;
        Unit *other;

        assert(u);

        /* If this service shall be shut down when unneeded then do
         * so. */

        if (!u->meta.stop_when_unneeded)
                return;

        if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)))
                return;

        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUIRED_BY], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        return;

        SET_FOREACH(other, u->meta.dependencies[UNIT_SOFT_REQUIRED_BY], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        return;

        SET_FOREACH(other, u->meta.dependencies[UNIT_WANTED_BY], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        return;

        log_debug("Service %s is not needed anymore. Stopping.", unit_id(u));

        /* Ok, nobody needs us anymore. Sniff. Then let's commit suicide */
        manager_add_job(u->meta.manager, JOB_STOP, u, JOB_FAIL, true, NULL);
}

static void retroactively_start_dependencies(Unit *u) {
        Iterator i;
        Unit *other;

        assert(u);
        assert(UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)));

        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUIRES], i)
                if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->meta.manager, JOB_START, other, JOB_REPLACE, true, NULL);

        SET_FOREACH(other, u->meta.dependencies[UNIT_SOFT_REQUIRES], i)
                if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->meta.manager, JOB_START, other, JOB_FAIL, false, NULL);

        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUISITE], i)
                if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->meta.manager, JOB_START, other, JOB_REPLACE, true, NULL);

        SET_FOREACH(other, u->meta.dependencies[UNIT_WANTS], i)
                if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->meta.manager, JOB_START, other, JOB_FAIL, false, NULL);

        SET_FOREACH(other, u->meta.dependencies[UNIT_CONFLICTS], i)
                if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->meta.manager, JOB_STOP, other, JOB_REPLACE, true, NULL);
}

static void retroactively_stop_dependencies(Unit *u) {
        Iterator i;
        Unit *other;

        assert(u);
        assert(UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)));

        if (u->meta.recursive_stop) {
                /* Pull down units need us recursively if enabled */
                SET_FOREACH(other, u->meta.dependencies[UNIT_REQUIRED_BY], i)
                        if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                                manager_add_job(u->meta.manager, JOB_STOP, other, JOB_REPLACE, true, NULL);
        }

        /* Garbage collect services that might not be needed anymore, if enabled */
        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUIRES], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_uneeded(other);
        SET_FOREACH(other, u->meta.dependencies[UNIT_SOFT_REQUIRES], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_uneeded(other);
        SET_FOREACH(other, u->meta.dependencies[UNIT_WANTS], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_uneeded(other);
        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUISITE], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_uneeded(other);
        SET_FOREACH(other, u->meta.dependencies[UNIT_SOFT_REQUISITE], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_uneeded(other);
}

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns) {
        assert(u);
        assert(os < _UNIT_ACTIVE_STATE_MAX);
        assert(ns < _UNIT_ACTIVE_STATE_MAX);
        assert(!(os == UNIT_ACTIVE && ns == UNIT_ACTIVATING));
        assert(!(os == UNIT_INACTIVE && ns == UNIT_DEACTIVATING));

        if (os == ns)
                return;

        if (!UNIT_IS_ACTIVE_OR_RELOADING(os) && UNIT_IS_ACTIVE_OR_RELOADING(ns))
                u->meta.active_enter_timestamp = now(CLOCK_REALTIME);
        else if (UNIT_IS_ACTIVE_OR_RELOADING(os) && !UNIT_IS_ACTIVE_OR_RELOADING(ns))
                u->meta.active_exit_timestamp = now(CLOCK_REALTIME);

        if (u->meta.job) {

                if (u->meta.job->state == JOB_WAITING)

                        /* So we reached a different state for this
                         * job. Let's see if we can run it now if it
                         * failed previously due to EAGAIN. */
                        job_add_to_run_queue(u->meta.job);

                else {
                        assert(u->meta.job->state == JOB_RUNNING);

                        /* Let's check whether this state change
                         * constitutes a finished job, or maybe
                         * cotradicts a running job and hence needs to
                         * invalidate jobs. */

                        switch (u->meta.job->type) {

                        case JOB_START:
                        case JOB_VERIFY_ACTIVE:

                                if (UNIT_IS_ACTIVE_OR_RELOADING(ns)) {
                                        job_finish_and_invalidate(u->meta.job, true);
                                        return;
                                } else if (ns == UNIT_ACTIVATING)
                                        return;
                                else
                                        job_finish_and_invalidate(u->meta.job, false);

                                break;

                        case JOB_RELOAD:
                        case JOB_RELOAD_OR_START:

                                if (ns == UNIT_ACTIVE) {
                                        job_finish_and_invalidate(u->meta.job, true);
                                        return;
                                } else if (ns == UNIT_ACTIVATING || ns == UNIT_ACTIVE_RELOADING)
                                        return;
                                else
                                        job_finish_and_invalidate(u->meta.job, false);

                                break;

                        case JOB_STOP:
                        case JOB_RESTART:
                        case JOB_TRY_RESTART:

                                if (ns == UNIT_INACTIVE) {
                                        job_finish_and_invalidate(u->meta.job, true);
                                        return;
                                } else if (ns == UNIT_DEACTIVATING)
                                        return;
                                else
                                        job_finish_and_invalidate(u->meta.job, false);

                                break;

                        default:
                                assert_not_reached("Job type unknown");
                        }
                }
        }

        /* If this state change happened without being requested by a
         * job, then let's retroactively start or stop dependencies */

        if (UNIT_IS_INACTIVE_OR_DEACTIVATING(os) && UNIT_IS_ACTIVE_OR_ACTIVATING(ns))
                retroactively_start_dependencies(u);
        else if (UNIT_IS_ACTIVE_OR_ACTIVATING(os) && UNIT_IS_INACTIVE_OR_DEACTIVATING(ns))
                retroactively_stop_dependencies(u);

        /* Maybe we finished startup and are now ready for being
         * stopped because unneeded? */
        unit_check_uneeded(u);

        unit_add_to_dbus_queue(u);
}

int unit_watch_fd(Unit *u, int fd, uint32_t events, Watch *w) {
        struct epoll_event ev;

        assert(u);
        assert(fd >= 0);
        assert(w);
        assert(w->type == WATCH_INVALID || (w->type == WATCH_FD && w->fd == fd && w->data.unit == u));

        zero(ev);
        ev.data.ptr = w;
        ev.events = events;

        if (epoll_ctl(u->meta.manager->epoll_fd,
                      w->type == WATCH_INVALID ? EPOLL_CTL_ADD : EPOLL_CTL_MOD,
                      fd,
                      &ev) < 0)
                return -errno;

        w->fd = fd;
        w->type = WATCH_FD;
        w->data.unit = u;

        return 0;
}

void unit_unwatch_fd(Unit *u, Watch *w) {
        assert(u);
        assert(w);

        if (w->type == WATCH_INVALID)
                return;

        assert(w->type == WATCH_FD);
        assert(w->data.unit == u);
        assert_se(epoll_ctl(u->meta.manager->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);

        w->fd = -1;
        w->type = WATCH_INVALID;
        w->data.unit = NULL;
}

int unit_watch_pid(Unit *u, pid_t pid) {
        assert(u);
        assert(pid >= 1);

        return hashmap_put(u->meta.manager->watch_pids, UINT32_TO_PTR(pid), u);
}

void unit_unwatch_pid(Unit *u, pid_t pid) {
        assert(u);
        assert(pid >= 1);

        hashmap_remove(u->meta.manager->watch_pids, UINT32_TO_PTR(pid));
}

int unit_watch_timer(Unit *u, usec_t delay, Watch *w) {
        struct itimerspec its;
        int flags, fd;
        bool ours;

        assert(u);
        assert(w);
        assert(w->type == WATCH_INVALID || (w->type == WATCH_TIMER && w->data.unit == u));

        /* This will try to reuse the old timer if there is one */

        if (w->type == WATCH_TIMER) {
                ours = false;
                fd = w->fd;
        } else {
                ours = true;
                if ((fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC)) < 0)
                        return -errno;
        }

        zero(its);

        if (delay <= 0) {
                /* Set absolute time in the past, but not 0, since we
                 * don't want to disarm the timer */
                its.it_value.tv_sec = 0;
                its.it_value.tv_nsec = 1;

                flags = TFD_TIMER_ABSTIME;
        } else {
                timespec_store(&its.it_value, delay);
                flags = 0;
        }

        /* This will also flush the elapse counter */
        if (timerfd_settime(fd, flags, &its, NULL) < 0)
                goto fail;

        if (w->type == WATCH_INVALID) {
                struct epoll_event ev;

                zero(ev);
                ev.data.ptr = w;
                ev.events = EPOLLIN;

                if (epoll_ctl(u->meta.manager->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                        goto fail;
        }

        w->fd = fd;
        w->type = WATCH_TIMER;
        w->data.unit = u;

        return 0;

fail:
        if (ours)
                close_nointr_nofail(fd);

        return -errno;
}

void unit_unwatch_timer(Unit *u, Watch *w) {
        assert(u);
        assert(w);

        if (w->type == WATCH_INVALID)
                return;

        assert(w->type == WATCH_TIMER && w->data.unit == u);

        assert_se(epoll_ctl(u->meta.manager->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);
        assert_se(close_nointr(w->fd) == 0);

        w->fd = -1;
        w->type = WATCH_INVALID;
        w->data.unit = NULL;
}

bool unit_job_is_applicable(Unit *u, JobType j) {
        assert(u);
        assert(j >= 0 && j < _JOB_TYPE_MAX);

        switch (j) {

        case JOB_VERIFY_ACTIVE:
        case JOB_START:
                return true;

        case JOB_STOP:
        case JOB_RESTART:
        case JOB_TRY_RESTART:
                return unit_can_start(u);

        case JOB_RELOAD:
                return unit_can_reload(u);

        case JOB_RELOAD_OR_START:
                return unit_can_reload(u) && unit_can_start(u);

        default:
                assert_not_reached("Invalid job type");
        }
}

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other) {

        static const UnitDependency inverse_table[_UNIT_DEPENDENCY_MAX] = {
                [UNIT_REQUIRES] = UNIT_REQUIRED_BY,
                [UNIT_SOFT_REQUIRES] = UNIT_SOFT_REQUIRED_BY,
                [UNIT_WANTS] = UNIT_WANTED_BY,
                [UNIT_REQUISITE] = UNIT_REQUIRED_BY,
                [UNIT_SOFT_REQUISITE] = UNIT_SOFT_REQUIRED_BY,
                [UNIT_REQUIRED_BY] = _UNIT_DEPENDENCY_INVALID,
                [UNIT_SOFT_REQUIRED_BY] = _UNIT_DEPENDENCY_INVALID,
                [UNIT_WANTED_BY] = _UNIT_DEPENDENCY_INVALID,
                [UNIT_CONFLICTS] = UNIT_CONFLICTS,
                [UNIT_BEFORE] = UNIT_AFTER,
                [UNIT_AFTER] = UNIT_BEFORE
        };
        int r;

        assert(u);
        assert(d >= 0 && d < _UNIT_DEPENDENCY_MAX);
        assert(inverse_table[d] != _UNIT_DEPENDENCY_INVALID);
        assert(other);

        /* We won't allow dependencies on ourselves. We will not
         * consider them an error however. */
        if (u == other)
                return 0;

        if ((r = set_ensure_allocated(&u->meta.dependencies[d], trivial_hash_func, trivial_compare_func)) < 0)
                return r;

        if ((r = set_ensure_allocated(&other->meta.dependencies[inverse_table[d]], trivial_hash_func, trivial_compare_func)) < 0)
                return r;

        if ((r = set_put(u->meta.dependencies[d], other)) < 0)
                return r;

        if ((r = set_put(other->meta.dependencies[inverse_table[d]], u)) < 0) {
                set_remove(u->meta.dependencies[d], other);
                return r;
        }

        unit_add_to_dbus_queue(u);
        return 0;
}

int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name) {
        Unit *other;
        int r;

        if ((r = manager_load_unit(u->meta.manager, name, &other)) < 0)
                return r;

        if ((r = unit_add_dependency(u, d, other)) < 0)
                return r;

        return 0;
}

const char *unit_path(void) {
        char *e;

        if ((e = getenv("UNIT_PATH")))
                if (path_is_absolute(e))
                    return e;

        return UNIT_PATH;
}

int set_unit_path(const char *p) {
        char *cwd, *c;
        int r;

        /* This is mostly for debug purposes */

        if (path_is_absolute(p)) {
                if (!(c = strdup(p)))
                        return -ENOMEM;
        } else {
                if (!(cwd = get_current_dir_name()))
                        return -errno;

                r = asprintf(&c, "%s/%s", cwd, p);
                free(cwd);

                if (r < 0)
                        return -ENOMEM;
        }

        if (setenv("UNIT_PATH", c, 0) < 0) {
                r = -errno;
                free(c);
                return r;
        }

        return 0;
}

char *unit_name_escape_path(const char *prefix, const char *path, const char *suffix) {
        char *r, *t;
        const char *f;
        size_t a, b, c;

        assert(path);

        /* Takes a path and a suffix and prefix and makes a nice
         * string suitable as unit name of it, escaping all weird
         * chars on the way.
         *
         * / becomes ., and all chars not alloweed in a unit name get
         * escaped as \xFF, including \ and ., of course. This
         * escaping is hence reversible.
         */

        if (!prefix)
                prefix = "";

        if (!suffix)
                suffix = "";

        a = strlen(prefix);
        b = strlen(path);
        c = strlen(suffix);

        if (!(r = new(char, a+b*4+c+1)))
                return NULL;

        memcpy(r, prefix, a);

        for (f = path, t = r+a; *f; f++) {
                if (*f == '/')
                        *(t++) = '.';
                else if (*f == '.' || *f == '\\' || !strchr(VALID_CHARS, *f)) {
                        *(t++) = '\\';
                        *(t++) = 'x';
                        *(t++) = hexchar(*f > 4);
                        *(t++) = hexchar(*f);
                } else
                        *(t++) = *f;
        }

        memcpy(t, suffix, c+1);

        return r;
}

char *unit_dbus_path(Unit *u) {
        char *p, *e;

        assert(u);

        if (!(e = bus_path_escape(unit_id(u))))
                return NULL;

        if (asprintf(&p, "/org/freedesktop/systemd1/unit/%s", e) < 0) {
                free(e);
                return NULL;
        }

        free(e);
        return p;
}

static const char* const unit_type_table[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = "service",
        [UNIT_TIMER] = "timer",
        [UNIT_SOCKET] = "socket",
        [UNIT_TARGET] = "target",
        [UNIT_DEVICE] = "device",
        [UNIT_MOUNT] = "mount",
        [UNIT_AUTOMOUNT] = "automount",
        [UNIT_SNAPSHOT] = "snapshot"
};

DEFINE_STRING_TABLE_LOOKUP(unit_type, UnitType);

static const char* const unit_load_state_table[_UNIT_LOAD_STATE_MAX] = {
        [UNIT_STUB] = "stub",
        [UNIT_LOADED] = "loaded",
        [UNIT_FAILED] = "failed"
};

DEFINE_STRING_TABLE_LOOKUP(unit_load_state, UnitLoadState);

static const char* const unit_active_state_table[_UNIT_ACTIVE_STATE_MAX] = {
        [UNIT_ACTIVE] = "active",
        [UNIT_INACTIVE] = "inactive",
        [UNIT_ACTIVATING] = "activating",
        [UNIT_DEACTIVATING] = "deactivating"
};

DEFINE_STRING_TABLE_LOOKUP(unit_active_state, UnitActiveState);

static const char* const unit_dependency_table[_UNIT_DEPENDENCY_MAX] = {
        [UNIT_REQUIRES] = "Requires",
        [UNIT_SOFT_REQUIRES] = "SoftRequires",
        [UNIT_WANTS] = "Wants",
        [UNIT_REQUISITE] = "Requisite",
        [UNIT_SOFT_REQUISITE] = "SoftRequisite",
        [UNIT_REQUIRED_BY] = "RequiredBy",
        [UNIT_SOFT_REQUIRED_BY] = "SoftRequiredBy",
        [UNIT_WANTED_BY] = "WantedBy",
        [UNIT_CONFLICTS] = "Conflicts",
        [UNIT_BEFORE] = "Before",
        [UNIT_AFTER] = "After",
};

DEFINE_STRING_TABLE_LOOKUP(unit_dependency, UnitDependency);
