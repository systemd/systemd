/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

        u->meta.type = t;

        if (!u->meta.id)
                u->meta.id = s;

        return 0;
}

void unit_add_to_load_queue(Unit *u) {
        assert(u);

        if (u->meta.load_state != UNIT_STUB || u->meta.in_load_queue)
                return;

        LIST_PREPEND(Meta, load_queue, u->meta.manager->load_queue, &u->meta);
        u->meta.in_load_queue = true;
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

        /* Detach from next 'bigger' objects */

        SET_FOREACH(t, u->meta.names, i)
                hashmap_remove_value(u->meta.manager->units, t, u);

        if (u->meta.in_load_queue)
                LIST_REMOVE(Meta, load_queue, u->meta.manager->load_queue, &u->meta);

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

        static const char* const load_state_table[_UNIT_LOAD_STATE_MAX] = {
                [UNIT_STUB] = "stub",
                [UNIT_LOADED] = "loaded",
                [UNIT_FAILED] = "failed"
        };

        static const char* const active_state_table[_UNIT_ACTIVE_STATE_MAX] = {
                [UNIT_ACTIVE] = "active",
                [UNIT_INACTIVE] = "inactive",
                [UNIT_ACTIVATING] = "activating",
                [UNIT_DEACTIVATING] = "deactivating"
        };

        static const char* const dependency_table[_UNIT_DEPENDENCY_MAX] = {
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

        char *t;
        UnitDependency d;
        Iterator i;
        char *prefix2;

        assert(u);

        if (!prefix)
                prefix = "";
        prefix2 = strappend(prefix, "\t");
        if (!prefix2)
                prefix2 = "";

        fprintf(f,
                "%s→ Unit %s:\n"
                "%s\tDescription: %s\n"
                "%s\tUnit Load State: %s\n"
                "%s\tUnit Active State: %s\n",
                prefix, unit_id(u),
                prefix, unit_description(u),
                prefix, load_state_table[u->meta.load_state],
                prefix, active_state_table[unit_active_state(u)]);

        if (u->meta.load_path)
                fprintf(f, "%s\tLoad Path: %s\n", prefix, u->meta.load_path);

        SET_FOREACH(t, u->meta.names, i)
                fprintf(f, "%s\tName: %s\n", prefix, t);

        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
                Unit *other;

                if (set_isempty(u->meta.dependencies[d]))
                        continue;

                SET_FOREACH(other, u->meta.dependencies[d], i)
                        fprintf(f, "%s\t%s: %s\n", prefix, dependency_table[d], unit_id(other));
        }

        if (UNIT_VTABLE(u)->dump)
                UNIT_VTABLE(u)->dump(u, f, prefix2);

        if (u->meta.job)
                job_dump(u->meta.job, f, prefix2);

        free(prefix2);
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
        return 0;

fail:
        u->meta.load_state = UNIT_FAILED;
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

        SET_FOREACH(other, u->meta.dependencies[UNIT_REQUIRED_BY], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        manager_add_job(u->meta.manager, JOB_STOP, other, JOB_REPLACE, true, NULL);
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
                        job_schedule_run(u->meta.job);

                else {
                        assert(u->meta.job->state == JOB_RUNNING);

                        /* Let's check of this state change
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
}

int unit_watch_fd(Unit *u, int fd, uint32_t events, Watch *w) {
        struct epoll_event ev;

        assert(u);
        assert(fd >= 0);
        assert(w);
        assert(w->type == WATCH_INVALID || (w->type == WATCH_FD && w->fd == fd && w->unit == u));

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
        w->unit = u;

        return 0;
}

void unit_unwatch_fd(Unit *u, Watch *w) {
        assert(u);
        assert(w);

        if (w->type == WATCH_INVALID)
                return;

        assert(w->type == WATCH_FD && w->unit == u);
        assert_se(epoll_ctl(u->meta.manager->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);

        w->fd = -1;
        w->type = WATCH_INVALID;
        w->unit = NULL;
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
        assert(w->type == WATCH_INVALID || (w->type == WATCH_TIMER && w->unit == u));

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
                ev.events = POLLIN;

                if (epoll_ctl(u->meta.manager->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                        goto fail;
        }

        w->fd = fd;
        w->type = WATCH_TIMER;
        w->unit = u;

        return 0;

fail:
        if (ours)
                assert_se(close_nointr(fd) == 0);

        return -errno;
}

void unit_unwatch_timer(Unit *u, Watch *w) {
        assert(u);
        assert(w);

        if (w->type == WATCH_INVALID)
                return;

        assert(w->type == WATCH_TIMER && w->unit == u);

        assert_se(epoll_ctl(u->meta.manager->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);
        assert_se(close_nointr(w->fd) == 0);

        w->fd = -1;
        w->type = WATCH_INVALID;
        w->unit = NULL;
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

char *unit_name_escape_path(const char *path, const char *suffix) {
        char *r, *t;
        const char *f;
        size_t a, b;

        assert(path);
        assert(suffix);

        /* Takes a path and a util suffix and makes a nice unit name
         * of it, escaping all weird chars on the way.
         *
         * / becomes _, and all chars not alloweed in a unit name get
         * escaped as \xFF, including the _ and the \ itself, of
         * course. This escaping is hence reversible.
         */

        a = strlen(path);
        b = strlen(suffix);

        if (!(r = new(char, a*4+b+1)))
                return NULL;

        for (f = path, t = r; *f; f++) {
                if (*f == '/')
                        *(t++) = '_';
                else if (*f == '_' || *f == '\\' || !strchr(VALID_CHARS, *f)) {
                        *(t++) = '\\';
                        *(t++) = 'x';
                        *(t++) = hexchar(*f > 4);
                        *(t++) = hexchar(*f);
                } else
                        *(t++) = *f;
        }

        memcpy(t, suffix, b+1);

        return r;
}
