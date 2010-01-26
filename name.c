/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/poll.h>

#include "set.h"
#include "name.h"
#include "macro.h"
#include "strv.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"

const NameVTable * const name_vtable[_NAME_TYPE_MAX] = {
        [NAME_SERVICE] = &service_vtable,
        [NAME_TIMER] = &timer_vtable,
        [NAME_SOCKET] = &socket_vtable,
        [NAME_TARGET] = &target_vtable,
        [NAME_DEVICE] = &device_vtable,
        [NAME_MOUNT] = &mount_vtable,
        [NAME_AUTOMOUNT] = &automount_vtable,
        [NAME_SNAPSHOT] = &snapshot_vtable
};

NameType name_type_from_string(const char *n) {
        NameType t;

        assert(n);

        for (t = 0; t < _NAME_TYPE_MAX; t++)
                if (endswith(n, name_vtable[t]->suffix))
                        return t;

        return _NAME_TYPE_INVALID;
}

#define VALID_CHARS                             \
        "0123456789"                            \
        "abcdefghijklmnopqrstuvwxyz"            \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"            \
        "-_"

bool name_is_valid(const char *n) {
        NameType t;
        const char *e, *i;

        assert(n);

        if (strlen(n) >= NAME_MAX)
                return false;

        t = name_type_from_string(n);
        if (t < 0 || t >= _NAME_TYPE_MAX)
                return false;

        if (!(e = strrchr(n, '.')))
                return false;

        for (i = n; i < e; i++)
                if (!strchr(VALID_CHARS, *i))
                        return false;

        return true;
}

Name *name_new(Manager *m) {
        Name *n;

        assert(m);

        if (!(n = new0(Name, 1)))
                return NULL;

        if (!(n->meta.names = set_new(string_hash_func, string_compare_func))) {
                free(n);
                return NULL;
        }

        n->meta.manager = m;
        n->meta.type = _NAME_TYPE_INVALID;

        return n;
}

int name_add_name(Name *n, const char *text) {
        NameType t;
        char *s;
        int r;

        assert(n);
        assert(text);

        if ((t = name_type_from_string(text)) == _NAME_TYPE_INVALID)
                return -EINVAL;

        if (n->meta.type != _NAME_TYPE_INVALID && t != n->meta.type)
                return -EINVAL;

        if (!(s = strdup(text)))
                return -ENOMEM;

        if ((r = set_put(n->meta.names, s)) < 0) {
                free(s);
                return r;
        }

        if ((r = hashmap_put(n->meta.manager->names, s, n)) < 0) {
                set_remove(n->meta.names, s);
                free(s);
                return r;
        }

        n->meta.type = t;

        if (!n->meta.id)
                n->meta.id = s;

        return 0;
}

void name_add_to_load_queue(Name *n) {
        assert(n);

        if (n->meta.load_state != NAME_STUB || n->meta.in_load_queue)
                return;

        LIST_PREPEND(Meta, load_queue, n->meta.manager->load_queue, &n->meta);
        n->meta.in_load_queue = true;
}

static void bidi_set_free(Name *name, Set *s) {
        Iterator i;
        Name *other;

        assert(name);

        /* Frees the set and makes sure we are dropped from the
         * inverse pointers */

        SET_FOREACH(other, s, i) {
                NameDependency d;

                for (d = 0; d < _NAME_DEPENDENCY_MAX; d++)
                        set_remove(other->meta.dependencies[d], name);
        }

        set_free(s);
}

void name_free(Name *name) {
        NameDependency d;
        Iterator i;
        char *t;

        assert(name);

        /* Detach from next 'bigger' objects */

        SET_FOREACH(t, name->meta.names, i)
                hashmap_remove_value(name->meta.manager->names, t, name);

        if (name->meta.in_load_queue)
                LIST_REMOVE(Meta, load_queue, name->meta.manager->load_queue, &name->meta);

        if (name->meta.load_state == NAME_LOADED)
                if (NAME_VTABLE(name)->done)
                        NAME_VTABLE(name)->done(name);

        /* Free data and next 'smaller' objects */
        if (name->meta.job)
                job_free(name->meta.job);

        for (d = 0; d < _NAME_DEPENDENCY_MAX; d++)
                bidi_set_free(name, name->meta.dependencies[d]);

        free(name->meta.description);

        while ((t = set_steal_first(name->meta.names)))
                free(t);
        set_free(name->meta.names);

        free(name);
}

NameActiveState name_active_state(Name *name) {
        assert(name);

        if (name->meta.load_state != NAME_LOADED)
                return NAME_INACTIVE;

        return NAME_VTABLE(name)->active_state(name);
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

/* FIXME: Does not rollback on failure! */
int name_merge(Name *name, Name *other) {
        int r;
        NameDependency d;

        assert(name);
        assert(other);
        assert(name->meta.manager == other->meta.manager);

        /* This merges 'other' into 'name'. FIXME: This does not
         * rollback on failure. */

        if (name->meta.type != other->meta.type)
                return -EINVAL;

        if (other->meta.load_state != NAME_STUB)
                return -EINVAL;

        /* Merge names */
        if ((r = ensure_merge(&name->meta.names, other->meta.names)) < 0)
                return r;

        /* Merge dependencies */
        for (d = 0; d < _NAME_DEPENDENCY_MAX; d++)
                /* fixme, the inverse mapping is missing */
                if ((r = ensure_merge(&name->meta.dependencies[d], other->meta.dependencies[d])) < 0)
                        return r;

        return 0;
}

const char* name_id(Name *n) {
        assert(n);

        if (n->meta.id)
                return n->meta.id;

        return set_first(n->meta.names);
}

const char *name_description(Name *n) {
        assert(n);

        if (n->meta.description)
                return n->meta.description;

        return name_id(n);
}

void name_dump(Name *n, FILE *f, const char *prefix) {

        static const char* const load_state_table[_NAME_LOAD_STATE_MAX] = {
                [NAME_STUB] = "stub",
                [NAME_LOADED] = "loaded",
                [NAME_FAILED] = "failed"
        };

        static const char* const active_state_table[_NAME_ACTIVE_STATE_MAX] = {
                [NAME_ACTIVE] = "active",
                [NAME_INACTIVE] = "inactive",
                [NAME_ACTIVATING] = "activating",
                [NAME_DEACTIVATING] = "deactivating"
        };

        static const char* const dependency_table[_NAME_DEPENDENCY_MAX] = {
                [NAME_REQUIRES] = "Requires",
                [NAME_SOFT_REQUIRES] = "SoftRequires",
                [NAME_WANTS] = "Wants",
                [NAME_REQUISITE] = "Requisite",
                [NAME_SOFT_REQUISITE] = "SoftRequisite",
                [NAME_REQUIRED_BY] = "RequiredBy",
                [NAME_SOFT_REQUIRED_BY] = "SoftRequiredBy",
                [NAME_WANTED_BY] = "WantedBy",
                [NAME_CONFLICTS] = "Conflicts",
                [NAME_BEFORE] = "Before",
                [NAME_AFTER] = "After",
        };

        char *t;
        NameDependency d;
        Iterator i;
        char *prefix2;

        assert(n);

        if (!prefix)
                prefix = "";
        prefix2 = strappend(prefix, "\t");
        if (!prefix2)
                prefix2 = "";

        fprintf(f,
                "%s→ Name %s:\n"
                "%s\tDescription: %s\n"
                "%s\tName Load State: %s\n"
                "%s\tName Active State: %s\n",
                prefix, name_id(n),
                prefix, name_description(n),
                prefix, load_state_table[n->meta.load_state],
                prefix, active_state_table[name_active_state(n)]);

        SET_FOREACH(t, n->meta.names, i)
                fprintf(f, "%s\tName: %s\n", prefix, t);

        for (d = 0; d < _NAME_DEPENDENCY_MAX; d++) {
                Name *other;

                if (set_isempty(n->meta.dependencies[d]))
                        continue;

                SET_FOREACH(other, n->meta.dependencies[d], i)
                        fprintf(f, "%s\t%s: %s\n", prefix, dependency_table[d], name_id(other));
        }

        if (NAME_VTABLE(n)->dump)
                NAME_VTABLE(n)->dump(n, f, prefix2);

        if (n->meta.job)
                job_dump(n->meta.job, f, prefix2);

        free(prefix2);
}

static int verify_type(Name *name) {
        char *n;
        Iterator i;

        assert(name);

        /* Checks that all aliases of this name have the same and valid type */

        SET_FOREACH(n, name->meta.names, i) {
                NameType t;

                if ((t = name_type_from_string(n)) == _NAME_TYPE_INVALID)
                        return -EINVAL;

                if (name->meta.type == _NAME_TYPE_INVALID) {
                        name->meta.type = t;
                        continue;
                }

                if (name->meta.type != t)
                        return -EINVAL;
        }

        if (name->meta.type == _NAME_TYPE_INVALID)
                return -EINVAL;

        return 0;
}

/* Common implementation for multiple backends */
int name_load_fragment_and_dropin(Name *n) {
        int r;

        assert(n);

        /* Load a .socket file */
        if ((r = name_load_fragment(n)) < 0)
                return r;

        /* Load drop-in directory data */
        if ((r = name_load_dropin(n)) < 0)
                return r;

        return 0;
}

int name_load(Name *name) {
        int r;

        assert(name);

        if (name->meta.in_load_queue) {
                LIST_REMOVE(Meta, load_queue, name->meta.manager->load_queue, &name->meta);
                name->meta.in_load_queue = false;
        }

        if (name->meta.load_state != NAME_STUB)
                return 0;

        if ((r = verify_type(name)) < 0)
                return r;

        if (NAME_VTABLE(name)->init)
                if ((r = NAME_VTABLE(name)->init(name)) < 0)
                        goto fail;

        name->meta.load_state = NAME_LOADED;
        return 0;

fail:
        name->meta.load_state = NAME_FAILED;
        return r;
}

/* Errors:
 *         -EBADR:    This name type does not support starting.
 *         -EALREADY: Name is already started.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int name_start(Name *n) {
        NameActiveState state;

        assert(n);

        if (!NAME_VTABLE(n)->start)
                return -EBADR;

        state = name_active_state(n);
        if (NAME_IS_ACTIVE_OR_RELOADING(state))
                return -EALREADY;

        /* We don't suppress calls to ->start() here when we are
         * already starting, to allow this request to be used as a
         * "hurry up" call, for example when the name is in some "auto
         * restart" state where it waits for a holdoff timer to elapse
         * before it will start again. */

        return NAME_VTABLE(n)->start(n);
}

bool name_can_start(Name *n) {
        assert(n);

        return !!NAME_VTABLE(n)->start;
}

/* Errors:
 *         -EBADR:    This name type does not support stopping.
 *         -EALREADY: Name is already stopped.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int name_stop(Name *n) {
        NameActiveState state;

        assert(n);

        if (!NAME_VTABLE(n)->stop)
                return -EBADR;

        state = name_active_state(n);
        if (state == NAME_INACTIVE)
                return -EALREADY;

        if (state == NAME_DEACTIVATING)
                return 0;

        return NAME_VTABLE(n)->stop(n);
}

/* Errors:
 *         -EBADR:    This name type does not support reloading.
 *         -ENOEXEC:  Name is not started.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int name_reload(Name *n) {
        NameActiveState state;

        assert(n);

        if (!name_can_reload(n))
                return -EBADR;

        state = name_active_state(n);
        if (name_active_state(n) == NAME_ACTIVE_RELOADING)
                return -EALREADY;

        if (name_active_state(n) != NAME_ACTIVE)
                return -ENOEXEC;

        return NAME_VTABLE(n)->reload(n);
}

bool name_can_reload(Name *n) {
        assert(n);

        if (!NAME_VTABLE(n)->reload)
                return false;

        if (!NAME_VTABLE(n)->can_reload)
                return true;

        return NAME_VTABLE(n)->can_reload(n);
}

static void retroactively_start_dependencies(Name *n) {
        Iterator i;
        Name *other;

        assert(n);
        assert(NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(n)));

        SET_FOREACH(other, n->meta.dependencies[NAME_REQUIRES], i)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_REPLACE, true, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_SOFT_REQUIRES], i)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_FAIL, false, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_REQUISITE], i)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_REPLACE, true, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_WANTS], i)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_FAIL, false, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_CONFLICTS], i)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_STOP, other, JOB_REPLACE, true, NULL);
}

static void retroactively_stop_dependencies(Name *n) {
        Iterator i;
        Name *other;

        assert(n);
        assert(NAME_IS_INACTIVE_OR_DEACTIVATING(name_active_state(n)));

        SET_FOREACH(other, n->meta.dependencies[NAME_REQUIRED_BY], i)
                if (!NAME_IS_INACTIVE_OR_DEACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_STOP, other, JOB_REPLACE, true, NULL);
}

void name_notify(Name *n, NameActiveState os, NameActiveState ns) {
        assert(n);
        assert(os < _NAME_ACTIVE_STATE_MAX);
        assert(ns < _NAME_ACTIVE_STATE_MAX);
        assert(!(os == NAME_ACTIVE && ns == NAME_ACTIVATING));
        assert(!(os == NAME_INACTIVE && ns == NAME_DEACTIVATING));

        if (os == ns)
                return;

        if (!NAME_IS_ACTIVE_OR_RELOADING(os) && NAME_IS_ACTIVE_OR_RELOADING(ns))
                n->meta.active_enter_timestamp = now(CLOCK_REALTIME);
        else if (NAME_IS_ACTIVE_OR_RELOADING(os) && !NAME_IS_ACTIVE_OR_RELOADING(ns))
                n->meta.active_exit_timestamp = now(CLOCK_REALTIME);

        if (n->meta.job) {

                if (n->meta.job->state == JOB_WAITING)

                        /* So we reached a different state for this
                         * job. Let's see if we can run it now if it
                         * failed previously due to EAGAIN. */
                        job_schedule_run(n->meta.job);

                else {
                        assert(n->meta.job->state == JOB_RUNNING);

                        /* Let's check of this state change
                         * constitutes a finished job, or maybe
                         * cotradicts a running job and hence needs to
                         * invalidate jobs. */

                        switch (n->meta.job->type) {

                                case JOB_START:
                                case JOB_VERIFY_ACTIVE:

                                        if (NAME_IS_ACTIVE_OR_RELOADING(ns)) {
                                                job_finish_and_invalidate(n->meta.job, true);
                                                return;
                                        } else if (ns == NAME_ACTIVATING)
                                                return;
                                        else
                                                job_finish_and_invalidate(n->meta.job, false);

                                        break;

                                case JOB_RELOAD:
                                case JOB_RELOAD_OR_START:

                                        if (ns == NAME_ACTIVE) {
                                                job_finish_and_invalidate(n->meta.job, true);
                                                return;
                                        } else if (ns == NAME_ACTIVATING || ns == NAME_ACTIVE_RELOADING)
                                                return;
                                        else
                                                job_finish_and_invalidate(n->meta.job, false);

                                        break;

                                case JOB_STOP:
                                case JOB_RESTART:
                                case JOB_TRY_RESTART:

                                        if (ns == NAME_INACTIVE) {
                                                job_finish_and_invalidate(n->meta.job, true);
                                                return;
                                        } else if (ns == NAME_DEACTIVATING)
                                                return;
                                        else
                                                job_finish_and_invalidate(n->meta.job, false);

                                        break;

                                default:
                                        assert_not_reached("Job type unknown");
                        }
                }
        }

        /* If this state change happened without being requested by a
         * job, then let's retroactively start or stop dependencies */

        if (NAME_IS_INACTIVE_OR_DEACTIVATING(os) && NAME_IS_ACTIVE_OR_ACTIVATING(ns))
                retroactively_start_dependencies(n);
        else if (NAME_IS_ACTIVE_OR_ACTIVATING(os) && NAME_IS_INACTIVE_OR_DEACTIVATING(ns))
                retroactively_stop_dependencies(n);
}

int name_watch_fd(Name *n, int fd, uint32_t events) {
        struct epoll_event ev;

        assert(n);
        assert(fd >= 0);

        zero(ev);
        ev.data.fd = fd;
        ev.data.ptr = n;
        ev.data.u32 = MANAGER_FD;
        ev.events = events;

        if (epoll_ctl(n->meta.manager->epoll_fd, EPOLL_CTL_ADD, fd, &ev) >= 0)
                return 0;

        if (errno == EEXIST)
                if (epoll_ctl(n->meta.manager->epoll_fd, EPOLL_CTL_MOD, fd, &ev) >= 0)
                        return 0;

        return -errno;
}

void name_unwatch_fd(Name *n, int fd) {
        assert(n);
        assert(fd >= 0);

        assert_se(epoll_ctl(n->meta.manager->epoll_fd, EPOLL_CTL_DEL, fd, NULL) >= 0 || errno == ENOENT);
}

int name_watch_pid(Name *n, pid_t pid) {
        assert(n);
        assert(pid >= 1);

        return hashmap_put(n->meta.manager->watch_pids, UINT32_TO_PTR(pid), n);
}

void name_unwatch_pid(Name *n, pid_t pid) {
        assert(n);
        assert(pid >= 1);

        hashmap_remove(n->meta.manager->watch_pids, UINT32_TO_PTR(pid));
}

int name_watch_timer(Name *n, usec_t delay, int *id) {
        struct epoll_event ev;
        int fd;
        struct itimerspec its;
        int flags;
        bool ours;

        assert(n);
        assert(id);

        /* This will try to reuse the old timer if there is one */

        if (*id >= 0) {
                ours = false;
                fd = *id;

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

        zero(ev);
        ev.data.fd = fd;
        ev.data.ptr = n;
        ev.data.u32 = MANAGER_TIMER;
        ev.events = POLLIN;

        if (epoll_ctl(n->meta.manager->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                goto fail;

        *id = fd;
        return 0;

fail:
        if (ours)
                assert_se(close_nointr(fd) == 0);

        return -errno;
}

void name_unwatch_timer(Name *n, int *id) {
        assert(n);
        assert(id);

        if (*id >= 0) {
                assert_se(epoll_ctl(n->meta.manager->epoll_fd, EPOLL_CTL_DEL, *id, NULL) >= 0);
                assert_se(close_nointr(*id) == 0);

                *id = -1;
        }
}

char *name_change_suffix(const char *t, const char *suffix) {
        char *e, *n;
        size_t a, b;

        assert(t);
        assert(name_is_valid(t));
        assert(suffix);

        assert_se(e = strrchr(t, '.'));
        a = e - t;
        b = strlen(suffix);

        if (!(n = new(char, a + b + 1)))
                return NULL;

        memcpy(n, t, a);
        memcpy(n+a, suffix, b+1);

        return n;
}

bool name_job_is_applicable(Name *n, JobType j) {
        assert(n);
        assert(j >= 0 && j < _JOB_TYPE_MAX);

        switch (j) {
                case JOB_VERIFY_ACTIVE:
                case JOB_START:
                        return true;

                case JOB_STOP:
                case JOB_RESTART:
                case JOB_TRY_RESTART:
                        return name_can_start(n);

                case JOB_RELOAD:
                        return name_can_reload(n);

                case JOB_RELOAD_OR_START:
                        return name_can_reload(n) && name_can_start(n);

                default:
                        assert_not_reached("Invalid job type");
        }
}

int name_add_dependency(Name *n, NameDependency d, Name *other) {

        static const NameDependency inverse_table[_NAME_DEPENDENCY_MAX] = {
                [NAME_REQUIRES] = NAME_REQUIRED_BY,
                [NAME_SOFT_REQUIRES] = NAME_SOFT_REQUIRED_BY,
                [NAME_WANTS] = NAME_WANTED_BY,
                [NAME_REQUISITE] = NAME_REQUIRED_BY,
                [NAME_SOFT_REQUISITE] = NAME_SOFT_REQUIRED_BY,
                [NAME_REQUIRED_BY] = _NAME_DEPENDENCY_INVALID,
                [NAME_SOFT_REQUIRED_BY] = _NAME_DEPENDENCY_INVALID,
                [NAME_WANTED_BY] = _NAME_DEPENDENCY_INVALID,
                [NAME_CONFLICTS] = NAME_CONFLICTS,
                [NAME_BEFORE] = NAME_AFTER,
                [NAME_AFTER] = NAME_BEFORE
        };
        int r;

        assert(n);
        assert(d >= 0 && d < _NAME_DEPENDENCY_MAX);
        assert(inverse_table[d] != _NAME_DEPENDENCY_INVALID);
        assert(other);

        if (n == other)
                return 0;

        if ((r = set_ensure_allocated(&n->meta.dependencies[d], trivial_hash_func, trivial_compare_func)) < 0)
                return r;

        if ((r = set_ensure_allocated(&other->meta.dependencies[inverse_table[d]], trivial_hash_func, trivial_compare_func)) < 0)
                return r;

        if ((r = set_put(n->meta.dependencies[d], other)) < 0)
                return r;

        if ((r = set_put(other->meta.dependencies[inverse_table[d]], n)) < 0) {
                set_remove(n->meta.dependencies[d], other);
                return r;
        }

        return 0;
}
