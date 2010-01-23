/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "set.h"
#include "name.h"
#include "macro.h"
#include "strv.h"
#include "load-fragment.h"
#include "load-dropin.h"

static const NameVTable * const name_vtable[_NAME_TYPE_MAX] = {
        [NAME_SERVICE] = &service_vtable,
        [NAME_TIMER] = &timer_vtable,
        [NAME_SOCKET] = &socket_vtable,
        [NAME_MILESTONE] = &milestone_vtable,
        [NAME_DEVICE] = &device_vtable,
        [NAME_MOUNT] = &mount_vtable,
        [NAME_AUTOMOUNT] = &automount_vtable,
        [NAME_SNAPSHOT] = &snapshot_vtable
};

#define NAME_VTABLE(n) name_vtable[(n)->meta.type]

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

        /* Not much initialization happening here at this time */
        n->meta.manager = m;
        n->meta.type = _NAME_TYPE_INVALID;

        /* We don't link the name here, that is left for name_link() */

        return n;
}

/* FIXME: Does not rollback on failure! */
int name_link_names(Name *n, bool replace) {
        char *t;
        void *state;
        int r;

        assert(n);

        if (!n->meta.linked)
                return 0;

        /* Link all names that aren't linked yet. */

        SET_FOREACH(t, n->meta.names, state)
                if (replace) {
                        if ((r = hashmap_replace(n->meta.manager->names, t, n)) < 0)
                                return r;
                } else {
                        if ((r = hashmap_put(n->meta.manager->names, t, n)) < 0)
                                return r;
                }

        return 0;
}

int name_link(Name *n) {
        int r;

        assert(n);
        assert(!set_isempty(n->meta.names));
        assert(!n->meta.linked);

        if ((r = name_sanitize(n)) < 0)
                return r;

        n->meta.linked = true;

        if ((r = name_link_names(n, false)) < 0) {
                char *t;
                void *state;

                /* Rollback the registered names */
                SET_FOREACH(t, n->meta.names, state)
                        hashmap_remove_value(n->meta.manager->names, t, n);

                n->meta.linked = false;
                return r;
        }

        if (n->meta.load_state == NAME_STUB)
                LIST_PREPEND(Meta, n->meta.manager->load_queue, &n->meta);

        return 0;
}

static void bidi_set_free(Name *name, Set *s) {
        void *state;
        Name *other;

        assert(name);

        /* Frees the set and makes sure we are dropped from the
         * inverse pointers */

        SET_FOREACH(other, s, state) {
                NameDependency d;

                for (d = 0; d < _NAME_DEPENDENCY_MAX; d++)
                        set_remove(other->meta.dependencies[d], name);
        }

        set_free(s);
}

void name_free(Name *name) {
        NameDependency d;
        char *t;

        assert(name);

        /* Detach from next 'bigger' objects */
        if (name->meta.linked) {
                char *t;
                void *state;

                SET_FOREACH(t, name->meta.names, state)
                        hashmap_remove_value(name->meta.manager->names, t, name);

                if (name->meta.load_state == NAME_STUB)
                        LIST_REMOVE(Meta, name->meta.manager->load_queue, &name->meta);
        }

        /* Free data and next 'smaller' objects */
        if (name->meta.job)
                job_free(name->meta.job);

        for (d = 0; d < _NAME_DEPENDENCY_MAX; d++)
                bidi_set_free(name, name->meta.dependencies[d]);

        if (NAME_VTABLE(name)->free_hook)
                NAME_VTABLE(name)->free_hook(name);

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

static int ensure_in_set(Set **s, void *data) {
        int r;

        assert(s);
        assert(data);

        if (!*s)
                if (!(*s = set_new(trivial_hash_func, trivial_compare_func)))
                        return -ENOMEM;

        if ((r = set_put(*s, data)) < 0)
                if (r != -EEXIST)
                        return r;

        return 0;
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
                if ((r = ensure_merge(&name->meta.dependencies[d], other->meta.dependencies[d])) < 0)
                        return r;

        /* Hookup new deps and names */
        if (name->meta.linked) {
                if ((r = name_sanitize(name)) < 0)
                        return r;

                if ((r = name_link_names(name, true)) < 0)
                        return r;
        }

        return 0;
}

/* FIXME: Does not rollback on failure! */
static int augment(Name *n) {
        int r;
        void* state;
        Name *other;

        assert(n);

        /* Adds in the missing links to make all dependencies
         * bidirectional. */

        SET_FOREACH(other, n->meta.dependencies[NAME_BEFORE], state)
                if ((r = ensure_in_set(&other->meta.dependencies[NAME_AFTER], n)) < 0)
                        return r;
        SET_FOREACH(other, n->meta.dependencies[NAME_AFTER], state)
                if ((r = ensure_in_set(&other->meta.dependencies[NAME_BEFORE], n)) < 0)
                        return r;

        SET_FOREACH(other, n->meta.dependencies[NAME_CONFLICTS], state)
                if ((r = ensure_in_set(&other->meta.dependencies[NAME_CONFLICTS], n)) < 0)
                        return r;

        SET_FOREACH(other, n->meta.dependencies[NAME_REQUIRES], state)
                if ((r = ensure_in_set(&other->meta.dependencies[NAME_REQUIRED_BY], n)) < 0)
                        return r;
        SET_FOREACH(other, n->meta.dependencies[NAME_REQUISITE], state)
                if ((r = ensure_in_set(&other->meta.dependencies[NAME_REQUIRED_BY], n)) < 0)
                        return r;

        SET_FOREACH(other, n->meta.dependencies[NAME_SOFT_REQUIRES], state)
                if ((r = ensure_in_set(&other->meta.dependencies[NAME_SOFT_REQUIRED_BY], n)) < 0)
                        return r;

        SET_FOREACH(other, n->meta.dependencies[NAME_WANTS], state)
                if ((r = ensure_in_set(&other->meta.dependencies[NAME_WANTED_BY], n)) < 0)
                        return r;

        return 0;
}

int name_sanitize(Name *n) {
        NameDependency d;

        assert(n);

        /* Remove loops */
        for (d = 0; d < _NAME_DEPENDENCY_MAX; d++)
                set_remove(n->meta.dependencies[d], n);

        return augment(n);
}

const char* name_id(Name *n) {
        assert(n);

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
                [NAME_CONFLICTS] = "Conflicts",
                [NAME_BEFORE] = "Before",
                [NAME_AFTER] = "After",
        };

        void *state;
        char *t;
        NameDependency d;

        assert(n);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%sName %s:\n"
                "%s\tDescription: %s\n"
                "%s\tName Load State: %s\n"
                "%s\tName Active State: %s\n",
                prefix, name_id(n),
                prefix, name_description(n),
                prefix, load_state_table[n->meta.load_state],
                prefix, active_state_table[name_active_state(n)]);

        SET_FOREACH(t, n->meta.names, state)
                fprintf(f, "%s\tName: %s\n", prefix, t);

        for (d = 0; d < _NAME_DEPENDENCY_MAX; d++) {
                void *state;
                Name *other;

                if (set_isempty(n->meta.dependencies[d]))
                        continue;

                SET_FOREACH(other, n->meta.dependencies[d], state)
                        fprintf(f, "%s\t%s: %s\n", prefix, dependency_table[d], name_id(other));
        }

        if (NAME_VTABLE(n)->dump)
                NAME_VTABLE(n)->dump(n, f, prefix);

        if (n->meta.job) {
                char *p;

                if (asprintf(&p, "%s\t", prefix) >= 0)
                        prefix = p;
                else
                        p = NULL;

                job_dump(n->meta.job, f, prefix);
                free(p);
        }
}

static int verify_type(Name *name) {
        char *n;
        void *state;

        assert(name);

        /* Checks that all aliases of this name have the same and valid type */

        SET_FOREACH(n, name->meta.names, state) {
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

        if (name->meta.load_state != NAME_STUB)
                return 0;

        if ((r = verify_type(name)) < 0)
                return r;

        if (NAME_VTABLE(name)->load)
                if ((r = NAME_VTABLE(name)->load(name)) < 0)
                        goto fail;

        if ((r = name_sanitize(name)) < 0)
                goto fail;

        if ((r = name_link_names(name, false)) < 0)
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

        if (state == NAME_ACTIVATING)
                return 0;

        return NAME_VTABLE(n)->start(n);
}

bool name_type_can_start(NameType t) {
        assert(t >= 0 && t < _NAME_TYPE_MAX);

        return !!name_vtable[t]->start;
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

        if (!NAME_VTABLE(n)->reload)
                return -EBADR;

        state = name_active_state(n);
        if (name_active_state(n) == NAME_ACTIVE_RELOADING)
                return -EALREADY;

        if (name_active_state(n) != NAME_ACTIVE)
                return -ENOEXEC;

        return NAME_VTABLE(n)->reload(n);
}

bool name_type_can_reload(NameType t) {
        assert(t >= 0 && t < _NAME_TYPE_MAX);
        return !!name_vtable[t]->reload;
}

static void retroactively_start_dependencies(Name *n) {
        void *state;
        Name *other;

        assert(n);
        assert(NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(n)));

        SET_FOREACH(other, n->meta.dependencies[NAME_REQUIRES], state)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_REPLACE, true, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_SOFT_REQUIRES], state)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_FAIL, false, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_REQUISITE], state)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_REPLACE, true, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_WANTS], state)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_START, other, JOB_FAIL, false, NULL);

        SET_FOREACH(other, n->meta.dependencies[NAME_CONFLICTS], state)
                if (!NAME_IS_ACTIVE_OR_ACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_STOP, other, JOB_REPLACE, true, NULL);
}

static void retroactively_stop_dependencies(Name *n) {
        void *state;
        Name *other;

        assert(n);
        assert(NAME_IS_INACTIVE_OR_DEACTIVATING(name_active_state(n)));

        SET_FOREACH(other, n->meta.dependencies[NAME_REQUIRED_BY], state)
                if (!NAME_IS_INACTIVE_OR_DEACTIVATING(name_active_state(other)))
                        manager_add_job(n->meta.manager, JOB_STOP, other, JOB_REPLACE, true, NULL);
}

int name_notify(Name *n, NameActiveState os, NameActiveState ns) {
        assert(n);
        assert(os < _NAME_ACTIVE_STATE_MAX);
        assert(ns < _NAME_ACTIVE_STATE_MAX);
        assert(!(os == NAME_ACTIVE && ns == NAME_ACTIVATING));
        assert(!(os == NAME_INACTIVE && ns == NAME_DEACTIVATING));

        if (os == ns)
                return 0;

        if (n->meta.job) {

                if (n->meta.job->state == JOB_WAITING)

                        /* So we reached a different state for this
                         * job. Let's see if we can run it now if it
                         * failed previously due to EAGAIN. */
                        job_run_and_invalidate(n->meta.job);

                else {
                        assert(n->meta.job->state == JOB_RUNNING);

                        /* Let's check of this state change
                         * constitutes a finished job, or maybe
                         * cotradicts a running job and hence needs to
                         * invalidate jobs. */

                        switch (n->meta.job->type) {

                                case JOB_START:
                                case JOB_VERIFY_ACTIVE:

                                        if (NAME_IS_ACTIVE_OR_RELOADING(ns))
                                                return job_finish_and_invalidate(n->meta.job, true);
                                        else if (ns == NAME_ACTIVATING)
                                                return 0;
                                        else
                                                job_finish_and_invalidate(n->meta.job, false);

                                        break;

                                case JOB_RELOAD:
                                case JOB_RELOAD_OR_START:

                                        if (ns == NAME_ACTIVE)
                                                return job_finish_and_invalidate(n->meta.job, true);
                                        else if (ns == NAME_ACTIVATING || ns == NAME_ACTIVE_RELOADING)
                                                return 0;
                                        else
                                                job_finish_and_invalidate(n->meta.job, false);

                                        break;

                                case JOB_STOP:
                                case JOB_RESTART:
                                case JOB_TRY_RESTART:

                                        if (ns == NAME_INACTIVE)
                                                return job_finish_and_invalidate(n->meta.job, true);
                                        else if (ns == NAME_DEACTIVATING)
                                                return 0;
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

        return 0;
}
