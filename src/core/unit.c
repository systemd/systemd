/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "systemd/sd-id128.h"
#include "systemd/sd-messages.h"
#include "set.h"
#include "unit.h"
#include "macro.h"
#include "strv.h"
#include "path-util.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "unit-name.h"
#include "dbus-unit.h"
#include "special.h"
#include "cgroup-util.h"
#include "missing.h"
#include "cgroup-attr.h"
#include "mkdir.h"
#include "label.h"
#include "fileio-label.h"
#include "bus-errors.h"

const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = &service_vtable,
        [UNIT_TIMER] = &timer_vtable,
        [UNIT_SOCKET] = &socket_vtable,
        [UNIT_TARGET] = &target_vtable,
        [UNIT_DEVICE] = &device_vtable,
        [UNIT_MOUNT] = &mount_vtable,
        [UNIT_AUTOMOUNT] = &automount_vtable,
        [UNIT_SNAPSHOT] = &snapshot_vtable,
        [UNIT_SWAP] = &swap_vtable,
        [UNIT_PATH] = &path_vtable
};

Unit *unit_new(Manager *m, size_t size) {
        Unit *u;

        assert(m);
        assert(size >= sizeof(Unit));

        u = malloc0(size);
        if (!u)
                return NULL;

        u->names = set_new(string_hash_func, string_compare_func);
        if (!u->names) {
                free(u);
                return NULL;
        }

        u->manager = m;
        u->type = _UNIT_TYPE_INVALID;
        u->deserialized_job = _JOB_TYPE_INVALID;
        u->default_dependencies = true;
        u->unit_file_state = _UNIT_FILE_STATE_INVALID;

        return u;
}

bool unit_has_name(Unit *u, const char *name) {
        assert(u);
        assert(name);

        return !!set_get(u->names, (char*) name);
}

int unit_add_name(Unit *u, const char *text) {
        UnitType t;
        char *s, *i = NULL;
        int r;

        assert(u);
        assert(text);

        if (unit_name_is_template(text)) {
                if (!u->instance)
                        return -EINVAL;

                s = unit_name_replace_instance(text, u->instance);
        } else
                s = strdup(text);

        if (!s)
                return -ENOMEM;

        if (!unit_name_is_valid(s, false)) {
                r = -EINVAL;
                goto fail;
        }

        assert_se((t = unit_name_to_type(s)) >= 0);

        if (u->type != _UNIT_TYPE_INVALID && t != u->type) {
                r = -EINVAL;
                goto fail;
        }

        if ((r = unit_name_to_instance(s, &i)) < 0)
                goto fail;

        if (i && unit_vtable[t]->no_instances) {
                r = -EINVAL;
                goto fail;
        }

        /* Ensure that this unit is either instanced or not instanced,
         * but not both. */
        if (u->type != _UNIT_TYPE_INVALID && !u->instance != !i) {
                r = -EINVAL;
                goto fail;
        }

        if (unit_vtable[t]->no_alias &&
            !set_isempty(u->names) &&
            !set_get(u->names, s)) {
                r = -EEXIST;
                goto fail;
        }

        if (hashmap_size(u->manager->units) >= MANAGER_MAX_NAMES) {
                r = -E2BIG;
                goto fail;
        }

        if ((r = set_put(u->names, s)) < 0) {
                if (r == -EEXIST)
                        r = 0;
                goto fail;
        }

        if ((r = hashmap_put(u->manager->units, s, u)) < 0) {
                set_remove(u->names, s);
                goto fail;
        }

        if (u->type == _UNIT_TYPE_INVALID) {

                u->type = t;
                u->id = s;
                u->instance = i;

                LIST_PREPEND(Unit, units_by_type, u->manager->units_by_type[t], u);

                if (UNIT_VTABLE(u)->init)
                        UNIT_VTABLE(u)->init(u);
        } else
                free(i);

        unit_add_to_dbus_queue(u);
        return 0;

fail:
        free(s);
        free(i);

        return r;
}

int unit_choose_id(Unit *u, const char *name) {
        char *s, *t = NULL, *i;
        int r;

        assert(u);
        assert(name);

        if (unit_name_is_template(name)) {

                if (!u->instance)
                        return -EINVAL;

                if (!(t = unit_name_replace_instance(name, u->instance)))
                        return -ENOMEM;

                name = t;
        }

        /* Selects one of the names of this unit as the id */
        s = set_get(u->names, (char*) name);
        free(t);

        if (!s)
                return -ENOENT;

        if ((r = unit_name_to_instance(s, &i)) < 0)
                return r;

        u->id = s;

        free(u->instance);
        u->instance = i;

        unit_add_to_dbus_queue(u);

        return 0;
}

int unit_set_description(Unit *u, const char *description) {
        char *s;

        assert(u);

        if (!(s = strdup(description)))
                return -ENOMEM;

        free(u->description);
        u->description = s;

        unit_add_to_dbus_queue(u);
        return 0;
}

bool unit_check_gc(Unit *u) {
        assert(u);

        if (u->load_state == UNIT_STUB)
                return true;

        if (UNIT_VTABLE(u)->no_gc)
                return true;

        if (u->no_gc)
                return true;

        if (u->job)
                return true;

        if (u->nop_job)
                return true;

        if (unit_active_state(u) != UNIT_INACTIVE)
                return true;

        if (u->refs)
                return true;

        if (UNIT_VTABLE(u)->check_gc)
                if (UNIT_VTABLE(u)->check_gc(u))
                        return true;

        return false;
}

void unit_add_to_load_queue(Unit *u) {
        assert(u);
        assert(u->type != _UNIT_TYPE_INVALID);

        if (u->load_state != UNIT_STUB || u->in_load_queue)
                return;

        LIST_PREPEND(Unit, load_queue, u->manager->load_queue, u);
        u->in_load_queue = true;
}

void unit_add_to_cleanup_queue(Unit *u) {
        assert(u);

        if (u->in_cleanup_queue)
                return;

        LIST_PREPEND(Unit, cleanup_queue, u->manager->cleanup_queue, u);
        u->in_cleanup_queue = true;
}

void unit_add_to_gc_queue(Unit *u) {
        assert(u);

        if (u->in_gc_queue || u->in_cleanup_queue)
                return;

        if (unit_check_gc(u))
                return;

        LIST_PREPEND(Unit, gc_queue, u->manager->gc_queue, u);
        u->in_gc_queue = true;

        u->manager->n_in_gc_queue ++;

        if (u->manager->gc_queue_timestamp <= 0)
                u->manager->gc_queue_timestamp = now(CLOCK_MONOTONIC);
}

void unit_add_to_dbus_queue(Unit *u) {
        assert(u);
        assert(u->type != _UNIT_TYPE_INVALID);

        if (u->load_state == UNIT_STUB || u->in_dbus_queue)
                return;

        /* Shortcut things if nobody cares */
        if (!bus_has_subscriber(u->manager)) {
                u->sent_dbus_new_signal = true;
                return;
        }

        LIST_PREPEND(Unit, dbus_queue, u->manager->dbus_unit_queue, u);
        u->in_dbus_queue = true;
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
                        set_remove(other->dependencies[d], u);

                unit_add_to_gc_queue(other);
        }

        set_free(s);
}

void unit_free(Unit *u) {
        UnitDependency d;
        Iterator i;
        char *t;

        assert(u);

        bus_unit_send_removed_signal(u);

        if (u->load_state != UNIT_STUB)
                if (UNIT_VTABLE(u)->done)
                        UNIT_VTABLE(u)->done(u);

        SET_FOREACH(t, u->names, i)
                hashmap_remove_value(u->manager->units, t, u);

        if (u->job) {
                Job *j = u->job;
                job_uninstall(j);
                job_free(j);
        }

        if (u->nop_job) {
                Job *j = u->nop_job;
                job_uninstall(j);
                job_free(j);
        }

        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                bidi_set_free(u, u->dependencies[d]);

        if (u->requires_mounts_for) {
                LIST_REMOVE(Unit, has_requires_mounts_for, u->manager->has_requires_mounts_for, u);
                strv_free(u->requires_mounts_for);
        }

        if (u->type != _UNIT_TYPE_INVALID)
                LIST_REMOVE(Unit, units_by_type, u->manager->units_by_type[u->type], u);

        if (u->in_load_queue)
                LIST_REMOVE(Unit, load_queue, u->manager->load_queue, u);

        if (u->in_dbus_queue)
                LIST_REMOVE(Unit, dbus_queue, u->manager->dbus_unit_queue, u);

        if (u->in_cleanup_queue)
                LIST_REMOVE(Unit, cleanup_queue, u->manager->cleanup_queue, u);

        if (u->in_gc_queue) {
                LIST_REMOVE(Unit, gc_queue, u->manager->gc_queue, u);
                u->manager->n_in_gc_queue--;
        }

        cgroup_bonding_free_list(u->cgroup_bondings, u->manager->n_reloading <= 0);
        cgroup_attribute_free_list(u->cgroup_attributes);

        free(u->description);
        strv_free(u->documentation);
        free(u->fragment_path);
        free(u->source_path);
        strv_free(u->dropin_paths);
        free(u->instance);

        set_free_free(u->names);

        condition_free_list(u->conditions);

        while (u->refs)
                unit_ref_unset(u->refs);

        free(u);
}

UnitActiveState unit_active_state(Unit *u) {
        assert(u);

        if (u->load_state == UNIT_MERGED)
                return unit_active_state(unit_follow_merge(u));

        /* After a reload it might happen that a unit is not correctly
         * loaded but still has a process around. That's why we won't
         * shortcut failed loading to UNIT_INACTIVE_FAILED. */

        return UNIT_VTABLE(u)->active_state(u);
}

const char* unit_sub_state_to_string(Unit *u) {
        assert(u);

        return UNIT_VTABLE(u)->sub_state_to_string(u);
}

static void complete_move(Set **s, Set **other) {
        assert(s);
        assert(other);

        if (!*other)
                return;

        if (*s)
                set_move(*s, *other);
        else {
                *s = *other;
                *other = NULL;
        }
}

static void merge_names(Unit *u, Unit *other) {
        char *t;
        Iterator i;

        assert(u);
        assert(other);

        complete_move(&u->names, &other->names);

        set_free_free(other->names);
        other->names = NULL;
        other->id = NULL;

        SET_FOREACH(t, u->names, i)
                assert_se(hashmap_replace(u->manager->units, t, u) == 0);
}

static void merge_dependencies(Unit *u, Unit *other, UnitDependency d) {
        Iterator i;
        Unit *back;
        int r;

        assert(u);
        assert(other);
        assert(d < _UNIT_DEPENDENCY_MAX);

        /* Fix backwards pointers */
        SET_FOREACH(back, other->dependencies[d], i) {
                UnitDependency k;

                for (k = 0; k < _UNIT_DEPENDENCY_MAX; k++)
                        if ((r = set_remove_and_put(back->dependencies[k], other, u)) < 0) {

                                if (r == -EEXIST)
                                        set_remove(back->dependencies[k], other);
                                else
                                        assert(r == -ENOENT);
                        }
        }

        complete_move(&u->dependencies[d], &other->dependencies[d]);

        set_free(other->dependencies[d]);
        other->dependencies[d] = NULL;
}

int unit_merge(Unit *u, Unit *other) {
        UnitDependency d;

        assert(u);
        assert(other);
        assert(u->manager == other->manager);
        assert(u->type != _UNIT_TYPE_INVALID);

        other = unit_follow_merge(other);

        if (other == u)
                return 0;

        if (u->type != other->type)
                return -EINVAL;

        if (!u->instance != !other->instance)
                return -EINVAL;

        if (other->load_state != UNIT_STUB &&
            other->load_state != UNIT_ERROR)
                return -EEXIST;

        if (other->job)
                return -EEXIST;

        if (other->nop_job)
                return -EEXIST;

        if (!UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other)))
                return -EEXIST;

        /* Merge names */
        merge_names(u, other);

        /* Redirect all references */
        while (other->refs)
                unit_ref_set(other->refs, u);

        /* Merge dependencies */
        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                merge_dependencies(u, other, d);

        other->load_state = UNIT_MERGED;
        other->merged_into = u;

        /* If there is still some data attached to the other node, we
         * don't need it anymore, and can free it. */
        if (other->load_state != UNIT_STUB)
                if (UNIT_VTABLE(other)->done)
                        UNIT_VTABLE(other)->done(other);

        unit_add_to_dbus_queue(u);
        unit_add_to_cleanup_queue(other);

        return 0;
}

int unit_merge_by_name(Unit *u, const char *name) {
        Unit *other;
        int r;
        char *s = NULL;

        assert(u);
        assert(name);

        if (unit_name_is_template(name)) {
                if (!u->instance)
                        return -EINVAL;

                if (!(s = unit_name_replace_instance(name, u->instance)))
                        return -ENOMEM;

                name = s;
        }

        if (!(other = manager_get_unit(u->manager, name)))
                r = unit_add_name(u, name);
        else
                r = unit_merge(u, other);

        free(s);
        return r;
}

Unit* unit_follow_merge(Unit *u) {
        assert(u);

        while (u->load_state == UNIT_MERGED)
                assert_se(u = u->merged_into);

        return u;
}

int unit_add_exec_dependencies(Unit *u, ExecContext *c) {
        int r;

        assert(u);
        assert(c);

        if (c->std_output != EXEC_OUTPUT_KMSG &&
            c->std_output != EXEC_OUTPUT_SYSLOG &&
            c->std_output != EXEC_OUTPUT_JOURNAL &&
            c->std_output != EXEC_OUTPUT_KMSG_AND_CONSOLE &&
            c->std_output != EXEC_OUTPUT_SYSLOG_AND_CONSOLE &&
            c->std_output != EXEC_OUTPUT_JOURNAL_AND_CONSOLE &&
            c->std_error != EXEC_OUTPUT_KMSG &&
            c->std_error != EXEC_OUTPUT_SYSLOG &&
            c->std_error != EXEC_OUTPUT_JOURNAL &&
            c->std_error != EXEC_OUTPUT_KMSG_AND_CONSOLE &&
            c->std_error != EXEC_OUTPUT_JOURNAL_AND_CONSOLE &&
            c->std_error != EXEC_OUTPUT_SYSLOG_AND_CONSOLE)
                return 0;

        /* If syslog or kernel logging is requested, make sure our own
         * logging daemon is run first. */

        if (u->manager->running_as == SYSTEMD_SYSTEM) {
                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_JOURNALD_SOCKET, NULL, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

const char *unit_description(Unit *u) {
        assert(u);

        if (u->description)
                return u->description;

        return strna(u->id);
}

void unit_dump(Unit *u, FILE *f, const char *prefix) {
        char *t, **j;
        UnitDependency d;
        Iterator i;
        char *p2;
        const char *prefix2;
        char
                timestamp1[FORMAT_TIMESTAMP_MAX],
                timestamp2[FORMAT_TIMESTAMP_MAX],
                timestamp3[FORMAT_TIMESTAMP_MAX],
                timestamp4[FORMAT_TIMESTAMP_MAX],
                timespan[FORMAT_TIMESPAN_MAX];
        Unit *following;

        assert(u);
        assert(u->type >= 0);

        if (!prefix)
                prefix = "";
        p2 = strappend(prefix, "\t");
        prefix2 = p2 ? p2 : prefix;

        fprintf(f,
                "%s-> Unit %s:\n"
                "%s\tDescription: %s\n"
                "%s\tInstance: %s\n"
                "%s\tUnit Load State: %s\n"
                "%s\tUnit Active State: %s\n"
                "%s\tInactive Exit Timestamp: %s\n"
                "%s\tActive Enter Timestamp: %s\n"
                "%s\tActive Exit Timestamp: %s\n"
                "%s\tInactive Enter Timestamp: %s\n"
                "%s\tGC Check Good: %s\n"
                "%s\tNeed Daemon Reload: %s\n",
                prefix, u->id,
                prefix, unit_description(u),
                prefix, strna(u->instance),
                prefix, unit_load_state_to_string(u->load_state),
                prefix, unit_active_state_to_string(unit_active_state(u)),
                prefix, strna(format_timestamp(timestamp1, sizeof(timestamp1), u->inactive_exit_timestamp.realtime)),
                prefix, strna(format_timestamp(timestamp2, sizeof(timestamp2), u->active_enter_timestamp.realtime)),
                prefix, strna(format_timestamp(timestamp3, sizeof(timestamp3), u->active_exit_timestamp.realtime)),
                prefix, strna(format_timestamp(timestamp4, sizeof(timestamp4), u->inactive_enter_timestamp.realtime)),
                prefix, yes_no(unit_check_gc(u)),
                prefix, yes_no(unit_need_daemon_reload(u)));

        SET_FOREACH(t, u->names, i)
                fprintf(f, "%s\tName: %s\n", prefix, t);

        STRV_FOREACH(j, u->documentation)
                fprintf(f, "%s\tDocumentation: %s\n", prefix, *j);

        if ((following = unit_following(u)))
                fprintf(f, "%s\tFollowing: %s\n", prefix, following->id);

        if (u->fragment_path)
                fprintf(f, "%s\tFragment Path: %s\n", prefix, u->fragment_path);

        if (u->source_path)
                fprintf(f, "%s\tSource Path: %s\n", prefix, u->source_path);

        STRV_FOREACH(j, u->dropin_paths)
                fprintf(f, "%s\tDropIn Path: %s\n", prefix, *j);

        if (u->job_timeout > 0)
                fprintf(f, "%s\tJob Timeout: %s\n", prefix, format_timespan(timespan, sizeof(timespan), u->job_timeout, 0));

        condition_dump_list(u->conditions, f, prefix);

        if (dual_timestamp_is_set(&u->condition_timestamp))
                fprintf(f,
                        "%s\tCondition Timestamp: %s\n"
                        "%s\tCondition Result: %s\n",
                        prefix, strna(format_timestamp(timestamp1, sizeof(timestamp1), u->condition_timestamp.realtime)),
                        prefix, yes_no(u->condition_result));

        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
                Unit *other;

                SET_FOREACH(other, u->dependencies[d], i)
                        fprintf(f, "%s\t%s: %s\n", prefix, unit_dependency_to_string(d), other->id);
        }

        if (!strv_isempty(u->requires_mounts_for)) {
                fprintf(f,
                        "%s\tRequiresMountsFor:", prefix);

                STRV_FOREACH(j, u->requires_mounts_for)
                        fprintf(f, " %s", *j);

                fputs("\n", f);
        }

        if (u->load_state == UNIT_LOADED) {
                CGroupBonding *b;
                CGroupAttribute *a;

                fprintf(f,
                        "%s\tStopWhenUnneeded: %s\n"
                        "%s\tRefuseManualStart: %s\n"
                        "%s\tRefuseManualStop: %s\n"
                        "%s\tDefaultDependencies: %s\n"
                        "%s\tOnFailureIsolate: %s\n"
                        "%s\tIgnoreOnIsolate: %s\n"
                        "%s\tIgnoreOnSnapshot: %s\n",
                        prefix, yes_no(u->stop_when_unneeded),
                        prefix, yes_no(u->refuse_manual_start),
                        prefix, yes_no(u->refuse_manual_stop),
                        prefix, yes_no(u->default_dependencies),
                        prefix, yes_no(u->on_failure_isolate),
                        prefix, yes_no(u->ignore_on_isolate),
                        prefix, yes_no(u->ignore_on_snapshot));

                LIST_FOREACH(by_unit, b, u->cgroup_bondings)
                        fprintf(f, "%s\tControlGroup: %s:%s\n",
                                prefix, b->controller, b->path);

                LIST_FOREACH(by_unit, a, u->cgroup_attributes) {
                        _cleanup_free_ char *v = NULL;

                        if (a->semantics && a->semantics->map_write)
                                a->semantics->map_write(a->semantics, a->value, &v);

                        fprintf(f, "%s\tControlGroupAttribute: %s %s \"%s\"\n",
                                prefix, a->controller, a->name, v ? v : a->value);
                }

                if (UNIT_VTABLE(u)->dump)
                        UNIT_VTABLE(u)->dump(u, f, prefix2);

        } else if (u->load_state == UNIT_MERGED)
                fprintf(f,
                        "%s\tMerged into: %s\n",
                        prefix, u->merged_into->id);
        else if (u->load_state == UNIT_ERROR)
                fprintf(f, "%s\tLoad Error Code: %s\n", prefix, strerror(-u->load_error));


        if (u->job)
                job_dump(u->job, f, prefix2);

        if (u->nop_job)
                job_dump(u->nop_job, f, prefix2);

        free(p2);
}

/* Common implementation for multiple backends */
int unit_load_fragment_and_dropin(Unit *u) {
        int r;

        assert(u);

        /* Load a .service file */
        if ((r = unit_load_fragment(u)) < 0)
                return r;

        if (u->load_state == UNIT_STUB)
                return -ENOENT;

        /* Load drop-in directory data */
        if ((r = unit_load_dropin(unit_follow_merge(u))) < 0)
                return r;

        return 0;
}

/* Common implementation for multiple backends */
int unit_load_fragment_and_dropin_optional(Unit *u) {
        int r;

        assert(u);

        /* Same as unit_load_fragment_and_dropin(), but whether
         * something can be loaded or not doesn't matter. */

        /* Load a .service file */
        if ((r = unit_load_fragment(u)) < 0)
                return r;

        if (u->load_state == UNIT_STUB)
                u->load_state = UNIT_LOADED;

        /* Load drop-in directory data */
        if ((r = unit_load_dropin(unit_follow_merge(u))) < 0)
                return r;

        return 0;
}

int unit_add_default_target_dependency(Unit *u, Unit *target) {
        assert(u);
        assert(target);

        if (target->type != UNIT_TARGET)
                return 0;

        /* Only add the dependency if both units are loaded, so that
         * that loop check below is reliable */
        if (u->load_state != UNIT_LOADED ||
            target->load_state != UNIT_LOADED)
                return 0;

        /* If either side wants no automatic dependencies, then let's
         * skip this */
        if (!u->default_dependencies ||
            !target->default_dependencies)
                return 0;

        /* Don't create loops */
        if (set_get(target->dependencies[UNIT_BEFORE], u))
                return 0;

        return unit_add_dependency(target, UNIT_AFTER, u, true);
}

static int unit_add_default_dependencies(Unit *u) {
        static const UnitDependency deps[] = {
                UNIT_REQUIRED_BY,
                UNIT_REQUIRED_BY_OVERRIDABLE,
                UNIT_WANTED_BY,
                UNIT_BOUND_BY
        };

        Unit *target;
        Iterator i;
        int r;
        unsigned k;

        assert(u);

        for (k = 0; k < ELEMENTSOF(deps); k++)
                SET_FOREACH(target, u->dependencies[deps[k]], i)
                        if ((r = unit_add_default_target_dependency(u, target)) < 0)
                                return r;

        return 0;
}

int unit_load(Unit *u) {
        int r;

        assert(u);

        if (u->in_load_queue) {
                LIST_REMOVE(Unit, load_queue, u->manager->load_queue, u);
                u->in_load_queue = false;
        }

        if (u->type == _UNIT_TYPE_INVALID)
                return -EINVAL;

        if (u->load_state != UNIT_STUB)
                return 0;

        if (UNIT_VTABLE(u)->load)
                if ((r = UNIT_VTABLE(u)->load(u)) < 0)
                        goto fail;

        if (u->load_state == UNIT_STUB) {
                r = -ENOENT;
                goto fail;
        }

        if (u->load_state == UNIT_LOADED &&
            u->default_dependencies)
                if ((r = unit_add_default_dependencies(u)) < 0)
                        goto fail;

        if (u->load_state == UNIT_LOADED) {
                r = unit_add_mount_links(u);
                if (r < 0)
                        return r;
        }

        if (u->on_failure_isolate &&
            set_size(u->dependencies[UNIT_ON_FAILURE]) > 1) {

                log_error_unit(u->id,
                               "More than one OnFailure= dependencies specified for %s but OnFailureIsolate= enabled. Refusing.", u->id);

                r = -EINVAL;
                goto fail;
        }

        assert((u->load_state != UNIT_MERGED) == !u->merged_into);

        unit_add_to_dbus_queue(unit_follow_merge(u));
        unit_add_to_gc_queue(u);

        return 0;

fail:
        u->load_state = UNIT_ERROR;
        u->load_error = r;
        unit_add_to_dbus_queue(u);
        unit_add_to_gc_queue(u);

        log_debug_unit(u->id, "Failed to load configuration for %s: %s",
                       u->id, strerror(-r));

        return r;
}

bool unit_condition_test(Unit *u) {
        assert(u);

        dual_timestamp_get(&u->condition_timestamp);
        u->condition_result = condition_test_list(u->conditions);

        return u->condition_result;
}

_pure_ static const char* unit_get_status_message_format(Unit *u, JobType t) {
        const UnitStatusMessageFormats *format_table;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        if (t != JOB_START && t != JOB_STOP)
                return NULL;

        format_table = &UNIT_VTABLE(u)->status_message_formats;
        if (!format_table)
                return NULL;

        return format_table->starting_stopping[t == JOB_STOP];
}

_pure_ static const char *unit_get_status_message_format_try_harder(Unit *u, JobType t) {
        const char *format;

        assert(u);
        assert(t >= 0);
        assert(t < _JOB_TYPE_MAX);

        format = unit_get_status_message_format(u, t);
        if (format)
                return format;

        /* Return generic strings */
        if (t == JOB_START)
                return "Starting %s.";
        else if (t == JOB_STOP)
                return "Stopping %s.";
        else if (t == JOB_RELOAD)
                return "Reloading %s.";

        return NULL;
}

static void unit_status_print_starting_stopping(Unit *u, JobType t) {
        const char *format;

        assert(u);

        /* We only print status messages for selected units on
         * selected operations. */

        format = unit_get_status_message_format(u, t);
        if (!format)
                return;

        unit_status_printf(u, "", format);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static void unit_status_log_starting_stopping_reloading(Unit *u, JobType t) {
        const char *format;
        char buf[LINE_MAX];
        sd_id128_t mid;

        assert(u);

        if (t != JOB_START && t != JOB_STOP && t != JOB_RELOAD)
                return;

        if (log_on_console())
                return;

        /* We log status messages for all units and all operations. */

        format = unit_get_status_message_format_try_harder(u, t);
        if (!format)
                return;

        snprintf(buf, sizeof(buf), format, unit_description(u));
        char_array_0(buf);

        mid = t == JOB_START ? SD_MESSAGE_UNIT_STARTING :
              t == JOB_STOP  ? SD_MESSAGE_UNIT_STOPPING :
                               SD_MESSAGE_UNIT_RELOADING;

        log_struct_unit(LOG_INFO,
                        u->id,
                        MESSAGE_ID(mid),
                        "MESSAGE=%s", buf,
                        NULL);
}
#pragma GCC diagnostic pop

/* Errors:
 *         -EBADR:     This unit type does not support starting.
 *         -EALREADY:  Unit is already started.
 *         -EAGAIN:    An operation is already in progress. Retry later.
 *         -ECANCELED: Too many requests for now.
 */
int unit_start(Unit *u) {
        UnitActiveState state;
        Unit *following;

        assert(u);

        if (u->load_state != UNIT_LOADED)
                return -EINVAL;

        /* If this is already started, then this will succeed. Note
         * that this will even succeed if this unit is not startable
         * by the user. This is relied on to detect when we need to
         * wait for units and when waiting is finished. */
        state = unit_active_state(u);
        if (UNIT_IS_ACTIVE_OR_RELOADING(state))
                return -EALREADY;

        /* If the conditions failed, don't do anything at all. If we
         * already are activating this call might still be useful to
         * speed up activation in case there is some hold-off time,
         * but we don't want to recheck the condition in that case. */
        if (state != UNIT_ACTIVATING &&
            !unit_condition_test(u)) {
                log_debug_unit(u->id, "Starting of %s requested but condition failed. Ignoring.", u->id);
                return -EALREADY;
        }

        /* Forward to the main object, if we aren't it. */
        if ((following = unit_following(u))) {
                log_debug_unit(u->id, "Redirecting start request from %s to %s.",
                               u->id, following->id);
                return unit_start(following);
        }

        unit_status_log_starting_stopping_reloading(u, JOB_START);
        unit_status_print_starting_stopping(u, JOB_START);

        /* If it is stopped, but we cannot start it, then fail */
        if (!UNIT_VTABLE(u)->start)
                return -EBADR;

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

bool unit_can_isolate(Unit *u) {
        assert(u);

        return unit_can_start(u) &&
                u->allow_isolate;
}

/* Errors:
 *         -EBADR:    This unit type does not support stopping.
 *         -EALREADY: Unit is already stopped.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 */
int unit_stop(Unit *u) {
        UnitActiveState state;
        Unit *following;

        assert(u);

        state = unit_active_state(u);
        if (UNIT_IS_INACTIVE_OR_FAILED(state))
                return -EALREADY;

        if ((following = unit_following(u))) {
                log_debug_unit(u->id, "Redirecting stop request from %s to %s.",
                               u->id, following->id);
                return unit_stop(following);
        }

        unit_status_log_starting_stopping_reloading(u, JOB_STOP);
        unit_status_print_starting_stopping(u, JOB_STOP);

        if (!UNIT_VTABLE(u)->stop)
                return -EBADR;

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
        Unit *following;

        assert(u);

        if (u->load_state != UNIT_LOADED)
                return -EINVAL;

        if (!unit_can_reload(u))
                return -EBADR;

        state = unit_active_state(u);
        if (state == UNIT_RELOADING)
                return -EALREADY;

        if (state != UNIT_ACTIVE)
                return -ENOEXEC;

        if ((following = unit_following(u))) {
                log_debug_unit(u->id, "Redirecting reload request from %s to %s.",
                               u->id, following->id);
                return unit_reload(following);
        }

        unit_status_log_starting_stopping_reloading(u, JOB_RELOAD);

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

static void unit_check_unneeded(Unit *u) {
        Iterator i;
        Unit *other;

        assert(u);

        /* If this service shall be shut down when unneeded then do
         * so. */

        if (!u->stop_when_unneeded)
                return;

        if (!UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)))
                return;

        SET_FOREACH(other, u->dependencies[UNIT_REQUIRED_BY], i)
                if (unit_active_or_pending(other))
                        return;

        SET_FOREACH(other, u->dependencies[UNIT_REQUIRED_BY_OVERRIDABLE], i)
                if (unit_active_or_pending(other))
                        return;

        SET_FOREACH(other, u->dependencies[UNIT_WANTED_BY], i)
                if (unit_active_or_pending(other))
                        return;

        SET_FOREACH(other, u->dependencies[UNIT_BOUND_BY], i)
                if (unit_active_or_pending(other))
                        return;

        log_info_unit(u->id, "Service %s is not needed anymore. Stopping.", u->id);

        /* Ok, nobody needs us anymore. Sniff. Then let's commit suicide */
        manager_add_job(u->manager, JOB_STOP, u, JOB_FAIL, true, NULL, NULL);
}

static void retroactively_start_dependencies(Unit *u) {
        Iterator i;
        Unit *other;

        assert(u);
        assert(UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)));

        SET_FOREACH(other, u->dependencies[UNIT_REQUIRES], i)
                if (!set_get(u->dependencies[UNIT_AFTER], other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_START, other, JOB_REPLACE, true, NULL, NULL);

        SET_FOREACH(other, u->dependencies[UNIT_BINDS_TO], i)
                if (!set_get(u->dependencies[UNIT_AFTER], other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_START, other, JOB_REPLACE, true, NULL, NULL);

        SET_FOREACH(other, u->dependencies[UNIT_REQUIRES_OVERRIDABLE], i)
                if (!set_get(u->dependencies[UNIT_AFTER], other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_START, other, JOB_FAIL, false, NULL, NULL);

        SET_FOREACH(other, u->dependencies[UNIT_WANTS], i)
                if (!set_get(u->dependencies[UNIT_AFTER], other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_START, other, JOB_FAIL, false, NULL, NULL);

        SET_FOREACH(other, u->dependencies[UNIT_CONFLICTS], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_STOP, other, JOB_REPLACE, true, NULL, NULL);

        SET_FOREACH(other, u->dependencies[UNIT_CONFLICTED_BY], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_STOP, other, JOB_REPLACE, true, NULL, NULL);
}

static void retroactively_stop_dependencies(Unit *u) {
        Iterator i;
        Unit *other;

        assert(u);
        assert(UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)));

        /* Pull down units which are bound to us recursively if enabled */
        SET_FOREACH(other, u->dependencies[UNIT_BOUND_BY], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_STOP, other, JOB_REPLACE, true, NULL, NULL);
}

static void check_unneeded_dependencies(Unit *u) {
        Iterator i;
        Unit *other;

        assert(u);
        assert(UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)));

        /* Garbage collect services that might not be needed anymore, if enabled */
        SET_FOREACH(other, u->dependencies[UNIT_REQUIRES], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_unneeded(other);
        SET_FOREACH(other, u->dependencies[UNIT_REQUIRES_OVERRIDABLE], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_unneeded(other);
        SET_FOREACH(other, u->dependencies[UNIT_WANTS], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_unneeded(other);
        SET_FOREACH(other, u->dependencies[UNIT_REQUISITE], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_unneeded(other);
        SET_FOREACH(other, u->dependencies[UNIT_REQUISITE_OVERRIDABLE], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_unneeded(other);
        SET_FOREACH(other, u->dependencies[UNIT_BINDS_TO], i)
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        unit_check_unneeded(other);
}

void unit_start_on_failure(Unit *u) {
        Unit *other;
        Iterator i;

        assert(u);

        if (set_size(u->dependencies[UNIT_ON_FAILURE]) <= 0)
                return;

        log_info_unit(u->id, "Triggering OnFailure= dependencies of %s.", u->id);

        SET_FOREACH(other, u->dependencies[UNIT_ON_FAILURE], i) {
                int r;

                r = manager_add_job(u->manager, JOB_START, other, u->on_failure_isolate ? JOB_ISOLATE : JOB_REPLACE, true, NULL, NULL);
                if (r < 0)
                        log_error_unit(u->id, "Failed to enqueue OnFailure= job: %s", strerror(-r));
        }
}

void unit_trigger_notify(Unit *u) {
        Unit *other;
        Iterator i;

        assert(u);

        SET_FOREACH(other, u->dependencies[UNIT_TRIGGERED_BY], i)
                if (UNIT_VTABLE(other)->trigger_notify)
                        UNIT_VTABLE(other)->trigger_notify(other, u);
}

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns, bool reload_success) {
        Manager *m;
        bool unexpected;

        assert(u);
        assert(os < _UNIT_ACTIVE_STATE_MAX);
        assert(ns < _UNIT_ACTIVE_STATE_MAX);

        /* Note that this is called for all low-level state changes,
         * even if they might map to the same high-level
         * UnitActiveState! That means that ns == os is OK an expected
         * behavior here. For example: if a mount point is remounted
         * this function will be called too! */

        m = u->manager;

        if (m->n_reloading <= 0) {
                dual_timestamp ts;

                dual_timestamp_get(&ts);

                if (UNIT_IS_INACTIVE_OR_FAILED(os) && !UNIT_IS_INACTIVE_OR_FAILED(ns))
                        u->inactive_exit_timestamp = ts;
                else if (!UNIT_IS_INACTIVE_OR_FAILED(os) && UNIT_IS_INACTIVE_OR_FAILED(ns))
                        u->inactive_enter_timestamp = ts;

                if (!UNIT_IS_ACTIVE_OR_RELOADING(os) && UNIT_IS_ACTIVE_OR_RELOADING(ns))
                        u->active_enter_timestamp = ts;
                else if (UNIT_IS_ACTIVE_OR_RELOADING(os) && !UNIT_IS_ACTIVE_OR_RELOADING(ns))
                        u->active_exit_timestamp = ts;
        }

        if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                cgroup_bonding_trim_list(u->cgroup_bondings, true);

        if (UNIT_IS_INACTIVE_OR_FAILED(os) != UNIT_IS_INACTIVE_OR_FAILED(ns)) {
                ExecContext *ec = unit_get_exec_context(u);
                if (ec && exec_context_may_touch_console(ec)) {
                        if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                                m->n_on_console--;
                        else
                                m->n_on_console++;
                }
        }

        if (u->job) {
                unexpected = false;

                if (u->job->state == JOB_WAITING)

                        /* So we reached a different state for this
                         * job. Let's see if we can run it now if it
                         * failed previously due to EAGAIN. */
                        job_add_to_run_queue(u->job);

                /* Let's check whether this state change constitutes a
                 * finished job, or maybe contradicts a running job and
                 * hence needs to invalidate jobs. */

                switch (u->job->type) {

                case JOB_START:
                case JOB_VERIFY_ACTIVE:

                        if (UNIT_IS_ACTIVE_OR_RELOADING(ns))
                                job_finish_and_invalidate(u->job, JOB_DONE, true);
                        else if (u->job->state == JOB_RUNNING && ns != UNIT_ACTIVATING) {
                                unexpected = true;

                                if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                                        job_finish_and_invalidate(u->job, ns == UNIT_FAILED ? JOB_FAILED : JOB_DONE, true);
                        }

                        break;

                case JOB_RELOAD:
                case JOB_RELOAD_OR_START:

                        if (u->job->state == JOB_RUNNING) {
                                if (ns == UNIT_ACTIVE)
                                        job_finish_and_invalidate(u->job, reload_success ? JOB_DONE : JOB_FAILED, true);
                                else if (ns != UNIT_ACTIVATING && ns != UNIT_RELOADING) {
                                        unexpected = true;

                                        if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                                                job_finish_and_invalidate(u->job, ns == UNIT_FAILED ? JOB_FAILED : JOB_DONE, true);
                                }
                        }

                        break;

                case JOB_STOP:
                case JOB_RESTART:
                case JOB_TRY_RESTART:

                        if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                                job_finish_and_invalidate(u->job, JOB_DONE, true);
                        else if (u->job->state == JOB_RUNNING && ns != UNIT_DEACTIVATING) {
                                unexpected = true;
                                job_finish_and_invalidate(u->job, JOB_FAILED, true);
                        }

                        break;

                default:
                        assert_not_reached("Job type unknown");
                }

        } else
                unexpected = true;

        if (m->n_reloading <= 0) {

                /* If this state change happened without being
                 * requested by a job, then let's retroactively start
                 * or stop dependencies. We skip that step when
                 * deserializing, since we don't want to create any
                 * additional jobs just because something is already
                 * activated. */

                if (unexpected) {
                        if (UNIT_IS_INACTIVE_OR_FAILED(os) && UNIT_IS_ACTIVE_OR_ACTIVATING(ns))
                                retroactively_start_dependencies(u);
                        else if (UNIT_IS_ACTIVE_OR_ACTIVATING(os) && UNIT_IS_INACTIVE_OR_DEACTIVATING(ns))
                                retroactively_stop_dependencies(u);
                }

                /* stop unneeded units regardless if going down was expected or not */
                if (UNIT_IS_ACTIVE_OR_ACTIVATING(os) && UNIT_IS_INACTIVE_OR_DEACTIVATING(ns))
                        check_unneeded_dependencies(u);

                if (ns != os && ns == UNIT_FAILED) {
                        log_notice_unit(u->id,
                                        "Unit %s entered failed state.", u->id);
                        unit_start_on_failure(u);
                }
        }

        /* Some names are special */
        if (UNIT_IS_ACTIVE_OR_RELOADING(ns)) {

                if (unit_has_name(u, SPECIAL_DBUS_SERVICE))
                        /* The bus just might have become available,
                         * hence try to connect to it, if we aren't
                         * yet connected. */
                        bus_init(m, true);

                if (u->type == UNIT_SERVICE &&
                    !UNIT_IS_ACTIVE_OR_RELOADING(os) &&
                    m->n_reloading <= 0) {
                        /* Write audit record if we have just finished starting up */
                        manager_send_unit_audit(m, u, AUDIT_SERVICE_START, true);
                        u->in_audit = true;
                }

                if (!UNIT_IS_ACTIVE_OR_RELOADING(os))
                        manager_send_unit_plymouth(m, u);

        } else {

                /* We don't care about D-Bus here, since we'll get an
                 * asynchronous notification for it anyway. */

                if (u->type == UNIT_SERVICE &&
                    UNIT_IS_INACTIVE_OR_FAILED(ns) &&
                    !UNIT_IS_INACTIVE_OR_FAILED(os) &&
                    m->n_reloading <= 0) {

                        /* Hmm, if there was no start record written
                         * write it now, so that we always have a nice
                         * pair */
                        if (!u->in_audit) {
                                manager_send_unit_audit(m, u, AUDIT_SERVICE_START, ns == UNIT_INACTIVE);

                                if (ns == UNIT_INACTIVE)
                                        manager_send_unit_audit(m, u, AUDIT_SERVICE_STOP, true);
                        } else
                                /* Write audit record if we have just finished shutting down */
                                manager_send_unit_audit(m, u, AUDIT_SERVICE_STOP, ns == UNIT_INACTIVE);

                        u->in_audit = false;
                }
        }

        manager_recheck_journal(m);
        unit_trigger_notify(u);

        /* Maybe we finished startup and are now ready for being
         * stopped because unneeded? */
        if (u->manager->n_reloading <= 0)
                unit_check_unneeded(u);

        unit_add_to_dbus_queue(u);
        unit_add_to_gc_queue(u);
}

int unit_watch_fd(Unit *u, int fd, uint32_t events, Watch *w) {
        struct epoll_event ev = {
                .data.ptr = w,
                .events = events,
        };

        assert(u);
        assert(fd >= 0);
        assert(w);
        assert(w->type == WATCH_INVALID || (w->type == WATCH_FD && w->fd == fd && w->data.unit == u));

        if (epoll_ctl(u->manager->epoll_fd,
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
        assert_se(epoll_ctl(u->manager->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);

        w->fd = -1;
        w->type = WATCH_INVALID;
        w->data.unit = NULL;
}

int unit_watch_pid(Unit *u, pid_t pid) {
        assert(u);
        assert(pid >= 1);

        /* Watch a specific PID. We only support one unit watching
         * each PID for now. */

        return hashmap_put(u->manager->watch_pids, LONG_TO_PTR(pid), u);
}

void unit_unwatch_pid(Unit *u, pid_t pid) {
        assert(u);
        assert(pid >= 1);

        hashmap_remove_value(u->manager->watch_pids, LONG_TO_PTR(pid), u);
}

int unit_watch_timer(Unit *u, clockid_t clock_id, bool relative, usec_t usec, Watch *w) {
        struct itimerspec its = {};
        int flags, fd;
        bool ours;

        assert(u);
        assert(w);
        assert(w->type == WATCH_INVALID || (w->type == WATCH_UNIT_TIMER && w->data.unit == u));

        /* This will try to reuse the old timer if there is one */

        if (w->type == WATCH_UNIT_TIMER) {
                assert(w->data.unit == u);
                assert(w->fd >= 0);

                ours = false;
                fd = w->fd;
        } else if (w->type == WATCH_INVALID) {

                ours = true;
                fd = timerfd_create(clock_id, TFD_NONBLOCK|TFD_CLOEXEC);
                if (fd < 0)
                        return -errno;
        } else
                assert_not_reached("Invalid watch type");

        if (usec <= 0) {
                /* Set absolute time in the past, but not 0, since we
                 * don't want to disarm the timer */
                its.it_value.tv_sec = 0;
                its.it_value.tv_nsec = 1;

                flags = TFD_TIMER_ABSTIME;
        } else {
                timespec_store(&its.it_value, usec);
                flags = relative ? 0 : TFD_TIMER_ABSTIME;
        }

        /* This will also flush the elapse counter */
        if (timerfd_settime(fd, flags, &its, NULL) < 0)
                goto fail;

        if (w->type == WATCH_INVALID) {
                struct epoll_event ev = {
                        .data.ptr = w,
                        .events = EPOLLIN,
                };

                if (epoll_ctl(u->manager->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                        goto fail;
        }

        w->type = WATCH_UNIT_TIMER;
        w->fd = fd;
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

        assert(w->type == WATCH_UNIT_TIMER);
        assert(w->data.unit == u);
        assert(w->fd >= 0);

        assert_se(epoll_ctl(u->manager->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);
        close_nointr_nofail(w->fd);

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
        case JOB_STOP:
        case JOB_NOP:
                return true;

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

int unit_add_dependency(Unit *u, UnitDependency d, Unit *other, bool add_reference) {

        static const UnitDependency inverse_table[_UNIT_DEPENDENCY_MAX] = {
                [UNIT_REQUIRES] = UNIT_REQUIRED_BY,
                [UNIT_REQUIRES_OVERRIDABLE] = UNIT_REQUIRED_BY_OVERRIDABLE,
                [UNIT_WANTS] = UNIT_WANTED_BY,
                [UNIT_REQUISITE] = UNIT_REQUIRED_BY,
                [UNIT_REQUISITE_OVERRIDABLE] = UNIT_REQUIRED_BY_OVERRIDABLE,
                [UNIT_BINDS_TO] = UNIT_BOUND_BY,
                [UNIT_PART_OF] = UNIT_CONSISTS_OF,
                [UNIT_REQUIRED_BY] = _UNIT_DEPENDENCY_INVALID,
                [UNIT_REQUIRED_BY_OVERRIDABLE] = _UNIT_DEPENDENCY_INVALID,
                [UNIT_WANTED_BY] = _UNIT_DEPENDENCY_INVALID,
                [UNIT_BOUND_BY] = UNIT_BINDS_TO,
                [UNIT_CONSISTS_OF] = UNIT_PART_OF,
                [UNIT_CONFLICTS] = UNIT_CONFLICTED_BY,
                [UNIT_CONFLICTED_BY] = UNIT_CONFLICTS,
                [UNIT_BEFORE] = UNIT_AFTER,
                [UNIT_AFTER] = UNIT_BEFORE,
                [UNIT_ON_FAILURE] = _UNIT_DEPENDENCY_INVALID,
                [UNIT_REFERENCES] = UNIT_REFERENCED_BY,
                [UNIT_REFERENCED_BY] = UNIT_REFERENCES,
                [UNIT_TRIGGERS] = UNIT_TRIGGERED_BY,
                [UNIT_TRIGGERED_BY] = UNIT_TRIGGERS,
                [UNIT_PROPAGATES_RELOAD_TO] = UNIT_RELOAD_PROPAGATED_FROM,
                [UNIT_RELOAD_PROPAGATED_FROM] = UNIT_PROPAGATES_RELOAD_TO,
        };
        int r, q = 0, v = 0, w = 0;

        assert(u);
        assert(d >= 0 && d < _UNIT_DEPENDENCY_MAX);
        assert(other);

        u = unit_follow_merge(u);
        other = unit_follow_merge(other);

        /* We won't allow dependencies on ourselves. We will not
         * consider them an error however. */
        if (u == other)
                return 0;

        if ((r = set_ensure_allocated(&u->dependencies[d], trivial_hash_func, trivial_compare_func)) < 0)
                return r;

        if (inverse_table[d] != _UNIT_DEPENDENCY_INVALID)
                if ((r = set_ensure_allocated(&other->dependencies[inverse_table[d]], trivial_hash_func, trivial_compare_func)) < 0)
                        return r;

        if (add_reference)
                if ((r = set_ensure_allocated(&u->dependencies[UNIT_REFERENCES], trivial_hash_func, trivial_compare_func)) < 0 ||
                    (r = set_ensure_allocated(&other->dependencies[UNIT_REFERENCED_BY], trivial_hash_func, trivial_compare_func)) < 0)
                        return r;

        if ((q = set_put(u->dependencies[d], other)) < 0)
                return q;

        if (inverse_table[d] != _UNIT_DEPENDENCY_INVALID)
                if ((v = set_put(other->dependencies[inverse_table[d]], u)) < 0) {
                        r = v;
                        goto fail;
                }

        if (add_reference) {
                if ((w = set_put(u->dependencies[UNIT_REFERENCES], other)) < 0) {
                        r = w;
                        goto fail;
                }

                if ((r = set_put(other->dependencies[UNIT_REFERENCED_BY], u)) < 0)
                        goto fail;
        }

        unit_add_to_dbus_queue(u);
        return 0;

fail:
        if (q > 0)
                set_remove(u->dependencies[d], other);

        if (v > 0)
                set_remove(other->dependencies[inverse_table[d]], u);

        if (w > 0)
                set_remove(u->dependencies[UNIT_REFERENCES], other);

        return r;
}

int unit_add_two_dependencies(Unit *u, UnitDependency d, UnitDependency e, Unit *other, bool add_reference) {
        int r;

        assert(u);

        if ((r = unit_add_dependency(u, d, other, add_reference)) < 0)
                return r;

        if ((r = unit_add_dependency(u, e, other, add_reference)) < 0)
                return r;

        return 0;
}

static const char *resolve_template(Unit *u, const char *name, const char*path, char **p) {
        char *s;

        assert(u);
        assert(name || path);
        assert(p);

        if (!name)
                name = path_get_file_name(path);

        if (!unit_name_is_template(name)) {
                *p = NULL;
                return name;
        }

        if (u->instance)
                s = unit_name_replace_instance(name, u->instance);
        else {
                _cleanup_free_ char *i = NULL;

                i = unit_name_to_prefix(u->id);
                if (!i)
                        return NULL;

                s = unit_name_replace_instance(name, i);
        }

        if (!s)
                return NULL;

        *p = s;
        return s;
}

int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name, const char *path, bool add_reference) {
        Unit *other;
        int r;
        _cleanup_free_ char *s = NULL;

        assert(u);
        assert(name || path);

        name = resolve_template(u, name, path, &s);
        if (!name)
                return -ENOMEM;

        r = manager_load_unit(u->manager, name, path, NULL, &other);
        if (r < 0)
                return r;

        return unit_add_dependency(u, d, other, add_reference);
}

int unit_add_two_dependencies_by_name(Unit *u, UnitDependency d, UnitDependency e, const char *name, const char *path, bool add_reference) {
        Unit *other;
        int r;
        char *s;

        assert(u);
        assert(name || path);

        if (!(name = resolve_template(u, name, path, &s)))
                return -ENOMEM;

        if ((r = manager_load_unit(u->manager, name, path, NULL, &other)) < 0)
                goto finish;

        r = unit_add_two_dependencies(u, d, e, other, add_reference);

finish:
        free(s);
        return r;
}

int unit_add_dependency_by_name_inverse(Unit *u, UnitDependency d, const char *name, const char *path, bool add_reference) {
        Unit *other;
        int r;
        char *s;

        assert(u);
        assert(name || path);

        if (!(name = resolve_template(u, name, path, &s)))
                return -ENOMEM;

        if ((r = manager_load_unit(u->manager, name, path, NULL, &other)) < 0)
                goto finish;

        r = unit_add_dependency(other, d, u, add_reference);

finish:
        free(s);
        return r;
}

int unit_add_two_dependencies_by_name_inverse(Unit *u, UnitDependency d, UnitDependency e, const char *name, const char *path, bool add_reference) {
        Unit *other;
        int r;
        char *s;

        assert(u);
        assert(name || path);

        if (!(name = resolve_template(u, name, path, &s)))
                return -ENOMEM;

        if ((r = manager_load_unit(u->manager, name, path, NULL, &other)) < 0)
                goto finish;

        if ((r = unit_add_two_dependencies(other, d, e, u, add_reference)) < 0)
                goto finish;

finish:
        free(s);
        return r;
}

int set_unit_path(const char *p) {
        _cleanup_free_ char *c = NULL;

        /* This is mostly for debug purposes */
        c = path_make_absolute_cwd(p);
        if (setenv("SYSTEMD_UNIT_PATH", c, 0) < 0)
                return -errno;

        return 0;
}

char *unit_dbus_path(Unit *u) {
        assert(u);

        if (!u->id)
                return NULL;

        return unit_dbus_path_from_name(u->id);
}

static int unit_add_cgroup(Unit *u, CGroupBonding *b) {
        int r;

        assert(u);
        assert(b);

        assert(b->path);

        if (!b->controller) {
                b->controller = strdup(SYSTEMD_CGROUP_CONTROLLER);
                if (!b->controller)
                        return log_oom();

                b->ours = true;
        }

        /* Ensure this hasn't been added yet */
        assert(!b->unit);

        if (streq(b->controller, SYSTEMD_CGROUP_CONTROLLER)) {
                CGroupBonding *l;

                l = hashmap_get(u->manager->cgroup_bondings, b->path);
                LIST_PREPEND(CGroupBonding, by_path, l, b);

                r = hashmap_replace(u->manager->cgroup_bondings, b->path, l);
                if (r < 0) {
                        LIST_REMOVE(CGroupBonding, by_path, l, b);
                        return r;
                }
        }

        LIST_PREPEND(CGroupBonding, by_unit, u->cgroup_bondings, b);
        b->unit = u;

        return 0;
}

char *unit_default_cgroup_path(Unit *u) {
        _cleanup_free_ char *escaped_instance = NULL;

        assert(u);

        escaped_instance = cg_escape(u->id);
        if (!escaped_instance)
                return NULL;

        if (u->instance) {
                _cleanup_free_ char *t = NULL, *escaped_template = NULL;

                t = unit_name_template(u->id);
                if (!t)
                        return NULL;

                escaped_template = cg_escape(t);
                if (!escaped_template)
                        return NULL;

                return strjoin(u->manager->cgroup_hierarchy, "/", escaped_template, "/", escaped_instance, NULL);
        } else
                return strjoin(u->manager->cgroup_hierarchy, "/", escaped_instance, NULL);
}

int unit_add_cgroup_from_text(Unit *u, const char *name, bool overwrite, CGroupBonding **ret) {
        char *controller = NULL, *path = NULL;
        CGroupBonding *b = NULL;
        bool ours = false;
        int r;

        assert(u);
        assert(name);

        r = cg_split_spec(name, &controller, &path);
        if (r < 0)
                return r;

        if (!path) {
                path = unit_default_cgroup_path(u);
                ours = true;
        }

        if (!controller) {
                controller = strdup("systemd");
                ours = true;
        }

        if (!path || !controller) {
                free(path);
                free(controller);
                return log_oom();
        }

        if (streq(controller, "systemd")) {
                /* Within the systemd unit hierarchy we do not allow changes. */
                if (path_startswith(path, "/system")) {
                        log_warning_unit(u->id, "Manipulating the systemd:/system cgroup hierarchy is not permitted.");
                        free(path);
                        free(controller);
                        return -EPERM;
                }
        }

        b = cgroup_bonding_find_list(u->cgroup_bondings, controller);
        if (b) {
                if (streq(path, b->path)) {
                        free(path);
                        free(controller);

                        if (ret)
                                *ret = b;
                        return 0;
                }

                if (overwrite && !b->essential) {
                        free(controller);

                        free(b->path);
                        b->path = path;

                        b->ours = ours;
                        b->realized = false;

                        if (ret)
                                *ret = b;

                        return 1;
                }

                r = -EEXIST;
                b = NULL;
                goto fail;
        }

        b = new0(CGroupBonding, 1);
        if (!b) {
                r = -ENOMEM;
                goto fail;
        }

        b->controller = controller;
        b->path = path;
        b->ours = ours;
        b->essential = streq(controller, SYSTEMD_CGROUP_CONTROLLER);

        r = unit_add_cgroup(u, b);
        if (r < 0)
                goto fail;

        if (ret)
                *ret = b;

        return 1;

fail:
        free(path);
        free(controller);
        free(b);

        return r;
}

static int unit_add_one_default_cgroup(Unit *u, const char *controller) {
        CGroupBonding *b = NULL;
        int r = -ENOMEM;

        assert(u);

        if (controller && !cg_controller_is_valid(controller, true))
                return -EINVAL;

        if (!controller)
                controller = SYSTEMD_CGROUP_CONTROLLER;

        if (cgroup_bonding_find_list(u->cgroup_bondings, controller))
                return 0;

        b = new0(CGroupBonding, 1);
        if (!b)
                return -ENOMEM;

        b->controller = strdup(controller);
        if (!b->controller)
                goto fail;

        b->path = unit_default_cgroup_path(u);
        if (!b->path)
                goto fail;

        b->ours = true;
        b->essential = streq(controller, SYSTEMD_CGROUP_CONTROLLER);

        r = unit_add_cgroup(u, b);
        if (r < 0)
                goto fail;

        return 1;

fail:
        free(b->path);
        free(b->controller);
        free(b);

        return r;
}

int unit_add_default_cgroups(Unit *u) {
        CGroupAttribute *a;
        char **c;
        int r;

        assert(u);

        /* Adds in the default cgroups, if they weren't specified
         * otherwise. */

        if (!u->manager->cgroup_hierarchy)
                return 0;

        r = unit_add_one_default_cgroup(u, NULL);
        if (r < 0)
                return r;

        STRV_FOREACH(c, u->manager->default_controllers)
                unit_add_one_default_cgroup(u, *c);

        LIST_FOREACH(by_unit, a, u->cgroup_attributes)
                unit_add_one_default_cgroup(u, a->controller);

        return 0;
}

CGroupBonding* unit_get_default_cgroup(Unit *u) {
        assert(u);

        return cgroup_bonding_find_list(u->cgroup_bondings, NULL);
}

int unit_add_cgroup_attribute(
                Unit *u,
                const CGroupSemantics *semantics,
                const char *controller,
                const char *name,
                const char *value,
                CGroupAttribute **ret) {

        _cleanup_free_ char *c = NULL;
        CGroupAttribute *a;
        int r;

        assert(u);
        assert(value);

        if (semantics) {
                /* Semantics always take precedence */
                if (semantics->name)
                        name = semantics->name;

                if (semantics->controller)
                        controller = semantics->controller;
        }

        if (!name)
                return -EINVAL;

        if (!controller) {
                r = cg_controller_from_attr(name, &c);
                if (r < 0)
                        return -EINVAL;

                controller = c;
        }

        if (!controller ||
            streq(controller, SYSTEMD_CGROUP_CONTROLLER) ||
            streq(controller, "systemd"))
                return -EINVAL;

        if (!filename_is_safe(name))
                return -EINVAL;

        if (!cg_controller_is_valid(controller, false))
                return -EINVAL;

        /* Check if this attribute already exists. Note that we will
         * explicitly check for the value here too, as there are
         * attributes which accept multiple values. */
        a = cgroup_attribute_find_list(u->cgroup_attributes, controller, name);
        if (a) {
                if (streq(value, a->value)) {
                        /* Exactly the same value is always OK, let's ignore this */
                        if (ret)
                                *ret = a;

                        return 0;
                }

                if (semantics && !semantics->multiple) {
                        char *v;

                        /* If this is a single-item entry, we can
                         * simply patch the existing attribute */

                        v = strdup(value);
                        if (!v)
                                return -ENOMEM;

                        free(a->value);
                        a->value = v;

                        if (ret)
                                *ret = a;
                        return 1;
                }
        }

        a = new0(CGroupAttribute, 1);
        if (!a)
                return -ENOMEM;

        if (c) {
                a->controller = c;
                c = NULL;
        } else
                a->controller = strdup(controller);

        a->name = strdup(name);
        a->value = strdup(value);

        if (!a->controller || !a->name || !a->value) {
                free(a->controller);
                free(a->name);
                free(a->value);
                free(a);
                return -ENOMEM;
        }

        a->semantics = semantics;
        a->unit = u;

        LIST_PREPEND(CGroupAttribute, by_unit, u->cgroup_attributes, a);

        if (ret)
                *ret = a;

        return 1;
}

int unit_load_related_unit(Unit *u, const char *type, Unit **_found) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(u);
        assert(type);
        assert(_found);

        t = unit_name_change_suffix(u->id, type);
        if (!t)
                return -ENOMEM;

        assert(!unit_has_name(u, t));

        r = manager_load_unit(u->manager, t, NULL, NULL, _found);
        assert(r < 0 || *_found != u);
        return r;
}

int unit_get_related_unit(Unit *u, const char *type, Unit **_found) {
        _cleanup_free_ char *t = NULL;
        Unit *found;

        assert(u);
        assert(type);
        assert(_found);

        t = unit_name_change_suffix(u->id, type);
        if (!t)
                return -ENOMEM;

        assert(!unit_has_name(u, t));

        found = manager_get_unit(u->manager, t);
        if (!found)
                return -ENOENT;

        *_found = found;
        return 0;
}

int unit_watch_bus_name(Unit *u, const char *name) {
        assert(u);
        assert(name);

        /* Watch a specific name on the bus. We only support one unit
         * watching each name for now. */

        return hashmap_put(u->manager->watch_bus, name, u);
}

void unit_unwatch_bus_name(Unit *u, const char *name) {
        assert(u);
        assert(name);

        hashmap_remove_value(u->manager->watch_bus, name, u);
}

bool unit_can_serialize(Unit *u) {
        assert(u);

        return UNIT_VTABLE(u)->serialize && UNIT_VTABLE(u)->deserialize_item;
}

int unit_serialize(Unit *u, FILE *f, FDSet *fds, bool serialize_jobs) {
        int r;

        assert(u);
        assert(f);
        assert(fds);

        if (!unit_can_serialize(u))
                return 0;

        if ((r = UNIT_VTABLE(u)->serialize(u, f, fds)) < 0)
                return r;


        if (serialize_jobs) {
                if (u->job) {
                        fprintf(f, "job\n");
                        job_serialize(u->job, f, fds);
                }

                if (u->nop_job) {
                        fprintf(f, "job\n");
                        job_serialize(u->nop_job, f, fds);
                }
        }

        dual_timestamp_serialize(f, "inactive-exit-timestamp", &u->inactive_exit_timestamp);
        dual_timestamp_serialize(f, "active-enter-timestamp", &u->active_enter_timestamp);
        dual_timestamp_serialize(f, "active-exit-timestamp", &u->active_exit_timestamp);
        dual_timestamp_serialize(f, "inactive-enter-timestamp", &u->inactive_enter_timestamp);
        dual_timestamp_serialize(f, "condition-timestamp", &u->condition_timestamp);

        if (dual_timestamp_is_set(&u->condition_timestamp))
                unit_serialize_item(u, f, "condition-result", yes_no(u->condition_result));

        /* End marker */
        fputc('\n', f);
        return 0;
}

void unit_serialize_item_format(Unit *u, FILE *f, const char *key, const char *format, ...) {
        va_list ap;

        assert(u);
        assert(f);
        assert(key);
        assert(format);

        fputs(key, f);
        fputc('=', f);

        va_start(ap, format);
        vfprintf(f, format, ap);
        va_end(ap);

        fputc('\n', f);
}

void unit_serialize_item(Unit *u, FILE *f, const char *key, const char *value) {
        assert(u);
        assert(f);
        assert(key);
        assert(value);

        fprintf(f, "%s=%s\n", key, value);
}

int unit_deserialize(Unit *u, FILE *f, FDSet *fds) {
        int r;

        assert(u);
        assert(f);
        assert(fds);

        if (!unit_can_serialize(u))
                return 0;

        for (;;) {
                char line[LINE_MAX], *l, *v;
                size_t k;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                return 0;
                        return -errno;
                }

                char_array_0(line);
                l = strstrip(line);

                /* End marker */
                if (l[0] == 0)
                        return 0;

                k = strcspn(l, "=");

                if (l[k] == '=') {
                        l[k] = 0;
                        v = l+k+1;
                } else
                        v = l+k;

                if (streq(l, "job")) {
                        if (v[0] == '\0') {
                                /* new-style serialized job */
                                Job *j = job_new_raw(u);
                                if (!j)
                                        return -ENOMEM;

                                r = job_deserialize(j, f, fds);
                                if (r < 0) {
                                        job_free(j);
                                        return r;
                                }

                                r = hashmap_put(u->manager->jobs, UINT32_TO_PTR(j->id), j);
                                if (r < 0) {
                                        job_free(j);
                                        return r;
                                }

                                r = job_install_deserialized(j);
                                if (r < 0) {
                                        hashmap_remove(u->manager->jobs, UINT32_TO_PTR(j->id));
                                        job_free(j);
                                        return r;
                                }

                                if (j->state == JOB_RUNNING)
                                        u->manager->n_running_jobs++;
                        } else {
                                /* legacy */
                                JobType type = job_type_from_string(v);
                                if (type < 0)
                                        log_debug("Failed to parse job type value %s", v);
                                else
                                        u->deserialized_job = type;
                        }
                        continue;
                } else if (streq(l, "inactive-exit-timestamp")) {
                        dual_timestamp_deserialize(v, &u->inactive_exit_timestamp);
                        continue;
                } else if (streq(l, "active-enter-timestamp")) {
                        dual_timestamp_deserialize(v, &u->active_enter_timestamp);
                        continue;
                } else if (streq(l, "active-exit-timestamp")) {
                        dual_timestamp_deserialize(v, &u->active_exit_timestamp);
                        continue;
                } else if (streq(l, "inactive-enter-timestamp")) {
                        dual_timestamp_deserialize(v, &u->inactive_enter_timestamp);
                        continue;
                } else if (streq(l, "condition-timestamp")) {
                        dual_timestamp_deserialize(v, &u->condition_timestamp);
                        continue;
                } else if (streq(l, "condition-result")) {
                        int b;

                        if ((b = parse_boolean(v)) < 0)
                                log_debug("Failed to parse condition result value %s", v);
                        else
                                u->condition_result = b;

                        continue;
                }

                if ((r = UNIT_VTABLE(u)->deserialize_item(u, l, v, fds)) < 0)
                        return r;
        }
}

int unit_add_node_link(Unit *u, const char *what, bool wants) {
        Unit *device;
        char *e;
        int r;

        assert(u);

        if (!what)
                return 0;

        /* Adds in links to the device node that this unit is based on */

        if (!is_device_path(what))
                return 0;

        e = unit_name_from_path(what, ".device");
        if (!e)
                return -ENOMEM;

        r = manager_load_unit(u->manager, e, NULL, NULL, &device);
        free(e);
        if (r < 0)
                return r;

        r = unit_add_two_dependencies(u, UNIT_AFTER, UNIT_BINDS_TO, device, true);
        if (r < 0)
                return r;

        if (wants) {
                r = unit_add_dependency(device, UNIT_WANTS, u, false);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_coldplug(Unit *u) {
        int r;

        assert(u);

        if (UNIT_VTABLE(u)->coldplug)
                if ((r = UNIT_VTABLE(u)->coldplug(u)) < 0)
                        return r;

        if (u->job) {
                r = job_coldplug(u->job);
                if (r < 0)
                        return r;
        } else if (u->deserialized_job >= 0) {
                /* legacy */
                r = manager_add_job(u->manager, u->deserialized_job, u, JOB_IGNORE_REQUIREMENTS, false, NULL, NULL);
                if (r < 0)
                        return r;

                u->deserialized_job = _JOB_TYPE_INVALID;
        }

        return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
void unit_status_printf(Unit *u, const char *status, const char *unit_status_msg_format) {
        manager_status_printf(u->manager, false, status, unit_status_msg_format, unit_description(u));
}
#pragma GCC diagnostic pop

bool unit_need_daemon_reload(Unit *u) {
        _cleanup_strv_free_ char **t = NULL;
        char **path;
        struct stat st;
        unsigned loaded_cnt, current_cnt;

        assert(u);

        if (u->fragment_path) {
                zero(st);
                if (stat(u->fragment_path, &st) < 0)
                        /* What, cannot access this anymore? */
                        return true;

                if (u->fragment_mtime > 0 &&
                    timespec_load(&st.st_mtim) != u->fragment_mtime)
                        return true;
        }

        if (u->source_path) {
                zero(st);
                if (stat(u->source_path, &st) < 0)
                        return true;

                if (u->source_mtime > 0 &&
                    timespec_load(&st.st_mtim) != u->source_mtime)
                        return true;
        }

        t = unit_find_dropin_paths(u);
        loaded_cnt = strv_length(t);
        current_cnt = strv_length(u->dropin_paths);

        if (loaded_cnt == current_cnt) {
                if (loaded_cnt == 0)
                        return false;

                if (strv_overlap(u->dropin_paths, t)) {
                        STRV_FOREACH(path, u->dropin_paths) {
                                zero(st);
                                if (stat(*path, &st) < 0)
                                        return true;

                                if (u->dropin_mtime > 0 &&
                                    timespec_load(&st.st_mtim) > u->dropin_mtime)
                                        return true;
                        }

                        return false;
                } else
                        return true;
        } else
                return true;
}

void unit_reset_failed(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->reset_failed)
                UNIT_VTABLE(u)->reset_failed(u);
}

Unit *unit_following(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->following)
                return UNIT_VTABLE(u)->following(u);

        return NULL;
}

bool unit_stop_pending(Unit *u) {
        assert(u);

        /* This call does check the current state of the unit. It's
         * hence useful to be called from state change calls of the
         * unit itself, where the state isn't updated yet. This is
         * different from unit_inactive_or_pending() which checks both
         * the current state and for a queued job. */

        return u->job && u->job->type == JOB_STOP;
}

bool unit_inactive_or_pending(Unit *u) {
        assert(u);

        /* Returns true if the unit is inactive or going down */

        if (UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)))
                return true;

        if (unit_stop_pending(u))
                return true;

        return false;
}

bool unit_active_or_pending(Unit *u) {
        assert(u);

        /* Returns true if the unit is active or going up */

        if (UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)))
                return true;

        if (u->job &&
            (u->job->type == JOB_START ||
             u->job->type == JOB_RELOAD_OR_START ||
             u->job->type == JOB_RESTART))
                return true;

        return false;
}

int unit_kill(Unit *u, KillWho w, int signo, DBusError *error) {
        assert(u);
        assert(w >= 0 && w < _KILL_WHO_MAX);
        assert(signo > 0);
        assert(signo < _NSIG);

        if (!UNIT_VTABLE(u)->kill)
                return -ENOTSUP;

        return UNIT_VTABLE(u)->kill(u, w, signo, error);
}

int unit_kill_common(
                Unit *u,
                KillWho who,
                int signo,
                pid_t main_pid,
                pid_t control_pid,
                DBusError *error) {

        int r = 0;

        if (who == KILL_MAIN && main_pid <= 0) {
                if (main_pid < 0)
                        dbus_set_error(error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no main processes", unit_type_to_string(u->type));
                else
                        dbus_set_error(error, BUS_ERROR_NO_SUCH_PROCESS, "No main process to kill");
                return -ESRCH;
        }

        if (who == KILL_CONTROL && control_pid <= 0) {
                if (control_pid < 0)
                        dbus_set_error(error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no control processes", unit_type_to_string(u->type));
                else
                        dbus_set_error(error, BUS_ERROR_NO_SUCH_PROCESS, "No control process to kill");
                return -ESRCH;
        }

        if (who == KILL_CONTROL || who == KILL_ALL)
                if (control_pid > 0)
                        if (kill(control_pid, signo) < 0)
                                r = -errno;

        if (who == KILL_MAIN || who == KILL_ALL)
                if (main_pid > 0)
                        if (kill(main_pid, signo) < 0)
                                r = -errno;

        if (who == KILL_ALL) {
                _cleanup_set_free_ Set *pid_set = NULL;
                int q;

                pid_set = set_new(trivial_hash_func, trivial_compare_func);
                if (!pid_set)
                        return -ENOMEM;

                /* Exclude the control/main pid from being killed via the cgroup */
                if (control_pid > 0) {
                        q = set_put(pid_set, LONG_TO_PTR(control_pid));
                        if (q < 0)
                                return q;
                }

                if (main_pid > 0) {
                        q = set_put(pid_set, LONG_TO_PTR(main_pid));
                        if (q < 0)
                                return q;
                }

                q = cgroup_bonding_kill_list(u->cgroup_bondings, signo, false, false, pid_set, NULL);
                if (q < 0 && q != -EAGAIN && q != -ESRCH && q != -ENOENT)
                        r = q;
        }

        return r;
}

int unit_following_set(Unit *u, Set **s) {
        assert(u);
        assert(s);

        if (UNIT_VTABLE(u)->following_set)
                return UNIT_VTABLE(u)->following_set(u, s);

        *s = NULL;
        return 0;
}

UnitFileState unit_get_unit_file_state(Unit *u) {
        assert(u);

        if (u->unit_file_state < 0 && u->fragment_path)
                u->unit_file_state = unit_file_get_state(
                                u->manager->running_as == SYSTEMD_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER,
                                NULL, path_get_file_name(u->fragment_path));

        return u->unit_file_state;
}

Unit* unit_ref_set(UnitRef *ref, Unit *u) {
        assert(ref);
        assert(u);

        if (ref->unit)
                unit_ref_unset(ref);

        ref->unit = u;
        LIST_PREPEND(UnitRef, refs, u->refs, ref);
        return u;
}

void unit_ref_unset(UnitRef *ref) {
        assert(ref);

        if (!ref->unit)
                return;

        LIST_REMOVE(UnitRef, refs, ref->unit->refs, ref);
        ref->unit = NULL;
}

int unit_add_one_mount_link(Unit *u, Mount *m) {
        char **i;

        assert(u);
        assert(m);

        if (u->load_state != UNIT_LOADED ||
            UNIT(m)->load_state != UNIT_LOADED)
                return 0;

        STRV_FOREACH(i, u->requires_mounts_for) {

                if (UNIT(m) == u)
                        continue;

                if (!path_startswith(*i, m->where))
                        continue;

                return unit_add_two_dependencies(u, UNIT_AFTER, UNIT_REQUIRES, UNIT(m), true);
        }

        return 0;
}

int unit_add_mount_links(Unit *u) {
        Unit *other;
        int r;

        assert(u);

        LIST_FOREACH(units_by_type, other, u->manager->units_by_type[UNIT_MOUNT]) {
                r = unit_add_one_mount_link(u, MOUNT(other));
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_exec_context_defaults(Unit *u, ExecContext *c) {
        unsigned i;
        int r;

        assert(u);
        assert(c);

        /* This only copies in the ones that need memory */

        for (i = 0; i < RLIMIT_NLIMITS; i++)
                if (u->manager->rlimit[i] && !c->rlimit[i]) {
                        c->rlimit[i] = newdup(struct rlimit, u->manager->rlimit[i], 1);
                        if (!c->rlimit[i])
                                return -ENOMEM;
                }

        if (u->manager->running_as == SYSTEMD_USER &&
            !c->working_directory) {

                r = get_home_dir(&c->working_directory);
                if (r < 0)
                        return r;
        }

        return 0;
}

ExecContext *unit_get_exec_context(Unit *u) {
        size_t offset;
        assert(u);

        offset = UNIT_VTABLE(u)->exec_context_offset;
        if (offset <= 0)
                return NULL;

        return (ExecContext*) ((uint8_t*) u + offset);
}

static int drop_in_file(Unit *u, bool runtime, const char *name, char **_p, char **_q) {
        char *p, *q;
        int r;

        assert(u);
        assert(name);
        assert(_p);
        assert(_q);

        if (u->manager->running_as == SYSTEMD_USER && runtime)
                return -ENOTSUP;

        if (!filename_is_safe(name))
                return -EINVAL;

        if (u->manager->running_as == SYSTEMD_USER) {
                _cleanup_free_ char *c = NULL;

                r = user_config_home(&c);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOENT;

                p = strjoin(c, "/", u->id, ".d", NULL);
        } else  if (runtime)
                p = strjoin("/run/systemd/system/", u->id, ".d", NULL);
        else
                p = strjoin("/etc/systemd/system/", u->id, ".d", NULL);
        if (!p)
                return -ENOMEM;

        q = strjoin(p, "/50-", name, ".conf", NULL);
        if (!q) {
                free(p);
                return -ENOMEM;
        }

        *_p = p;
        *_q = q;
        return 0;
}

int unit_write_drop_in(Unit *u, bool runtime, const char *name, const char *data) {
        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        assert(u);

        r = drop_in_file(u, runtime, name, &p, &q);
        if (r < 0)
                return r;

        mkdir_p(p, 0755);
        return write_string_file_atomic_label(q, data);
}

int unit_remove_drop_in(Unit *u, bool runtime, const char *name) {
        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        assert(u);

        r = drop_in_file(u, runtime, name, &p, &q);
        if (unlink(q) < 0)
                r = -errno;
        else
                r = 0;

        rmdir(p);
        return r;
}

int unit_kill_context(
                Unit *u,
                KillContext *c,
                bool sigkill,
                pid_t main_pid,
                pid_t control_pid,
                bool main_pid_alien) {

        int sig, wait_for_exit = 0, r;

        assert(u);
        assert(c);

        if (c->kill_mode == KILL_NONE)
                return 0;

        sig = sigkill ? SIGKILL : c->kill_signal;

        if (main_pid > 0) {
                r = kill_and_sigcont(main_pid, sig);

                if (r < 0 && r != -ESRCH) {
                        _cleanup_free_ char *comm = NULL;
                        get_process_comm(main_pid, &comm);

                        log_warning_unit(u->id, "Failed to kill main process %li (%s): %s",
                                         (long) main_pid, strna(comm), strerror(-r));
                } else
                        wait_for_exit = !main_pid_alien;
        }

        if (control_pid > 0) {
                r = kill_and_sigcont(control_pid, sig);

                if (r < 0 && r != -ESRCH) {
                        _cleanup_free_ char *comm = NULL;
                        get_process_comm(control_pid, &comm);

                        log_warning_unit(u->id,
                                         "Failed to kill control process %li (%s): %s",
                                         (long) control_pid, strna(comm), strerror(-r));
                } else
                        wait_for_exit = true;
        }

        if (c->kill_mode == KILL_CONTROL_GROUP) {
                _cleanup_set_free_ Set *pid_set = NULL;

                pid_set = set_new(trivial_hash_func, trivial_compare_func);
                if (!pid_set)
                        return -ENOMEM;

                /* Exclude the main/control pids from being killed via the cgroup */
                if (main_pid > 0) {
                        r = set_put(pid_set, LONG_TO_PTR(main_pid));
                        if (r < 0)
                                return r;
                }

                if (control_pid > 0) {
                        r = set_put(pid_set, LONG_TO_PTR(control_pid));
                        if (r < 0)
                                return r;
                }

                r = cgroup_bonding_kill_list(u->cgroup_bondings, sig, true, false, pid_set, NULL);
                if (r < 0) {
                        if (r != -EAGAIN && r != -ESRCH && r != -ENOENT)
                                log_warning_unit(u->id, "Failed to kill control group: %s", strerror(-r));
                } else if (r > 0)
                        wait_for_exit = true;
        }

        return wait_for_exit;
}

static const char* const unit_active_state_table[_UNIT_ACTIVE_STATE_MAX] = {
        [UNIT_ACTIVE] = "active",
        [UNIT_RELOADING] = "reloading",
        [UNIT_INACTIVE] = "inactive",
        [UNIT_FAILED] = "failed",
        [UNIT_ACTIVATING] = "activating",
        [UNIT_DEACTIVATING] = "deactivating"
};

DEFINE_STRING_TABLE_LOOKUP(unit_active_state, UnitActiveState);

static const char* const unit_dependency_table[_UNIT_DEPENDENCY_MAX] = {
        [UNIT_REQUIRES] = "Requires",
        [UNIT_REQUIRES_OVERRIDABLE] = "RequiresOverridable",
        [UNIT_REQUISITE] = "Requisite",
        [UNIT_REQUISITE_OVERRIDABLE] = "RequisiteOverridable",
        [UNIT_WANTS] = "Wants",
        [UNIT_BINDS_TO] = "BindsTo",
        [UNIT_PART_OF] = "PartOf",
        [UNIT_REQUIRED_BY] = "RequiredBy",
        [UNIT_REQUIRED_BY_OVERRIDABLE] = "RequiredByOverridable",
        [UNIT_WANTED_BY] = "WantedBy",
        [UNIT_BOUND_BY] = "BoundBy",
        [UNIT_CONSISTS_OF] = "ConsistsOf",
        [UNIT_CONFLICTS] = "Conflicts",
        [UNIT_CONFLICTED_BY] = "ConflictedBy",
        [UNIT_BEFORE] = "Before",
        [UNIT_AFTER] = "After",
        [UNIT_ON_FAILURE] = "OnFailure",
        [UNIT_TRIGGERS] = "Triggers",
        [UNIT_TRIGGERED_BY] = "TriggeredBy",
        [UNIT_PROPAGATES_RELOAD_TO] = "PropagatesReloadTo",
        [UNIT_RELOAD_PROPAGATED_FROM] = "ReloadPropagatedFrom",
        [UNIT_REFERENCES] = "References",
        [UNIT_REFERENCED_BY] = "ReferencedBy",
};

DEFINE_STRING_TABLE_LOOKUP(unit_dependency, UnitDependency);
