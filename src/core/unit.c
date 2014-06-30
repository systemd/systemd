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

#include "sd-id128.h"
#include "sd-messages.h"
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
#include "mkdir.h"
#include "label.h"
#include "fileio-label.h"
#include "bus-errors.h"
#include "dbus.h"
#include "execute.h"
#include "virt.h"
#include "dropin.h"

const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = &service_vtable,
        [UNIT_SOCKET] = &socket_vtable,
        [UNIT_BUSNAME] = &busname_vtable,
        [UNIT_TARGET] = &target_vtable,
        [UNIT_SNAPSHOT] = &snapshot_vtable,
        [UNIT_DEVICE] = &device_vtable,
        [UNIT_MOUNT] = &mount_vtable,
        [UNIT_AUTOMOUNT] = &automount_vtable,
        [UNIT_SWAP] = &swap_vtable,
        [UNIT_TIMER] = &timer_vtable,
        [UNIT_PATH] = &path_vtable,
        [UNIT_SLICE] = &slice_vtable,
        [UNIT_SCOPE] = &scope_vtable
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
        u->on_failure_job_mode = JOB_REPLACE;

        return u;
}

bool unit_has_name(Unit *u, const char *name) {
        assert(u);
        assert(name);

        return !!set_get(u->names, (char*) name);
}

static void unit_init(Unit *u) {
        CGroupContext *cc;
        ExecContext *ec;
        KillContext *kc;

        assert(u);
        assert(u->manager);
        assert(u->type >= 0);

        cc = unit_get_cgroup_context(u);
        if (cc) {
                cgroup_context_init(cc);

                /* Copy in the manager defaults into the cgroup
                 * context, _before_ the rest of the settings have
                 * been initialized */

                cc->cpu_accounting = u->manager->default_cpu_accounting;
                cc->blockio_accounting = u->manager->default_blockio_accounting;
                cc->memory_accounting = u->manager->default_memory_accounting;
        }

        ec = unit_get_exec_context(u);
        if (ec)
                exec_context_init(ec);

        kc = unit_get_kill_context(u);
        if (kc)
                kill_context_init(kc);

        if (UNIT_VTABLE(u)->init)
                UNIT_VTABLE(u)->init(u);
}

int unit_add_name(Unit *u, const char *text) {
        _cleanup_free_ char *s = NULL, *i = NULL;
        UnitType t;
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

        if (!unit_name_is_valid(s, TEMPLATE_INVALID))
                return -EINVAL;

        assert_se((t = unit_name_to_type(s)) >= 0);

        if (u->type != _UNIT_TYPE_INVALID && t != u->type)
                return -EINVAL;

        r = unit_name_to_instance(s, &i);
        if (r < 0)
                return r;

        if (i && unit_vtable[t]->no_instances)
                return -EINVAL;

        /* Ensure that this unit is either instanced or not instanced,
         * but not both. */
        if (u->type != _UNIT_TYPE_INVALID && !u->instance != !i)
                return -EINVAL;

        if (unit_vtable[t]->no_alias &&
            !set_isempty(u->names) &&
            !set_get(u->names, s))
                return -EEXIST;

        if (hashmap_size(u->manager->units) >= MANAGER_MAX_NAMES)
                return -E2BIG;

        r = set_put(u->names, s);
        if (r < 0) {
                if (r == -EEXIST)
                        return 0;

                return r;
        }

        r = hashmap_put(u->manager->units, s, u);
        if (r < 0) {
                set_remove(u->names, s);
                return r;
        }

        if (u->type == _UNIT_TYPE_INVALID) {
                u->type = t;
                u->id = s;
                u->instance = i;

                LIST_PREPEND(units_by_type, u->manager->units_by_type[t], u);

                unit_init(u);

                i = NULL;
        }

        s = NULL;

        unit_add_to_dbus_queue(u);
        return 0;
}

int unit_choose_id(Unit *u, const char *name) {
        _cleanup_free_ char *t = NULL;
        char *s, *i;
        int r;

        assert(u);
        assert(name);

        if (unit_name_is_template(name)) {

                if (!u->instance)
                        return -EINVAL;

                t = unit_name_replace_instance(name, u->instance);
                if (!t)
                        return -ENOMEM;

                name = t;
        }

        /* Selects one of the names of this unit as the id */
        s = set_get(u->names, (char*) name);
        if (!s)
                return -ENOENT;

        r = unit_name_to_instance(s, &i);
        if (r < 0)
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

        if (isempty(description))
                s = NULL;
        else {
                s = strdup(description);
                if (!s)
                        return -ENOMEM;
        }

        free(u->description);
        u->description = s;

        unit_add_to_dbus_queue(u);
        return 0;
}

bool unit_check_gc(Unit *u) {
        assert(u);

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

        LIST_PREPEND(load_queue, u->manager->load_queue, u);
        u->in_load_queue = true;
}

void unit_add_to_cleanup_queue(Unit *u) {
        assert(u);

        if (u->in_cleanup_queue)
                return;

        LIST_PREPEND(cleanup_queue, u->manager->cleanup_queue, u);
        u->in_cleanup_queue = true;
}

void unit_add_to_gc_queue(Unit *u) {
        assert(u);

        if (u->in_gc_queue || u->in_cleanup_queue)
                return;

        if (unit_check_gc(u))
                return;

        LIST_PREPEND(gc_queue, u->manager->gc_queue, u);
        u->in_gc_queue = true;

        u->manager->n_in_gc_queue ++;
}

void unit_add_to_dbus_queue(Unit *u) {
        assert(u);
        assert(u->type != _UNIT_TYPE_INVALID);

        if (u->load_state == UNIT_STUB || u->in_dbus_queue)
                return;

        /* Shortcut things if nobody cares */
        if (sd_bus_track_count(u->manager->subscribed) <= 0 &&
            set_isempty(u->manager->private_buses)) {
                u->sent_dbus_new_signal = true;
                return;
        }

        LIST_PREPEND(dbus_queue, u->manager->dbus_unit_queue, u);
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

static void unit_remove_transient(Unit *u) {
        char **i;

        assert(u);

        if (!u->transient)
                return;

        if (u->fragment_path)
                unlink(u->fragment_path);

        STRV_FOREACH(i, u->dropin_paths) {
                _cleanup_free_ char *p = NULL;
                int r;

                unlink(*i);

                r = path_get_parent(*i, &p);
                if (r >= 0)
                        rmdir(p);
        }
}

static void unit_free_requires_mounts_for(Unit *u) {
        char **j;

        STRV_FOREACH(j, u->requires_mounts_for) {
                char s[strlen(*j) + 1];

                PATH_FOREACH_PREFIX_MORE(s, *j) {
                        char *y;
                        Set *x;

                        x = hashmap_get2(u->manager->units_requiring_mounts_for, s, (void**) &y);
                        if (!x)
                                continue;

                        set_remove(x, u);

                        if (set_isempty(x)) {
                                hashmap_remove(u->manager->units_requiring_mounts_for, y);
                                free(y);
                                set_free(x);
                        }
                }
        }

        strv_free(u->requires_mounts_for);
        u->requires_mounts_for = NULL;
}

static void unit_done(Unit *u) {
        ExecContext *ec;
        CGroupContext *cc;

        assert(u);

        if (u->type < 0)
                return;

        if (UNIT_VTABLE(u)->done)
                UNIT_VTABLE(u)->done(u);

        ec = unit_get_exec_context(u);
        if (ec)
                exec_context_done(ec);

        cc = unit_get_cgroup_context(u);
        if (cc)
                cgroup_context_done(cc);
}

void unit_free(Unit *u) {
        UnitDependency d;
        Iterator i;
        char *t;

        assert(u);

        if (u->manager->n_reloading <= 0)
                unit_remove_transient(u);

        bus_unit_send_removed_signal(u);

        unit_done(u);

        unit_free_requires_mounts_for(u);

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

        if (u->type != _UNIT_TYPE_INVALID)
                LIST_REMOVE(units_by_type, u->manager->units_by_type[u->type], u);

        if (u->in_load_queue)
                LIST_REMOVE(load_queue, u->manager->load_queue, u);

        if (u->in_dbus_queue)
                LIST_REMOVE(dbus_queue, u->manager->dbus_unit_queue, u);

        if (u->in_cleanup_queue)
                LIST_REMOVE(cleanup_queue, u->manager->cleanup_queue, u);

        if (u->in_gc_queue) {
                LIST_REMOVE(gc_queue, u->manager->gc_queue, u);
                u->manager->n_in_gc_queue--;
        }

        if (u->in_cgroup_queue)
                LIST_REMOVE(cgroup_queue, u->manager->cgroup_queue, u);

        if (u->cgroup_path) {
                hashmap_remove(u->manager->cgroup_unit, u->cgroup_path);
                free(u->cgroup_path);
        }

        set_remove(u->manager->failed_units, u);
        set_remove(u->manager->startup_units, u);

        free(u->description);
        strv_free(u->documentation);
        free(u->fragment_path);
        free(u->source_path);
        strv_free(u->dropin_paths);
        free(u->instance);

        set_free_free(u->names);

        unit_unwatch_all_pids(u);

        condition_free_list(u->conditions);

        unit_ref_unset(&u->slice);

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

                for (k = 0; k < _UNIT_DEPENDENCY_MAX; k++) {
                        r = set_remove_and_put(back->dependencies[k], other, u);
                        if (r == -EEXIST)
                                set_remove(back->dependencies[k], other);
                        else
                                assert(r >= 0 || r == -ENOENT);
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
            other->load_state != UNIT_NOT_FOUND)
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
        _cleanup_free_ char *s = NULL;

        assert(u);
        assert(name);

        if (unit_name_is_template(name)) {
                if (!u->instance)
                        return -EINVAL;

                s = unit_name_replace_instance(name, u->instance);
                if (!s)
                        return -ENOMEM;

                name = s;
        }

        other = manager_get_unit(u->manager, name);
        if (!other)
                r = unit_add_name(u, name);
        else
                r = unit_merge(u, other);

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

        if (c->working_directory) {
                r = unit_require_mounts_for(u, c->working_directory);
                if (r < 0)
                        return r;
        }

        if (c->root_directory) {
                r = unit_require_mounts_for(u, c->root_directory);
                if (r < 0)
                        return r;
        }

        if (u->manager->running_as != SYSTEMD_SYSTEM)
                return 0;

        if (c->private_tmp) {
                r = unit_require_mounts_for(u, "/tmp");
                if (r < 0)
                        return r;

                r = unit_require_mounts_for(u, "/var/tmp");
                if (r < 0)
                        return r;
        }

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

        r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_JOURNALD_SOCKET, NULL, true);
        if (r < 0)
                return r;

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
        _cleanup_free_ char *p2 = NULL;
        const char *prefix2;
        char
                timestamp1[FORMAT_TIMESTAMP_MAX],
                timestamp2[FORMAT_TIMESTAMP_MAX],
                timestamp3[FORMAT_TIMESTAMP_MAX],
                timestamp4[FORMAT_TIMESTAMP_MAX],
                timespan[FORMAT_TIMESPAN_MAX];
        Unit *following;
        _cleanup_set_free_ Set *following_set = NULL;
        int r;

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
                "%s\tNeed Daemon Reload: %s\n"
                "%s\tTransient: %s\n"
                "%s\tSlice: %s\n"
                "%s\tCGroup: %s\n"
                "%s\tCGroup realized: %s\n"
                "%s\tCGroup mask: 0x%x\n"
                "%s\tCGroup members mask: 0x%x\n",
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
                prefix, yes_no(unit_need_daemon_reload(u)),
                prefix, yes_no(u->transient),
                prefix, strna(unit_slice_name(u)),
                prefix, strna(u->cgroup_path),
                prefix, yes_no(u->cgroup_realized),
                prefix, u->cgroup_realized_mask,
                prefix, u->cgroup_members_mask);

        SET_FOREACH(t, u->names, i)
                fprintf(f, "%s\tName: %s\n", prefix, t);

        STRV_FOREACH(j, u->documentation)
                fprintf(f, "%s\tDocumentation: %s\n", prefix, *j);

        following = unit_following(u);
        if (following)
                fprintf(f, "%s\tFollowing: %s\n", prefix, following->id);

        r = unit_following_set(u, &following_set);
        if (r >= 0) {
                Unit *other;

                SET_FOREACH(other, following_set, i)
                        fprintf(f, "%s\tFollowing Set Member: %s\n", prefix, other->id);
        }

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

                fprintf(f,
                        "%s\tStopWhenUnneeded: %s\n"
                        "%s\tRefuseManualStart: %s\n"
                        "%s\tRefuseManualStop: %s\n"
                        "%s\tDefaultDependencies: %s\n"
                        "%s\tOnFailureJobMode: %s\n"
                        "%s\tIgnoreOnIsolate: %s\n"
                        "%s\tIgnoreOnSnapshot: %s\n",
                        prefix, yes_no(u->stop_when_unneeded),
                        prefix, yes_no(u->refuse_manual_start),
                        prefix, yes_no(u->refuse_manual_stop),
                        prefix, yes_no(u->default_dependencies),
                        prefix, job_mode_to_string(u->on_failure_job_mode),
                        prefix, yes_no(u->ignore_on_isolate),
                        prefix, yes_no(u->ignore_on_snapshot));

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

}

/* Common implementation for multiple backends */
int unit_load_fragment_and_dropin(Unit *u) {
        int r;

        assert(u);

        /* Load a .{service,socket,...} file */
        r = unit_load_fragment(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_STUB)
                return -ENOENT;

        /* Load drop-in directory data */
        r = unit_load_dropin(unit_follow_merge(u));
        if (r < 0)
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
        r = unit_load_fragment(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_STUB)
                u->load_state = UNIT_LOADED;

        /* Load drop-in directory data */
        r = unit_load_dropin(unit_follow_merge(u));
        if (r < 0)
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

static int unit_add_target_dependencies(Unit *u) {

        static const UnitDependency deps[] = {
                UNIT_REQUIRED_BY,
                UNIT_REQUIRED_BY_OVERRIDABLE,
                UNIT_WANTED_BY,
                UNIT_BOUND_BY
        };

        Unit *target;
        Iterator i;
        unsigned k;
        int r = 0;

        assert(u);

        for (k = 0; k < ELEMENTSOF(deps); k++)
                SET_FOREACH(target, u->dependencies[deps[k]], i) {
                        r = unit_add_default_target_dependency(u, target);
                        if (r < 0)
                                return r;
                }

        return r;
}

static int unit_add_slice_dependencies(Unit *u) {
        assert(u);

        if (!unit_get_cgroup_context(u))
                return 0;

        if (UNIT_ISSET(u->slice))
                return unit_add_two_dependencies(u, UNIT_AFTER, UNIT_WANTS, UNIT_DEREF(u->slice), true);

        return unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_WANTS, SPECIAL_ROOT_SLICE, NULL, true);
}

static int unit_add_mount_dependencies(Unit *u) {
        char **i;
        int r;

        assert(u);

        STRV_FOREACH(i, u->requires_mounts_for) {
                char prefix[strlen(*i) + 1];

                PATH_FOREACH_PREFIX_MORE(prefix, *i) {
                        Unit *m;

                        r = manager_get_unit_by_path(u->manager, prefix, ".mount", &m);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;
                        if (m == u)
                                continue;

                        if (m->load_state != UNIT_LOADED)
                                continue;

                        r = unit_add_dependency(u, UNIT_AFTER, m, true);
                        if (r < 0)
                                return r;

                        if (m->fragment_path) {
                                r = unit_add_dependency(u, UNIT_REQUIRES, m, true);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

static int unit_add_startup_units(Unit *u) {
        CGroupContext *c;
        int r = 0;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        if (c->startup_cpu_shares == (unsigned long) -1 &&
            c->startup_blockio_weight == (unsigned long) -1)
                return 0;

        r = set_put(u->manager->startup_units, u);
        if (r == -EEXIST)
                return 0;

        return r;
}

int unit_load(Unit *u) {
        int r;

        assert(u);

        if (u->in_load_queue) {
                LIST_REMOVE(load_queue, u->manager->load_queue, u);
                u->in_load_queue = false;
        }

        if (u->type == _UNIT_TYPE_INVALID)
                return -EINVAL;

        if (u->load_state != UNIT_STUB)
                return 0;

        if (UNIT_VTABLE(u)->load) {
                r = UNIT_VTABLE(u)->load(u);
                if (r < 0)
                        goto fail;
        }

        if (u->load_state == UNIT_STUB) {
                r = -ENOENT;
                goto fail;
        }

        if (u->load_state == UNIT_LOADED) {

                r = unit_add_target_dependencies(u);
                if (r < 0)
                        goto fail;

                r = unit_add_slice_dependencies(u);
                if (r < 0)
                        goto fail;

                r = unit_add_mount_dependencies(u);
                if (r < 0)
                        goto fail;

                r = unit_add_startup_units(u);
                if (r < 0)
                        goto fail;

                if (u->on_failure_job_mode == JOB_ISOLATE && set_size(u->dependencies[UNIT_ON_FAILURE]) > 1) {
                        log_error_unit(u->id, "More than one OnFailure= dependencies specified for %s but OnFailureJobMode=isolate set. Refusing.", u->id);
                        r = -EINVAL;
                        goto fail;
                }

                unit_update_cgroup_members_masks(u);
        }

        assert((u->load_state != UNIT_MERGED) == !u->merged_into);

        unit_add_to_dbus_queue(unit_follow_merge(u));
        unit_add_to_gc_queue(u);

        return 0;

fail:
        u->load_state = u->load_state == UNIT_STUB ? UNIT_NOT_FOUND : UNIT_ERROR;
        u->load_error = r;
        unit_add_to_dbus_queue(u);
        unit_add_to_gc_queue(u);

        log_debug_unit(u->id, "Failed to load configuration for %s: %s",
                       u->id, strerror(-r));

        return r;
}

static bool unit_condition_test(Unit *u) {
        assert(u);

        dual_timestamp_get(&u->condition_timestamp);
        u->condition_result = condition_test_list(u->id, u->conditions);

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

        DISABLE_WARNING_FORMAT_NONLITERAL;
        unit_status_printf(u, "", format);
        REENABLE_WARNING;
}

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

        DISABLE_WARNING_FORMAT_NONLITERAL;
        snprintf(buf, sizeof(buf), format, unit_description(u));
        char_array_0(buf);
        REENABLE_WARNING;

        mid = t == JOB_START ? SD_MESSAGE_UNIT_STARTING :
              t == JOB_STOP  ? SD_MESSAGE_UNIT_STOPPING :
                               SD_MESSAGE_UNIT_RELOADING;

        log_struct_unit(LOG_INFO,
                        u->id,
                        MESSAGE_ID(mid),
                        "MESSAGE=%s", buf,
                        NULL);
}

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
        following = unit_following(u);
        if (following) {
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

        if (state != UNIT_ACTIVE) {
                log_warning_unit(u->id, "Unit %s cannot be reloaded because it is inactive.",
                                 u->id);
                return -ENOEXEC;
        }

        following = unit_following(u);
        if (following) {
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

                r = manager_add_job(u->manager, JOB_START, other, u->on_failure_job_mode, true, NULL, NULL);
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
         * UnitActiveState! That means that ns == os is an expected
         * behavior here. For example: if a mount point is remounted
         * this function will be called too! */

        m = u->manager;

        /* Update timestamps for state changes */
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

        /* Keep track of failed units */
        if (ns == UNIT_FAILED && os != UNIT_FAILED)
                set_put(u->manager->failed_units, u);
        else if (os == UNIT_FAILED && ns != UNIT_FAILED)
                set_remove(u->manager->failed_units, u);

        /* Make sure the cgroup is always removed when we become inactive */
        if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                unit_destroy_cgroup(u);

        /* Note that this doesn't apply to RemainAfterExit services exiting
         * successfully, since there's no change of state in that case. Which is
         * why it is handled in service_set_state() */
        if (UNIT_IS_INACTIVE_OR_FAILED(os) != UNIT_IS_INACTIVE_OR_FAILED(ns)) {
                ExecContext *ec;

                ec = unit_get_exec_context(u);
                if (ec && exec_context_may_touch_console(ec)) {
                        if (UNIT_IS_INACTIVE_OR_FAILED(ns)) {
                                m->n_on_console --;

                                if (m->n_on_console == 0)
                                        /* unset no_console_output flag, since the console is free */
                                        m->no_console_output = false;
                        } else
                                m->n_on_console ++;
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
                if (UNIT_IS_INACTIVE_OR_DEACTIVATING(ns))
                        check_unneeded_dependencies(u);

                if (ns != os && ns == UNIT_FAILED) {
                        log_notice_unit(u->id, "Unit %s entered failed state.", u->id);
                        unit_start_on_failure(u);
                }
        }

        /* Some names are special */
        if (UNIT_IS_ACTIVE_OR_RELOADING(ns)) {

                if (unit_has_name(u, SPECIAL_DBUS_SERVICE))
                        /* The bus might have just become available,
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

int unit_watch_pid(Unit *u, pid_t pid) {
        int q, r;

        assert(u);
        assert(pid >= 1);

        /* Watch a specific PID. We only support one or two units
         * watching each PID for now, not more. */

        r = set_ensure_allocated(&u->pids, trivial_hash_func, trivial_compare_func);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&u->manager->watch_pids1, trivial_hash_func, trivial_compare_func);
        if (r < 0)
                return r;

        r = hashmap_put(u->manager->watch_pids1, LONG_TO_PTR(pid), u);
        if (r == -EEXIST) {
                r = hashmap_ensure_allocated(&u->manager->watch_pids2, trivial_hash_func, trivial_compare_func);
                if (r < 0)
                        return r;

                r = hashmap_put(u->manager->watch_pids2, LONG_TO_PTR(pid), u);
        }

        q = set_put(u->pids, LONG_TO_PTR(pid));
        if (q < 0)
                return q;

        return r;
}

void unit_unwatch_pid(Unit *u, pid_t pid) {
        assert(u);
        assert(pid >= 1);

        hashmap_remove_value(u->manager->watch_pids1, LONG_TO_PTR(pid), u);
        hashmap_remove_value(u->manager->watch_pids2, LONG_TO_PTR(pid), u);
        set_remove(u->pids, LONG_TO_PTR(pid));
}

void unit_unwatch_all_pids(Unit *u) {
        assert(u);

        while (!set_isempty(u->pids))
                unit_unwatch_pid(u, PTR_TO_LONG(set_first(u->pids)));

        set_free(u->pids);
        u->pids = NULL;
}

static int unit_watch_pids_in_path(Unit *u, const char *path) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int ret = 0, r;

        assert(u);
        assert(path);

        /* Adds all PIDs from a specific cgroup path to the set of PIDs we watch. */

        r = cg_enumerate_processes(SYSTEMD_CGROUP_CONTROLLER, path, &f);
        if (r >= 0) {
                pid_t pid;

                while ((r = cg_read_pid(f, &pid)) > 0) {
                        r = unit_watch_pid(u, pid);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }
                if (r < 0 && ret >= 0)
                        ret = r;

        } else if (ret >= 0)
                ret = r;

        r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, path, &d);
        if (r >= 0) {
                char *fn;

                while ((r = cg_read_subgroup(d, &fn)) > 0) {
                        _cleanup_free_ char *p = NULL;

                        p = strjoin(path, "/", fn, NULL);
                        free(fn);

                        if (!p)
                                return -ENOMEM;

                        r = unit_watch_pids_in_path(u, p);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }
                if (r < 0 && ret >= 0)
                        ret = r;

        } else if (ret >= 0)
                ret = r;

        return ret;
}

int unit_watch_all_pids(Unit *u) {
        assert(u);

        /* Adds all PIDs from our cgroup to the set of PIDs we watch */

        if (!u->cgroup_path)
                return -ENOENT;

        return unit_watch_pids_in_path(u, u->cgroup_path);
}

void unit_tidy_watch_pids(Unit *u, pid_t except1, pid_t except2) {
        Iterator i;
        void *e;

        assert(u);

        /* Cleans dead PIDs from our list */

        SET_FOREACH(e, u->pids, i) {
                pid_t pid = PTR_TO_LONG(e);

                if (pid == except1 || pid == except2)
                        continue;

                if (!pid_is_unwaited(pid))
                        unit_unwatch_pid(u, pid);
        }
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
                [UNIT_JOINS_NAMESPACE_OF] = UNIT_JOINS_NAMESPACE_OF,
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

        r = set_ensure_allocated(&u->dependencies[d], trivial_hash_func, trivial_compare_func);
        if (r < 0)
                return r;

        if (inverse_table[d] != _UNIT_DEPENDENCY_INVALID) {
                r = set_ensure_allocated(&other->dependencies[inverse_table[d]], trivial_hash_func, trivial_compare_func);
                if (r < 0)
                        return r;
        }

        if (add_reference) {
                r = set_ensure_allocated(&u->dependencies[UNIT_REFERENCES], trivial_hash_func, trivial_compare_func);
                if (r < 0)
                        return r;

                r = set_ensure_allocated(&other->dependencies[UNIT_REFERENCED_BY], trivial_hash_func, trivial_compare_func);
                if (r < 0)
                        return r;
        }

        q = set_put(u->dependencies[d], other);
        if (q < 0)
                return q;

        if (inverse_table[d] != _UNIT_DEPENDENCY_INVALID && inverse_table[d] != d) {
                v = set_put(other->dependencies[inverse_table[d]], u);
                if (v < 0) {
                        r = v;
                        goto fail;
                }
        }

        if (add_reference) {
                w = set_put(u->dependencies[UNIT_REFERENCES], other);
                if (w < 0) {
                        r = w;
                        goto fail;
                }

                r = set_put(other->dependencies[UNIT_REFERENCED_BY], u);
                if (r < 0)
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
                name = basename(path);

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
        _cleanup_free_ char *s = NULL;

        assert(u);
        assert(name || path);

        if (!(name = resolve_template(u, name, path, &s)))
                return -ENOMEM;

        if ((r = manager_load_unit(u->manager, name, path, NULL, &other)) < 0)
                return r;

        r = unit_add_two_dependencies(u, d, e, other, add_reference);

        return r;
}

int unit_add_dependency_by_name_inverse(Unit *u, UnitDependency d, const char *name, const char *path, bool add_reference) {
        Unit *other;
        int r;
        _cleanup_free_ char *s = NULL;

        assert(u);
        assert(name || path);

        if (!(name = resolve_template(u, name, path, &s)))
                return -ENOMEM;

        if ((r = manager_load_unit(u->manager, name, path, NULL, &other)) < 0)
                return r;

        r = unit_add_dependency(other, d, u, add_reference);

        return r;
}

int unit_add_two_dependencies_by_name_inverse(Unit *u, UnitDependency d, UnitDependency e, const char *name, const char *path, bool add_reference) {
        Unit *other;
        int r;
        _cleanup_free_ char *s = NULL;

        assert(u);
        assert(name || path);

        if (!(name = resolve_template(u, name, path, &s)))
                return -ENOMEM;

        if ((r = manager_load_unit(u->manager, name, path, NULL, &other)) < 0)
                return r;

        if ((r = unit_add_two_dependencies(other, d, e, u, add_reference)) < 0)
                return r;

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

char *unit_default_cgroup_path(Unit *u) {
        _cleanup_free_ char *escaped = NULL, *slice = NULL;
        int r;

        assert(u);

        if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                return strdup(u->manager->cgroup_root);

        if (UNIT_ISSET(u->slice) && !unit_has_name(UNIT_DEREF(u->slice), SPECIAL_ROOT_SLICE)) {
                r = cg_slice_to_path(UNIT_DEREF(u->slice)->id, &slice);
                if (r < 0)
                        return NULL;
        }

        escaped = cg_escape(u->id);
        if (!escaped)
                return NULL;

        if (slice)
                return strjoin(u->manager->cgroup_root, "/", slice, "/", escaped, NULL);
        else
                return strjoin(u->manager->cgroup_root, "/", escaped, NULL);
}

int unit_add_default_slice(Unit *u, CGroupContext *c) {
        _cleanup_free_ char *b = NULL;
        const char *slice_name;
        Unit *slice;
        int r;

        assert(u);
        assert(c);

        if (UNIT_ISSET(u->slice))
                return 0;

        if (u->instance) {
                _cleanup_free_ char *prefix = NULL, *escaped = NULL;

                /* Implicitly place all instantiated units in their
                 * own per-template slice */

                prefix = unit_name_to_prefix(u->id);
                if (!prefix)
                        return -ENOMEM;

                /* The prefix is already escaped, but it might include
                 * "-" which has a special meaning for slice units,
                 * hence escape it here extra. */
                escaped = strreplace(prefix, "-", "\\x2d");
                if (!escaped)
                        return -ENOMEM;

                if (u->manager->running_as == SYSTEMD_SYSTEM)
                        b = strjoin("system-", escaped, ".slice", NULL);
                else
                        b = strappend(escaped, ".slice");
                if (!b)
                        return -ENOMEM;

                slice_name = b;
        } else
                slice_name =
                        u->manager->running_as == SYSTEMD_SYSTEM
                        ? SPECIAL_SYSTEM_SLICE
                        : SPECIAL_ROOT_SLICE;

        r = manager_load_unit(u->manager, slice_name, NULL, NULL, &slice);
        if (r < 0)
                return r;

        unit_ref_set(&u->slice, slice);
        return 0;
}

const char *unit_slice_name(Unit *u) {
        assert(u);

        if (!UNIT_ISSET(u->slice))
                return NULL;

        return UNIT_DEREF(u->slice)->id;
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

        if (unit_can_serialize(u)) {
                ExecRuntime *rt;

                r = UNIT_VTABLE(u)->serialize(u, f, fds);
                if (r < 0)
                        return r;

                rt = unit_get_exec_runtime(u);
                if (rt) {
                        r = exec_runtime_serialize(rt, u, f, fds);
                        if (r < 0)
                                return r;
                }
        }

        dual_timestamp_serialize(f, "inactive-exit-timestamp", &u->inactive_exit_timestamp);
        dual_timestamp_serialize(f, "active-enter-timestamp", &u->active_enter_timestamp);
        dual_timestamp_serialize(f, "active-exit-timestamp", &u->active_exit_timestamp);
        dual_timestamp_serialize(f, "inactive-enter-timestamp", &u->inactive_enter_timestamp);
        dual_timestamp_serialize(f, "condition-timestamp", &u->condition_timestamp);

        if (dual_timestamp_is_set(&u->condition_timestamp))
                unit_serialize_item(u, f, "condition-result", yes_no(u->condition_result));

        unit_serialize_item(u, f, "transient", yes_no(u->transient));

        if (u->cgroup_path)
                unit_serialize_item(u, f, "cgroup", u->cgroup_path);

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
        ExecRuntime **rt = NULL;
        size_t offset;
        int r;

        assert(u);
        assert(f);
        assert(fds);

        offset = UNIT_VTABLE(u)->exec_runtime_offset;
        if (offset > 0)
                rt = (ExecRuntime**) ((uint8_t*) u + offset);

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

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse condition result value %s", v);
                        else
                                u->condition_result = b;

                        continue;

                } else if (streq(l, "transient")) {
                        int b;

                        b = parse_boolean(v);
                        if (b < 0)
                                log_debug("Failed to parse transient bool %s", v);
                        else
                                u->transient = b;

                        continue;
                } else if (streq(l, "cgroup")) {
                        char *s;

                        s = strdup(v);
                        if (!s)
                                return -ENOMEM;

                        if (u->cgroup_path) {
                                void *p;

                                p = hashmap_remove(u->manager->cgroup_unit, u->cgroup_path);
                                log_info("Removing cgroup_path %s from hashmap (%p)",
                                         u->cgroup_path, p);
                                free(u->cgroup_path);
                        }

                        u->cgroup_path = s;
                        assert(hashmap_put(u->manager->cgroup_unit, s, u) == 1);

                        continue;
                }

                if (unit_can_serialize(u)) {
                        if (rt) {
                                r = exec_runtime_deserialize_item(rt, u, l, v, fds);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        continue;
                        }

                        r = UNIT_VTABLE(u)->deserialize_item(u, l, v, fds);
                        if (r < 0)
                                return r;
                }
        }
}

int unit_add_node_link(Unit *u, const char *what, bool wants) {
        Unit *device;
        _cleanup_free_ char *e = NULL;
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

void unit_status_printf(Unit *u, const char *status, const char *unit_status_msg_format) {
        DISABLE_WARNING_FORMAT_NONLITERAL;
        manager_status_printf(u->manager, false, status, unit_status_msg_format, unit_description(u));
        REENABLE_WARNING;
}

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

int unit_kill(Unit *u, KillWho w, int signo, sd_bus_error *error) {
        assert(u);
        assert(w >= 0 && w < _KILL_WHO_MAX);
        assert(signo > 0);
        assert(signo < _NSIG);

        if (!UNIT_VTABLE(u)->kill)
                return -ENOTSUP;

        return UNIT_VTABLE(u)->kill(u, w, signo, error);
}

static Set *unit_pid_set(pid_t main_pid, pid_t control_pid) {
        Set *pid_set;
        int r;

        pid_set = set_new(trivial_hash_func, trivial_compare_func);
        if (!pid_set)
                return NULL;

        /* Exclude the main/control pids from being killed via the cgroup */
        if (main_pid > 0) {
                r = set_put(pid_set, LONG_TO_PTR(main_pid));
                if (r < 0)
                        goto fail;
        }

        if (control_pid > 0) {
                r = set_put(pid_set, LONG_TO_PTR(control_pid));
                if (r < 0)
                        goto fail;
        }

        return pid_set;

fail:
        set_free(pid_set);
        return NULL;
}

int unit_kill_common(
                Unit *u,
                KillWho who,
                int signo,
                pid_t main_pid,
                pid_t control_pid,
                sd_bus_error *error) {

        int r = 0;

        if (who == KILL_MAIN && main_pid <= 0) {
                if (main_pid < 0)
                        sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no main processes", unit_type_to_string(u->type));
                else
                        sd_bus_error_set_const(error, BUS_ERROR_NO_SUCH_PROCESS, "No main process to kill");
                return -ESRCH;
        }

        if (who == KILL_CONTROL && control_pid <= 0) {
                if (control_pid < 0)
                        sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no control processes", unit_type_to_string(u->type));
                else
                        sd_bus_error_set_const(error, BUS_ERROR_NO_SUCH_PROCESS, "No control process to kill");
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

        if (who == KILL_ALL && u->cgroup_path) {
                _cleanup_set_free_ Set *pid_set = NULL;
                int q;

                /* Exclude the main/control pids from being killed via the cgroup */
                pid_set = unit_pid_set(main_pid, control_pid);
                if (!pid_set)
                        return -ENOMEM;

                q = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, signo, false, true, false, pid_set);
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
                                NULL, basename(u->fragment_path));

        return u->unit_file_state;
}

Unit* unit_ref_set(UnitRef *ref, Unit *u) {
        assert(ref);
        assert(u);

        if (ref->unit)
                unit_ref_unset(ref);

        ref->unit = u;
        LIST_PREPEND(refs, u->refs, ref);
        return u;
}

void unit_ref_unset(UnitRef *ref) {
        assert(ref);

        if (!ref->unit)
                return;

        LIST_REMOVE(refs, ref->unit->refs, ref);
        ref->unit = NULL;
}

int unit_patch_contexts(Unit *u) {
        CGroupContext *cc;
        ExecContext *ec;
        unsigned i;
        int r;

        assert(u);

        /* Patch in the manager defaults into the exec and cgroup
         * contexts, _after_ the rest of the settings have been
         * initialized */

        ec = unit_get_exec_context(u);
        if (ec) {
                /* This only copies in the ones that need memory */
                for (i = 0; i < _RLIMIT_MAX; i++)
                        if (u->manager->rlimit[i] && !ec->rlimit[i]) {
                                ec->rlimit[i] = newdup(struct rlimit, u->manager->rlimit[i], 1);
                                if (!ec->rlimit[i])
                                        return -ENOMEM;
                        }

                if (u->manager->running_as == SYSTEMD_USER &&
                    !ec->working_directory) {

                        r = get_home_dir(&ec->working_directory);
                        if (r < 0)
                                return r;
                }

                if (u->manager->running_as == SYSTEMD_USER &&
                    (ec->syscall_whitelist ||
                     !set_isempty(ec->syscall_filter) ||
                     !set_isempty(ec->syscall_archs) ||
                     ec->address_families_whitelist ||
                     !set_isempty(ec->address_families)))
                        ec->no_new_privileges = true;

                if (ec->private_devices)
                        ec->capability_bounding_set_drop |= (uint64_t) 1ULL << (uint64_t) CAP_MKNOD;
        }

        cc = unit_get_cgroup_context(u);
        if (cc) {

                if (ec &&
                    ec->private_devices &&
                    cc->device_policy == CGROUP_AUTO)
                        cc->device_policy = CGROUP_CLOSED;
        }

        return 0;
}

ExecContext *unit_get_exec_context(Unit *u) {
        size_t offset;
        assert(u);

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->exec_context_offset;
        if (offset <= 0)
                return NULL;

        return (ExecContext*) ((uint8_t*) u + offset);
}

KillContext *unit_get_kill_context(Unit *u) {
        size_t offset;
        assert(u);

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->kill_context_offset;
        if (offset <= 0)
                return NULL;

        return (KillContext*) ((uint8_t*) u + offset);
}

CGroupContext *unit_get_cgroup_context(Unit *u) {
        size_t offset;

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->cgroup_context_offset;
        if (offset <= 0)
                return NULL;

        return (CGroupContext*) ((uint8_t*) u + offset);
}

ExecRuntime *unit_get_exec_runtime(Unit *u) {
        size_t offset;

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->exec_runtime_offset;
        if (offset <= 0)
                return NULL;

        return *(ExecRuntime**) ((uint8_t*) u + offset);
}

static int unit_drop_in_dir(Unit *u, UnitSetPropertiesMode mode, bool transient, char **dir) {
        if (u->manager->running_as == SYSTEMD_USER) {
                int r;

                r = user_config_home(dir);
                if (r == 0)
                        return -ENOENT;
                return r;
        }

        if (mode == UNIT_PERSISTENT && !transient)
                *dir = strdup("/etc/systemd/system");
        else
                *dir = strdup("/run/systemd/system");
        if (!*dir)
                return -ENOMEM;

        return 0;
}

static int unit_drop_in_file(Unit *u,
                             UnitSetPropertiesMode mode, const char *name, char **p, char **q) {
        _cleanup_free_ char *dir = NULL;
        int r;

        assert(u);

        r = unit_drop_in_dir(u, mode, u->transient, &dir);
        if (r < 0)
                return r;

        return drop_in_file(dir, u->id, 50, name, p, q);
}

int unit_write_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *data) {

        _cleanup_free_ char *dir = NULL;
        int r;

        assert(u);

        if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
                return 0;

        r = unit_drop_in_dir(u, mode, u->transient, &dir);
        if (r < 0)
                return r;

        return write_drop_in(dir, u->id, 50, name, data);
}

int unit_write_drop_in_format(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        assert(u);
        assert(name);
        assert(format);

        if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
                return 0;

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return unit_write_drop_in(u, mode, name, p);
}

int unit_write_drop_in_private(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *data) {
        _cleanup_free_ char *ndata = NULL;

        assert(u);
        assert(name);
        assert(data);

        if (!UNIT_VTABLE(u)->private_section)
                return -EINVAL;

        if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
                return 0;

        ndata = strjoin("[", UNIT_VTABLE(u)->private_section, "]\n", data, NULL);
        if (!ndata)
                return -ENOMEM;

        return unit_write_drop_in(u, mode, name, ndata);
}

int unit_write_drop_in_private_format(Unit *u, UnitSetPropertiesMode mode, const char *name, const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        assert(u);
        assert(name);
        assert(format);

        if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
                return 0;

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return unit_write_drop_in_private(u, mode, name, p);
}

int unit_remove_drop_in(Unit *u, UnitSetPropertiesMode mode, const char *name) {
        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        assert(u);

        if (!IN_SET(mode, UNIT_PERSISTENT, UNIT_RUNTIME))
                return 0;

        r = unit_drop_in_file(u, mode, name, &p, &q);
        if (r < 0)
                return r;

        if (unlink(q) < 0)
                r = errno == ENOENT ? 0 : -errno;
        else
                r = 1;

        rmdir(p);
        return r;
}

int unit_make_transient(Unit *u) {
        int r;

        assert(u);

        u->load_state = UNIT_STUB;
        u->load_error = 0;
        u->transient = true;

        free(u->fragment_path);
        u->fragment_path = NULL;

        if (u->manager->running_as == SYSTEMD_USER) {
                _cleanup_free_ char *c = NULL;

                r = user_config_home(&c);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOENT;

                u->fragment_path = strjoin(c, "/", u->id, NULL);
                if (!u->fragment_path)
                        return -ENOMEM;

                mkdir_p(c, 0755);
        } else {
                u->fragment_path = strappend("/run/systemd/system/", u->id);
                if (!u->fragment_path)
                        return -ENOMEM;

                mkdir_p("/run/systemd/system", 0755);
        }

        return write_string_file_atomic_label(u->fragment_path, "# Transient stub");
}

int unit_kill_context(
                Unit *u,
                KillContext *c,
                bool sigkill,
                pid_t main_pid,
                pid_t control_pid,
                bool main_pid_alien) {

        int sig, wait_for_exit = false, r;

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

                        log_warning_unit(u->id, "Failed to kill main process " PID_FMT " (%s): %s", main_pid, strna(comm), strerror(-r));
                } else {
                        if (!main_pid_alien)
                                wait_for_exit = true;

                        if (c->send_sighup && !sigkill)
                                kill(main_pid, SIGHUP);
                }
        }

        if (control_pid > 0) {
                r = kill_and_sigcont(control_pid, sig);

                if (r < 0 && r != -ESRCH) {
                        _cleanup_free_ char *comm = NULL;
                        get_process_comm(control_pid, &comm);

                        log_warning_unit(u->id, "Failed to kill control process " PID_FMT " (%s): %s", control_pid, strna(comm), strerror(-r));
                } else {
                        wait_for_exit = true;

                        if (c->send_sighup && !sigkill)
                                kill(control_pid, SIGHUP);
                }
        }

        if ((c->kill_mode == KILL_CONTROL_GROUP || (c->kill_mode == KILL_MIXED && sigkill)) && u->cgroup_path) {
                _cleanup_set_free_ Set *pid_set = NULL;

                /* Exclude the main/control pids from being killed via the cgroup */
                pid_set = unit_pid_set(main_pid, control_pid);
                if (!pid_set)
                        return -ENOMEM;

                r = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, sig, true, true, false, pid_set);
                if (r < 0) {
                        if (r != -EAGAIN && r != -ESRCH && r != -ENOENT)
                                log_warning_unit(u->id, "Failed to kill control group: %s", strerror(-r));
                } else if (r > 0) {

                        /* FIXME: For now, we will not wait for the
                         * cgroup members to die, simply because
                         * cgroup notification is unreliable. It
                         * doesn't work at all in containers, and
                         * outside of containers it can be confused
                         * easily by leaving directories in the
                         * cgroup. */

                        /* wait_for_exit = true; */

                        if (c->send_sighup && !sigkill) {
                                set_free(pid_set);

                                pid_set = unit_pid_set(main_pid, control_pid);
                                if (!pid_set)
                                        return -ENOMEM;

                                cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, SIGHUP, false, true, false, pid_set);
                        }
                }
        }

        return wait_for_exit;
}

int unit_require_mounts_for(Unit *u, const char *path) {
        char prefix[strlen(path) + 1], *p;
        int r;

        assert(u);
        assert(path);

        /* Registers a unit for requiring a certain path and all its
         * prefixes. We keep a simple array of these paths in the
         * unit, since its usually short. However, we build a prefix
         * table for all possible prefixes so that new appearing mount
         * units can easily determine which units to make themselves a
         * dependency of. */

        if (!path_is_absolute(path))
                return -EINVAL;

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        path_kill_slashes(p);

        if (!path_is_safe(p)) {
                free(p);
                return -EPERM;
        }

        if (strv_contains(u->requires_mounts_for, p)) {
                free(p);
                return 0;
        }

        r = strv_consume(&u->requires_mounts_for, p);
        if (r < 0)
                return r;

        PATH_FOREACH_PREFIX_MORE(prefix, p) {
                Set *x;

                x = hashmap_get(u->manager->units_requiring_mounts_for, prefix);
                if (!x) {
                        char *q;

                        if (!u->manager->units_requiring_mounts_for) {
                                u->manager->units_requiring_mounts_for = hashmap_new(string_hash_func, string_compare_func);
                                if (!u->manager->units_requiring_mounts_for)
                                        return -ENOMEM;
                        }

                        q = strdup(prefix);
                        if (!q)
                                return -ENOMEM;

                        x = set_new(NULL, NULL);
                        if (!x) {
                                free(q);
                                return -ENOMEM;
                        }

                        r = hashmap_put(u->manager->units_requiring_mounts_for, q, x);
                        if (r < 0) {
                                free(q);
                                set_free(x);
                                return r;
                        }
                }

                r = set_put(x, u);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_setup_exec_runtime(Unit *u) {
        ExecRuntime **rt;
        size_t offset;
        Iterator i;
        Unit *other;

        offset = UNIT_VTABLE(u)->exec_runtime_offset;
        assert(offset > 0);

        /* Check if ther already is an ExecRuntime for this unit? */
        rt = (ExecRuntime**) ((uint8_t*) u + offset);
        if (*rt)
                return 0;

        /* Try to get it from somebody else */
        SET_FOREACH(other, u->dependencies[UNIT_JOINS_NAMESPACE_OF], i) {

                *rt = unit_get_exec_runtime(other);
                if (*rt) {
                        exec_runtime_ref(*rt);
                        return 0;
                }
        }

        return exec_runtime_make(rt, unit_get_exec_context(u), u->id);
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
        [UNIT_JOINS_NAMESPACE_OF] = "JoinsNamespaceOf",
        [UNIT_REFERENCES] = "References",
        [UNIT_REFERENCED_BY] = "ReferencedBy",
};

DEFINE_STRING_TABLE_LOOKUP(unit_dependency, UnitDependency);
