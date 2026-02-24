/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <linux/capability.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-id128.h"
#include "sd-messages.h"

#include "all-units.h"
#include "alloc-util.h"
#include "ansi-color.h"
#include "bitfield.h"
#include "bpf-restrict-fs.h"
#include "bus-common-errors.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "chase.h"
#include "chattr-util.h"
#include "condition.h"
#include "dbus-unit.h"
#include "dropin.h"
#include "dynamic-user.h"
#include "env-util.h"
#include "escape.h"
#include "exec-credential.h"
#include "execute.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "id128-util.h"
#include "install.h"
#include "iovec-util.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "logarithm.h"
#include "mkdir-label.h"
#include "manager.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "netlink-internal.h"
#include "path-util.h"
#include "process-util.h"
#include "quota-util.h"
#include "rm-rf.h"
#include "serialize.h"
#include "set.h"
#include "signal-util.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "special.h"
#include "specifier.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "unit.h"
#include "unit-name.h"
#include "user-util.h"
#include "varlink.h"

/* Thresholds for logging at INFO level about resource consumption */
#define MENTIONWORTHY_CPU_NSEC     (1 * NSEC_PER_SEC)
#define MENTIONWORTHY_MEMORY_BYTES (64 * U64_MB)
#define MENTIONWORTHY_IO_BYTES     (1 * U64_MB)
#define MENTIONWORTHY_IP_BYTES     UINT64_C(0)

/* Thresholds for logging at NOTICE level about resource consumption */
#define NOTICEWORTHY_CPU_NSEC     (10 * NSEC_PER_MINUTE)
#define NOTICEWORTHY_MEMORY_BYTES (512 * U64_MB)
#define NOTICEWORTHY_IO_BYTES     (10 * U64_MB)
#define NOTICEWORTHY_IP_BYTES     (128 * U64_MB)

const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE]   = &service_vtable,
        [UNIT_SOCKET]    = &socket_vtable,
        [UNIT_TARGET]    = &target_vtable,
        [UNIT_DEVICE]    = &device_vtable,
        [UNIT_MOUNT]     = &mount_vtable,
        [UNIT_AUTOMOUNT] = &automount_vtable,
        [UNIT_SWAP]      = &swap_vtable,
        [UNIT_TIMER]     = &timer_vtable,
        [UNIT_PATH]      = &path_vtable,
        [UNIT_SLICE]     = &slice_vtable,
        [UNIT_SCOPE]     = &scope_vtable,
};

Unit* unit_new(Manager *m, size_t size) {
        Unit *u;

        assert(m);
        assert(size >= sizeof(Unit));

        u = malloc0(size);
        if (!u)
                return NULL;

        u->manager = m;
        u->type = _UNIT_TYPE_INVALID;
        u->default_dependencies = true;
        u->unit_file_state = _UNIT_FILE_STATE_INVALID;
        u->unit_file_preset = _PRESET_ACTION_INVALID;
        u->on_failure_job_mode = JOB_REPLACE;
        u->on_success_job_mode = JOB_FAIL;
        u->job_timeout = USEC_INFINITY;
        u->job_running_timeout = USEC_INFINITY;
        u->ref_uid = UID_INVALID;
        u->ref_gid = GID_INVALID;

        u->failure_action_exit_status = u->success_action_exit_status = -1;

        u->last_section_private = -1;

        u->start_ratelimit = m->defaults.start_limit;

        u->auto_start_stop_ratelimit = (const RateLimit) {
                .interval = 10 * USEC_PER_SEC,
                .burst = 16
        };

        return u;
}

int unit_new_for_name(Manager *m, size_t size, const char *name, Unit **ret) {
        _cleanup_(unit_freep) Unit *u = NULL;
        int r;

        u = unit_new(m, size);
        if (!u)
                return -ENOMEM;

        r = unit_add_name(u, name);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(u);

        return r;
}

bool unit_has_name(const Unit *u, const char *name) {
        assert(u);
        assert(name);

        return streq_ptr(name, u->id) ||
               set_contains(u->aliases, name);
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

                cc->io_accounting = u->manager->defaults.io_accounting;
                cc->memory_accounting = u->manager->defaults.memory_accounting;
                cc->tasks_accounting = u->manager->defaults.tasks_accounting;
                cc->ip_accounting = u->manager->defaults.ip_accounting;

                if (u->type != UNIT_SLICE)
                        cc->tasks_max = u->manager->defaults.tasks_max;

                cc->memory_pressure_watch = u->manager->defaults.memory_pressure_watch;
                cc->memory_pressure_threshold_usec = u->manager->defaults.memory_pressure_threshold_usec;
        }

        ec = unit_get_exec_context(u);
        if (ec) {
                exec_context_init(ec);

                if (u->manager->defaults.oom_score_adjust_set) {
                        ec->oom_score_adjust = u->manager->defaults.oom_score_adjust;
                        ec->oom_score_adjust_set = true;
                }

                ec->restrict_suid_sgid = u->manager->defaults.restrict_suid_sgid;

                if (MANAGER_IS_SYSTEM(u->manager))
                        ec->keyring_mode = EXEC_KEYRING_SHARED;
                else {
                        ec->keyring_mode = EXEC_KEYRING_INHERIT;

                        /* User manager might have its umask redefined by PAM or UMask=. In this
                         * case let the units it manages inherit this value by default. They can
                         * still tune this value through their own unit file */
                        (void) get_process_umask(0, &ec->umask);
                }
        }

        kc = unit_get_kill_context(u);
        if (kc)
                kill_context_init(kc);

        if (UNIT_VTABLE(u)->init)
                UNIT_VTABLE(u)->init(u);
}

static int unit_add_alias(Unit *u, char *donated_name) {
        int r;

        /* Make sure that u->names is allocated. We may leave u->names
         * empty if we fail later, but this is not a problem. */
        r = set_ensure_put(&u->aliases, &string_hash_ops_free, donated_name);
        if (r < 0)
                return r;
        assert(r > 0);

        return 0;
}

int unit_add_name(Unit *u, const char *text) {
        _cleanup_free_ char *name = NULL, *instance = NULL;
        UnitType t;
        int r;

        assert(u);
        assert(text);

        if (unit_name_is_valid(text, UNIT_NAME_TEMPLATE)) {
                if (!u->instance)
                        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                                    "Instance is not set when adding name '%s'.", text);

                r = unit_name_replace_instance(text, u->instance, &name);
                if (r < 0)
                        return log_unit_debug_errno(u, r,
                                                    "Failed to build instance name from '%s': %m", text);
        } else {
                name = strdup(text);
                if (!name)
                        return -ENOMEM;
        }

        if (unit_has_name(u, name))
                return 0;

        if (hashmap_contains(u->manager->units, name))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EEXIST),
                                            "Unit already exist when adding name '%s'.", name);

        if (!unit_name_is_valid(name, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Name '%s' is invalid.", name);

        t = unit_name_to_type(name);
        if (t < 0)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "failed to derive unit type from name '%s'.", name);

        if (u->type != _UNIT_TYPE_INVALID && t != u->type)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Unit type is illegal: u->type(%d) and t(%d) for name '%s'.",
                                            u->type, t, name);

        r = unit_name_to_instance(name, &instance);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to extract instance from name '%s': %m", name);

        if (instance && !unit_type_may_template(t))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL), "Templates are not allowed for name '%s'.", name);

        /* Ensure that this unit either has no instance, or that the instance matches. */
        if (u->type != _UNIT_TYPE_INVALID && !streq_ptr(u->instance, instance))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Cannot add name %s, the instances don't match (\"%s\" != \"%s\").",
                                            name, instance, u->instance);

        if (u->id && !unit_type_may_alias(t))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EEXIST),
                                            "Cannot add name %s, aliases are not allowed for %s units.",
                                            name, unit_type_to_string(t));

        if (hashmap_size(u->manager->units) >= MANAGER_MAX_NAMES)
                return log_unit_warning_errno(u, SYNTHETIC_ERRNO(E2BIG), "Cannot add name, manager has too many units.");

        /* Add name to the global hashmap first, because that's easier to undo */
        r = hashmap_put(u->manager->units, name, u);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Add unit to hashmap failed for name '%s': %m", text);

        if (u->id) {
                r = unit_add_alias(u, name); /* unit_add_alias() takes ownership of the name on success */
                if (r < 0) {
                        hashmap_remove(u->manager->units, name);
                        return r;
                }
                TAKE_PTR(name);

        } else {
                /* A new name, we don't need the set yet. */
                assert(u->type == _UNIT_TYPE_INVALID);
                assert(!u->instance);

                u->type = t;
                u->id = TAKE_PTR(name);
                u->instance = TAKE_PTR(instance);

                LIST_PREPEND(units_by_type, u->manager->units_by_type[t], u);
                unit_init(u);
        }

        unit_add_to_dbus_queue(u);
        return 0;
}

int unit_choose_id(Unit *u, const char *name) {
        _cleanup_free_ char *t = NULL;
        char *s;
        int r;

        assert(u);
        assert(name);

        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                if (!u->instance)
                        return -EINVAL;

                r = unit_name_replace_instance(name, u->instance, &t);
                if (r < 0)
                        return r;

                name = t;
        }

        if (streq_ptr(u->id, name))
                return 0; /* Nothing to do. */

        /* Selects one of the aliases of this unit as the id */
        s = set_get(u->aliases, (char*) name);
        if (!s)
                return -ENOENT;

        if (u->id) {
                r = set_remove_and_put(u->aliases, name, u->id);
                if (r < 0)
                        return r;
        } else
                assert_se(set_remove(u->aliases, name)); /* see set_get() above… */

        u->id = s; /* Old u->id is now stored in the set, and s is not stored anywhere */
        unit_add_to_dbus_queue(u);

        return 0;
}

int unit_set_description(Unit *u, const char *description) {
        int r;

        assert(u);

        r = free_and_strdup(&u->description, empty_to_null(description));
        if (r < 0)
                return r;
        if (r > 0)
                unit_add_to_dbus_queue(u);

        return 0;
}

static bool unit_success_failure_handler_has_jobs(Unit *unit) {
        Unit *other;

        UNIT_FOREACH_DEPENDENCY(other, unit, UNIT_ATOM_ON_SUCCESS)
                if (other->job || other->nop_job)
                        return true;

        UNIT_FOREACH_DEPENDENCY(other, unit, UNIT_ATOM_ON_FAILURE)
                if (other->job || other->nop_job)
                        return true;

        return false;
}

void unit_release_resources(Unit *u) {
        UnitActiveState state;
        ExecContext *ec;

        assert(u);

        if (u->job || u->nop_job)
                return;

        if (u->perpetual)
                return;

        state = unit_active_state(u);
        if (!UNIT_IS_INACTIVE_OR_FAILED(state))
                return;

        if (unit_will_restart(u))
                return;

        ec = unit_get_exec_context(u);
        if (ec && ec->runtime_directory_preserve_mode == EXEC_PRESERVE_RESTART)
                exec_context_destroy_runtime_directory(ec, u->manager->prefix[EXEC_DIRECTORY_RUNTIME]);

        if (UNIT_VTABLE(u)->release_resources)
                UNIT_VTABLE(u)->release_resources(u);
}

bool unit_may_gc(Unit *u) {
        UnitActiveState state;
        int r;

        assert(u);

        /* Checks whether the unit is ready to be unloaded for garbage collection.  Returns true when the
         * unit may be collected, and false if there's some reason to keep it loaded.
         *
         * References from other units are *not* checked here. Instead, this is done in unit_gc_sweep(), but
         * using markers to properly collect dependency loops.
         */

        if (u->job || u->nop_job)
                return false;

        if (u->perpetual)
                return false;

        /* if we saw a cgroup empty event for this unit, stay around until we processed it so that we remove
         * the empty cgroup if possible. Similar, process any pending OOM events if they are already queued
         * before we release the unit. */
        if (u->in_cgroup_empty_queue || u->in_cgroup_oom_queue)
                return false;

        /* Make sure to send out D-Bus events before we unload the unit */
        if (u->in_dbus_queue)
                return false;

        if (sd_bus_track_count(u->bus_track) > 0)
                return false;

        state = unit_active_state(u);

        /* But we keep the unit object around for longer when it is referenced or configured to not be
         * gc'ed */
        switch (u->collect_mode) {

        case COLLECT_INACTIVE:
                if (state != UNIT_INACTIVE)
                        return false;

                break;

        case COLLECT_INACTIVE_OR_FAILED:
                if (!UNIT_IS_INACTIVE_OR_FAILED(state))
                        return false;

                break;

        default:
                assert_not_reached();
        }

        /* Check if any OnFailure= or on Success= jobs may be pending */
        if (unit_success_failure_handler_has_jobs(u))
                return false;

        /* If the unit has a cgroup, then check whether there's anything in it. If so, we should stay
         * around. Units with active processes should never be collected. */
        r = unit_cgroup_is_empty(u);
        if (r <= 0 && !IN_SET(r, -ENXIO, -EOWNERDEAD))
                return false; /* ENXIO/EOWNERDEAD means: currently not realized */

        if (unit_can_start(u) && BIT_SET(u->markers, UNIT_MARKER_NEEDS_START))
                return false;

        if (!UNIT_VTABLE(u)->may_gc)
                return true;

        return UNIT_VTABLE(u)->may_gc(u);
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

        if (!unit_may_gc(u))
                return;

        LIST_PREPEND(gc_queue, u->manager->gc_unit_queue, u);
        u->in_gc_queue = true;
}

void unit_add_to_dbus_queue(Unit *u) {
        assert(u);
        assert(u->type != _UNIT_TYPE_INVALID);

        if (u->load_state == UNIT_STUB || u->in_dbus_queue)
                return;

        /* Shortcut things if nobody cares */
        if (sd_bus_track_count(u->manager->subscribed) <= 0 &&
            sd_bus_track_count(u->bus_track) <= 0 &&
            set_isempty(u->manager->private_buses)) {
                u->sent_dbus_new_signal = true;
                return;
        }

        LIST_PREPEND(dbus_queue, u->manager->dbus_unit_queue, u);
        u->in_dbus_queue = true;
}

void unit_submit_to_stop_when_unneeded_queue(Unit *u) {
        assert(u);

        if (u->in_stop_when_unneeded_queue)
                return;

        if (!u->stop_when_unneeded)
                return;

        if (!UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                return;

        LIST_PREPEND(stop_when_unneeded_queue, u->manager->stop_when_unneeded_queue, u);
        u->in_stop_when_unneeded_queue = true;
}

void unit_submit_to_start_when_upheld_queue(Unit *u) {
        assert(u);

        if (u->in_start_when_upheld_queue)
                return;

        if (!UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(u)))
                return;

        if (!unit_has_dependency(u, UNIT_ATOM_START_STEADILY, NULL))
                return;

        LIST_PREPEND(start_when_upheld_queue, u->manager->start_when_upheld_queue, u);
        u->in_start_when_upheld_queue = true;
}

void unit_submit_to_stop_when_bound_queue(Unit *u) {
        assert(u);

        if (u->in_stop_when_bound_queue)
                return;

        if (!UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                return;

        if (!unit_has_dependency(u, UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT, NULL))
                return;

        LIST_PREPEND(stop_when_bound_queue, u->manager->stop_when_bound_queue, u);
        u->in_stop_when_bound_queue = true;
}

static bool unit_can_release_resources(Unit *u) {
        ExecContext *ec;

        assert(u);

        if (UNIT_VTABLE(u)->release_resources)
                return true;

        ec = unit_get_exec_context(u);
        if (ec && ec->runtime_directory_preserve_mode == EXEC_PRESERVE_RESTART)
                return true;

        return false;
}

void unit_submit_to_release_resources_queue(Unit *u) {
        assert(u);

        if (u->in_release_resources_queue)
                return;

        if (u->job || u->nop_job)
                return;

        if (u->perpetual)
                return;

        if (!unit_can_release_resources(u))
                return;

        LIST_PREPEND(release_resources_queue, u->manager->release_resources_queue, u);
        u->in_release_resources_queue = true;
}

void unit_add_to_stop_notify_queue(Unit *u) {
        assert(u);

        if (u->in_stop_notify_queue)
                return;

        assert(UNIT_VTABLE(u)->stop_notify);

        LIST_PREPEND(stop_notify_queue, u->manager->stop_notify_queue, u);
        u->in_stop_notify_queue = true;
}

void unit_remove_from_stop_notify_queue(Unit *u) {
        assert(u);

        if (!u->in_stop_notify_queue)
                return;

        LIST_REMOVE(stop_notify_queue, u->manager->stop_notify_queue, u);
        u->in_stop_notify_queue = false;
}

static void unit_clear_dependencies(Unit *u) {
        assert(u);

        /* Removes all dependencies configured on u and their reverse dependencies. */

        for (Hashmap *deps; (deps = hashmap_steal_first(u->dependencies));) {

                for (Unit *other; (other = hashmap_steal_first_key(deps));) {
                        Hashmap *other_deps;

                        HASHMAP_FOREACH(other_deps, other->dependencies)
                                hashmap_remove(other_deps, u);

                        unit_add_to_gc_queue(other);
                        other->dependency_generation++;
                }

                hashmap_free(deps);
        }

        u->dependencies = hashmap_free(u->dependencies);
        u->dependency_generation++;
}

static void unit_remove_transient(Unit *u) {
        assert(u);
        assert(u->manager);

        if (!u->transient)
                return;

        STRV_FOREACH(i, u->dropin_paths) {
                _cleanup_free_ char *p = NULL, *pp = NULL;

                if (path_extract_directory(*i, &p) < 0) /* Get the drop-in directory from the drop-in file */
                        continue;

                if (path_extract_directory(p, &pp) < 0) /* Get the config directory from the drop-in directory */
                        continue;

                /* Only drop transient drop-ins */
                if (!path_equal(u->manager->lookup_paths.transient, pp))
                        continue;

                (void) unlink(*i);
                (void) rmdir(p);
        }

        if (u->fragment_path) {
                (void) unlink(u->fragment_path);
                (void) unit_file_remove_from_name_map(
                                &u->manager->lookup_paths,
                                &u->manager->unit_cache_timestamp_hash,
                                &u->manager->unit_id_map,
                                &u->manager->unit_name_map,
                                &u->manager->unit_path_cache,
                                u->fragment_path);
        }
}

static void unit_free_mounts_for(Unit *u) {
        assert(u);

        for (UnitMountDependencyType t = 0; t < _UNIT_MOUNT_DEPENDENCY_TYPE_MAX; ++t) {
                for (;;) {
                        _cleanup_free_ char *path = NULL;

                        path = hashmap_steal_first_key(u->mounts_for[t]);
                        if (!path)
                                break;

                        char s[strlen(path) + 1];

                        PATH_FOREACH_PREFIX_MORE(s, path) {
                                char *y;
                                Set *x;

                                x = hashmap_get2(u->manager->units_needing_mounts_for[t], s, (void**) &y);
                                if (!x)
                                        continue;

                                (void) set_remove(x, u);

                                if (set_isempty(x)) {
                                        assert_se(hashmap_remove(u->manager->units_needing_mounts_for[t], y));
                                        free(y);
                                        set_free(x);
                                }
                        }
                }

                u->mounts_for[t] = hashmap_free(u->mounts_for[t]);
        }
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

Unit* unit_free(Unit *u) {
        Unit *slice;
        char *t;

        if (!u)
                return NULL;

        sd_event_source_disable_unref(u->auto_start_stop_event_source);

        u->transient_file = safe_fclose(u->transient_file);

        if (!MANAGER_IS_RELOADING(u->manager))
                unit_remove_transient(u);

        bus_unit_send_removed_signal(u);

        unit_done(u);

        u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
        u->bus_track = sd_bus_track_unref(u->bus_track);
        u->deserialized_refs = strv_free(u->deserialized_refs);
        u->pending_freezer_invocation = sd_bus_message_unref(u->pending_freezer_invocation);

        unit_free_mounts_for(u);

        SET_FOREACH(t, u->aliases)
                hashmap_remove_value(u->manager->units, t, u);
        if (u->id)
                hashmap_remove_value(u->manager->units, u->id, u);

        if (!sd_id128_is_null(u->invocation_id))
                hashmap_remove_value(u->manager->units_by_invocation_id, &u->invocation_id, u);

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

        /* A unit is being dropped from the tree, make sure our family is realized properly. Do this after we
         * detach the unit from slice tree in order to eliminate its effect on controller masks. */
        slice = UNIT_GET_SLICE(u);
        unit_clear_dependencies(u);
        if (slice)
                unit_add_family_to_cgroup_realize_queue(slice);

        if (u->on_console)
                manager_unref_console(u->manager);

        unit_release_cgroup(u, /* drop_cgroup_runtime= */ true);

        if (!MANAGER_IS_RELOADING(u->manager))
                unit_unlink_state_files(u);

        unit_unref_uid_gid(u, false);

        (void) manager_update_failed_units(u->manager, u, false);
        set_remove(u->manager->startup_units, u);

        unit_unwatch_all_pids(u);

        while (u->refs_by_target)
                unit_ref_unset(u->refs_by_target);

        if (u->type != _UNIT_TYPE_INVALID)
                LIST_REMOVE(units_by_type, u->manager->units_by_type[u->type], u);

        if (u->in_load_queue)
                LIST_REMOVE(load_queue, u->manager->load_queue, u);

        if (u->in_dbus_queue)
                LIST_REMOVE(dbus_queue, u->manager->dbus_unit_queue, u);

        if (u->in_cleanup_queue)
                LIST_REMOVE(cleanup_queue, u->manager->cleanup_queue, u);

        if (u->in_gc_queue)
                LIST_REMOVE(gc_queue, u->manager->gc_unit_queue, u);

        if (u->in_cgroup_realize_queue)
                LIST_REMOVE(cgroup_realize_queue, u->manager->cgroup_realize_queue, u);

        if (u->in_cgroup_empty_queue)
                LIST_REMOVE(cgroup_empty_queue, u->manager->cgroup_empty_queue, u);

        if (u->in_cgroup_oom_queue)
                LIST_REMOVE(cgroup_oom_queue, u->manager->cgroup_oom_queue, u);

        if (u->in_target_deps_queue)
                LIST_REMOVE(target_deps_queue, u->manager->target_deps_queue, u);

        if (u->in_stop_when_unneeded_queue)
                LIST_REMOVE(stop_when_unneeded_queue, u->manager->stop_when_unneeded_queue, u);

        if (u->in_start_when_upheld_queue)
                LIST_REMOVE(start_when_upheld_queue, u->manager->start_when_upheld_queue, u);

        if (u->in_stop_when_bound_queue)
                LIST_REMOVE(stop_when_bound_queue, u->manager->stop_when_bound_queue, u);

        if (u->in_release_resources_queue)
                LIST_REMOVE(release_resources_queue, u->manager->release_resources_queue, u);

        unit_remove_from_stop_notify_queue(u);

        condition_free_list(u->conditions);
        condition_free_list(u->asserts);

        free(u->description);
        strv_free(u->documentation);
        free(u->fragment_path);
        free(u->source_path);
        strv_free(u->dropin_paths);
        free(u->instance);

        free(u->job_timeout_reboot_arg);
        free(u->reboot_arg);

        free(u->access_selinux_context);

        set_free(u->aliases);
        free(u->id);

        activation_details_unref(u->activation_details);

        return mfree(u);
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

static int unit_merge_names(Unit *u, Unit *other) {
        char *name;
        int r;

        assert(u);
        assert(other);

        r = unit_add_alias(u, other->id);
        if (r < 0)
                return r;

        r = set_move(u->aliases, other->aliases);
        if (r < 0) {
                set_remove(u->aliases, other->id);
                return r;
        }

        TAKE_PTR(other->id);
        other->aliases = set_free(other->aliases);

        SET_FOREACH(name, u->aliases)
                assert_se(hashmap_replace(u->manager->units, name, u) == 0);

        return 0;
}

static int unit_reserve_dependencies(Unit *u, Unit *other) {
        size_t n_reserve;
        Hashmap* deps;
        void *d;
        int r;

        assert(u);
        assert(other);

        /* Let's reserve some space in the dependency hashmaps so that later on merging the units cannot
         * fail.
         *
         * First make some room in the per dependency type hashmaps. Using the summed size of both units'
         * hashmaps is an estimate that is likely too high since they probably use some of the same
         * types. But it's never too low, and that's all we need. */

        n_reserve = MIN(hashmap_size(other->dependencies), LESS_BY((size_t) _UNIT_DEPENDENCY_MAX, hashmap_size(u->dependencies)));
        if (n_reserve > 0) {
                r = hashmap_ensure_allocated(&u->dependencies, NULL);
                if (r < 0)
                        return r;

                r = hashmap_reserve(u->dependencies, n_reserve);
                if (r < 0)
                        return r;
        }

        /* Now, enlarge our per dependency type hashmaps by the number of entries in the same hashmap of the
         * other unit's dependencies.
         *
         * NB: If u does not have a dependency set allocated for some dependency type, there is no need to
         * reserve anything for. In that case other's set will be transferred as a whole to u by
         * complete_move(). */

        HASHMAP_FOREACH_KEY(deps, d, u->dependencies) {
                Hashmap *other_deps;

                other_deps = hashmap_get(other->dependencies, d);

                r = hashmap_reserve(deps, hashmap_size(other_deps));
                if (r < 0)
                        return r;
        }

        return 0;
}

static bool unit_should_warn_about_dependency(UnitDependency dependency) {
        /* Only warn about some unit types */
        return IN_SET(dependency,
                      UNIT_CONFLICTS,
                      UNIT_CONFLICTED_BY,
                      UNIT_BEFORE,
                      UNIT_AFTER,
                      UNIT_ON_SUCCESS,
                      UNIT_ON_FAILURE,
                      UNIT_TRIGGERS,
                      UNIT_TRIGGERED_BY);
}

static int unit_per_dependency_type_hashmap_update(
                Hashmap *per_type,
                Unit *other,
                UnitDependencyMask origin_mask,
                UnitDependencyMask destination_mask) {

        UnitDependencyInfo info;
        int r;

        assert(other);
        assert_cc(sizeof(void*) == sizeof(info));

        /* Acquire the UnitDependencyInfo entry for the Unit* we are interested in, and update it if it
         * exists, or insert it anew if not. */

        info.data = hashmap_get(per_type, other);
        if (info.data) {
                /* Entry already exists. Add in our mask. */

                if (FLAGS_SET(origin_mask, info.origin_mask) &&
                    FLAGS_SET(destination_mask, info.destination_mask))
                        return 0; /* NOP */

                info.origin_mask |= origin_mask;
                info.destination_mask |= destination_mask;

                r = hashmap_update(per_type, other, info.data);
        } else {
                info = (UnitDependencyInfo) {
                        .origin_mask = origin_mask,
                        .destination_mask = destination_mask,
                };

                r = hashmap_put(per_type, other, info.data);
        }
        if (r < 0)
                return r;

        return 1;
}

static void unit_merge_dependencies(Unit *u, Unit *other) {
        Hashmap *deps;
        void *dt; /* Actually of type UnitDependency, except that we don't bother casting it here,
                   * since the hashmaps all want it as void pointer. */

        assert(u);
        assert(other);

        if (u == other)
                return;

        /* First, remove dependency to other. */
        HASHMAP_FOREACH_KEY(deps, dt, u->dependencies) {
                if (hashmap_remove(deps, other) && unit_should_warn_about_dependency(UNIT_DEPENDENCY_FROM_PTR(dt)))
                        log_unit_warning(u, "Dependency %s=%s is dropped, as %s is merged into %s.",
                                         unit_dependency_to_string(UNIT_DEPENDENCY_FROM_PTR(dt)),
                                         other->id, other->id, u->id);

                if (hashmap_isempty(deps))
                        hashmap_free(hashmap_remove(u->dependencies, dt));
        }

        for (;;) {
                _cleanup_hashmap_free_ Hashmap *other_deps = NULL;
                UnitDependencyInfo di_back;
                Unit *back;

                /* Let's focus on one dependency type at a time, that 'other' has defined. */
                other_deps = hashmap_steal_first_key_and_value(other->dependencies, &dt);
                if (!other_deps)
                        break; /* done! */

                deps = hashmap_get(u->dependencies, dt);

                /* Now iterate through all dependencies of this dependency type, of 'other'. We refer to the
                 * referenced units as 'back'. */
                HASHMAP_FOREACH_KEY(di_back.data, back, other_deps) {
                        Hashmap *back_deps;
                        void *back_dt;

                        if (back == u) {
                                /* This is a dependency pointing back to the unit we want to merge with?
                                 * Suppress it (but warn) */
                                if (unit_should_warn_about_dependency(UNIT_DEPENDENCY_FROM_PTR(dt)))
                                        log_unit_warning(u, "Dependency %s=%s in %s is dropped, as %s is merged into %s.",
                                                         unit_dependency_to_string(UNIT_DEPENDENCY_FROM_PTR(dt)),
                                                         u->id, other->id, other->id, u->id);

                                hashmap_remove(other_deps, back);
                                continue;
                        }

                        /* Now iterate through all deps of 'back', and fix the ones pointing to 'other' to
                         * point to 'u' instead. */
                        HASHMAP_FOREACH_KEY(back_deps, back_dt, back->dependencies) {
                                UnitDependencyInfo di_move;

                                di_move.data = hashmap_remove(back_deps, other);
                                if (!di_move.data)
                                        continue;

                                assert_se(unit_per_dependency_type_hashmap_update(
                                                          back_deps,
                                                          u,
                                                          di_move.origin_mask,
                                                          di_move.destination_mask) >= 0);
                        }

                        /* The target unit already has dependencies of this type, let's then merge this individually. */
                        if (deps)
                                assert_se(unit_per_dependency_type_hashmap_update(
                                                          deps,
                                                          back,
                                                          di_back.origin_mask,
                                                          di_back.destination_mask) >= 0);
                }

                /* Now all references towards 'other' of the current type 'dt' are corrected to point to 'u'.
                 * Lets's now move the deps of type 'dt' from 'other' to 'u'. If the unit does not have
                 * dependencies of this type, let's move them per type wholesale. */
                if (!deps)
                        assert_se(hashmap_put(u->dependencies, dt, TAKE_PTR(other_deps)) >= 0);
        }

        other->dependencies = hashmap_free(other->dependencies);

        u->dependency_generation++;
        other->dependency_generation++;
}

int unit_merge(Unit *u, Unit *other) {
        int r;

        assert(u);
        assert(other);
        assert(u->manager == other->manager);
        assert(u->type != _UNIT_TYPE_INVALID);

        other = unit_follow_merge(other);

        if (other == u)
                return 0;

        if (u->type != other->type)
                return -EINVAL;

        if (!unit_type_may_alias(u->type)) /* Merging only applies to unit names that support aliases */
                return -EEXIST;

        if (!IN_SET(other->load_state, UNIT_STUB, UNIT_NOT_FOUND))
                return -EEXIST;

        if (!streq_ptr(u->instance, other->instance))
                return -EINVAL;

        if (other->job)
                return -EEXIST;

        if (other->nop_job)
                return -EEXIST;

        if (!UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other)))
                return -EEXIST;

        /* Make reservations to ensure merge_dependencies() won't fail. We don't rollback reservations if we
         * fail. We don't have a way to undo reservations. A reservation is not a leak. */
        r = unit_reserve_dependencies(u, other);
        if (r < 0)
                return r;

        /* Redirect all references */
        while (other->refs_by_target)
                unit_ref_set(other->refs_by_target, other->refs_by_target->source, u);

        /* Merge dependencies */
        unit_merge_dependencies(u, other);

        /* Merge names. It is better to do that after merging deps, otherwise the log message contains n/a. */
        r = unit_merge_names(u, other);
        if (r < 0)
                return r;

        other->load_state = UNIT_MERGED;
        other->merged_into = u;

        if (!u->activation_details)
                u->activation_details = activation_details_ref(other->activation_details);

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
        _cleanup_free_ char *s = NULL;
        Unit *other;
        int r;

        /* Either add name to u, or if a unit with name already exists, merge it with u.
         * If name is a template, do the same for name@instance, where instance is u's instance. */

        assert(u);
        assert(name);

        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                if (!u->instance)
                        return -EINVAL;

                r = unit_name_replace_instance(name, u->instance, &s);
                if (r < 0)
                        return r;

                name = s;
        }

        other = manager_get_unit(u->manager, name);
        if (other)
                return unit_merge(u, other);

        return unit_add_name(u, name);
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

        /* Unlike unit_add_dependency() or friends, this always returns 0 on success. */

        if (c->working_directory) {
                r = unit_add_mounts_for(
                                u,
                                c->working_directory,
                                UNIT_DEPENDENCY_FILE,
                                c->working_directory_missing_ok ? UNIT_MOUNT_WANTS : UNIT_MOUNT_REQUIRES);
                if (r < 0)
                        return r;
        }

        if (c->root_directory) {
                r = unit_add_mounts_for(u, c->root_directory, UNIT_DEPENDENCY_FILE, UNIT_MOUNT_WANTS);
                if (r < 0)
                        return r;
        }

        if (c->root_image) {
                r = unit_add_mounts_for(u, c->root_image, UNIT_DEPENDENCY_FILE, UNIT_MOUNT_WANTS);
                if (r < 0)
                        return r;
        }

        if (c->root_mstack) {
                r = unit_add_mounts_for(u, c->root_mstack, UNIT_DEPENDENCY_FILE, UNIT_MOUNT_WANTS);
                if (r < 0)
                        return r;
        }

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                if (!u->manager->prefix[dt])
                        continue;

                FOREACH_ARRAY(i, c->directories[dt].items, c->directories[dt].n_items) {
                        _cleanup_free_ char *p = NULL;

                        p = path_join(u->manager->prefix[dt], i->path);
                        if (!p)
                                return -ENOMEM;

                        r = unit_add_mounts_for(u, p, UNIT_DEPENDENCY_FILE, UNIT_MOUNT_REQUIRES);
                        if (r < 0)
                                return r;
                }
        }

        if (!MANAGER_IS_SYSTEM(u->manager))
                return 0;

        /* For the following three directory types we need write access, and /var/ is possibly on the root
         * fs. Hence order after systemd-remount-fs.service, to ensure things are writable. */
        if (c->directories[EXEC_DIRECTORY_STATE].n_items > 0 ||
            c->directories[EXEC_DIRECTORY_CACHE].n_items > 0 ||
            c->directories[EXEC_DIRECTORY_LOGS].n_items > 0) {
                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_REMOUNT_FS_SERVICE, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        /* This must be already set in unit_patch_contexts(). */
        assert(c->private_var_tmp >= 0 && c->private_var_tmp < _PRIVATE_TMP_MAX);

        if (c->private_tmp == PRIVATE_TMP_CONNECTED) {
                assert(c->private_var_tmp == PRIVATE_TMP_CONNECTED);

                r = unit_add_mounts_for(u, "/tmp/", UNIT_DEPENDENCY_FILE, UNIT_MOUNT_WANTS);
                if (r < 0)
                        return r;

                r = unit_add_mounts_for(u, "/var/tmp/", UNIT_DEPENDENCY_FILE, UNIT_MOUNT_WANTS);
                if (r < 0)
                        return r;

                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_TMPFILES_SETUP_SERVICE, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;

        } else if (c->private_var_tmp == PRIVATE_TMP_DISCONNECTED && !exec_context_with_rootfs(c)) {
                /* Even if PrivateTmp=disconnected, we still require /var/tmp/ mountpoint to be present,
                 * i.e. /var/ needs to be mounted. See comments in unit_patch_contexts(). */
                r = unit_add_mounts_for(u, "/var/", UNIT_DEPENDENCY_FILE, UNIT_MOUNT_WANTS);
                if (r < 0)
                        return r;
        }

        if (c->root_image || c->root_mstack) {
                /* We need to wait for /dev/loopX to appear when doing RootImage=, hence let's add an
                 * implicit dependency on udev. (And for RootMStack= we might need it) */

                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_UDEVD_SERVICE, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        /* If syslog or kernel logging is requested (or log namespacing is), make sure our own logging daemon
         * is run first. */
        if (c->log_namespace) {
                static const struct {
                        const char *template;
                        UnitType type;
                } deps[] = {
                        { "systemd-journald",         UNIT_SOCKET,  },
                        { "systemd-journald-varlink", UNIT_SOCKET,  },
                        { "systemd-journald-sync",    UNIT_SERVICE, },
                };

                FOREACH_ELEMENT(i, deps) {
                        _cleanup_free_ char *unit = NULL;

                        r = unit_name_build_from_type(i->template, c->log_namespace, i->type, &unit);
                        if (r < 0)
                                return r;

                        r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_REQUIRES, unit, true, UNIT_DEPENDENCY_FILE);
                        if (r < 0)
                                return r;
                }
        } else if (IN_SET(c->std_output, EXEC_OUTPUT_JOURNAL, EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
                                         EXEC_OUTPUT_KMSG, EXEC_OUTPUT_KMSG_AND_CONSOLE) ||
                   IN_SET(c->std_error,  EXEC_OUTPUT_JOURNAL, EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
                                         EXEC_OUTPUT_KMSG, EXEC_OUTPUT_KMSG_AND_CONSOLE)) {

                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_JOURNALD_SOCKET, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        return 0;
}

const char* unit_description(Unit *u) {
        assert(u);

        if (u->description)
                return u->description;

        return strna(u->id);
}

const char* unit_status_string(Unit *u, char **ret_combined_buffer) {
        assert(u);
        assert(u->id);

        /* Return u->id, u->description, or "{u->id} - {u->description}".
         * Versions with u->description are only used if it is set.
         * The last option is used if configured and the caller provided the 'ret_combined_buffer'
         * pointer.
         *
         * Note that *ret_combined_buffer may be set to NULL. */

        if (!u->description ||
            u->manager->status_unit_format == STATUS_UNIT_FORMAT_NAME ||
            (u->manager->status_unit_format == STATUS_UNIT_FORMAT_COMBINED && !ret_combined_buffer) ||
            streq(u->description, u->id)) {

                if (ret_combined_buffer)
                        *ret_combined_buffer = NULL;
                return u->id;
        }

        if (ret_combined_buffer) {
                if (u->manager->status_unit_format == STATUS_UNIT_FORMAT_COMBINED) {
                        *ret_combined_buffer = strjoin(u->id, " - ", u->description);
                        if (*ret_combined_buffer)
                                return *ret_combined_buffer;
                        log_oom(); /* Fall back to ->description */
                } else
                        *ret_combined_buffer = NULL;
        }

        return u->description;
}

/* Common implementation for multiple backends */
int unit_load_fragment_and_dropin(Unit *u, bool fragment_required) {
        int r;

        assert(u);

        /* Load a .{service,socket,...} file */
        r = unit_load_fragment(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_MASKED)
                return 0;

        if (u->load_state == UNIT_STUB) {
                if (fragment_required)
                        return -ENOENT;

                u->load_state = UNIT_LOADED;
        }

        u = unit_follow_merge(u);

        /* Load drop-in directory data. If u is an alias, we might be reloading the
         * target unit needlessly. But we cannot be sure which drops-ins have already
         * been loaded and which not, at least without doing complicated book-keeping,
         * so let's always reread all drop-ins. */
        r = unit_load_dropin(u);
        if (r < 0)
                return r;

        if (u->source_path) {
                struct stat st;

                if (stat(u->source_path, &st) >= 0)
                        u->source_mtime = timespec_load(&st.st_mtim);
                else
                        u->source_mtime = 0;
        }

        return 0;
}

void unit_add_to_target_deps_queue(Unit *u) {
        Manager *m = ASSERT_PTR(ASSERT_PTR(u)->manager);

        if (u->in_target_deps_queue)
                return;

        LIST_PREPEND(target_deps_queue, m->target_deps_queue, u);
        u->in_target_deps_queue = true;
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
        if (unit_has_dependency(target, UNIT_ATOM_BEFORE, u))
                return 0;

        return unit_add_dependency(target, UNIT_AFTER, u, true, UNIT_DEPENDENCY_DEFAULT);
}

static int unit_add_slice_dependencies(Unit *u) {
        Unit *slice;

        assert(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return 0;

        /* Slice units are implicitly ordered against their parent slices (as this relationship is encoded in the
           name), while all other units are ordered based on configuration (as in their case Slice= configures the
           relationship). */
        UnitDependencyMask mask = u->type == UNIT_SLICE ? UNIT_DEPENDENCY_IMPLICIT : UNIT_DEPENDENCY_FILE;

        slice = UNIT_GET_SLICE(u);
        if (slice) {
                if (!IN_SET(slice->freezer_state, FREEZER_RUNNING, FREEZER_THAWING))
                        u->freezer_state = FREEZER_FROZEN_BY_PARENT;

                return unit_add_two_dependencies(u, UNIT_AFTER, UNIT_REQUIRES, slice, true, mask);
        }

        if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                return 0;

        return unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_REQUIRES, SPECIAL_ROOT_SLICE, true, mask);
}

static int unit_add_mount_dependencies(Unit *u) {
        bool changed = false;
        int r;

        assert(u);

        for (UnitMountDependencyType t = 0; t < _UNIT_MOUNT_DEPENDENCY_TYPE_MAX; ++t) {
                UnitDependencyInfo di;
                const char *path;

                HASHMAP_FOREACH_KEY(di.data, path, u->mounts_for[t]) {

                        char prefix[strlen(ASSERT_PTR(path)) + 1];

                        PATH_FOREACH_PREFIX_MORE(prefix, path) {
                                _cleanup_free_ char *p = NULL;
                                Unit *m;

                                r = unit_name_from_path(prefix, ".mount", &p);
                                if (r == -EINVAL)
                                        continue; /* If the path cannot be converted to a mount unit name,
                                                   * then it's not manageable as a unit by systemd, and
                                                   * hence we don't need a dependency on it. Let's thus
                                                   * silently ignore the issue. */
                                if (r < 0)
                                        return r;

                                m = manager_get_unit(u->manager, p);
                                if (!m) {
                                        /* Make sure to load the mount unit if it exists. If so the
                                         * dependencies on this unit will be added later during the loading
                                         * of the mount unit. */
                                        (void) manager_load_unit_prepare(
                                                        u->manager,
                                                        p,
                                                        /* path= */ NULL,
                                                        /* e= */ NULL,
                                                        &m);
                                        continue;
                                }
                                if (m == u)
                                        continue;

                                if (m->load_state != UNIT_LOADED)
                                        continue;

                                r = unit_add_dependency(
                                                u,
                                                UNIT_AFTER,
                                                m,
                                                /* add_reference= */ true,
                                                di.origin_mask);
                                if (r < 0)
                                        return r;
                                changed = changed || r > 0;

                                if (m->fragment_path) {
                                        r = unit_add_dependency(
                                                        u,
                                                        unit_mount_dependency_type_to_dependency_type(t),
                                                        m,
                                                        /* add_reference= */ true,
                                                        di.origin_mask);
                                        if (r < 0)
                                                return r;
                                        changed = changed || r > 0;
                                }
                        }
                }
        }

        return changed;
}

static int unit_add_oomd_dependencies(Unit *u) {
        CGroupContext *c;
        CGroupMask mask;
        int r;

        assert(u);

        if (!u->default_dependencies)
                return 0;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        bool wants_oomd = c->moom_swap == MANAGED_OOM_KILL || c->moom_mem_pressure == MANAGED_OOM_KILL;
        if (!wants_oomd)
                return 0;

        r = cg_mask_supported(&mask);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine supported controllers: %m");

        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return 0;

        return unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_WANTS, "systemd-oomd.service", true, UNIT_DEPENDENCY_FILE);
}

static int unit_add_startup_units(Unit *u) {
        if (!unit_has_startup_cgroup_constraints(u))
                return 0;

        return set_ensure_put(&u->manager->startup_units, NULL, u);
}

static const struct {
        UnitDependencyAtom atom;
        size_t job_mode_offset;
        const char *dependency_name;
        const char *job_mode_setting_name;
} on_termination_settings[] = {
        { UNIT_ATOM_ON_SUCCESS, offsetof(Unit, on_success_job_mode), "OnSuccess=", "OnSuccessJobMode=" },
        { UNIT_ATOM_ON_FAILURE, offsetof(Unit, on_failure_job_mode), "OnFailure=", "OnFailureJobMode=" },
};

static int unit_validate_on_termination_job_modes(Unit *u) {
        assert(u);

        /* Verify that if On{Success,Failure}JobMode=isolate, only one unit gets specified. */

        FOREACH_ELEMENT(setting, on_termination_settings) {
                JobMode job_mode = *(JobMode*) ((uint8_t*) u + setting->job_mode_offset);

                if (job_mode != JOB_ISOLATE)
                        continue;

                Unit *other, *found = NULL;
                UNIT_FOREACH_DEPENDENCY(other, u, setting->atom) {
                        if (!found)
                                found = other;
                        else if (found != other)
                                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC),
                                                            "More than one %s dependencies specified but %sisolate set. Refusing.",
                                                            setting->dependency_name, setting->job_mode_setting_name);
                }
        }

        return 0;
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

        if (u->transient_file) {
                /* Finalize transient file: if this is a transient unit file, as soon as we reach unit_load() the setup
                 * is complete, hence let's synchronize the unit file we just wrote to disk. */

                r = fflush_and_check(u->transient_file);
                if (r < 0)
                        goto fail;

                u->transient_file = safe_fclose(u->transient_file);
                u->fragment_mtime = now(CLOCK_REALTIME);
        }

        r = UNIT_VTABLE(u)->load(u);
        if (r < 0)
                goto fail;

        assert(u->load_state != UNIT_STUB);

        if (u->load_state == UNIT_LOADED) {
                unit_add_to_target_deps_queue(u);

                r = unit_add_slice_dependencies(u);
                if (r < 0)
                        goto fail;

                r = unit_add_mount_dependencies(u);
                if (r < 0)
                        goto fail;

                r = unit_add_oomd_dependencies(u);
                if (r < 0)
                        goto fail;

                r = unit_add_startup_units(u);
                if (r < 0)
                        goto fail;

                r = unit_validate_on_termination_job_modes(u);
                if (r < 0)
                        goto fail;

                if (u->job_running_timeout != USEC_INFINITY && u->job_running_timeout > u->job_timeout)
                        log_unit_warning(u, "JobRunningTimeoutSec= is greater than JobTimeoutSec=, it has no effect.");

                /* We finished loading, let's ensure our parents recalculate the members mask */
                unit_invalidate_cgroup_members_masks(u);
        }

        assert((u->load_state != UNIT_MERGED) == !u->merged_into);

        unit_add_to_dbus_queue(unit_follow_merge(u));
        unit_add_to_gc_queue(u);
        (void) manager_varlink_send_managed_oom_update(u);

        return 0;

fail:
        /* We convert ENOEXEC errors to the UNIT_BAD_SETTING load state here. Configuration parsing code
         * should hence return ENOEXEC to ensure units are placed in this state after loading. */

        u->load_state = u->load_state == UNIT_STUB ? UNIT_NOT_FOUND :
                                     r == -ENOEXEC ? UNIT_BAD_SETTING :
                                                     UNIT_ERROR;
        u->load_error = r;

        /* Record the timestamp on the cache, so that if the cache gets updated between now and the next time
         * an attempt is made to load this unit, we know we need to check again. */
        if (u->load_state == UNIT_NOT_FOUND)
                u->fragment_not_found_timestamp_hash = u->manager->unit_cache_timestamp_hash;

        unit_add_to_dbus_queue(u);
        unit_add_to_gc_queue(u);

        return log_unit_debug_errno(u, r, "Failed to load configuration: %m");
}

_printf_(7, 8)
static int log_unit_internal(void *userdata, int level, int error, const char *file, int line, const char *func, const char *format, ...) {
        Unit *u = userdata;
        va_list ap;
        int r;

        if (u && !unit_log_level_test(u, level))
                return -ERRNO_VALUE(error);

        va_start(ap, format);
        if (u)
                r = log_object_internalv(level, error, file, line, func,
                                         unit_log_field(u),
                                         u->id,
                                         unit_invocation_log_field(u),
                                         u->invocation_id_string,
                                         format, ap);
        else
                r = log_internalv(level, error,  file, line, func, format, ap);
        va_end(ap);

        return r;
}

static bool unit_test_condition(Unit *u) {
        _cleanup_strv_free_ char **env = NULL;
        int r;

        assert(u);

        dual_timestamp_now(&u->condition_timestamp);

        r = manager_get_effective_environment(u->manager, &env);
        if (r < 0) {
                log_unit_error_errno(u, r, "Failed to determine effective environment: %m");
                u->condition_result = true;
        } else
                u->condition_result = condition_test_list(
                                u->conditions,
                                env,
                                condition_type_to_string,
                                log_unit_internal,
                                u);

        unit_add_to_dbus_queue(u);
        return u->condition_result;
}

static bool unit_test_assert(Unit *u) {
        _cleanup_strv_free_ char **env = NULL;
        int r;

        assert(u);

        dual_timestamp_now(&u->assert_timestamp);

        r = manager_get_effective_environment(u->manager, &env);
        if (r < 0) {
                log_unit_error_errno(u, r, "Failed to determine effective environment: %m");
                u->assert_result = CONDITION_ERROR;
        } else
                u->assert_result = condition_test_list(
                                u->asserts,
                                env,
                                assert_type_to_string,
                                log_unit_internal,
                                u);

        unit_add_to_dbus_queue(u);
        return u->assert_result;
}

void unit_status_printf(
                Unit *u,
                StatusType status_type,
                const char *status,
                const char *format,
                const char *ident) {

        assert(u);

        if (log_get_show_color()) {
                if (u->manager->status_unit_format == STATUS_UNIT_FORMAT_COMBINED && strchr(ident, ' '))
                        ident = strjoina(ANSI_HIGHLIGHT, u->id, ANSI_NORMAL, " - ", u->description);
                else
                        ident = strjoina(ANSI_HIGHLIGHT, ident, ANSI_NORMAL);
        }

        DISABLE_WARNING_FORMAT_NONLITERAL;
        manager_status_printf(u->manager, status_type, status, format, ident);
        REENABLE_WARNING;
}

int unit_test_start_limit(Unit *u) {
        const char *reason;

        assert(u);

        if (ratelimit_below(&u->start_ratelimit)) {
                u->start_limit_hit = false;
                return 0;
        }

        log_unit_warning(u, "Start request repeated too quickly.");
        u->start_limit_hit = true;

        reason = strjoina("unit ", u->id, " failed");

        emergency_action(
                        u->manager,
                        u->start_limit_action,
                        EMERGENCY_ACTION_IS_WATCHDOG|EMERGENCY_ACTION_WARN|EMERGENCY_ACTION_SLEEP_5S,
                        u->reboot_arg,
                        /* exit_status= */ -1,
                        reason);

        return -ECANCELED;
}

static bool unit_verify_deps(Unit *u) {
        Unit *other;

        assert(u);

        /* Checks whether all BindsTo= dependencies of this unit are fulfilled — if they are also combined
         * with After=. We do not check Requires= or Requisite= here as they only should have an effect on
         * the job processing, but do not have any effect afterwards. We don't check BindsTo= dependencies
         * that are not used in conjunction with After= as for them any such check would make things entirely
         * racy. */

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT) {

                if (!unit_has_dependency(u, UNIT_ATOM_AFTER, other))
                        continue;

                if (!UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(other))) {
                        log_unit_notice(u, "Bound to unit %s, but unit isn't active.", other->id);
                        return false;
                }
        }

        return true;
}

/* Errors that aren't really errors:
 *         -EALREADY:     Unit is already started.
 *         -ECOMM:        Condition failed
 *         -EAGAIN:       An operation is already in progress. Retry later.
 *
 * Errors that are real errors:
 *         -EBADR:        This unit type does not support starting.
 *         -ECANCELED:    Start limit hit, too many requests for now
 *         -EPROTO:       Assert failed
 *         -EINVAL:       Unit not loaded
 *         -EOPNOTSUPP:   Unit type not supported
 *         -ENOLINK:      The necessary dependencies are not fulfilled.
 *         -ESTALE:       This unit has been started before and can't be started a second time
 *         -EDEADLK:      This unit is frozen
 *         -ENOENT:       This is a triggering unit and unit to trigger is not loaded
 *         -ETOOMANYREFS: The hard concurrency limit of at least one of the slices the unit is contained in has been reached
 */
int unit_start(Unit *u, ActivationDetails *details) {
        UnitActiveState state;
        Unit *following;
        int r;

        assert(u);

        /* Let's hold off running start jobs for mount units when /proc/self/mountinfo monitor is ratelimited. */
        if (UNIT_VTABLE(u)->subsystem_ratelimited) {
                r = UNIT_VTABLE(u)->subsystem_ratelimited(u->manager);
                if (r < 0)
                        return r;
                if (r > 0)
                        return -EAGAIN;
        }

        /* If this is already started, then this will succeed. Note that this will even succeed if this unit
         * is not startable by the user. This is relied on to detect when we need to wait for units and when
         * waiting is finished. */
        state = unit_active_state(u);
        if (UNIT_IS_ACTIVE_OR_RELOADING(state))
                return -EALREADY;
        if (IN_SET(state, UNIT_DEACTIVATING, UNIT_MAINTENANCE))
                return -EAGAIN;

        /* Units that aren't loaded cannot be started */
        if (u->load_state != UNIT_LOADED)
                return -EINVAL;

        /* Refuse starting scope units more than once */
        if (UNIT_VTABLE(u)->once_only && dual_timestamp_is_set(&u->inactive_enter_timestamp))
                return -ESTALE;

        /* If the conditions were unmet, don't do anything at all. If we already are activating this call might
         * still be useful to speed up activation in case there is some hold-off time, but we don't want to
         * recheck the condition in that case. */
        if (state != UNIT_ACTIVATING &&
            !unit_test_condition(u))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(ECOMM), "Starting requested but condition not met. Not starting unit.");

        /* If the asserts failed, fail the entire job */
        if (state != UNIT_ACTIVATING &&
            !unit_test_assert(u))
                return log_unit_notice_errno(u, SYNTHETIC_ERRNO(EPROTO), "Starting requested but asserts failed.");

        /* Units of types that aren't supported cannot be started. Note that we do this test only after the
         * condition checks, so that we rather return condition check errors (which are usually not
         * considered a true failure) than "not supported" errors (which are considered a failure).
         */
        if (!unit_type_supported(u->type))
                return -EOPNOTSUPP;

        /* Let's make sure that the deps really are in order before we start this. Normally the job engine
         * should have taken care of this already, but let's check this here again. After all, our
         * dependencies might not be in effect anymore, due to a reload or due to an unmet condition. */
        if (!unit_verify_deps(u))
                return -ENOLINK;

        /* Forward to the main object, if we aren't it. */
        following = unit_following(u);
        if (following) {
                log_unit_debug(u, "Redirecting start request from %s to %s.", u->id, following->id);
                return unit_start(following, details);
        }

        /* Check to make sure the unit isn't frozen */
        if (u->freezer_state != FREEZER_RUNNING)
                return -EDEADLK;

        /* Check our ability to start early so that ratelimited or already starting/started units don't
         * cause us to enter a busy loop. */
        if (UNIT_VTABLE(u)->test_startable) {
                r = UNIT_VTABLE(u)->test_startable(u);
                if (r <= 0)
                        return r;
        }

        /* If it is stopped, but we cannot start it, then fail */
        if (!UNIT_VTABLE(u)->start)
                return -EBADR;

        if (UNIT_IS_INACTIVE_OR_FAILED(state)) {
                Slice *slice = SLICE(UNIT_GET_SLICE(u));

                if (slice) {
                        /* Check hard concurrency limit. Note this is partially redundant, we already checked
                         * this when enqueuing jobs. However, between the time when we enqueued this and the
                         * time we are dispatching the queue the configuration might have changed, hence
                         * check here again */
                        if (slice_concurrency_hard_max_reached(slice, u))
                                return -ETOOMANYREFS;

                        /* Also check soft concurrenty limit, and return EAGAIN so that the job is kept in
                         * the queue */
                        if (slice_concurrency_soft_max_reached(slice, u))
                                return -EAGAIN; /* Try again, keep in queue */
                }
        }

        /* We don't suppress calls to ->start() here when we are already starting, to allow this request to
         * be used as a "hurry up" call, for example when the unit is in some "auto restart" state where it
         * waits for a holdoff timer to elapse before it will start again. */

        unit_add_to_dbus_queue(u);

        if (!u->activation_details) /* Older details object wins */
                u->activation_details = activation_details_ref(details);

        return UNIT_VTABLE(u)->start(u);
}

bool unit_can_start(Unit *u) {
        assert(u);

        if (u->load_state != UNIT_LOADED)
                return false;

        if (!unit_type_supported(u->type))
                return false;

        /* Scope units may be started only once */
        if (UNIT_VTABLE(u)->once_only && dual_timestamp_is_set(&u->inactive_exit_timestamp))
                return false;

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
 *         -EDEADLK:  Unit is frozen
 */
int unit_stop(Unit *u) {
        UnitActiveState state;
        Unit *following;

        assert(u);

        state = unit_active_state(u);
        if (UNIT_IS_INACTIVE_OR_FAILED(state))
                return -EALREADY;

        following = unit_following(u);
        if (following) {
                log_unit_debug(u, "Redirecting stop request from %s to %s.", u->id, following->id);
                return unit_stop(following);
        }

        /* Check to make sure the unit isn't frozen */
        if (u->freezer_state != FREEZER_RUNNING)
                return -EDEADLK;

        if (!UNIT_VTABLE(u)->stop)
                return -EBADR;

        unit_add_to_dbus_queue(u);

        return UNIT_VTABLE(u)->stop(u);
}

bool unit_can_stop(Unit *u) {
        assert(u);

        /* Note: if we return true here, it does not mean that the unit may be successfully stopped.
         * Extrinsic units follow external state and they may stop following external state changes
         * (hence we return true here), but an attempt to do this through the manager will fail. */

        if (!unit_type_supported(u->type))
                return false;

        if (u->perpetual)
                return false;

        return !!UNIT_VTABLE(u)->stop;
}

/* Errors:
 *         -EBADR:    This unit type does not support reloading.
 *         -ENOEXEC:  Unit is not started.
 *         -EAGAIN:   An operation is already in progress. Retry later.
 *         -EDEADLK:  Unit is frozen.
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
        if (IN_SET(state, UNIT_RELOADING, UNIT_REFRESHING))
                /* "refreshing" means some resources in the unit namespace is being updated. Unlike reload,
                 * the unit processes aren't made aware of refresh. Let's put the job back to queue
                 * in both cases, as refresh typically takes place before reload and it's better to wait
                 * for it rather than failing. */
                return -EAGAIN;

        if (state != UNIT_ACTIVE)
                return log_unit_warning_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "Unit cannot be reloaded because it is inactive.");

        following = unit_following(u);
        if (following) {
                log_unit_debug(u, "Redirecting reload request from %s to %s.", u->id, following->id);
                return unit_reload(following);
        }

        /* Check to make sure the unit isn't frozen */
        if (u->freezer_state != FREEZER_RUNNING)
                return -EDEADLK;

        unit_add_to_dbus_queue(u);

        if (!UNIT_VTABLE(u)->reload) {
                /* Unit doesn't have a reload function, but we need to propagate the reload anyway */
                unit_notify(u, unit_active_state(u), unit_active_state(u), /* reload_success= */ true);
                return 0;
        }

        return UNIT_VTABLE(u)->reload(u);
}

bool unit_can_reload(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->can_reload)
                return UNIT_VTABLE(u)->can_reload(u);

        if (unit_has_dependency(u, UNIT_ATOM_PROPAGATES_RELOAD_TO, NULL))
                return true;

        return UNIT_VTABLE(u)->reload;
}

bool unit_is_unneeded(Unit *u) {
        Unit *other;
        assert(u);

        if (!u->stop_when_unneeded)
                return false;

        /* Don't clean up while the unit is transitioning or is even inactive. */
        if (unit_active_state(u) != UNIT_ACTIVE)
                return false;
        if (u->job)
                return false;

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED) {
                /* If a dependent unit has a job queued, is active or transitioning, or is marked for
                 * restart, then don't clean this one up. */

                if (other->job)
                        return false;

                if (!UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other)))
                        return false;

                if (unit_will_restart(other))
                        return false;
        }

        return true;
}

bool unit_is_upheld_by_active(Unit *u, Unit **ret_culprit) {
        Unit *other;

        assert(u);

        /* Checks if the unit needs to be started because it currently is not running, but some other unit
         * that is active declared an Uphold= dependencies on it */

        if (!UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(u)) || u->job) {
                if (ret_culprit)
                        *ret_culprit = NULL;
                return false;
        }

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_START_STEADILY) {
                if (other->job)
                        continue;

                if (UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(other))) {
                        if (ret_culprit)
                                *ret_culprit = other;
                        return true;
                }
        }

        if (ret_culprit)
                *ret_culprit = NULL;
        return false;
}

bool unit_is_bound_by_inactive(Unit *u, Unit **ret_culprit) {
        Unit *other;

        assert(u);

        /* Checks whether this unit is bound to another unit that is inactive, i.e. whether we should stop
         * because the other unit is down. */

        if (unit_active_state(u) != UNIT_ACTIVE || u->job) {
                /* Don't clean up while the unit is transitioning or is even inactive. */
                if (ret_culprit)
                        *ret_culprit = NULL;
                return false;
        }

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT) {
                if (other->job)
                        continue;

                if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(other))) {
                        if (ret_culprit)
                                *ret_culprit = other;

                        return true;
                }
        }

        if (ret_culprit)
                *ret_culprit = NULL;
        return false;
}

static void check_unneeded_dependencies(Unit *u) {
        Unit *other;
        assert(u);

        /* Add all units this unit depends on to the queue that processes StopWhenUnneeded= behaviour. */

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE)
                unit_submit_to_stop_when_unneeded_queue(other);
}

static void check_uphold_dependencies(Unit *u) {
        Unit *other;
        assert(u);

        /* Add all units this unit depends on to the queue that processes Uphold= behaviour. */

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE)
                unit_submit_to_start_when_upheld_queue(other);
}

static void check_bound_by_dependencies(Unit *u) {
        Unit *other;
        assert(u);

        /* Add all units this unit depends on to the queue that processes BindsTo= stop behaviour. */

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE)
                unit_submit_to_stop_when_bound_queue(other);
}

static void retroactively_start_dependencies(Unit *u) {
        Unit *other;

        assert(u);
        assert(UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)));

        UNIT_FOREACH_DEPENDENCY_SAFE(other, u, UNIT_ATOM_RETROACTIVE_START_REPLACE) /* Requires= + BindsTo= */
                if (!unit_has_dependency(u, UNIT_ATOM_AFTER, other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        (void) manager_add_job(u->manager, JOB_START, other, JOB_REPLACE, /* reterr_error= */ NULL, /* ret= */ NULL);

        UNIT_FOREACH_DEPENDENCY_SAFE(other, u, UNIT_ATOM_RETROACTIVE_START_FAIL) /* Wants= */
                if (!unit_has_dependency(u, UNIT_ATOM_AFTER, other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        (void) manager_add_job(u->manager, JOB_START, other, JOB_FAIL, /* reterr_error= */ NULL, /* ret= */ NULL);

        UNIT_FOREACH_DEPENDENCY_SAFE(other, u, UNIT_ATOM_RETROACTIVE_STOP_ON_START) /* Conflicts= (and inverse) */
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        (void) manager_add_job(u->manager, JOB_STOP, other, JOB_REPLACE, /* reterr_error= */ NULL, /* ret= */ NULL);
}

static void retroactively_stop_dependencies(Unit *u) {
        Unit *other;

        assert(u);
        assert(UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)));

        /* Pull down units which are bound to us recursively if enabled */
        UNIT_FOREACH_DEPENDENCY_SAFE(other, u, UNIT_ATOM_RETROACTIVE_STOP_ON_STOP) /* BoundBy= */
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        (void) manager_add_job(u->manager, JOB_STOP, other, JOB_REPLACE, /* reterr_error= */ NULL, /* ret= */ NULL);
}

void unit_start_on_termination_deps(Unit *u, UnitDependencyAtom atom) {
        const char *dependency_name = NULL;
        JobMode job_mode;
        unsigned n_jobs = 0;
        int r;

        /* Act on OnFailure= and OnSuccess= dependencies */

        assert(u);
        assert(u->manager);
        assert(IN_SET(atom, UNIT_ATOM_ON_SUCCESS, UNIT_ATOM_ON_FAILURE));

        FOREACH_ELEMENT(setting, on_termination_settings)
                if (atom == setting->atom) {
                        job_mode = *(JobMode*) ((uint8_t*) u + setting->job_mode_offset);
                        dependency_name = setting->dependency_name;
                        break;
                }

        assert(dependency_name);

        Unit *other;
        UNIT_FOREACH_DEPENDENCY_SAFE(other, u, atom) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                if (n_jobs == 0)
                        log_unit_info(u, "Triggering %s dependencies.", dependency_name);

                r = manager_add_job(u->manager, JOB_START, other, job_mode, &error, /* ret= */ NULL);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to enqueue %s%s job, ignoring: %s",
                                               dependency_name, other->id, bus_error_message(&error, r));
                n_jobs++;
        }

        if (n_jobs > 0)
                log_unit_debug(u, "Triggering %s dependencies done (%u %s).",
                               dependency_name, n_jobs, n_jobs == 1 ? "job" : "jobs");
}

void unit_trigger_notify(Unit *u) {
        Unit *other;

        assert(u);

        UNIT_FOREACH_DEPENDENCY_SAFE(other, u, UNIT_ATOM_TRIGGERED_BY)
                if (UNIT_VTABLE(other)->trigger_notify)
                        UNIT_VTABLE(other)->trigger_notify(other, u);
}

static int raise_level(int log_level, bool condition_info, bool condition_notice) {
        if (condition_notice && log_level > LOG_NOTICE)
                return LOG_NOTICE;
        if (condition_info && log_level > LOG_INFO)
                return LOG_INFO;
        return log_level;
}

static int unit_log_resources(Unit *u) {

        static const struct {
                const char *journal_field;
                const char *message_suffix;
        } memory_fields[_CGROUP_MEMORY_ACCOUNTING_METRIC_CACHED_LAST + 1] = {
                [CGROUP_MEMORY_PEAK]         = { "MEMORY_PEAK",                "memory peak"         },
                [CGROUP_MEMORY_SWAP_PEAK]    = { "MEMORY_SWAP_PEAK",           "memory swap peak"    },
        }, ip_fields[_CGROUP_IP_ACCOUNTING_METRIC_MAX] = {
                [CGROUP_IP_INGRESS_BYTES]    = { "IP_METRIC_INGRESS_BYTES",    "incoming IP traffic" },
                [CGROUP_IP_EGRESS_BYTES]     = { "IP_METRIC_EGRESS_BYTES",     "outgoing IP traffic" },
                [CGROUP_IP_INGRESS_PACKETS]  = { "IP_METRIC_INGRESS_PACKETS",  NULL                  },
                [CGROUP_IP_EGRESS_PACKETS]   = { "IP_METRIC_EGRESS_PACKETS",   NULL                  },
        }, io_fields[_CGROUP_IO_ACCOUNTING_METRIC_MAX] = {
                [CGROUP_IO_READ_BYTES]       = { "IO_METRIC_READ_BYTES",       "read from disk"      },
                [CGROUP_IO_WRITE_BYTES]      = { "IO_METRIC_WRITE_BYTES",      "written to disk"     },
                [CGROUP_IO_READ_OPERATIONS]  = { "IO_METRIC_READ_OPERATIONS",  NULL                  },
                [CGROUP_IO_WRITE_OPERATIONS] = { "IO_METRIC_WRITE_OPERATIONS", NULL                  },
        };

        struct iovec *iovec = NULL;
        size_t n_iovec = 0;
        _cleanup_free_ char *message = NULL, *t = NULL;
        nsec_t cpu_nsec = NSEC_INFINITY;
        int log_level = LOG_DEBUG; /* May be raised if resources consumed over a threshold */

        assert(u);

        CLEANUP_ARRAY(iovec, n_iovec, iovec_array_free);

        iovec = new(struct iovec, 1 + (_CGROUP_MEMORY_ACCOUNTING_METRIC_CACHED_LAST + 1) +
                                  _CGROUP_IP_ACCOUNTING_METRIC_MAX + _CGROUP_IO_ACCOUNTING_METRIC_MAX + 4);
        if (!iovec)
                return log_oom();

        /* Invoked whenever a unit enters failed or dead state. Logs information about consumed resources if resource
         * accounting was enabled for a unit. It does this in two ways: a friendly human-readable string with reduced
         * information and the complete data in structured fields. */

        (void) unit_get_cpu_usage(u, &cpu_nsec);
        if (cpu_nsec != NSEC_INFINITY) {
                /* Format the CPU time for inclusion in the structured log message */
                if (asprintf(&t, "CPU_USAGE_NSEC=%" PRIu64, cpu_nsec) < 0)
                        return log_oom();
                iovec[n_iovec++] = IOVEC_MAKE_STRING(TAKE_PTR(t));

                /* Format the CPU time for inclusion in the human language message string */
                if (dual_timestamp_is_set(&u->inactive_exit_timestamp) &&
                    dual_timestamp_is_set(&u->inactive_enter_timestamp)) {
                        usec_t wall_clock_usec = usec_sub_unsigned(u->inactive_enter_timestamp.monotonic, u->inactive_exit_timestamp.monotonic);
                        if (strextendf_with_separator(&message, ", ",
                                                      "Consumed %s CPU time over %s wall clock time",
                                                      FORMAT_TIMESPAN(cpu_nsec / NSEC_PER_USEC, USEC_PER_MSEC),
                                                      FORMAT_TIMESPAN(wall_clock_usec, USEC_PER_MSEC)) < 0)
                                return log_oom();
                } else {
                        if (strextendf_with_separator(&message, ", ",
                                                      "Consumed %s CPU time",
                                                      FORMAT_TIMESPAN(cpu_nsec / NSEC_PER_USEC, USEC_PER_MSEC)) < 0)
                                return log_oom();
                }

                log_level = raise_level(log_level,
                                        cpu_nsec > MENTIONWORTHY_CPU_NSEC,
                                        cpu_nsec > NOTICEWORTHY_CPU_NSEC);
        }

        for (CGroupMemoryAccountingMetric metric = 0; metric <= _CGROUP_MEMORY_ACCOUNTING_METRIC_CACHED_LAST; metric++) {
                uint64_t value = UINT64_MAX;

                assert(memory_fields[metric].journal_field);
                assert(memory_fields[metric].message_suffix);

                (void) unit_get_memory_accounting(u, metric, &value);
                if (value == UINT64_MAX)
                        continue;

                if (asprintf(&t, "%s=%" PRIu64, memory_fields[metric].journal_field, value) < 0)
                        return log_oom();
                iovec[n_iovec++] = IOVEC_MAKE_STRING(TAKE_PTR(t));

                /* If value is 0, we don't log it in the MESSAGE= field. */
                if (value == 0)
                        continue;

                if (strextendf_with_separator(&message, ", ", "%s %s",
                                              FORMAT_BYTES(value), memory_fields[metric].message_suffix) < 0)
                        return log_oom();

                log_level = raise_level(log_level,
                                        value > MENTIONWORTHY_MEMORY_BYTES,
                                        value > NOTICEWORTHY_MEMORY_BYTES);
        }

        for (CGroupIOAccountingMetric k = 0; k < _CGROUP_IO_ACCOUNTING_METRIC_MAX; k++) {
                uint64_t value = UINT64_MAX;

                assert(io_fields[k].journal_field);

                (void) unit_get_io_accounting(u, k, &value);
                if (value == UINT64_MAX)
                        continue;

                /* Format IO accounting data for inclusion in the structured log message */
                if (asprintf(&t, "%s=%" PRIu64, io_fields[k].journal_field, value) < 0)
                        return log_oom();
                iovec[n_iovec++] = IOVEC_MAKE_STRING(TAKE_PTR(t));

                /* If value is 0, we don't log it in the MESSAGE= field. */
                if (value == 0)
                        continue;

                /* Format the IO accounting data for inclusion in the human language message string, but only
                 * for the bytes counters (and not for the operations counters) */
                if (io_fields[k].message_suffix) {
                        if (strextendf_with_separator(&message, ", ", "%s %s",
                                                      FORMAT_BYTES(value), io_fields[k].message_suffix) < 0)
                                return log_oom();

                        log_level = raise_level(log_level,
                                                value > MENTIONWORTHY_IO_BYTES,
                                                value > NOTICEWORTHY_IO_BYTES);
                }
        }

        for (CGroupIPAccountingMetric m = 0; m < _CGROUP_IP_ACCOUNTING_METRIC_MAX; m++) {
                uint64_t value = UINT64_MAX;

                assert(ip_fields[m].journal_field);

                (void) unit_get_ip_accounting(u, m, &value);
                if (value == UINT64_MAX)
                        continue;

                /* Format IP accounting data for inclusion in the structured log message */
                if (asprintf(&t, "%s=%" PRIu64, ip_fields[m].journal_field, value) < 0)
                        return log_oom();
                iovec[n_iovec++] = IOVEC_MAKE_STRING(TAKE_PTR(t));

                /* If value is 0, we don't log it in the MESSAGE= field. */
                if (value == 0)
                        continue;

                /* Format the IP accounting data for inclusion in the human language message string, but only
                 * for the bytes counters (and not for the packets counters) */
                if (ip_fields[m].message_suffix) {
                        if (strextendf_with_separator(&message, ", ", "%s %s",
                                                      FORMAT_BYTES(value), ip_fields[m].message_suffix) < 0)
                                return log_oom();

                        log_level = raise_level(log_level,
                                                value > MENTIONWORTHY_IP_BYTES,
                                                value > NOTICEWORTHY_IP_BYTES);
                }
        }

        /* This check is here because it is the earliest point following all possible log_level assignments.
         * (If log_level is assigned anywhere after this point, move this check.) */
        if (!unit_log_level_test(u, log_level))
                return 0;

        /* Is there any accounting data available at all? */
        if (n_iovec == 0) {
                assert(!message);
                return 0;
        }

        t = strjoin("MESSAGE=", u->id, ": ", message ?: "Completed", ".");
        if (!t)
                return log_oom();
        iovec[n_iovec++] = IOVEC_MAKE_STRING(TAKE_PTR(t));

        if (!set_iovec_string_field(iovec, &n_iovec, "MESSAGE_ID=", SD_MESSAGE_UNIT_RESOURCES_STR))
                return log_oom();

        if (!set_iovec_string_field(iovec, &n_iovec, unit_log_field(u), u->id))
                return log_oom();

        if (!set_iovec_string_field(iovec, &n_iovec, unit_invocation_log_field(u), u->invocation_id_string))
                return log_oom();

        log_unit_struct_iovec(u, log_level, iovec, n_iovec);

        return 0;
}

static void unit_update_on_console(Unit *u) {
        bool b;

        assert(u);

        b = unit_needs_console(u);
        if (u->on_console == b)
                return;

        u->on_console = b;
        if (b)
                manager_ref_console(u->manager);
        else
                manager_unref_console(u->manager);
}

static void unit_emit_audit_start(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->audit_start_message_type <= 0)
                return;

        /* Write audit record if we have just finished starting up */
        manager_send_unit_audit(u->manager, u, UNIT_VTABLE(u)->audit_start_message_type, /* success= */ true);
        u->in_audit = true;
}

static void unit_emit_audit_stop(Unit *u, UnitActiveState state) {
        assert(u);

        if (UNIT_VTABLE(u)->audit_start_message_type <= 0)
                return;

        if (u->in_audit) {
                /* Write audit record if we have just finished shutting down */
                manager_send_unit_audit(u->manager, u, UNIT_VTABLE(u)->audit_stop_message_type, /* success= */ state == UNIT_INACTIVE);
                u->in_audit = false;
        } else {
                /* Hmm, if there was no start record written write it now, so that we always have a nice pair */
                manager_send_unit_audit(u->manager, u, UNIT_VTABLE(u)->audit_start_message_type, /* success= */ state == UNIT_INACTIVE);

                if (state == UNIT_INACTIVE)
                        manager_send_unit_audit(u->manager, u, UNIT_VTABLE(u)->audit_stop_message_type, /* success= */ true);
        }
}

static bool unit_process_job(Job *j, UnitActiveState ns, bool reload_success) {
        bool unexpected = false;

        assert(j);
        assert(j->installed);

        if (j->state == JOB_WAITING)
                /* So we reached a different state for this job. Let's see if we can run it now if it failed previously
                 * due to EAGAIN. */
                job_add_to_run_queue(j);

        /* Let's check whether the unit's new state constitutes a finished job, or maybe contradicts a running job and
         * hence needs to invalidate jobs. */

        switch (j->type) {

        case JOB_START:
        case JOB_VERIFY_ACTIVE:

                if (UNIT_IS_ACTIVE_OR_RELOADING(ns))
                        job_finish_and_invalidate(j, JOB_DONE, /* recursive= */ true, /* already= */ false);
                else if (j->state == JOB_RUNNING && ns != UNIT_ACTIVATING) {
                        unexpected = true;

                        if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                                job_finish_and_invalidate(j, ns == UNIT_FAILED ? JOB_FAILED : JOB_DONE, /* recursive= */ true, /* already= */ false);
                }

                break;

        case JOB_RELOAD:

                if (j->state == JOB_RUNNING) {
                        if (ns == UNIT_ACTIVE)
                                job_finish_and_invalidate(j, reload_success ? JOB_DONE : JOB_FAILED, /* recursive= */ true, /* already= */ false);
                        else if (!IN_SET(ns, UNIT_ACTIVATING, UNIT_RELOADING, UNIT_REFRESHING)) {
                                unexpected = true;
                                job_finish_and_invalidate(j, reload_success ? JOB_CANCELED : JOB_FAILED, /* recursive= */ true, /* already= */ false);
                        }
                }

                break;

        case JOB_STOP:
        case JOB_RESTART:

                if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                        job_finish_and_invalidate(j, JOB_DONE, /* recursive= */ true, /* already= */ false);
                else if (j->state == JOB_RUNNING && ns != UNIT_DEACTIVATING) {
                        unexpected = true;
                        job_finish_and_invalidate(j, JOB_FAILED, /* recursive= */ true, /* already= */ false);
                }

                break;

        default:
                assert_not_reached();
        }

        return unexpected;
}

static void unit_recursive_add_to_run_queue(Unit *u) {
        assert(u);

        if (u->job)
                job_add_to_run_queue(u->job);

        Unit *child;
        UNIT_FOREACH_DEPENDENCY(child, u, UNIT_ATOM_SLICE_OF) {

                if (!child->job)
                        continue;

                unit_recursive_add_to_run_queue(child);
        }
}

static void unit_check_concurrency_limit(Unit *u) {
        assert(u);

        Unit *slice = UNIT_GET_SLICE(u);
        if (!slice)
                return;

        /* If a unit was stopped, maybe it has pending siblings (or children thereof) that can be started now */

        if (SLICE(slice)->concurrency_soft_max != UINT_MAX) {
                Unit *sibling;
                UNIT_FOREACH_DEPENDENCY(sibling, slice, UNIT_ATOM_SLICE_OF) {
                        if (sibling == u)
                                continue;

                        unit_recursive_add_to_run_queue(sibling);
                }
        }

        /* Also go up the tree. */
        unit_check_concurrency_limit(slice);
}

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns, bool reload_success) {
        assert(u);
        assert(os < _UNIT_ACTIVE_STATE_MAX);
        assert(ns < _UNIT_ACTIVE_STATE_MAX);

        /* Note that this is called for all low-level state changes, even if they might map to the same high-level
         * UnitActiveState! That means that ns == os is an expected behavior here. For example: if a mount point is
         * remounted this function will be called too! */

        Manager *m = ASSERT_PTR(u->manager);

        /* Let's enqueue the change signal early. In case this unit has a job associated we want that this unit is in
         * the bus queue, so that any job change signal queued will force out the unit change signal first. */
        unit_add_to_dbus_queue(u);

        /* Update systemd-oomd on the property/state change.
         *
         * Always send an update if the unit is going into an inactive state so systemd-oomd knows to
         * stop monitoring.
         * Also send an update whenever the unit goes active; this is to handle a case where an override file
         * sets one of the ManagedOOM*= properties to "kill", then later removes it. systemd-oomd needs to
         * know to stop monitoring when the unit changes from "kill" -> "auto" on daemon-reload, but we don't
         * have the information on the property. Thus, indiscriminately send an update. */
        if (os != ns && (UNIT_IS_INACTIVE_OR_FAILED(ns) || UNIT_IS_ACTIVE_OR_RELOADING(ns)))
                (void) manager_varlink_send_managed_oom_update(u);

        /* Update timestamps for state changes */
        if (!MANAGER_IS_RELOADING(m)) {
                dual_timestamp_now(&u->state_change_timestamp);

                if (UNIT_IS_INACTIVE_OR_FAILED(os) && !UNIT_IS_INACTIVE_OR_FAILED(ns))
                        u->inactive_exit_timestamp = u->state_change_timestamp;
                else if (!UNIT_IS_INACTIVE_OR_FAILED(os) && UNIT_IS_INACTIVE_OR_FAILED(ns))
                        u->inactive_enter_timestamp = u->state_change_timestamp;

                if (!UNIT_IS_ACTIVE_OR_RELOADING(os) && UNIT_IS_ACTIVE_OR_RELOADING(ns))
                        u->active_enter_timestamp = u->state_change_timestamp;
                else if (UNIT_IS_ACTIVE_OR_RELOADING(os) && !UNIT_IS_ACTIVE_OR_RELOADING(ns))
                        u->active_exit_timestamp = u->state_change_timestamp;
        }

        /* Keep track of failed units */
        (void) manager_update_failed_units(m, u, ns == UNIT_FAILED);

        /* Make sure the cgroup and state files are always removed when we become inactive */
        if (UNIT_IS_INACTIVE_OR_FAILED(ns)) {
                SET_FLAG(u->markers,
                         (1u << UNIT_MARKER_NEEDS_RELOAD)|(1u << UNIT_MARKER_NEEDS_RESTART)|(1u << UNIT_MARKER_NEEDS_STOP),
                         false);
                unit_prune_cgroup(u);
                unit_unlink_state_files(u);
        } else if (UNIT_IS_ACTIVE_OR_ACTIVATING(ns))
                SET_FLAG(u->markers, 1u << UNIT_MARKER_NEEDS_START, false);
        else if (ns != os && ns == UNIT_RELOADING)
                SET_FLAG(u->markers, 1u << UNIT_MARKER_NEEDS_RELOAD, false);

        unit_update_on_console(u);

        if (!MANAGER_IS_RELOADING(m)) {
                bool unexpected;

                /* Let's propagate state changes to the job */
                if (u->job)
                        unexpected = unit_process_job(u->job, ns, reload_success);
                else
                        unexpected = true;

                /* If this state change happened without being requested by a job, then let's retroactively start or
                 * stop dependencies. We skip that step when deserializing, since we don't want to create any
                 * additional jobs just because something is already activated. */

                if (unexpected) {
                        if (UNIT_IS_INACTIVE_OR_FAILED(os) && UNIT_IS_ACTIVE_OR_ACTIVATING(ns))
                                retroactively_start_dependencies(u);
                        else if (UNIT_IS_ACTIVE_OR_ACTIVATING(os) && UNIT_IS_INACTIVE_OR_DEACTIVATING(ns))
                                retroactively_stop_dependencies(u);
                }

                if (UNIT_IS_ACTIVE_OR_RELOADING(ns) && !UNIT_IS_ACTIVE_OR_RELOADING(os)) {
                        /* This unit just finished starting up */

                        unit_emit_audit_start(u);
                        manager_send_unit_plymouth(m, u);
                        manager_send_unit_supervisor(m, u, /* active= */ true);

                } else if (UNIT_IS_INACTIVE_OR_FAILED(ns) && !UNIT_IS_INACTIVE_OR_FAILED(os)) {
                        /* This unit just stopped/failed. */

                        unit_emit_audit_stop(u, ns);
                        manager_send_unit_supervisor(m, u, /* active= */ false);
                        unit_log_resources(u);
                }

                if (ns == UNIT_INACTIVE && !IN_SET(os, UNIT_FAILED, UNIT_INACTIVE, UNIT_MAINTENANCE))
                        unit_start_on_termination_deps(u, UNIT_ATOM_ON_SUCCESS);
                else if (ns != os && ns == UNIT_FAILED)
                        unit_start_on_termination_deps(u, UNIT_ATOM_ON_FAILURE);
        }

        manager_recheck_journal(m);
        manager_recheck_dbus(m);

        unit_trigger_notify(u);

        if (!MANAGER_IS_RELOADING(m)) {
                const char *reason;

                if (os != UNIT_FAILED && ns == UNIT_FAILED) {
                        reason = strjoina("unit ", u->id, " failed");
                        emergency_action(m, u->failure_action, EMERGENCY_ACTION_WARN|EMERGENCY_ACTION_SLEEP_5S, u->reboot_arg, unit_failure_action_exit_status(u), reason);
                } else if (!UNIT_IS_INACTIVE_OR_FAILED(os) && ns == UNIT_INACTIVE) {
                        reason = strjoina("unit ", u->id, " succeeded");
                        emergency_action(m, u->success_action, /* flags= */ 0, u->reboot_arg, unit_success_action_exit_status(u), reason);
                }
        }

        /* And now, add the unit or depending units to various queues that will act on the new situation if
         * needed. These queues generally check for continuous state changes rather than events (like most of
         * the state propagation above), and do work deferred instead of instantly, since they typically
         * don't want to run during reloading, and usually involve checking combined state of multiple units
         * at once. */

        if (UNIT_IS_INACTIVE_OR_FAILED(ns)) {
                /* Stop unneeded units and bound-by units regardless if going down was expected or not */
                check_unneeded_dependencies(u);
                check_bound_by_dependencies(u);

                /* Maybe someone wants us to remain up? */
                unit_submit_to_start_when_upheld_queue(u);

                /* Maybe the unit should be GC'ed now? */
                unit_add_to_gc_queue(u);

                /* Maybe we can release some resources now? */
                unit_submit_to_release_resources_queue(u);

                /* Maybe the concurrency limits now allow dispatching of another start job in this slice? */
                unit_check_concurrency_limit(u);

                /* Maybe someone else has been waiting for us to stop? */
                m->may_dispatch_stop_notify_queue = true;

        } else if (UNIT_IS_ACTIVE_OR_RELOADING(ns)) {
                /* Start uphold units regardless if going up was expected or not */
                check_uphold_dependencies(u);

                /* Maybe we finished startup and are now ready for being stopped because unneeded? */
                unit_submit_to_stop_when_unneeded_queue(u);

                /* Maybe we finished startup, but something we needed has vanished? Let's die then. (This happens
                 * when something BindsTo= to a Type=oneshot unit, as these units go directly from starting to
                 * inactive, without ever entering started.) */
                unit_submit_to_stop_when_bound_queue(u);
        }
}

int unit_watch_pidref(Unit *u, const PidRef *pid, bool exclusive) {
        _cleanup_(pidref_freep) PidRef *pid_dup = NULL;
        int r;

        /* Adds a specific PID to the set of PIDs this unit watches. */

        assert(u);
        assert(pidref_is_set(pid));

        /* Caller might be sure that this PID belongs to this unit only. Let's take this
         * opportunity to remove any stalled references to this PID as they can be created
         * easily (when watching a process which is not our direct child). */
        if (exclusive)
                manager_unwatch_pidref(u->manager, pid);

        if (set_contains(u->pids, pid)) { /* early exit if already being watched */
                assert(!exclusive);
                return 0;
        }

        r = pidref_dup(pid, &pid_dup);
        if (r < 0)
                return r;

        /* First, insert into the set of PIDs maintained by the unit */
        r = set_ensure_put(&u->pids, &pidref_hash_ops_free, pid_dup);
        if (r < 0)
                return r;

        pid = TAKE_PTR(pid_dup); /* continue with our copy now that we have installed it properly in our set */

        /* Second, insert it into the simple global table, see if that works */
        r = hashmap_ensure_put(&u->manager->watch_pids, &pidref_hash_ops, pid, u);
        if (r != -EEXIST)
                return r;

        /* OK, the key is already assigned to a different unit. That's fine, then add us via the second
         * hashmap that points to an array. */

        PidRef *old_pid = NULL;
        Unit **array = hashmap_get2(u->manager->watch_pids_more, pid, (void**) &old_pid);

        /* Count entries in array */
        size_t n = 0;
        for (; array && array[n]; n++)
                ;

        /* Allocate a new array */
        _cleanup_free_ Unit **new_array = new(Unit*, n + 2);
        if (!new_array)
                return -ENOMEM;

        /* Append us to the end */
        memcpy_safe(new_array, array, sizeof(Unit*) * n);
        new_array[n] = u;
        new_array[n+1] = NULL;

        /* Add or replace the old array */
        r = hashmap_ensure_replace(&u->manager->watch_pids_more, &pidref_hash_ops, old_pid ?: pid, new_array);
        if (r < 0)
                return r;

        TAKE_PTR(new_array); /* Now part of the hash table */
        free(array);         /* Which means we can now delete the old version */
        return 0;
}

void unit_unwatch_pidref(Unit *u, const PidRef *pid) {
        assert(u);
        assert(pidref_is_set(pid));

        /* Remove from the set we maintain for this unit. (And destroy the returned pid eventually) */
        _cleanup_(pidref_freep) PidRef *pid1 = set_remove(u->pids, pid);
        if (!pid1)
                return; /* Early exit if this PID was never watched by us */

        /* First let's drop the unit from the simple hash table, if it is included there */
        PidRef *pid2 = NULL;
        Unit *uu = hashmap_get2(u->manager->watch_pids, pid, (void**) &pid2);

        /* Quick validation: iff we are in the watch_pids table then the PidRef object must be the same as in our local pids set */
        assert((uu == u) == (pid1 == pid2));

        if (uu == u)
                /* OK, we are in the first table. Let's remove it there then, and we are done already. */
                assert_se(hashmap_remove_value(u->manager->watch_pids, pid2, uu));
        else {
                /* We weren't in the first table, then let's consult the 2nd table that points to an array */
                PidRef *pid3 = NULL;
                Unit **array = hashmap_get2(u->manager->watch_pids_more, pid, (void**) &pid3);

                /* Let's iterate through the array, dropping our own entry */
                size_t m = 0, n = 0;
                for (; array && array[n]; n++)
                        if (array[n] != u)
                                array[m++] = array[n];
                if (n == m)
                        return; /* Not there */

                array[m] = NULL; /* set trailing NULL marker on the new end */

                if (m == 0) {
                        /* The array is now empty, remove the entire entry */
                        assert_se(hashmap_remove_value(u->manager->watch_pids_more, pid3, array));
                        free(array);
                } else {
                        /* The array is not empty, but let's make sure the entry is not keyed by the PidRef
                         * we will delete, but by the PidRef object of the Unit that is now first in the
                         * array. */

                        PidRef *new_pid3 = ASSERT_PTR(set_get(array[0]->pids, pid));
                        assert_se(hashmap_replace(u->manager->watch_pids_more, new_pid3, array) >= 0);
                }
        }
}

void unit_unwatch_all_pids(Unit *u) {
        assert(u);

        while (!set_isempty(u->pids))
                unit_unwatch_pidref(u, set_first(u->pids));

        u->pids = set_free(u->pids);
}

void unit_unwatch_pidref_done(Unit *u, PidRef *pidref) {
        assert(u);

        if (!pidref_is_set(pidref))
                return;

        unit_unwatch_pidref(u, pidref);
        pidref_done(pidref);
}

bool unit_job_is_applicable(Unit *u, JobType j) {
        assert(u);
        assert(j >= 0 && j < _JOB_TYPE_MAX);

        switch (j) {

        case JOB_VERIFY_ACTIVE:
        case JOB_START:
        case JOB_NOP:
                /* Note that we don't check unit_can_start() here. That's because .device units and suchlike are not
                 * startable by us but may appear due to external events, and it thus makes sense to permit enqueuing
                 * jobs for it. */
                return true;

        case JOB_STOP:
                /* Similar as above. However, perpetual units can never be stopped (neither explicitly nor due to
                 * external events), hence it makes no sense to permit enqueuing such a request either. */
                return !u->perpetual;

        case JOB_RESTART:
        case JOB_TRY_RESTART:
                return unit_can_stop(u) && unit_can_start(u);

        case JOB_RELOAD:
        case JOB_TRY_RELOAD:
                return unit_can_reload(u);

        case JOB_RELOAD_OR_START:
                return unit_can_reload(u) && unit_can_start(u);

        default:
                assert_not_reached();
        }
}

static Hashmap *unit_get_dependency_hashmap_per_type(Unit *u, UnitDependency d) {
        Hashmap *deps;

        assert(u);
        assert(d >= 0 && d < _UNIT_DEPENDENCY_MAX);

        deps = hashmap_get(u->dependencies, UNIT_DEPENDENCY_TO_PTR(d));
        if (!deps) {
                _cleanup_hashmap_free_ Hashmap *h = NULL;

                h = hashmap_new(NULL);
                if (!h)
                        return NULL;

                if (hashmap_ensure_put(&u->dependencies, NULL, UNIT_DEPENDENCY_TO_PTR(d), h) < 0)
                        return NULL;

                deps = TAKE_PTR(h);
        }

        return deps;
}

typedef enum NotifyDependencyFlags {
        NOTIFY_DEPENDENCY_UPDATE_FROM = 1 << 0,
        NOTIFY_DEPENDENCY_UPDATE_TO   = 1 << 1,
} NotifyDependencyFlags;

static int unit_add_dependency_impl(
                Unit *u,
                UnitDependency d,
                Unit *other,
                UnitDependencyMask mask) {

        static const UnitDependency inverse_table[_UNIT_DEPENDENCY_MAX] = {
                [UNIT_REQUIRES]               = UNIT_REQUIRED_BY,
                [UNIT_REQUISITE]              = UNIT_REQUISITE_OF,
                [UNIT_WANTS]                  = UNIT_WANTED_BY,
                [UNIT_BINDS_TO]               = UNIT_BOUND_BY,
                [UNIT_PART_OF]                = UNIT_CONSISTS_OF,
                [UNIT_UPHOLDS]                = UNIT_UPHELD_BY,
                [UNIT_REQUIRED_BY]            = UNIT_REQUIRES,
                [UNIT_REQUISITE_OF]           = UNIT_REQUISITE,
                [UNIT_WANTED_BY]              = UNIT_WANTS,
                [UNIT_BOUND_BY]               = UNIT_BINDS_TO,
                [UNIT_CONSISTS_OF]            = UNIT_PART_OF,
                [UNIT_UPHELD_BY]              = UNIT_UPHOLDS,
                [UNIT_CONFLICTS]              = UNIT_CONFLICTED_BY,
                [UNIT_CONFLICTED_BY]          = UNIT_CONFLICTS,
                [UNIT_BEFORE]                 = UNIT_AFTER,
                [UNIT_AFTER]                  = UNIT_BEFORE,
                [UNIT_ON_SUCCESS]             = UNIT_ON_SUCCESS_OF,
                [UNIT_ON_SUCCESS_OF]          = UNIT_ON_SUCCESS,
                [UNIT_ON_FAILURE]             = UNIT_ON_FAILURE_OF,
                [UNIT_ON_FAILURE_OF]          = UNIT_ON_FAILURE,
                [UNIT_TRIGGERS]               = UNIT_TRIGGERED_BY,
                [UNIT_TRIGGERED_BY]           = UNIT_TRIGGERS,
                [UNIT_PROPAGATES_RELOAD_TO]   = UNIT_RELOAD_PROPAGATED_FROM,
                [UNIT_RELOAD_PROPAGATED_FROM] = UNIT_PROPAGATES_RELOAD_TO,
                [UNIT_PROPAGATES_STOP_TO]     = UNIT_STOP_PROPAGATED_FROM,
                [UNIT_STOP_PROPAGATED_FROM]   = UNIT_PROPAGATES_STOP_TO,
                [UNIT_JOINS_NAMESPACE_OF]     = UNIT_JOINS_NAMESPACE_OF, /* symmetric! 👓 */
                [UNIT_REFERENCES]             = UNIT_REFERENCED_BY,
                [UNIT_REFERENCED_BY]          = UNIT_REFERENCES,
                [UNIT_IN_SLICE]               = UNIT_SLICE_OF,
                [UNIT_SLICE_OF]               = UNIT_IN_SLICE,
        };

        Hashmap *u_deps, *other_deps;
        UnitDependencyInfo u_info, u_info_old, other_info, other_info_old;
        NotifyDependencyFlags flags = 0;
        int r;

        assert(u);
        assert(other);
        assert(d >= 0 && d < _UNIT_DEPENDENCY_MAX);
        assert(inverse_table[d] >= 0 && inverse_table[d] < _UNIT_DEPENDENCY_MAX);
        assert(mask > 0 && mask < _UNIT_DEPENDENCY_MASK_FULL);

        /* Ensure the following two hashmaps for each unit exist:
         * - the top-level dependency hashmap that maps UnitDependency → Hashmap(Unit* → UnitDependencyInfo),
         * - the inner hashmap, that maps Unit* → UnitDependencyInfo, for the specified dependency type. */
        u_deps = unit_get_dependency_hashmap_per_type(u, d);
        if (!u_deps)
                return -ENOMEM;

        other_deps = unit_get_dependency_hashmap_per_type(other, inverse_table[d]);
        if (!other_deps)
                return -ENOMEM;

        /* Save the original dependency info. */
        u_info.data = u_info_old.data = hashmap_get(u_deps, other);
        other_info.data = other_info_old.data = hashmap_get(other_deps, u);

        /* Update dependency info. */
        u_info.origin_mask |= mask;
        other_info.destination_mask |= mask;

        /* Save updated dependency info. */
        if (u_info.data != u_info_old.data) {
                r = hashmap_replace(u_deps, other, u_info.data);
                if (r < 0)
                        return r;

                flags = NOTIFY_DEPENDENCY_UPDATE_FROM;
                u->dependency_generation++;
        }

        if (other_info.data != other_info_old.data) {
                r = hashmap_replace(other_deps, u, other_info.data);
                if (r < 0) {
                        if (u_info.data != u_info_old.data) {
                                /* Restore the old dependency. */
                                if (u_info_old.data)
                                        (void) hashmap_update(u_deps, other, u_info_old.data);
                                else
                                        hashmap_remove(u_deps, other);
                        }
                        return r;
                }

                flags |= NOTIFY_DEPENDENCY_UPDATE_TO;
                other->dependency_generation++;
        }

        return flags;
}

int unit_add_dependency(
                Unit *u,
                UnitDependency d,
                Unit *other,
                bool add_reference,
                UnitDependencyMask mask) {

        UnitDependencyAtom a;
        int r;

        /* Helper to know whether sending a notification is necessary or not: if the dependency is already
         * there, no need to notify! */
        NotifyDependencyFlags notify_flags;

        assert(u);
        assert(d >= 0 && d < _UNIT_DEPENDENCY_MAX);
        assert(other);

        u = unit_follow_merge(u);
        other = unit_follow_merge(other);
        a = unit_dependency_to_atom(d);
        assert(a >= 0);

        /* We won't allow dependencies on ourselves. We will not consider them an error however. */
        if (u == other) {
                if (unit_should_warn_about_dependency(d))
                        log_unit_warning(u, "Dependency %s=%s is dropped.",
                                         unit_dependency_to_string(d), u->id);
                return 0;
        }

        if (u->manager && FLAGS_SET(u->manager->test_run_flags, MANAGER_TEST_RUN_IGNORE_DEPENDENCIES))
                return 0;

        /* Note that ordering a device unit after a unit is permitted since it allows its job running
         * timeout to be started at a specific time. */
        if (FLAGS_SET(a, UNIT_ATOM_BEFORE) && other->type == UNIT_DEVICE) {
                log_unit_warning(u, "Dependency Before=%s ignored (.device units cannot be delayed)", other->id);
                return 0;
        }

        if (FLAGS_SET(a, UNIT_ATOM_ON_FAILURE) && !UNIT_VTABLE(u)->can_fail) {
                log_unit_warning(u, "Requested dependency OnFailure=%s ignored (%s units cannot fail).", other->id, unit_type_to_string(u->type));
                return 0;
        }

        if (FLAGS_SET(a, UNIT_ATOM_TRIGGERS) && !UNIT_VTABLE(u)->can_trigger)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Requested dependency Triggers=%s refused (%s units cannot trigger other units).", other->id, unit_type_to_string(u->type));
        if (FLAGS_SET(a, UNIT_ATOM_TRIGGERED_BY) && !UNIT_VTABLE(other)->can_trigger)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Requested dependency TriggeredBy=%s refused (%s units cannot trigger other units).", other->id, unit_type_to_string(other->type));

        if (FLAGS_SET(a, UNIT_ATOM_IN_SLICE) && other->type != UNIT_SLICE)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Requested dependency Slice=%s refused (%s is not a slice unit).", other->id, other->id);
        if (FLAGS_SET(a, UNIT_ATOM_SLICE_OF) && u->type != UNIT_SLICE)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Requested dependency SliceOf=%s refused (%s is not a slice unit).", other->id, u->id);

        if (FLAGS_SET(a, UNIT_ATOM_IN_SLICE) && !UNIT_HAS_CGROUP_CONTEXT(u))
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Requested dependency Slice=%s refused (%s is not a cgroup unit).", other->id, u->id);

        if (FLAGS_SET(a, UNIT_ATOM_SLICE_OF) && !UNIT_HAS_CGROUP_CONTEXT(other))
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "Requested dependency SliceOf=%s refused (%s is not a cgroup unit).", other->id, other->id);

        r = unit_add_dependency_impl(u, d, other, mask);
        if (r < 0)
                return r;
        notify_flags = r;

        if (add_reference) {
                r = unit_add_dependency_impl(u, UNIT_REFERENCES, other, mask);
                if (r < 0)
                        return r;
                notify_flags |= r;
        }

        if (FLAGS_SET(notify_flags, NOTIFY_DEPENDENCY_UPDATE_FROM))
                unit_add_to_dbus_queue(u);
        if (FLAGS_SET(notify_flags, NOTIFY_DEPENDENCY_UPDATE_TO))
                unit_add_to_dbus_queue(other);

        return notify_flags != 0;
}

int unit_add_two_dependencies(Unit *u, UnitDependency d, UnitDependency e, Unit *other, bool add_reference, UnitDependencyMask mask) {
        int r = 0, s = 0;

        assert(u);
        assert(d >= 0 || e >= 0);

        if (d >= 0) {
                r = unit_add_dependency(u, d, other, add_reference, mask);
                if (r < 0)
                        return r;
        }

        if (e >= 0) {
                s = unit_add_dependency(u, e, other, add_reference, mask);
                if (s < 0)
                        return s;
        }

        return r > 0 || s > 0;
}

static int resolve_template(Unit *u, const char *name, char **buf, const char **ret) {
        int r;

        assert(u);
        assert(name);
        assert(buf);
        assert(ret);

        if (!unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                *buf = NULL;
                *ret = name;
                return 0;
        }

        if (u->instance)
                r = unit_name_replace_instance(name, u->instance, buf);
        else {
                _cleanup_free_ char *i = NULL;

                r = unit_name_to_prefix(u->id, &i);
                if (r < 0)
                        return r;

                r = unit_name_replace_instance(name, i, buf);
        }
        if (r < 0)
                return r;

        *ret = *buf;
        return 0;
}

int unit_add_dependency_by_name(Unit *u, UnitDependency d, const char *name, bool add_reference, UnitDependencyMask mask) {
        _cleanup_free_ char *buf = NULL;
        Unit *other;
        int r;

        assert(u);
        assert(name);

        r = resolve_template(u, name, &buf, &name);
        if (r < 0)
                return r;

        if (u->manager && FLAGS_SET(u->manager->test_run_flags, MANAGER_TEST_RUN_IGNORE_DEPENDENCIES))
                return 0;

        r = manager_load_unit(u->manager, name, NULL, NULL, &other);
        if (r < 0)
                return r;

        return unit_add_dependency(u, d, other, add_reference, mask);
}

int unit_add_two_dependencies_by_name(Unit *u, UnitDependency d, UnitDependency e, const char *name, bool add_reference, UnitDependencyMask mask) {
        _cleanup_free_ char *buf = NULL;
        Unit *other;
        int r;

        assert(u);
        assert(name);

        r = resolve_template(u, name, &buf, &name);
        if (r < 0)
                return r;

        if (u->manager && FLAGS_SET(u->manager->test_run_flags, MANAGER_TEST_RUN_IGNORE_DEPENDENCIES))
                return 0;

        r = manager_load_unit(u->manager, name, NULL, NULL, &other);
        if (r < 0)
                return r;

        return unit_add_two_dependencies(u, d, e, other, add_reference, mask);
}

int setenv_unit_path(const char *p) {
        assert(p);

        /* This is mostly for debug purposes */
        return RET_NERRNO(setenv("SYSTEMD_UNIT_PATH", p, /* overwrite= */ true));
}

char* unit_dbus_path(Unit *u) {
        assert(u);

        if (!u->id)
                return NULL;

        return unit_dbus_path_from_name(u->id);
}

char* unit_dbus_path_invocation_id(Unit *u) {
        assert(u);

        if (sd_id128_is_null(u->invocation_id))
                return NULL;

        return unit_dbus_path_from_name(u->invocation_id_string);
}

int unit_set_invocation_id(Unit *u, sd_id128_t id) {
        int r;

        assert(u);

        /* Set the invocation ID for this unit. If we cannot, this will not roll back, but reset the whole thing. */

        if (sd_id128_equal(u->invocation_id, id))
                return 0;

        if (!sd_id128_is_null(u->invocation_id))
                (void) hashmap_remove_value(u->manager->units_by_invocation_id, &u->invocation_id, u);

        if (sd_id128_is_null(id)) {
                r = 0;
                goto reset;
        }

        r = hashmap_ensure_allocated(&u->manager->units_by_invocation_id, &id128_hash_ops);
        if (r < 0)
                goto reset;

        u->invocation_id = id;
        sd_id128_to_string(id, u->invocation_id_string);

        r = hashmap_put(u->manager->units_by_invocation_id, &u->invocation_id, u);
        if (r < 0)
                goto reset;

        return 0;

reset:
        u->invocation_id = SD_ID128_NULL;
        u->invocation_id_string[0] = 0;
        return r;
}

int unit_set_slice(Unit *u, Unit *slice) {
        int r;

        assert(u);
        assert(slice);

        /* Sets the unit slice if it has not been set before. Is extra careful, to only allow this for units
         * that actually have a cgroup context. Also, we don't allow to set this for slices (since the parent
         * slice is derived from the name). Make sure the unit we set is actually a slice. */

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return -EOPNOTSUPP;

        if (u->type == UNIT_SLICE)
                return -EINVAL;

        if (unit_active_state(u) != UNIT_INACTIVE)
                return -EBUSY;

        if (slice->type != UNIT_SLICE)
                return -EINVAL;

        if (unit_has_name(u, SPECIAL_INIT_SCOPE) &&
            !unit_has_name(slice, SPECIAL_ROOT_SLICE))
                return -EPERM;

        if (UNIT_GET_SLICE(u) == slice)
                return 0;

        /* Disallow slice changes if @u is already bound to cgroups */
        if (UNIT_GET_SLICE(u)) {
                CGroupRuntime *crt = unit_get_cgroup_runtime(u);
                if (crt && crt->cgroup_path)
                        return -EBUSY;
        }

        /* Remove any slices assigned prior; we should only have one UNIT_IN_SLICE dependency */
        if (UNIT_GET_SLICE(u))
                unit_remove_dependencies(u, UNIT_DEPENDENCY_SLICE_PROPERTY);

        r = unit_add_dependency(u, UNIT_IN_SLICE, slice, true, UNIT_DEPENDENCY_SLICE_PROPERTY);
        if (r < 0)
                return r;

        return 1;
}

int unit_set_default_slice(Unit *u) {
        const char *slice_name;
        Unit *slice;
        int r;

        assert(u);

        if (u->manager && FLAGS_SET(u->manager->test_run_flags, MANAGER_TEST_RUN_IGNORE_DEPENDENCIES))
                return 0;

        if (UNIT_GET_SLICE(u))
                return 0;

        if (u->instance) {
                _cleanup_free_ char *prefix = NULL, *escaped = NULL;

                /* Implicitly place all instantiated units in their
                 * own per-template slice */

                r = unit_name_to_prefix(u->id, &prefix);
                if (r < 0)
                        return r;

                /* The prefix is already escaped, but it might include
                 * "-" which has a special meaning for slice units,
                 * hence escape it here extra. */
                escaped = unit_name_escape(prefix);
                if (!escaped)
                        return -ENOMEM;

                if (MANAGER_IS_SYSTEM(u->manager))
                        slice_name = strjoina("system-", escaped, ".slice");
                else
                        slice_name = strjoina("app-", escaped, ".slice");

        } else if (unit_is_extrinsic(u))
                /* Keep all extrinsic units (e.g. perpetual units and swap and mount units in user mode) in
                 * the root slice. They don't really belong in one of the subslices. */
                slice_name = SPECIAL_ROOT_SLICE;

        else if (MANAGER_IS_SYSTEM(u->manager))
                slice_name = SPECIAL_SYSTEM_SLICE;
        else
                slice_name = SPECIAL_APP_SLICE;

        r = manager_load_unit(u->manager, slice_name, NULL, NULL, &slice);
        if (r < 0)
                return r;

        return unit_set_slice(u, slice);
}

const char* unit_slice_name(Unit *u) {
        Unit *slice;
        assert(u);

        slice = UNIT_GET_SLICE(u);
        if (!slice)
                return NULL;

        return slice->id;
}

int unit_load_related_unit(Unit *u, const char *type, Unit **_found) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(u);
        assert(type);
        assert(_found);

        r = unit_name_change_suffix(u->id, type, &t);
        if (r < 0)
                return r;
        if (unit_has_name(u, t))
                return -EINVAL;

        r = manager_load_unit(u->manager, t, NULL, NULL, _found);
        assert(r < 0 || *_found != u);
        return r;
}

static int signal_name_owner_changed_install_handler(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int r;

        e = sd_bus_message_get_error(message);
        if (!e) {
                log_unit_trace(u, "Successfully installed NameOwnerChanged signal match.");
                return 0;
        }

        r = sd_bus_error_get_errno(e);
        log_unit_error_errno(u, r,
                             "Unexpected error response on installing NameOwnerChanged signal match: %s",
                             bus_error_message(e, r));

        /* If we failed to install NameOwnerChanged signal, also unref the bus slot of GetNameOwner(). */
        u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
        u->get_name_owner_slot = sd_bus_slot_unref(u->get_name_owner_slot);

        if (UNIT_VTABLE(u)->bus_name_owner_change)
                UNIT_VTABLE(u)->bus_name_owner_change(u, NULL);

        return 0;
}

static int signal_name_owner_changed(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        const char *new_owner;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = sd_bus_message_read(message, "sss", NULL, NULL, &new_owner);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (UNIT_VTABLE(u)->bus_name_owner_change)
                UNIT_VTABLE(u)->bus_name_owner_change(u, empty_to_null(new_owner));

        return 0;
}

static int get_name_owner_handler(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        const sd_bus_error *e;
        const char *new_owner;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        u->get_name_owner_slot = sd_bus_slot_unref(u->get_name_owner_slot);

        e = sd_bus_message_get_error(message);
        if (e) {
                if (!sd_bus_error_has_name(e, SD_BUS_ERROR_NAME_HAS_NO_OWNER)) {
                        r = sd_bus_error_get_errno(e);
                        log_unit_error_errno(u, r,
                                             "Unexpected error response from GetNameOwner(): %s",
                                             bus_error_message(e, r));
                }

                new_owner = NULL;
        } else {
                r = sd_bus_message_read(message, "s", &new_owner);
                if (r < 0)
                        return bus_log_parse_error(r);

                assert(!isempty(new_owner));
        }

        if (UNIT_VTABLE(u)->bus_name_owner_change)
                UNIT_VTABLE(u)->bus_name_owner_change(u, new_owner);

        return 0;
}

int unit_install_bus_match(Unit *u, sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const char *match;
        usec_t timeout_usec = 0;
        int r;

        assert(u);
        assert(bus);
        assert(name);

        if (u->match_bus_slot || u->get_name_owner_slot)
                return -EBUSY;

        /* NameOwnerChanged and GetNameOwner is used to detect when a service finished starting up. The dbus
         * call timeout shouldn't be earlier than that. If we couldn't get the start timeout, use the default
         * value defined above. */
        if (UNIT_VTABLE(u)->get_timeout_start_usec)
                timeout_usec = UNIT_VTABLE(u)->get_timeout_start_usec(u);

        match = strjoina("type='signal',"
                         "sender='org.freedesktop.DBus',"
                         "path='/org/freedesktop/DBus',"
                         "interface='org.freedesktop.DBus',"
                         "member='NameOwnerChanged',"
                         "arg0='", name, "'");

        r = bus_add_match_full(
                        bus,
                        &u->match_bus_slot,
                        /* asynchronous= */ true,
                        match,
                        signal_name_owner_changed,
                        signal_name_owner_changed_install_handler,
                        u,
                        timeout_usec);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "GetNameOwner");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", name);
        if (r < 0)
                return r;

        r = sd_bus_call_async(
                        bus,
                        &u->get_name_owner_slot,
                        m,
                        get_name_owner_handler,
                        u,
                        timeout_usec);
        if (r < 0) {
                u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
                return r;
        }

        log_unit_debug(u, "Watching D-Bus name '%s'.", name);
        return 0;
}

int unit_watch_bus_name(Unit *u, const char *name) {
        int r;

        assert(u);
        assert(name);

        /* Watch a specific name on the bus. We only support one unit
         * watching each name for now. */

        if (u->manager->api_bus) {
                /* If the bus is already available, install the match directly.
                 * Otherwise, just put the name in the list. bus_setup_api() will take care later. */
                r = unit_install_bus_match(u, u->manager->api_bus, name);
                if (r < 0)
                        return log_warning_errno(r, "Failed to subscribe to NameOwnerChanged signal for '%s': %m", name);
        }

        r = hashmap_put(u->manager->watch_bus, name, u);
        if (r < 0) {
                u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
                u->get_name_owner_slot = sd_bus_slot_unref(u->get_name_owner_slot);
                return log_warning_errno(r, "Failed to put bus name to hashmap: %m");
        }

        return 0;
}

void unit_unwatch_bus_name(Unit *u, const char *name) {
        assert(u);
        assert(name);

        (void) hashmap_remove_value(u->manager->watch_bus, name, u);
        u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
        u->get_name_owner_slot = sd_bus_slot_unref(u->get_name_owner_slot);
}

int unit_add_node_dependency(Unit *u, const char *what, UnitDependency dep, UnitDependencyMask mask) {
        _cleanup_free_ char *e = NULL;
        Unit *device;
        int r;

        assert(u);

        /* Adds in links to the device node that this unit is based on */
        if (isempty(what))
                return 0;

        if (!is_device_path(what))
                return 0;

        /* When device units aren't supported (such as in a container), don't create dependencies on them. */
        if (!unit_type_supported(UNIT_DEVICE))
                return 0;

        r = unit_name_from_path(what, ".device", &e);
        if (r < 0)
                return r;

        r = manager_load_unit(u->manager, e, NULL, NULL, &device);
        if (r < 0)
                return r;

        if (dep == UNIT_REQUIRES && device_shall_be_bound_by(device, u))
                dep = UNIT_BINDS_TO;

        return unit_add_two_dependencies(u, UNIT_AFTER,
                                         MANAGER_IS_SYSTEM(u->manager) ? dep : UNIT_WANTS,
                                         device, true, mask);
}

int unit_add_blockdev_dependency(Unit *u, const char *what, UnitDependencyMask mask) {
        _cleanup_free_ char *escaped = NULL, *target = NULL;
        int r;

        assert(u);

        if (isempty(what))
                return 0;

        if (!path_startswith(what, "/dev/"))
                return 0;

        /* If we don't support devices, then also don't bother with blockdev@.target */
        if (!unit_type_supported(UNIT_DEVICE))
                return 0;

        r = unit_name_path_escape(what, &escaped);
        if (r < 0)
                return r;

        r = unit_name_build("blockdev", escaped, ".target", &target);
        if (r < 0)
                return r;

        return unit_add_dependency_by_name(u, UNIT_AFTER, target, true, mask);
}

int unit_coldplug(Unit *u) {
        int r = 0;

        assert(u);

        /* Make sure we don't enter a loop, when coldplugging recursively. */
        if (u->coldplugged)
                return 0;

        u->coldplugged = true;

        STRV_FOREACH(i, u->deserialized_refs)
                RET_GATHER(r, bus_unit_track_add_name(u, *i));

        u->deserialized_refs = strv_free(u->deserialized_refs);

        if (UNIT_VTABLE(u)->coldplug)
                RET_GATHER(r, UNIT_VTABLE(u)->coldplug(u));

        if (u->job)
                RET_GATHER(r, job_coldplug(u->job));
        if (u->nop_job)
                RET_GATHER(r, job_coldplug(u->nop_job));

        return r;
}

void unit_catchup(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->catchup)
                UNIT_VTABLE(u)->catchup(u);

        unit_cgroup_catchup(u);
}

static bool fragment_mtime_newer(const char *path, usec_t mtime, bool path_masked) {
        struct stat st;

        if (!path)
                return false;

        /* If the source is some virtual kernel file system, then we assume we watch it anyway, and hence pretend we
         * are never out-of-date. */
        if (PATH_STARTSWITH_SET(path, "/proc", "/sys"))
                return false;

        if (stat(path, &st) < 0)
                /* What, cannot access this anymore? */
                return true;

        if (path_masked)
                /* For masked files check if they are still so */
                return !null_or_empty(&st);
        else
                /* For non-empty files check the mtime */
                return timespec_load(&st.st_mtim) > mtime;

        return false;
}

bool unit_need_daemon_reload(Unit *u) {
        assert(u);
        assert(u->manager);

        if (u->manager->unit_file_state_outdated)
                return true;

        /* For unit files, we allow masking… */
        if (fragment_mtime_newer(u->fragment_path, u->fragment_mtime,
                                 u->load_state == UNIT_MASKED))
                return true;

        /* Source paths should not be masked… */
        if (fragment_mtime_newer(u->source_path, u->source_mtime, false))
                return true;

        if (u->load_state == UNIT_LOADED) {
                _cleanup_strv_free_ char **dropins = NULL;

                (void) unit_find_dropin_paths(u, /* use_unit_path_cache= */ false, &dropins);

                if (!strv_equal(u->dropin_paths, dropins))
                        return true;

                /* … any drop-ins that are masked are simply omitted from the list. */
                STRV_FOREACH(path, u->dropin_paths)
                        if (fragment_mtime_newer(*path, u->dropin_mtime, false))
                                return true;
        }

        return false;
}

void unit_reset_failed(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->reset_failed)
                UNIT_VTABLE(u)->reset_failed(u);

        ratelimit_reset(&u->start_ratelimit);
        u->start_limit_hit = false;

        (void) unit_set_debug_invocation(u, /* enable= */ false);
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

        return unit_has_job_type(u, JOB_STOP);
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

        if (u->job && IN_SET(u->job->type, JOB_START, JOB_RESTART))
                return true;

        return false;
}

bool unit_will_restart_default(Unit *u) {
        assert(u);

        return unit_has_job_type(u, JOB_START);
}

bool unit_will_restart(Unit *u) {
        assert(u);

        if (!UNIT_VTABLE(u)->will_restart)
                return false;

        return UNIT_VTABLE(u)->will_restart(u);
}

void unit_notify_cgroup_oom(Unit *u, bool managed_oom) {
        assert(u);

        if (UNIT_VTABLE(u)->notify_cgroup_oom)
                UNIT_VTABLE(u)->notify_cgroup_oom(u, managed_oom);
}

static int unit_pid_set(Unit *u, Set **pid_set) {
        int r;

        assert(u);
        assert(pid_set);

        set_clear(*pid_set); /* This updates input. */

        /* Exclude the main/control pids from being killed via the cgroup */

        PidRef *pid;
        FOREACH_ARGUMENT(pid, unit_main_pid(u), unit_control_pid(u))
                if (pidref_is_set(pid)) {
                        r = set_ensure_put(pid_set, NULL, PID_TO_PTR(pid->pid));
                        if (r < 0)
                                return r;
                }

        return 0;
}

static int kill_common_log(const PidRef *pid, int signo, void *userdata) {
        _cleanup_free_ char *comm = NULL;
        Unit *u = ASSERT_PTR(userdata);

        (void) pidref_get_comm(pid, &comm);

        log_unit_info(u, "Sending signal SIG%s to process " PID_FMT " (%s) on client request.",
                      signal_to_string(signo), pid->pid, strna(comm));

        return 1;
}

static int kill_or_sigqueue(PidRef *pidref, int signo, int code, int value) {
        assert(pidref_is_set(pidref));
        assert(SIGNAL_VALID(signo));

        switch (code) {

        case SI_USER:
                log_debug("Killing " PID_FMT " with signal SIG%s.", pidref->pid, signal_to_string(signo));
                return pidref_kill(pidref, signo);

        case SI_QUEUE:
                log_debug("Enqueuing value %i to " PID_FMT " on signal SIG%s.", value, pidref->pid, signal_to_string(signo));
                return pidref_sigqueue(pidref, signo, value);

        default:
                assert_not_reached();
        }
}

static int unit_kill_one(
                Unit *u,
                PidRef *pidref,
                const char *type,
                int signo,
                int code,
                int value,
                sd_bus_error *ret_error) {

        int r;

        assert(u);
        assert(type);

        if (!pidref_is_set(pidref))
                return 0;

        _cleanup_free_ char *comm = NULL;
        (void) pidref_get_comm(pidref, &comm);

        r = kill_or_sigqueue(pidref, signo, code, value);
        if (r == -ESRCH)
                return 0;
        if (r < 0) {
                /* Report this failure both to the logs and to the client */
                if (ret_error)
                        sd_bus_error_set_errnof(
                                        ret_error, r,
                                        "Failed to send signal SIG%s to %s process " PID_FMT " (%s): %m",
                                        signal_to_string(signo), type, pidref->pid, strna(comm));

                return log_unit_warning_errno(
                                u, r,
                                "Failed to send signal SIG%s to %s process " PID_FMT " (%s) on client request: %m",
                                signal_to_string(signo), type, pidref->pid, strna(comm));
        }

        log_unit_info(u, "Sent signal SIG%s to %s process " PID_FMT " (%s) on client request.",
                      signal_to_string(signo), type, pidref->pid, strna(comm));
        return 1; /* killed */
}

int unit_kill(
                Unit *u,
                KillWhom whom,
                const char *subgroup,
                int signo,
                int code,
                int value,
                sd_bus_error *ret_error) {

        PidRef *main_pid, *control_pid;
        bool killed = false;
        int ret = 0, r;

        /* This is the common implementation for explicit user-requested killing of unit processes, shared by
         * various unit types. Do not confuse with unit_kill_context(), which is what we use when we want to
         * stop a service ourselves. */

        assert(u);
        assert(whom >= 0);
        assert(whom < _KILL_WHOM_MAX);
        assert(SIGNAL_VALID(signo));
        assert(IN_SET(code, SI_USER, SI_QUEUE));

        if (subgroup) {
                if (!IN_SET(whom, KILL_CGROUP, KILL_CGROUP_FAIL))
                        return sd_bus_error_set(ret_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                                "Killing by subgroup is only supported for 'cgroup' or 'cgroup-kill' modes.");

                if (!unit_cgroup_delegate(u))
                        return sd_bus_error_set(ret_error, SD_BUS_ERROR_NOT_SUPPORTED,
                                                "Killing by subgroup is only available for units with control group delegation enabled.");
        }

        main_pid = unit_main_pid(u);
        control_pid = unit_control_pid(u);

        if (!UNIT_HAS_CGROUP_CONTEXT(u) && !main_pid && !control_pid)
                return sd_bus_error_set(ret_error, SD_BUS_ERROR_NOT_SUPPORTED, "Unit type does not support process killing.");

        if (IN_SET(whom, KILL_MAIN, KILL_MAIN_FAIL)) {
                if (!main_pid)
                        return sd_bus_error_setf(ret_error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no main processes", unit_type_to_string(u->type));
                if (!pidref_is_set(main_pid))
                        return sd_bus_error_set_const(ret_error, BUS_ERROR_NO_SUCH_PROCESS, "No main process to kill");
        }

        if (IN_SET(whom, KILL_CONTROL, KILL_CONTROL_FAIL)) {
                if (!control_pid)
                        return sd_bus_error_setf(ret_error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no control processes", unit_type_to_string(u->type));
                if (!pidref_is_set(control_pid))
                        return sd_bus_error_set_const(ret_error, BUS_ERROR_NO_SUCH_PROCESS, "No control process to kill");
        }

        if (IN_SET(whom, KILL_CONTROL, KILL_CONTROL_FAIL, KILL_ALL, KILL_ALL_FAIL)) {
                r = unit_kill_one(u, control_pid, "control", signo, code, value, ret_error);
                RET_GATHER(ret, r);
                killed = killed || r > 0;
        }

        if (IN_SET(whom, KILL_MAIN, KILL_MAIN_FAIL, KILL_ALL, KILL_ALL_FAIL)) {
                r = unit_kill_one(u, main_pid, "main", signo, code, value, ret >= 0 ? ret_error : NULL);
                RET_GATHER(ret, r);
                killed = killed || r > 0;
        }

        /* Note: if we shall enqueue rather than kill we won't do this via the cgroup mechanism, since it
         * doesn't really make much sense (and given that enqueued values are a relatively expensive
         * resource, and we shouldn't allow us to be subjects for such allocation sprees) */
        if (IN_SET(whom, KILL_ALL, KILL_ALL_FAIL, KILL_CGROUP, KILL_CGROUP_FAIL) && code == SI_USER) {
                CGroupRuntime *crt = unit_get_cgroup_runtime(u);
                if (crt && crt->cgroup_path) {
                        _cleanup_set_free_ Set *pid_set = NULL;
                        _cleanup_free_ char *joined = NULL;
                        const char *p;

                        if (empty_or_root(subgroup))
                                p = crt->cgroup_path;
                        else {
                                joined = path_join(crt->cgroup_path, subgroup);
                                if (!joined)
                                        return -ENOMEM;

                                p = joined;
                        }

                        if (signo == SIGKILL) {
                                r = cg_kill_kernel_sigkill(p);
                                if (r >= 0) {
                                        killed = true;
                                        log_unit_info(u, "Killed unit cgroup '%s' with SIGKILL on client request.", p);
                                        goto finish;
                                }
                                if (r != -EOPNOTSUPP) {
                                        if (ret >= 0)
                                                sd_bus_error_set_errnof(ret_error, r,
                                                                        "Failed to kill unit cgroup: %m");
                                        RET_GATHER(ret, log_unit_warning_errno(u, r, "Failed to kill unit cgroup '%s': %m", p));
                                        goto finish;
                                }
                                /* Fall back to manual enumeration */
                        } else if (IN_SET(whom, KILL_ALL, KILL_ALL_FAIL)) {
                                /* Exclude the main/control pids from being killed via the cgroup if not
                                 * SIGKILL */
                                r = unit_pid_set(u, &pid_set);
                                if (r < 0)
                                        return log_oom();
                        }

                        r = cg_kill_recursive(p, signo, /* flags= */ 0, pid_set, kill_common_log, u);
                        if (r < 0 && !IN_SET(r, -ESRCH, -ENOENT)) {
                                if (ret >= 0)
                                        sd_bus_error_set_errnof(
                                                        ret_error, r,
                                                        "Failed to send signal SIG%s to processes in unit cgroup '%s': %m",
                                                        signal_to_string(signo), p);

                                RET_GATHER(ret, log_unit_warning_errno(
                                                        u, r,
                                                        "Failed to send signal SIG%s to processes in unit cgroup '%s' on client request: %m",
                                                        signal_to_string(signo), p));
                        }
                        killed = killed || r > 0;
                }
        }

finish:
        /* If the "fail" versions of the operation are requested, then complain if the set of processes we killed is empty */
        if (ret >= 0 && !killed && IN_SET(whom, KILL_ALL_FAIL, KILL_CONTROL_FAIL, KILL_MAIN_FAIL, KILL_CGROUP_FAIL))
                return sd_bus_error_set_const(ret_error, BUS_ERROR_NO_SUCH_PROCESS, "No matching processes to kill");

        return ret;
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
        int r;

        assert(u);

        if (u->unit_file_state >= 0 || !u->fragment_path)
                return u->unit_file_state;

        /* If we know this is a transient unit no need to ask the unit file state for details. Let's bypass
         * the more expensive on-disk check. */
        if (u->transient)
                return (u->unit_file_state = UNIT_FILE_TRANSIENT);

        r = unit_file_get_state(
                        u->manager->runtime_scope,
                        /* root_dir= */ NULL,
                        u->id,
                        &u->unit_file_state);
        if (r < 0)
                u->unit_file_state = UNIT_FILE_BAD;

        return u->unit_file_state;
}

PresetAction unit_get_unit_file_preset(Unit *u) {
        int r;

        assert(u);

        if (u->unit_file_preset >= 0)
                return u->unit_file_preset;

        /* If this is a transient or perpetual unit file it doesn't make much sense to ask the preset
         * database about this, because enabling/disabling makes no sense for either. Hence don't. */
        if (!u->fragment_path || u->transient || u->perpetual)
                return (u->unit_file_preset = -ENOEXEC);

        _cleanup_free_ char *bn = NULL;
        r = path_extract_filename(u->fragment_path, &bn);
        if (r < 0)
                return (u->unit_file_preset = r);
        if (r == O_DIRECTORY)
                return (u->unit_file_preset = -EISDIR);

        return (u->unit_file_preset = unit_file_query_preset(
                                u->manager->runtime_scope,
                                /* root_dir= */ NULL,
                                bn,
                                /* cached= */ NULL));
}

Unit* unit_ref_set(UnitRef *ref, Unit *source, Unit *target) {
        assert(ref);
        assert(source);
        assert(target);

        if (ref->target)
                unit_ref_unset(ref);

        ref->source = source;
        ref->target = target;
        LIST_PREPEND(refs_by_target, target->refs_by_target, ref);
        return target;
}

void unit_ref_unset(UnitRef *ref) {
        assert(ref);

        if (!ref->target)
                return;

        /* We are about to drop a reference to the unit, make sure the garbage collection has a look at it as it might
         * be unreferenced now. */
        unit_add_to_gc_queue(ref->target);

        LIST_REMOVE(refs_by_target, ref->target->refs_by_target, ref);
        ref->source = ref->target = NULL;
}

static int user_from_unit_name(Unit *u, char **ret) {

        static const uint8_t hash_key[] = {
                0x58, 0x1a, 0xaf, 0xe6, 0x28, 0x58, 0x4e, 0x96,
                0xb4, 0x4e, 0xf5, 0x3b, 0x8c, 0x92, 0x07, 0xec
        };

        _cleanup_free_ char *n = NULL;
        int r;

        r = unit_name_to_prefix(u->id, &n);
        if (r < 0)
                return r;

        if (valid_user_group_name(n, 0)) {
                *ret = TAKE_PTR(n);
                return 0;
        }

        /* If we can't use the unit name as a user name, then let's hash it and use that */
        if (asprintf(ret, "_du%016" PRIx64, siphash24(n, strlen(n), hash_key)) < 0)
                return -ENOMEM;

        return 0;
}

static int unit_verify_contexts(const Unit *u) {
        assert(u);

        const ExecContext *ec = unit_get_exec_context(u);
        if (!ec)
                return 0;

        if (MANAGER_IS_USER(u->manager) && ec->dynamic_user)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "DynamicUser= enabled for user unit, which is not supported. Refusing.");

        if (ec->dynamic_user && ec->working_directory_home)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "WorkingDirectory=~ is not allowed under DynamicUser=yes. Refusing.");

        if (ec->working_directory && path_below_api_vfs(ec->working_directory) &&
            exec_needs_mount_namespace(ec, /* params= */ NULL, /* runtime= */ NULL))
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "WorkingDirectory= may not be below /proc/, /sys/ or /dev/ when using mount namespacing. Refusing.");

        if (exec_needs_pid_namespace(ec, /* params= */ NULL) && !UNIT_VTABLE(u)->notify_pidref)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "PrivatePIDs= setting is only supported for service units. Refusing.");

        if ((ec->user || ec->dynamic_user || ec->group || ec->pam_name) && ec->private_users == PRIVATE_USERS_MANAGED)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "PrivateUsers=managed may not be used in combination with User=/DynamicUser=/Group=/PAMName=, refusing.");

        if (ec->user_namespace_path && ec->private_users != PRIVATE_USERS_NO)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "PrivateUsers= may not be used with custom UserNamespacePath=, refusing.");

        const KillContext *kc = unit_get_kill_context(u);

        if (ec->pam_name && kc && !IN_SET(kc->kill_mode, KILL_CONTROL_GROUP, KILL_MIXED))
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "Unit has PAM enabled. Kill mode must be set to 'control-group' or 'mixed'. Refusing.");

        return 0;
}

static PrivateTmp unit_get_private_var_tmp(const Unit *u, const ExecContext *c) {
        assert(u);
        assert(c);
        assert(c->private_tmp >= 0 && c->private_tmp < _PRIVATE_TMP_MAX);

        /* Disable disconnected private tmpfs on /var/tmp/ when DefaultDependencies=no and
         * RootImage=/RootDirectory= are not set, as /var/ may be a separated partition.
         * See issue #37258. */

        /* PrivateTmp=yes/no also enables/disables private tmpfs on /var/tmp/. */
        if (c->private_tmp != PRIVATE_TMP_DISCONNECTED)
                return c->private_tmp;

        /* When DefaultDependencies=yes, disconnected tmpfs is also enabled on /var/tmp/, and an explicit
         * dependency to the mount on /var/ will be added in unit_add_exec_dependencies(). */
        if (u->default_dependencies)
                return PRIVATE_TMP_DISCONNECTED;

        /* When RootImage=/RootDirectory= is enabled, /var/ should be prepared by the image or directory,
         * hence we can mount a disconnected tmpfs on /var/tmp/. */
        if (exec_context_with_rootfs(c))
                return PRIVATE_TMP_DISCONNECTED;

        /* Even if DefaultDependencies=no, enable disconnected tmpfs when
         * RequiresMountsFor=/WantsMountsFor=/var/ is explicitly set. */
        for (UnitMountDependencyType t = 0; t < _UNIT_MOUNT_DEPENDENCY_TYPE_MAX; t++)
                if (hashmap_contains(u->mounts_for[t], "/var/"))
                        return PRIVATE_TMP_DISCONNECTED;

        /* Check the same but for After= with Requires=/Requisite=/Wants= or friends. */
        Unit *m = manager_get_unit(u->manager, "var.mount");
        if (!m)
                return PRIVATE_TMP_NO;

        if (!unit_has_dependency(u, UNIT_ATOM_AFTER, m))
                return PRIVATE_TMP_NO;

        if (unit_has_dependency(u, UNIT_ATOM_PULL_IN_START, m) ||
            unit_has_dependency(u, UNIT_ATOM_PULL_IN_VERIFY, m) ||
            unit_has_dependency(u, UNIT_ATOM_PULL_IN_START_IGNORED, m))
                return PRIVATE_TMP_DISCONNECTED;

        return PRIVATE_TMP_NO;
}

int unit_patch_contexts(Unit *u) {
        CGroupContext *cc;
        ExecContext *ec;
        int r;

        assert(u);

        /* Patch in the manager defaults into the exec and cgroup
         * contexts, _after_ the rest of the settings have been
         * initialized */

        ec = unit_get_exec_context(u);
        if (ec) {
                /* This only copies in the ones that need memory */
                for (unsigned i = 0; i < _RLIMIT_MAX; i++)
                        if (u->manager->defaults.rlimit[i] && !ec->rlimit[i]) {
                                ec->rlimit[i] = newdup(struct rlimit, u->manager->defaults.rlimit[i], 1);
                                if (!ec->rlimit[i])
                                        return -ENOMEM;
                        }

                if (MANAGER_IS_USER(u->manager) && !ec->working_directory) {
                        r = get_home_dir(&ec->working_directory);
                        if (r < 0)
                                return r;

                        if (!ec->working_directory_home)
                                /* If home directory is implied by us, allow it to be missing. */
                                ec->working_directory_missing_ok = true;
                }

                if (ec->private_devices)
                        ec->capability_bounding_set &= ~((UINT64_C(1) << CAP_MKNOD) | (UINT64_C(1) << CAP_SYS_RAWIO));

                if (ec->protect_kernel_modules)
                        ec->capability_bounding_set &= ~(UINT64_C(1) << CAP_SYS_MODULE);

                if (ec->protect_kernel_logs)
                        ec->capability_bounding_set &= ~(UINT64_C(1) << CAP_SYSLOG);

                if (ec->protect_clock)
                        ec->capability_bounding_set &= ~((UINT64_C(1) << CAP_SYS_TIME) | (UINT64_C(1) << CAP_WAKE_ALARM));

                if (ec->dynamic_user) {
                        if (!ec->user) {
                                r = user_from_unit_name(u, &ec->user);
                                if (r < 0)
                                        return r;
                        }

                        if (!ec->group) {
                                ec->group = strdup(ec->user);
                                if (!ec->group)
                                        return -ENOMEM;
                        }

                        /* If the dynamic user option is on, let's make sure that the unit can't leave its
                         * UID/GID around in the file system or on IPC objects. Hence enforce a strict
                         * sandbox. */

                        /* With DynamicUser= we want private directories, so if the user hasn't manually
                         * selected PrivateTmp=, enable it, but to a fully private (disconnected) tmpfs
                         * instance. */
                        if (ec->private_tmp == PRIVATE_TMP_NO)
                                ec->private_tmp = PRIVATE_TMP_DISCONNECTED;
                        ec->remove_ipc = true;
                        ec->protect_system = PROTECT_SYSTEM_STRICT;
                        if (ec->protect_home == PROTECT_HOME_NO)
                                ec->protect_home = PROTECT_HOME_READ_ONLY;

                        /* Make sure this service can neither benefit from SUID/SGID binaries nor create
                         * them. */
                        ec->no_new_privileges = true;
                        ec->restrict_suid_sgid = true;
                }

                ec->private_var_tmp = unit_get_private_var_tmp(u, ec);

                FOREACH_ARRAY(d, ec->directories, _EXEC_DIRECTORY_TYPE_MAX)
                        exec_directory_sort(d);
        }

        cc = unit_get_cgroup_context(u);
        if (cc && ec) {

                if (ec->private_devices &&
                    cc->device_policy == CGROUP_DEVICE_POLICY_AUTO)
                        cc->device_policy = CGROUP_DEVICE_POLICY_CLOSED;

                /* Only add these if needed, as they imply that everything else is blocked. */
                if (cgroup_context_has_device_policy(cc)) {
                        if (ec->root_image || ec->mount_images || ec->root_mstack) {

                                /* When RootImage= or MountImages= is specified, the following devices are
                                 * touched. For RootMStack= there's the possibility the are touched. */
                                FOREACH_STRING(p, "/dev/loop-control", "/dev/mapper/control") {
                                        r = cgroup_context_add_device_allow(cc, p, CGROUP_DEVICE_READ|CGROUP_DEVICE_WRITE);
                                        if (r < 0)
                                                return r;
                                }
                                FOREACH_STRING(p, "block-loop", "block-blkext", "block-device-mapper") {
                                        r = cgroup_context_add_device_allow(cc, p, CGROUP_DEVICE_READ|CGROUP_DEVICE_WRITE|CGROUP_DEVICE_MKNOD);
                                        if (r < 0)
                                                return r;
                                }

                                /* Make sure "block-loop" can be resolved, i.e. make sure "loop" shows up in /proc/devices.
                                * Same for mapper and verity. */
                                FOREACH_STRING(p, "modprobe@loop.service", "modprobe@dm_mod.service", "modprobe@dm_verity.service") {
                                        r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_WANTS, p, true, UNIT_DEPENDENCY_FILE);
                                        if (r < 0)
                                                return r;
                                }
                        }

                        if (ec->protect_clock) {
                                r = cgroup_context_add_device_allow(cc, "char-rtc", CGROUP_DEVICE_READ);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return unit_verify_contexts(u);
}

ExecContext *unit_get_exec_context(const Unit *u) {
        size_t offset;
        assert(u);

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->exec_context_offset;
        if (offset <= 0)
                return NULL;

        return (ExecContext*) ((uint8_t*) u + offset);
}

KillContext *unit_get_kill_context(const Unit *u) {
        size_t offset;
        assert(u);

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->kill_context_offset;
        if (offset <= 0)
                return NULL;

        return (KillContext*) ((uint8_t*) u + offset);
}

CGroupContext *unit_get_cgroup_context(const Unit *u) {
        size_t offset;

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->cgroup_context_offset;
        if (offset <= 0)
                return NULL;

        return (CGroupContext*) ((uint8_t*) u + offset);
}

ExecRuntime *unit_get_exec_runtime(const Unit *u) {
        size_t offset;

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->exec_runtime_offset;
        if (offset <= 0)
                return NULL;

        return *(ExecRuntime**) ((uint8_t*) u + offset);
}

CGroupRuntime *unit_get_cgroup_runtime(const Unit *u) {
        size_t offset;

        if (u->type < 0)
                return NULL;

        offset = UNIT_VTABLE(u)->cgroup_runtime_offset;
        if (offset <= 0)
                return NULL;

        return *(CGroupRuntime**) ((uint8_t*) u + offset);
}

static const char* unit_drop_in_dir(Unit *u, UnitWriteFlags flags) {
        assert(u);

        if (UNIT_WRITE_FLAGS_NOOP(flags))
                return NULL;

        if (u->transient) /* Redirect drop-ins for transient units always into the transient directory. */
                return u->manager->lookup_paths.transient;

        if (flags & UNIT_PERSISTENT)
                return u->manager->lookup_paths.persistent_control;

        if (flags & UNIT_RUNTIME)
                return u->manager->lookup_paths.runtime_control;

        return NULL;
}

const char* unit_escape_setting(const char *s, UnitWriteFlags flags, char **buf) {
        assert(s);
        assert(popcount(flags & (UNIT_ESCAPE_EXEC_SYNTAX_ENV | UNIT_ESCAPE_EXEC_SYNTAX | UNIT_ESCAPE_C)) <= 1);
        assert(buf);

        _cleanup_free_ char *t = NULL;

        /* Returns a string with any escaping done. If no escaping was necessary, *buf is set to NULL, and
         * the input pointer is returned as-is. If an allocation was needed, the return buffer pointer is
         * written to *buf. This means the return value always contains a properly escaped version, but *buf
         * only contains a pointer if an allocation was made. Callers can use this to optimize memory
         * allocations. */

        if (flags & UNIT_ESCAPE_SPECIFIERS) {
                t = specifier_escape(s);
                if (!t)
                        return NULL;

                s = t;
        }

        /* We either do C-escaping or shell-escaping, to additionally escape characters that we parse for
         * ExecStart= and friends, i.e. '$' and quotes. */

        if (flags & (UNIT_ESCAPE_EXEC_SYNTAX_ENV | UNIT_ESCAPE_EXEC_SYNTAX)) {
                char *t2;

                if (flags & UNIT_ESCAPE_EXEC_SYNTAX_ENV) {
                        t2 = strreplace(s, "$", "$$");
                        if (!t2)
                                return NULL;
                        free_and_replace(t, t2);
                }

                t2 = shell_escape(t ?: s, "\"");
                if (!t2)
                        return NULL;
                free_and_replace(t, t2);

                s = t;

        } else if (flags & UNIT_ESCAPE_C) {
                char *t2;

                t2 = cescape(s);
                if (!t2)
                        return NULL;
                free_and_replace(t, t2);

                s = t;
        }

        *buf = TAKE_PTR(t);
        return s;
}

char* unit_concat_strv(char **l, UnitWriteFlags flags) {
        _cleanup_free_ char *result = NULL;
        size_t n = 0;

        /* Takes a list of strings, escapes them, and concatenates them. This may be used to format command
         * lines in a way suitable for ExecStart= stanzas. */

        STRV_FOREACH(i, l) {
                _cleanup_free_ char *buf = NULL;
                const char *p;
                size_t a;
                char *q;

                p = unit_escape_setting(*i, flags, &buf);
                if (!p)
                        return NULL;

                a = (n > 0) + 1 + strlen(p) + 1; /* separating space + " + entry + " */
                if (!GREEDY_REALLOC(result, n + a + 1))
                        return NULL;

                q = result + n;
                if (n > 0)
                        *(q++) = ' ';

                *(q++) = '"';
                q = stpcpy(q, p);
                *(q++) = '"';

                n += a;
        }

        if (!GREEDY_REALLOC(result, n + 1))
                return NULL;

        result[n] = 0;

        return TAKE_PTR(result);
}

int unit_write_setting(Unit *u, UnitWriteFlags flags, const char *name, const char *data) {
        _cleanup_free_ char *p = NULL, *q = NULL, *escaped = NULL;
        const char *dir, *wrapped;
        int r;

        assert(u);
        assert(name);
        assert(data);

        if (UNIT_WRITE_FLAGS_NOOP(flags))
                return 0;

        data = unit_escape_setting(data, flags, &escaped);
        if (!data)
                return -ENOMEM;

        /* Prefix the section header. If we are writing this out as transient file, then let's suppress this if the
         * previous section header is the same */

        if (flags & UNIT_PRIVATE) {
                if (!UNIT_VTABLE(u)->private_section)
                        return -EINVAL;

                if (!u->transient_file || u->last_section_private < 0)
                        data = strjoina("[", UNIT_VTABLE(u)->private_section, "]\n", data);
                else if (u->last_section_private == 0)
                        data = strjoina("\n[", UNIT_VTABLE(u)->private_section, "]\n", data);
        } else {
                if (!u->transient_file || u->last_section_private < 0)
                        data = strjoina("[Unit]\n", data);
                else if (u->last_section_private > 0)
                        data = strjoina("\n[Unit]\n", data);
        }

        if (u->transient_file) {
                /* When this is a transient unit file in creation, then let's not create a new drop-in,
                 * but instead write to the transient unit file. */
                fputs_with_newline(u->transient_file, data);

                /* Remember which section we wrote this entry to */
                u->last_section_private = !!(flags & UNIT_PRIVATE);
                return 0;
        }

        dir = unit_drop_in_dir(u, flags);
        if (!dir)
                return -EINVAL;

        wrapped = strjoina("# This is a drop-in unit file extension, created via \"systemctl set-property\"\n"
                           "# or an equivalent operation. Do not edit.\n",
                           data,
                           "\n");

        r = drop_in_file(dir, u->id, 50, name, &p, &q);
        if (r < 0)
                return r;

        (void) mkdir_p_label(p, 0755);

        /* Make sure the drop-in dir is registered in our path cache. This way we don't need to stupidly
         * recreate the cache after every drop-in we write. */
        if (u->manager->unit_path_cache) {
                r = set_put_strdup_full(&u->manager->unit_path_cache, &path_hash_ops_free, p);
                if (r < 0)
                        return r;
        }

        r = write_string_file(q, wrapped, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **dropins = NULL;
        r = unit_find_dropin_paths(u, /* use_unit_path_cache= */ true, &dropins);
        if (r < 0)
                return r;
        strv_free_and_replace(u->dropin_paths, dropins);

        u->dropin_mtime = now(CLOCK_REALTIME);

        return 0;
}

int unit_write_settingf(Unit *u, UnitWriteFlags flags, const char *name, const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        assert(u);
        assert(name);
        assert(format);

        if (UNIT_WRITE_FLAGS_NOOP(flags))
                return 0;

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return unit_write_setting(u, flags, name, p);
}

int unit_make_transient(Unit *u) {
        _cleanup_free_ char *path = NULL;
        FILE *f;

        assert(u);

        if (!UNIT_VTABLE(u)->can_transient)
                return -EOPNOTSUPP;

        (void) mkdir_p_label(u->manager->lookup_paths.transient, 0755);

        path = path_join(u->manager->lookup_paths.transient, u->id);
        if (!path)
                return -ENOMEM;

        /* Let's open the file we'll write the transient settings into. This file is kept open as long as we are
         * creating the transient, and is closed in unit_load(), as soon as we start loading the file. */

        WITH_UMASK(0022) {
                f = fopen(path, "we");
                if (!f)
                        return -errno;
        }

        safe_fclose(u->transient_file);
        u->transient_file = f;

        free_and_replace(u->fragment_path, path);

        u->source_path = mfree(u->source_path);
        u->dropin_paths = strv_free(u->dropin_paths);
        u->fragment_mtime = u->source_mtime = u->dropin_mtime = 0;

        u->load_state = UNIT_STUB;
        u->load_error = 0;
        u->transient = true;

        unit_add_to_dbus_queue(u);
        unit_add_to_gc_queue(u);

        fputs("# This is a transient unit file, created programmatically via the systemd API. Do not edit.\n",
              u->transient_file);

        return 0;
}

static bool ignore_leftover_process(const char *comm) {
        return comm && comm[0] == '('; /* Most likely our own helper process (PAM?), ignore */
}

static int log_kill(const PidRef *pid, int sig, void *userdata) {
        const Unit *u = ASSERT_PTR(userdata);
        _cleanup_free_ char *comm = NULL;

        assert(pidref_is_set(pid));

        (void) pidref_get_comm(pid, &comm);

        if (ignore_leftover_process(comm))
                /* Although we didn't log anything, as this callback is used in unit_kill_context we must return 1
                 * here to let the manager know that a process was killed. */
                return 1;

        log_unit_notice(u,
                        "Killing process " PID_FMT " (%s) with signal SIG%s.",
                        pid->pid,
                        strna(comm),
                        signal_to_string(sig));

        return 1;
}

static int operation_to_signal(
                const KillContext *c,
                KillOperation k,
                bool *ret_noteworthy) {

        assert(c);
        assert(ret_noteworthy);

        switch (k) {

        case KILL_TERMINATE:
        case KILL_TERMINATE_AND_LOG:
                *ret_noteworthy = k == KILL_TERMINATE_AND_LOG;
                return c->kill_signal;

        case KILL_RESTART:
                *ret_noteworthy = false;
                return restart_kill_signal(c);

        case KILL_KILL:
                *ret_noteworthy = true;
                return c->final_kill_signal;

        case KILL_WATCHDOG:
                *ret_noteworthy = true;
                return c->watchdog_signal;

        default:
                assert_not_reached();
        }
}

static int unit_kill_context_one(
                Unit *u,
                const PidRef *pidref,
                const char *type,
                bool is_alien,
                int sig,
                bool send_sighup,
                cg_kill_log_func_t log_func) {

        int r;

        assert(u);
        assert(type);

        /* This returns > 0 if it makes sense to wait for SIGCHLD for the process, == 0 if not. */

        if (!pidref_is_set(pidref))
                return 0;

        if (log_func)
                log_func(pidref, sig, u);

        r = pidref_kill_and_sigcont(pidref, sig);
        if (r == -ESRCH)
                return !is_alien;
        if (r < 0) {
                _cleanup_free_ char *comm = NULL;

                (void) pidref_get_comm(pidref, &comm);
                return log_unit_warning_errno(u, r, "Failed to kill %s process " PID_FMT " (%s), ignoring: %m", type, pidref->pid, strna(comm));
        }

        if (send_sighup)
                (void) pidref_kill(pidref, SIGHUP);

        return !is_alien;
}

int unit_kill_context(Unit *u, KillOperation k) {
        bool wait_for_exit = false, send_sighup;
        cg_kill_log_func_t log_func = NULL;
        int sig, r;

        assert(u);

        /* Kill the processes belonging to this unit, in preparation for shutting the unit down.  Returns > 0
         * if we killed something worth waiting for, 0 otherwise. Do not confuse with unit_kill_common()
         * which is used for user-requested killing of unit processes. */

        KillContext *c = unit_get_kill_context(u);
        if (!c || c->kill_mode == KILL_NONE)
                return 0;

        bool noteworthy;
        sig = operation_to_signal(c, k, &noteworthy);
        if (noteworthy)
                log_func = log_kill;

        send_sighup =
                c->send_sighup &&
                IN_SET(k, KILL_TERMINATE, KILL_TERMINATE_AND_LOG) &&
                sig != SIGHUP;

        bool is_alien;
        PidRef *main_pid = unit_main_pid_full(u, &is_alien);
        r = unit_kill_context_one(u, main_pid, "main", is_alien, sig, send_sighup, log_func);
        wait_for_exit = wait_for_exit || r > 0;

        r = unit_kill_context_one(u, unit_control_pid(u), "control", /* is_alien= */ false, sig, send_sighup, log_func);
        wait_for_exit = wait_for_exit || r > 0;

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (crt && crt->cgroup_path &&
            (c->kill_mode == KILL_CONTROL_GROUP || (c->kill_mode == KILL_MIXED && k == KILL_KILL))) {
                _cleanup_set_free_ Set *pid_set = NULL;

                /* Exclude the main/control pids from being killed via the cgroup */
                r = unit_pid_set(u, &pid_set);
                if (r < 0)
                        return r;

                r = cg_kill_recursive(
                                crt->cgroup_path,
                                sig,
                                CGROUP_SIGCONT|CGROUP_IGNORE_SELF,
                                pid_set,
                                log_func, u);
                if (r < 0) {
                        if (!IN_SET(r, -EAGAIN, -ESRCH, -ENOENT))
                                log_unit_warning_errno(u, r, "Failed to kill control group %s, ignoring: %m", empty_to_root(crt->cgroup_path));

                } else if (r > 0) {

                        wait_for_exit = true;

                        if (send_sighup) {
                                r = unit_pid_set(u, &pid_set);
                                if (r < 0)
                                        return r;

                                (void) cg_kill_recursive(
                                                crt->cgroup_path,
                                                SIGHUP,
                                                CGROUP_IGNORE_SELF,
                                                pid_set,
                                                /* log_kill= */ NULL,
                                                /* userdata= */ NULL);
                        }
                }
        }

        return wait_for_exit;
}

int unit_add_mounts_for(Unit *u, const char *path, UnitDependencyMask mask, UnitMountDependencyType type) {
        Hashmap **unit_map, **manager_map;
        int r;

        assert(u);
        assert(path);
        assert(type >= 0 && type < _UNIT_MOUNT_DEPENDENCY_TYPE_MAX);

        unit_map = &u->mounts_for[type];
        manager_map = &u->manager->units_needing_mounts_for[type];

        /* Registers a unit for requiring a certain path and all its prefixes. We keep a hashtable of these
         * paths in the unit (from the path to the UnitDependencyInfo structure indicating how to the
         * dependency came to be). However, we build a prefix table for all possible prefixes so that new
         * appearing mount units can easily determine which units to make themselves a dependency of. */

        if (!path_is_absolute(path))
                return -EINVAL;

        if (hashmap_contains(*unit_map, path)) /* Exit quickly if the path is already covered. */
                return 0;

        if (!unit_type_supported(UNIT_MOUNT)) {
                log_once(LOG_NOTICE, "Mount unit not supported, skipping *MountsFor= dependencies.");
                return 0;
        }

        /* Use the canonical form of the path as the stored key. We call path_is_normalized()
         * only after simplification, since path_is_normalized() rejects paths with '.'.
         * path_is_normalized() also verifies that the path fits in PATH_MAX. */
        _cleanup_free_ char *p = NULL;
        r = path_simplify_alloc(path, &p);
        if (r < 0)
                return r;
        path = p;

        if (!path_is_normalized(path))
                return -EPERM;

        UnitDependencyInfo di = {
                .origin_mask = mask
        };

        r = hashmap_ensure_put(unit_map, &path_hash_ops, p, di.data);
        if (r < 0)
                return r;
        assert(r > 0);
        TAKE_PTR(p); /* path remains a valid pointer to the string stored in the hashmap */

        char prefix[strlen(path) + 1];
        PATH_FOREACH_PREFIX_MORE(prefix, path) {
                Set *x;

                x = hashmap_get(*manager_map, prefix);
                if (!x) {
                        _cleanup_free_ char *q = NULL;

                        r = hashmap_ensure_allocated(manager_map, &path_hash_ops);
                        if (r < 0)
                                return r;

                        q = strdup(prefix);
                        if (!q)
                                return -ENOMEM;

                        x = set_new(NULL);
                        if (!x)
                                return -ENOMEM;

                        r = hashmap_put(*manager_map, q, x);
                        if (r < 0) {
                                set_free(x);
                                return r;
                        }
                        q = NULL;
                }

                r = set_put(x, u);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_setup_exec_runtime(Unit *u) {
        _cleanup_(exec_shared_runtime_unrefp) ExecSharedRuntime *esr = NULL;
        _cleanup_(dynamic_creds_unrefp) DynamicCreds *dcreds = NULL;
        _cleanup_set_free_ Set *units = NULL;
        ExecRuntime **rt;
        ExecContext *ec;
        size_t offset;
        Unit *other;
        int r;

        offset = UNIT_VTABLE(u)->exec_runtime_offset;
        assert(offset > 0);

        /* Check if there already is an ExecRuntime for this unit? */
        rt = (ExecRuntime**) ((uint8_t*) u + offset);
        if (*rt)
                return 0;

        ec = ASSERT_PTR(unit_get_exec_context(u));

        r = unit_get_transitive_dependency_set(u, UNIT_ATOM_JOINS_NAMESPACE_OF, &units);
        if (r < 0)
                return r;

        /* Try to get it from somebody else */
        SET_FOREACH(other, units) {
                r = exec_shared_runtime_acquire(u->manager, NULL, other->id, false, &esr);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;
        }

        if (!esr) {
                r = exec_shared_runtime_acquire(u->manager, ec, u->id, true, &esr);
                if (r < 0)
                        return r;
        }

        if (ec->dynamic_user) {
                r = dynamic_creds_make(u->manager, ec->user, ec->group, &dcreds);
                if (r < 0)
                        return r;
        }

        r = exec_runtime_make(u, ec, esr, dcreds, rt);
        if (r < 0)
                return r;

        TAKE_PTR(esr);
        TAKE_PTR(dcreds);

        return r;
}

CGroupRuntime* unit_setup_cgroup_runtime(Unit *u) {
        assert(u);
        assert(UNIT_HAS_CGROUP_CONTEXT(u));

        size_t offset = UNIT_VTABLE(u)->cgroup_runtime_offset;
        assert(offset > 0);

        CGroupRuntime **rt = (CGroupRuntime**) ((uint8_t*) u + offset);
        if (*rt)
                return *rt;

        return (*rt = cgroup_runtime_new());
}

bool unit_type_supported(UnitType t) {
        static int8_t cache[_UNIT_TYPE_MAX] = {}; /* -1: disabled, 1: enabled: 0: don't know */
        int r;

        assert(t >= 0 && t < _UNIT_TYPE_MAX);

        if (cache[t] == 0) {
                char *e;

                e = strjoina("SYSTEMD_SUPPORT_", unit_type_to_string(t));

                r = getenv_bool(ascii_strupper(e));
                if (r < 0 && r != -ENXIO)
                        log_debug_errno(r, "Failed to parse $%s, ignoring: %m", e);

                cache[t] = r == 0 ? -1 : 1;
        }
        if (cache[t] < 0)
                return false;

        if (!unit_vtable[t]->supported)
                return true;

        return unit_vtable[t]->supported();
}

void unit_warn_if_dir_nonempty(Unit *u, const char* where) {
        int r;

        assert(u);
        assert(where);

        if (!unit_log_level_test(u, LOG_NOTICE))
                return;

        r = dir_is_empty(where, /* ignore_hidden_or_backup= */ false);
        if (r > 0 || r == -ENOTDIR)
                return;
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to check directory %s: %m", where);
                return;
        }

        log_unit_struct(u, LOG_NOTICE,
                        LOG_MESSAGE_ID(SD_MESSAGE_OVERMOUNTING_STR),
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Directory %s to mount over is not empty, mounting anyway.", where),
                        LOG_ITEM("WHERE=%s", where));
}

int unit_log_noncanonical_mount_path(Unit *u, const char *where) {
        assert(u);
        assert(where);

        /* No need to mention "." or "..", they would already have been rejected by unit_name_from_path() */
        log_unit_struct(u, LOG_ERR,
                        LOG_MESSAGE_ID(SD_MESSAGE_NON_CANONICAL_MOUNT_STR),
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Mount path %s is not canonical (contains a symlink).", where),
                        LOG_ITEM("WHERE=%s", where));

        return -ELOOP;
}

int unit_fail_if_noncanonical_mount_path(Unit *u, const char* where) {
        int r;

        assert(u);
        assert(where);

        _cleanup_free_ char *canonical_where = NULL;
        r = chase(where, /* root= */ NULL, CHASE_NONEXISTENT, &canonical_where, /* ret_fd= */ NULL);
        if (r < 0) {
                log_unit_debug_errno(u, r, "Failed to check %s for symlinks, ignoring: %m", where);
                return 0;
        }

        /* We will happily ignore a trailing slash (or any redundant slashes) */
        if (path_equal(where, canonical_where))
                return 0;

        return unit_log_noncanonical_mount_path(u, where);
}

bool unit_is_pristine(Unit *u) {
        assert(u);

        /* Check if the unit already exists or is already around, in a number of different ways. Note that to
         * cater for unit types such as slice, we are generally fine with units that are marked UNIT_LOADED
         * even though nothing was actually loaded, as those unit types don't require a file on disk.
         *
         * Note that we don't check for drop-ins here, because we allow drop-ins for transient units
         * identically to non-transient units, both unit-specific and hierarchical. E.g. for a-b-c.service:
         * service.d/….conf, a-.service.d/….conf, a-b-.service.d/….conf, a-b-c.service.d/….conf.
         */

        return IN_SET(u->load_state, UNIT_NOT_FOUND, UNIT_LOADED) &&
               !u->fragment_path &&
               !u->source_path &&
               !u->job &&
               !u->merged_into;
}

PidRef* unit_control_pid(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->control_pid)
                return UNIT_VTABLE(u)->control_pid(u);

        return NULL;
}

PidRef* unit_main_pid_full(Unit *u, bool *ret_is_alien) {
        assert(u);

        if (UNIT_VTABLE(u)->main_pid)
                return UNIT_VTABLE(u)->main_pid(u, ret_is_alien);

        if (ret_is_alien)
                *ret_is_alien = false;
        return NULL;
}

static void unit_modify_user_nft_set(Unit *u, bool add, NFTSetSource source, uint32_t element) {
        int r;

        assert(u);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return;

        CGroupContext *c;
        c = unit_get_cgroup_context(u);
        if (!c)
                return;

        if (!u->manager->nfnl) {
                r = sd_nfnl_socket_open(&u->manager->nfnl);
                if (r < 0)
                        return;
        }

        FOREACH_ARRAY(nft_set, c->nft_set_context.sets, c->nft_set_context.n_sets) {
                if (nft_set->source != source)
                        continue;

                r = nft_set_element_modify_any(u->manager->nfnl, add, nft_set->nfproto, nft_set->table, nft_set->set, &element, sizeof(element));
                if (r < 0)
                        log_warning_errno(r, "Failed to %s NFT set entry: family %s, table %s, set %s, ID %u, ignoring: %m",
                                          add? "add" : "delete", nfproto_to_string(nft_set->nfproto), nft_set->table, nft_set->set, element);
                else
                        log_debug("%s NFT set entry: family %s, table %s, set %s, ID %u",
                                  add? "Added" : "Deleted", nfproto_to_string(nft_set->nfproto), nft_set->table, nft_set->set, element);
        }
}

static void unit_unref_uid_internal(
                Unit *u,
                uid_t *ref_uid,
                bool destroy_now,
                void (*_manager_unref_uid)(Manager *m, uid_t uid, bool destroy_now)) {

        assert(u);
        assert(ref_uid);
        assert(_manager_unref_uid);

        /* Generic implementation of both unit_unref_uid() and unit_unref_gid(), under the assumption that uid_t and
         * gid_t are actually the same time, with the same validity rules.
         *
         * Drops a reference to UID/GID from a unit. */

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        assert_cc(UID_INVALID == (uid_t) GID_INVALID);

        if (!uid_is_valid(*ref_uid))
                return;

        _manager_unref_uid(u->manager, *ref_uid, destroy_now);
        *ref_uid = UID_INVALID;
}

static void unit_unref_uid(Unit *u, bool destroy_now) {
        assert(u);

        unit_modify_user_nft_set(u, /* add= */ false, NFT_SET_SOURCE_USER, u->ref_uid);

        unit_unref_uid_internal(u, &u->ref_uid, destroy_now, manager_unref_uid);
}

static void unit_unref_gid(Unit *u, bool destroy_now) {
        assert(u);

        unit_modify_user_nft_set(u, /* add= */ false, NFT_SET_SOURCE_GROUP, u->ref_gid);

        unit_unref_uid_internal(u, (uid_t*) &u->ref_gid, destroy_now, manager_unref_gid);
}

void unit_unref_uid_gid(Unit *u, bool destroy_now) {
        assert(u);

        unit_unref_uid(u, destroy_now);
        unit_unref_gid(u, destroy_now);
}

static int unit_ref_uid_internal(
                Unit *u,
                uid_t *ref_uid,
                uid_t uid,
                bool clean_ipc,
                int (*_manager_ref_uid)(Manager *m, uid_t uid, bool clean_ipc)) {

        int r;

        assert(u);
        assert(ref_uid);
        assert(uid_is_valid(uid));
        assert(_manager_ref_uid);

        /* Generic implementation of both unit_ref_uid() and unit_ref_guid(), under the assumption that uid_t and gid_t
         * are actually the same type, and have the same validity rules.
         *
         * Adds a reference on a specific UID/GID to this unit. Each unit referencing the same UID/GID maintains a
         * reference so that we can destroy the UID/GID's IPC resources as soon as this is requested and the counter
         * drops to zero. */

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        assert_cc(UID_INVALID == (uid_t) GID_INVALID);

        if (*ref_uid == uid)
                return 0;

        if (uid_is_valid(*ref_uid)) /* Already set? */
                return -EBUSY;

        r = _manager_ref_uid(u->manager, uid, clean_ipc);
        if (r < 0)
                return r;

        *ref_uid = uid;
        return 1;
}

static int unit_ref_uid(Unit *u, uid_t uid, bool clean_ipc) {
        return unit_ref_uid_internal(u, &u->ref_uid, uid, clean_ipc, manager_ref_uid);
}

static int unit_ref_gid(Unit *u, gid_t gid, bool clean_ipc) {
        return unit_ref_uid_internal(u, (uid_t*) &u->ref_gid, (uid_t) gid, clean_ipc, manager_ref_gid);
}

static int unit_ref_uid_gid_internal(Unit *u, uid_t uid, gid_t gid, bool clean_ipc) {
        int r = 0, q = 0;

        assert(u);

        /* Reference both a UID and a GID in one go. Either references both, or neither. */

        if (uid_is_valid(uid)) {
                r = unit_ref_uid(u, uid, clean_ipc);
                if (r < 0)
                        return r;
        }

        if (gid_is_valid(gid)) {
                q = unit_ref_gid(u, gid, clean_ipc);
                if (q < 0) {
                        if (r > 0)
                                unit_unref_uid(u, false);

                        return q;
                }
        }

        return r > 0 || q > 0;
}

int unit_ref_uid_gid(Unit *u, uid_t uid, gid_t gid) {
        ExecContext *c;
        int r;

        assert(u);

        c = unit_get_exec_context(u);

        r = unit_ref_uid_gid_internal(u, uid, gid, c ? c->remove_ipc : false);
        if (r < 0)
                return log_unit_warning_errno(u, r, "Couldn't add UID/GID reference to unit, proceeding without: %m");

        unit_modify_user_nft_set(u, /* add= */ true, NFT_SET_SOURCE_USER, uid);
        unit_modify_user_nft_set(u, /* add= */ true, NFT_SET_SOURCE_GROUP, gid);

        return r;
}

void unit_notify_user_lookup(Unit *u, uid_t uid, gid_t gid) {
        int r;

        assert(u);

        /* This is invoked whenever one of the forked off processes let's us know the UID/GID its user name/group names
         * resolved to. We keep track of which UID/GID is currently assigned in order to be able to destroy its IPC
         * objects when no service references the UID/GID anymore. */

        r = unit_ref_uid_gid(u, uid, gid);
        if (r > 0)
                unit_add_to_dbus_queue(u);
}

int unit_acquire_invocation_id(Unit *u) {
        sd_id128_t id;
        int r;

        assert(u);

        r = sd_id128_randomize(&id);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to generate invocation ID for unit: %m");

        r = unit_set_invocation_id(u, id);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to set invocation ID for unit: %m");

        unit_add_to_dbus_queue(u);
        return 0;
}

int unit_set_exec_params(Unit *u, ExecParameters *p) {
        int r;

        assert(u);
        assert(p);

        /* Copy parameters from manager */
        r = manager_get_effective_environment(u->manager, &p->environment);
        if (r < 0)
                return r;

        p->runtime_scope = u->manager->runtime_scope;

        r = strdup_to(&p->confirm_spawn, manager_get_confirm_spawn(u->manager));
        if (r < 0)
                return r;

        p->prefix = u->manager->prefix;
        SET_FLAG(p->flags, EXEC_PASS_LOG_UNIT|EXEC_CHOWN_DIRECTORIES, MANAGER_IS_SYSTEM(u->manager));

        /* Copy parameters from unit */
        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        p->cgroup_path = crt ? crt->cgroup_path : NULL;
        SET_FLAG(p->flags, EXEC_CGROUP_DELEGATE, unit_cgroup_delegate(u));

        p->received_credentials_directory = u->manager->received_credentials_directory;
        p->received_encrypted_credentials_directory = u->manager->received_encrypted_credentials_directory;

        p->shall_confirm_spawn = u->manager->confirm_spawn;

        p->fallback_smack_process_label = u->manager->defaults.smack_process_label;

        if (u->manager->restrict_fs && p->bpf_restrict_fs_map_fd < 0) {
                int fd = bpf_restrict_fs_map_fd(u);
                if (fd < 0)
                        return fd;

                p->bpf_restrict_fs_map_fd = fd;
        }

        p->user_lookup_fd = u->manager->user_lookup_fds[1];
        p->handoff_timestamp_fd = u->manager->handoff_timestamp_fds[1];
        if (UNIT_VTABLE(u)->notify_pidref)
                p->pidref_transport_fd = u->manager->pidref_transport_fds[1];

        p->cgroup_id = crt ? crt->cgroup_id : 0;
        p->invocation_id = u->invocation_id;
        sd_id128_to_string(p->invocation_id, p->invocation_id_string);
        p->unit_id = strdup(u->id);
        if (!p->unit_id)
                return -ENOMEM;

        p->debug_invocation = u->debug_invocation;

        return 0;
}

int unit_fork_helper_process_full(Unit *u, const char *name, bool into_cgroup, ForkFlags flags, PidRef *ret) {
        CGroupRuntime *crt = NULL;
        int r;

        assert(u);
        assert((flags & (FORK_RESET_SIGNALS|FORK_DETACH|FORK_WAIT)) == 0); /* these don't really make sense for manager */
        assert(ret);

        /* Forks off a helper process and makes sure it is a member of the unit's cgroup, if configured to
         * do so. Returns == 0 in the child, and > 0 in the parent. The pidref parameter is always filled in
         * with the child's PID reference. */

        if (into_cgroup) {
                r = unit_realize_cgroup(u);
                if (r < 0)
                        return r;

                crt = unit_get_cgroup_runtime(u);
        }

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(name, FORK_REOPEN_LOG|FORK_DEATHSIG_SIGTERM|flags, &pidref);
        if (r < 0)
                return r;
        if (r > 0) {
                *ret = TAKE_PIDREF(pidref);
                return r;
        }

        /* Child */

        (void) default_signals(SIGNALS_CRASH_HANDLER, SIGNALS_IGNORE);
        (void) ignore_signals(SIGPIPE);

        if (crt && crt->cgroup_path) {
                r = cg_attach(crt->cgroup_path, 0);
                if (r < 0) {
                        log_unit_error_errno(u, r, "Failed to join unit cgroup %s: %m", empty_to_root(crt->cgroup_path));
                        _exit(EXIT_CGROUP);
                }
        }

        *ret = TAKE_PIDREF(pidref);
        return 0;
}

int unit_fork_helper_process(Unit *u, const char *name, bool into_cgroup, PidRef *ret) {
        return unit_fork_helper_process_full(u, name, into_cgroup, /* flags= */ 0, ret);
}

int unit_fork_and_watch_rm_rf(Unit *u, char **paths, PidRef *ret_pid) {
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        int r;

        assert(u);
        assert(ret_pid);

        r = unit_fork_helper_process(u, "(sd-rmrf)", /* into_cgroup= */ true, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                int ret = EXIT_SUCCESS;

                STRV_FOREACH(i, paths) {
                        r = rm_rf(*i, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_MISSING_OK);
                        if (r < 0) {
                                log_error_errno(r, "Failed to remove '%s': %m", *i);
                                ret = EXIT_FAILURE;
                        }
                }

                _exit(ret);
        }

        r = unit_watch_pidref(u, &pid, /* exclusive= */ true);
        if (r < 0)
                return r;

        *ret_pid = TAKE_PIDREF(pid);
        return 0;
}

static void unit_update_dependency_mask(Hashmap *deps, Unit *other, UnitDependencyInfo di) {
        assert(deps);
        assert(other);

        if (di.origin_mask == 0 && di.destination_mask == 0)
                /* No bit set anymore, let's drop the whole entry */
                assert_se(hashmap_remove(deps, other));
        else
                /* Mask was reduced, let's update the entry */
                assert_se(hashmap_update(deps, other, di.data) == 0);
}

void unit_remove_dependencies(Unit *u, UnitDependencyMask mask) {
        Hashmap *deps;
        assert(u);

        /* Removes all dependencies u has on other units marked for ownership by 'mask'. */

        if (mask == 0)
                return;

        HASHMAP_FOREACH(deps, u->dependencies) {
                bool done;

                do {
                        UnitDependencyInfo di;
                        Unit *other;

                        done = true;

                        HASHMAP_FOREACH_KEY(di.data, other, deps) {
                                Hashmap *other_deps;

                                if (FLAGS_SET(~mask, di.origin_mask))
                                        continue;

                                di.origin_mask &= ~mask;
                                unit_update_dependency_mask(deps, other, di);

                                /* We updated the dependency from our unit to the other unit now. But most
                                 * dependencies imply a reverse dependency. Hence, let's delete that one
                                 * too. For that we go through all dependency types on the other unit and
                                 * delete all those which point to us and have the right mask set. */

                                HASHMAP_FOREACH(other_deps, other->dependencies) {
                                        UnitDependencyInfo dj;

                                        dj.data = hashmap_get(other_deps, u);
                                        if (FLAGS_SET(~mask, dj.destination_mask))
                                                continue;

                                        dj.destination_mask &= ~mask;
                                        unit_update_dependency_mask(other_deps, u, dj);
                                }

                                unit_add_to_gc_queue(other);

                                /* The unit 'other' may not be wanted by the unit 'u'. */
                                unit_submit_to_stop_when_unneeded_queue(other);

                                u->dependency_generation++;
                                other->dependency_generation++;

                                done = false;
                                break;
                        }

                } while (!done);
        }
}

static int unit_get_invocation_path(Unit *u, char **ret) {
        char *p;
        int r;

        assert(u);
        assert(ret);

        if (MANAGER_IS_SYSTEM(u->manager))
                p = strjoin("/run/systemd/units/invocation:", u->id);
        else {
                _cleanup_free_ char *user_path = NULL;

                r = xdg_user_runtime_dir("/systemd/units/invocation:", &user_path);
                if (r < 0)
                        return r;

                p = strjoin(user_path, u->id);
        }
        if (!p)
                return -ENOMEM;

        *ret = p;
        return 0;
}

static int unit_export_invocation_id(Unit *u) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(u);

        if (u->exported_invocation_id)
                return 0;

        if (sd_id128_is_null(u->invocation_id))
                return 0;

        r = unit_get_invocation_path(u, &p);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to get invocation path: %m");

        r = symlinkat_atomic_full(u->invocation_id_string, AT_FDCWD, p, SYMLINK_LABEL);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to create invocation ID symlink %s: %m", p);

        u->exported_invocation_id = true;
        return 0;
}

static int unit_export_log_level_max(Unit *u, int log_level_max, bool overwrite) {
        const char *p;
        char buf[2];
        int r;

        assert(u);

        /* When the debug_invocation logic runs, overwrite will be true as we always want to switch the max
         * log level that the journal applies, and we want to always restore the previous level once done */

        if (!overwrite && u->exported_log_level_max)
                return 0;

        if (log_level_max < 0)
                return 0;

        assert(log_level_max <= 7);

        buf[0] = '0' + log_level_max;
        buf[1] = 0;

        p = strjoina("/run/systemd/units/log-level-max:", u->id);
        r = symlink_atomic(buf, p);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to create maximum log level symlink %s: %m", p);

        u->exported_log_level_max = true;
        return 0;
}

static int unit_export_log_extra_fields(Unit *u, const ExecContext *c) {
        _cleanup_close_ int fd = -EBADF;
        struct iovec *iovec;
        const char *p;
        char *pattern;
        le64_t *sizes;
        ssize_t n;
        int r;

        if (u->exported_log_extra_fields)
                return 0;

        if (c->n_log_extra_fields <= 0)
                return 0;

        sizes = newa(le64_t, c->n_log_extra_fields);
        iovec = newa(struct iovec, c->n_log_extra_fields * 2);

        for (size_t i = 0; i < c->n_log_extra_fields; i++) {
                sizes[i] = htole64(c->log_extra_fields[i].iov_len);

                iovec[i*2] = IOVEC_MAKE(sizes + i, sizeof(le64_t));
                iovec[i*2+1] = c->log_extra_fields[i];
        }

        p = strjoina("/run/systemd/units/log-extra-fields:", u->id);
        pattern = strjoina(p, ".XXXXXX");

        fd = mkostemp_safe(pattern);
        if (fd < 0)
                return log_unit_debug_errno(u, fd, "Failed to create extra fields file %s: %m", p);

        n = writev(fd, iovec, c->n_log_extra_fields*2);
        if (n < 0) {
                r = log_unit_debug_errno(u, errno, "Failed to write extra fields: %m");
                goto fail;
        }

        (void) fchmod(fd, 0644);

        if (rename(pattern, p) < 0) {
                r = log_unit_debug_errno(u, errno, "Failed to rename extra fields file: %m");
                goto fail;
        }

        u->exported_log_extra_fields = true;
        return 0;

fail:
        (void) unlink(pattern);
        return r;
}

static int unit_export_log_ratelimit_interval(Unit *u, const ExecContext *c) {
        _cleanup_free_ char *buf = NULL;
        const char *p;
        int r;

        assert(u);
        assert(c);

        if (u->exported_log_ratelimit_interval)
                return 0;

        if (c->log_ratelimit.interval == 0)
                return 0;

        p = strjoina("/run/systemd/units/log-rate-limit-interval:", u->id);

        if (asprintf(&buf, "%" PRIu64, c->log_ratelimit.interval) < 0)
                return log_oom();

        r = symlink_atomic(buf, p);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to create log rate limit interval symlink %s: %m", p);

        u->exported_log_ratelimit_interval = true;
        return 0;
}

static int unit_export_log_ratelimit_burst(Unit *u, const ExecContext *c) {
        _cleanup_free_ char *buf = NULL;
        const char *p;
        int r;

        assert(u);
        assert(c);

        if (u->exported_log_ratelimit_burst)
                return 0;

        if (c->log_ratelimit.burst == 0)
                return 0;

        p = strjoina("/run/systemd/units/log-rate-limit-burst:", u->id);

        if (asprintf(&buf, "%u", c->log_ratelimit.burst) < 0)
                return log_oom();

        r = symlink_atomic(buf, p);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to create log rate limit burst symlink %s: %m", p);

        u->exported_log_ratelimit_burst = true;
        return 0;
}

void unit_export_state_files(Unit *u) {
        const ExecContext *c;

        assert(u);

        if (!u->id)
                return;

        if (MANAGER_IS_TEST_RUN(u->manager))
                return;

        /* Exports a couple of unit properties to /run/systemd/units/, so that journald can quickly query this data
         * from there. Ideally, journald would use IPC to query this, like everybody else, but that's hard, as long as
         * the IPC system itself and PID 1 also log to the journal.
         *
         * Note that these files really shouldn't be considered API for anyone else, as use a runtime file system as
         * IPC replacement is not compatible with today's world of file system namespaces. However, this doesn't really
         * apply to communication between the journal and systemd, as we assume that these two daemons live in the same
         * namespace at least.
         *
         * Note that some of the "files" exported here are actually symlinks and not regular files. Symlinks work
         * better for storing small bits of data, in particular as we can write them with two system calls, and read
         * them with one. */

        (void) unit_export_invocation_id(u);

        if (!MANAGER_IS_SYSTEM(u->manager))
                return;

        c = unit_get_exec_context(u);
        if (c) {
                (void) unit_export_log_level_max(u, c->log_level_max, /* overwrite= */ false);
                (void) unit_export_log_extra_fields(u, c);
                (void) unit_export_log_ratelimit_interval(u, c);
                (void) unit_export_log_ratelimit_burst(u, c);
        }
}

void unit_unlink_state_files(Unit *u) {
        const char *p;

        assert(u);

        if (!u->id)
                return;

        /* Undoes the effect of unit_export_state() */

        if (u->exported_invocation_id) {
                _cleanup_free_ char *invocation_path = NULL;
                int r = unit_get_invocation_path(u, &invocation_path);
                if (r >= 0) {
                        (void) unlink(invocation_path);
                        u->exported_invocation_id = false;
                }
        }

        if (!MANAGER_IS_SYSTEM(u->manager))
                return;

        if (u->exported_log_level_max) {
                p = strjoina("/run/systemd/units/log-level-max:", u->id);
                (void) unlink(p);

                u->exported_log_level_max = false;
        }

        if (u->exported_log_extra_fields) {
                p = strjoina("/run/systemd/units/extra-fields:", u->id);
                (void) unlink(p);

                u->exported_log_extra_fields = false;
        }

        if (u->exported_log_ratelimit_interval) {
                p = strjoina("/run/systemd/units/log-rate-limit-interval:", u->id);
                (void) unlink(p);

                u->exported_log_ratelimit_interval = false;
        }

        if (u->exported_log_ratelimit_burst) {
                p = strjoina("/run/systemd/units/log-rate-limit-burst:", u->id);
                (void) unlink(p);

                u->exported_log_ratelimit_burst = false;
        }
}

int unit_set_debug_invocation(Unit *u, bool enable) {
        int r;

        assert(u);

        if (u->debug_invocation == enable)
                return 0; /* Nothing to do */

        u->debug_invocation = enable;

        /* Ensure that the new log level is exported for the journal, in place of the previous one */
        if (u->exported_log_level_max) {
                const ExecContext *ec = unit_get_exec_context(u);
                if (ec) {
                        r = unit_export_log_level_max(u, enable ? LOG_PRI(LOG_DEBUG) : ec->log_level_max, /* overwrite= */ true);
                        if (r < 0)
                                return r;
                }
        }

        return 1;
}

int unit_prepare_exec(Unit *u) {
        int r;

        assert(u);

        /* Prepares everything so that we can fork of a process for this unit */

        r = unit_realize_cgroup(u);
        if (r < 0)
                return r;

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (crt && crt->reset_accounting) {
                (void) unit_reset_accounting(u);
                crt->reset_accounting = false;
        }

        unit_export_state_files(u);

        r = unit_setup_exec_runtime(u);
        if (r < 0)
                return r;

        return 0;
}

static int unit_log_leftover_process_start(const PidRef *pid, int sig, void *userdata) {
        const Unit *u = ASSERT_PTR(userdata);
        _cleanup_free_ char *comm = NULL;

        assert(pidref_is_set(pid));

        (void) pidref_get_comm(pid, &comm);

        if (ignore_leftover_process(comm))
                return 0;

        /* During start we print a warning */

        log_unit_warning(u,
                         "Found left-over process " PID_FMT " (%s) in control group while starting unit. Ignoring.\n"
                         "This usually indicates unclean termination of a previous run, or service implementation deficiencies.",
                         pid->pid, strna(comm));

        return 1;
}

static int unit_log_leftover_process_stop(const PidRef *pid, int sig, void *userdata) {
        const Unit *u = ASSERT_PTR(userdata);
        _cleanup_free_ char *comm = NULL;

        assert(pidref_is_set(pid));

        (void) pidref_get_comm(pid, &comm);

        if (ignore_leftover_process(comm))
                return 0;

        /* During stop we only print an informational message */

        log_unit_info(u,
                      "Unit process " PID_FMT " (%s) remains running after unit stopped.",
                      pid->pid, strna(comm));

        return 1;
}

int unit_warn_leftover_processes(Unit *u, bool start) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(u);

        r = unit_get_cgroup_path_with_fallback(u, &cgroup);
        if (r < 0)
                return r;

        return cg_kill_recursive(
                        cgroup,
                        /* sig= */ 0,
                        /* flags= */ 0,
                        /* killed_pids= */ NULL,
                        start ? unit_log_leftover_process_start : unit_log_leftover_process_stop,
                        u);
}

bool unit_needs_console(Unit *u) {
        ExecContext *ec;
        UnitActiveState state;

        assert(u);

        state = unit_active_state(u);

        if (UNIT_IS_INACTIVE_OR_FAILED(state))
                return false;

        if (UNIT_VTABLE(u)->needs_console)
                return UNIT_VTABLE(u)->needs_console(u);

        /* If this unit type doesn't implement this call, let's use a generic fallback implementation: */
        ec = unit_get_exec_context(u);
        if (!ec)
                return false;

        return exec_context_may_touch_console(ec);
}

int unit_pid_attachable(Unit *u, PidRef *pid, sd_bus_error *reterr_error) {
        int r;

        assert(u);

        /* Checks whether the specified PID is generally good for attaching, i.e. a valid PID, not our manager itself,
         * and not a kernel thread either */

        /* First, a simple range check */
        if (!pidref_is_set(pid))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Process identifier is not valid.");

        /* Some extra safety check */
        if (pid->pid == 1 || pidref_is_self(pid))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Process " PID_FMT " is a manager process, refusing.", pid->pid);

        /* Don't even begin to bother with kernel threads */
        r = pidref_is_kernel_thread(pid);
        if (r == -ESRCH)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN, "Process with ID " PID_FMT " does not exist.", pid->pid);
        if (r < 0)
                return sd_bus_error_set_errnof(reterr_error, r, "Failed to determine whether process " PID_FMT " is a kernel thread: %m", pid->pid);
        if (r > 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Process " PID_FMT " is a kernel thread, refusing.", pid->pid);

        return 0;
}

int unit_get_log_level_max(const Unit *u) {
        if (u) {
                if (u->debug_invocation)
                        return LOG_DEBUG;

                ExecContext *ec = unit_get_exec_context(u);
                if (ec && ec->log_level_max >= 0)
                        return ec->log_level_max;
        }

        return log_get_max_level();
}

bool unit_log_level_test(const Unit *u, int level) {
        assert(u);
        return LOG_PRI(level) <= unit_get_log_level_max(u);
}

void unit_log_success(Unit *u) {
        assert(u);

        /* Let's show message "Deactivated successfully" in debug mode (when manager is user) rather than in info mode.
         * This message has low information value for regular users and it might be a bit overwhelming on a system with
         * a lot of devices. */
        log_unit_struct(u,
                        MANAGER_IS_USER(u->manager) ? LOG_DEBUG : LOG_INFO,
                        LOG_MESSAGE_ID(SD_MESSAGE_UNIT_SUCCESS_STR),
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Deactivated successfully."));
}

void unit_log_failure(Unit *u, const char *result) {
        assert(u);
        assert(result);

        log_unit_struct(u, LOG_WARNING,
                        LOG_MESSAGE_ID(SD_MESSAGE_UNIT_FAILURE_RESULT_STR),
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Failed with result '%s'.", result),
                        LOG_ITEM("UNIT_RESULT=%s", result));
}

void unit_log_skip(Unit *u, const char *result) {
        assert(u);
        assert(result);

        log_unit_struct(u, LOG_INFO,
                        LOG_MESSAGE_ID(SD_MESSAGE_UNIT_SKIPPED_STR),
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Skipped due to '%s'.", result),
                        LOG_ITEM("UNIT_RESULT=%s", result));
}

void unit_log_process_exit(
                Unit *u,
                const char *kind,
                const char *command,
                bool success,
                int code,
                int status) {

        int level;

        assert(u);
        assert(kind);

        /* If this is a successful exit, let's log about the exit code on DEBUG level. If this is a failure
         * and the process exited on its own via exit(), then let's make this a NOTICE, under the assumption
         * that the service already logged the reason at a higher log level on its own. Otherwise, make it a
         * WARNING. */
        if (success)
                level = LOG_DEBUG;
        else if (code == CLD_EXITED)
                level = LOG_NOTICE;
        else
                level = LOG_WARNING;

        log_unit_struct(u, level,
                        LOG_MESSAGE_ID(SD_MESSAGE_UNIT_PROCESS_EXIT_STR),
                        LOG_UNIT_MESSAGE(u, "%s exited, code=%s, status=%i/%s%s",
                                         kind,
                                         sigchld_code_to_string(code), status,
                                         strna(code == CLD_EXITED
                                               ? exit_status_to_string(status, EXIT_STATUS_FULL)
                                               : signal_to_string(status)),
                                         success ? " (success)" : ""),
                        LOG_ITEM("EXIT_CODE=%s", sigchld_code_to_string(code)),
                        LOG_ITEM("EXIT_STATUS=%i", status),
                        LOG_ITEM("COMMAND=%s", strna(command)),
                        LOG_UNIT_INVOCATION_ID(u));
}

int unit_exit_status(Unit *u) {
        assert(u);

        /* Returns the exit status to propagate for the most recent cycle of this unit. Returns a value in the range
         * 0…255 if there's something to propagate. EOPNOTSUPP if the concept does not apply to this unit type, ENODATA
         * if no data is currently known (for example because the unit hasn't deactivated yet) and EBADE if the main
         * service process has exited abnormally (signal/coredump). */

        if (!UNIT_VTABLE(u)->exit_status)
                return -EOPNOTSUPP;

        return UNIT_VTABLE(u)->exit_status(u);
}

int unit_failure_action_exit_status(Unit *u) {
        int r;

        assert(u);

        /* Returns the exit status to propagate on failure, or an error if there's nothing to propagate */

        if (u->failure_action_exit_status >= 0)
                return u->failure_action_exit_status;

        r = unit_exit_status(u);
        if (r == -EBADE) /* Exited, but not cleanly (i.e. by signal or such) */
                return 255;

        return r;
}

int unit_success_action_exit_status(Unit *u) {
        int r;

        assert(u);

        /* Returns the exit status to propagate on success, or an error if there's nothing to propagate */

        if (u->success_action_exit_status >= 0)
                return u->success_action_exit_status;

        r = unit_exit_status(u);
        if (r == -EBADE) /* Exited, but not cleanly (i.e. by signal or such) */
                return 255;

        return r;
}

int unit_test_trigger_loaded(Unit *u) {
        Unit *trigger;

        /* Tests whether the unit to trigger is loaded */

        trigger = UNIT_TRIGGER(u);
        if (!trigger)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOENT),
                                            "Refusing to start, no unit to trigger.");
        if (trigger->load_state != UNIT_LOADED)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOENT),
                                            "Refusing to start, unit %s to trigger not loaded.", trigger->id);

        return 0;
}

void unit_destroy_runtime_data(Unit *u, const ExecContext *context, bool destroy_runtime_dir) {
        assert(u);
        assert(u->manager);
        assert(context);

        /* EXEC_PRESERVE_RESTART is handled via unit_release_resources()! */
        if (destroy_runtime_dir && context->runtime_directory_preserve_mode == EXEC_PRESERVE_NO)
                exec_context_destroy_runtime_directory(context, u->manager->prefix[EXEC_DIRECTORY_RUNTIME]);

        exec_context_destroy_credentials(context, u->manager->prefix[EXEC_DIRECTORY_RUNTIME], u->id);
        exec_context_destroy_mount_ns_dir(u);
}

int unit_clean(Unit *u, ExecCleanMask mask) {
        UnitActiveState state;

        assert(u);

        /* Special return values:
         *
         *   -EOPNOTSUPP → cleaning not supported for this unit type
         *   -EUNATCH    → cleaning not defined for this resource type
         *   -EBUSY      → unit currently can't be cleaned since it's running or not properly loaded, or has
         *                 a job queued or similar
         */

        if (!UNIT_VTABLE(u)->clean)
                return -EOPNOTSUPP;

        if (mask == 0)
                return -EUNATCH;

        if (u->load_state != UNIT_LOADED)
                return -EBUSY;

        if (u->job)
                return -EBUSY;

        state = unit_active_state(u);
        if (state != UNIT_INACTIVE)
                return -EBUSY;

        return UNIT_VTABLE(u)->clean(u, mask);
}

int unit_can_clean(Unit *u, ExecCleanMask *ret) {
        assert(u);

        if (!UNIT_VTABLE(u)->clean ||
            u->load_state != UNIT_LOADED) {
                *ret = 0;
                return 0;
        }

        /* When the clean() method is set, can_clean() really should be set too */
        assert(UNIT_VTABLE(u)->can_clean);

        return UNIT_VTABLE(u)->can_clean(u, ret);
}

bool unit_can_start_refuse_manual(Unit *u) {
        return unit_can_start(u) && !u->refuse_manual_start;
}

bool unit_can_stop_refuse_manual(Unit *u) {
        return unit_can_stop(u) && !u->refuse_manual_stop;
}

bool unit_can_isolate_refuse_manual(Unit *u) {
        return unit_can_isolate(u) && !u->refuse_manual_start;
}

void unit_next_freezer_state(Unit *u, FreezerAction action, FreezerState *ret_next, FreezerState *ret_objective) {
        FreezerState current, parent, next, objective;

        assert(u);
        assert(action >= 0);
        assert(action < _FREEZER_ACTION_MAX);
        assert(ret_next);
        assert(ret_objective);

        /* This function determines the correct freezer state transitions for a unit
         * given the action being requested. It returns the next state, and also the "objective",
         * which is either FREEZER_FROZEN or FREEZER_RUNNING, depending on what actual state we
         * ultimately want to achieve. */

        current = u->freezer_state;

        Unit *slice = UNIT_GET_SLICE(u);
        if (slice)
                parent = slice->freezer_state;
        else
                parent = FREEZER_RUNNING;

        switch (action) {

        case FREEZER_FREEZE:
                /* We always "promote" a freeze initiated by parent into a normal freeze */
                if (IN_SET(current, FREEZER_FROZEN, FREEZER_FROZEN_BY_PARENT))
                        next = FREEZER_FROZEN;
                else
                        next = FREEZER_FREEZING;
                break;

        case FREEZER_THAW:
                /* Thawing is the most complicated operation here, because we can't thaw a unit
                 * if its parent is frozen. So we instead "demote" a normal freeze into a freeze
                 * initiated by parent if the parent is frozen */
                if (IN_SET(current, FREEZER_RUNNING, FREEZER_THAWING,
                                    FREEZER_FREEZING_BY_PARENT, FREEZER_FROZEN_BY_PARENT)) /* Should usually be refused by unit_freezer_action */
                        next = current;
                else if (current == FREEZER_FREEZING) {
                        if (IN_SET(parent, FREEZER_RUNNING, FREEZER_THAWING))
                                next = FREEZER_THAWING;
                        else
                                next = FREEZER_FREEZING_BY_PARENT;
                } else if (current == FREEZER_FROZEN) {
                        if (IN_SET(parent, FREEZER_RUNNING, FREEZER_THAWING))
                                next = FREEZER_THAWING;
                        else
                                next = FREEZER_FROZEN_BY_PARENT;
                } else
                        assert_not_reached();
                break;

        case FREEZER_PARENT_FREEZE:
                /* We need to avoid accidentally demoting units frozen manually */
                if (IN_SET(current, FREEZER_FREEZING, FREEZER_FROZEN, FREEZER_FROZEN_BY_PARENT))
                        next = current;
                else
                        next = FREEZER_FREEZING_BY_PARENT;
                break;

        case FREEZER_PARENT_THAW:
                /* We don't want to thaw units from a parent if they were frozen
                 * manually, so for such units this action is a no-op */
                if (IN_SET(current, FREEZER_RUNNING, FREEZER_FREEZING, FREEZER_FROZEN))
                        next = current;
                else
                        next = FREEZER_THAWING;
                break;

        default:
                assert_not_reached();
        }

        objective = freezer_state_objective(next);
        assert(IN_SET(objective, FREEZER_RUNNING, FREEZER_FROZEN));

        *ret_next = next;
        *ret_objective = objective;
}

bool unit_can_freeze(const Unit *u) {
        assert(u);

        if (unit_has_name(u, SPECIAL_ROOT_SLICE) || unit_has_name(u, SPECIAL_INIT_SCOPE))
                return false;

        if (UNIT_VTABLE(u)->can_freeze)
                return UNIT_VTABLE(u)->can_freeze(u);

        return UNIT_VTABLE(u)->freezer_action;
}

void unit_set_freezer_state(Unit *u, FreezerState state) {
        assert(u);
        assert(state >= 0);
        assert(state < _FREEZER_STATE_MAX);

        if (u->freezer_state == state)
                return;

        log_unit_debug(u, "Freezer state changed %s -> %s",
                       freezer_state_to_string(u->freezer_state), freezer_state_to_string(state));

        u->freezer_state = state;

        unit_add_to_dbus_queue(u);
}

void unit_freezer_complete(Unit *u, FreezerState kernel_state) {
        bool expected;

        assert(u);
        assert(IN_SET(kernel_state, FREEZER_RUNNING, FREEZER_FROZEN));

        expected = IN_SET(u->freezer_state, FREEZER_RUNNING, FREEZER_THAWING) == (kernel_state == FREEZER_RUNNING);

        unit_set_freezer_state(u, expected ? freezer_state_finish(u->freezer_state) : kernel_state);
        log_unit_info(u, "Unit now %s.", u->freezer_state == FREEZER_RUNNING ? "thawed" :
                                         freezer_state_to_string(u->freezer_state));

        /* If the cgroup's final state is against what's requested by us, report as canceled. */
        bus_unit_send_pending_freezer_message(u, /* canceled= */ !expected);
}

int unit_freezer_action(Unit *u, FreezerAction action) {
        UnitActiveState s;
        int r;

        assert(u);
        assert(IN_SET(action, FREEZER_FREEZE, FREEZER_THAW));

        if (!unit_can_freeze(u))
                return -EOPNOTSUPP;

        if (u->job)
                return -EBUSY;

        if (u->load_state != UNIT_LOADED)
                return -EHOSTDOWN;

        s = unit_active_state(u);
        if (s != UNIT_ACTIVE)
                return -EHOSTDOWN;

        if (action == FREEZER_FREEZE && IN_SET(u->freezer_state, FREEZER_FREEZING, FREEZER_FREEZING_BY_PARENT))
                return -EALREADY;
        if (action == FREEZER_THAW && u->freezer_state == FREEZER_THAWING)
                return -EALREADY;
        if (action == FREEZER_THAW && IN_SET(u->freezer_state, FREEZER_FREEZING_BY_PARENT, FREEZER_FROZEN_BY_PARENT))
                return -EDEADLK;

        r = UNIT_VTABLE(u)->freezer_action(u, action);
        if (r <= 0)
                return r;

        assert(IN_SET(u->freezer_state, FREEZER_FREEZING, FREEZER_FREEZING_BY_PARENT, FREEZER_THAWING));
        return 1;
}

Condition *unit_find_failed_condition(Unit *u) {
        Condition *failed_trigger = NULL;
        bool has_succeeded_trigger = false;

        if (u->condition_result)
                return NULL;

        LIST_FOREACH(conditions, c, u->conditions)
                if (c->trigger) {
                        if (c->result == CONDITION_SUCCEEDED)
                                 has_succeeded_trigger = true;
                        else if (!failed_trigger)
                                 failed_trigger = c;
                } else if (c->result != CONDITION_SUCCEEDED)
                        return c;

        return failed_trigger && !has_succeeded_trigger ? failed_trigger : NULL;
}

int unit_can_live_mount(Unit *u, sd_bus_error *reterr_error) {
        assert(u);

        if (!UNIT_VTABLE(u)->live_mount)
                return sd_bus_error_setf(
                                reterr_error,
                                SD_BUS_ERROR_NOT_SUPPORTED,
                                "Live mounting not supported by unit type '%s'",
                                unit_type_to_string(u->type));

        if (u->load_state != UNIT_LOADED)
                return sd_bus_error_setf(
                                reterr_error,
                                BUS_ERROR_NO_SUCH_UNIT,
                                "Unit '%s' not loaded, cannot live mount",
                                u->id);

        if (!UNIT_VTABLE(u)->can_live_mount)
                return 0;

        return UNIT_VTABLE(u)->can_live_mount(u, reterr_error);
}

int unit_live_mount(
                Unit *u,
                const char *src,
                const char *dst,
                sd_bus_message *message,
                MountInNamespaceFlags flags,
                const MountOptions *options,
                sd_bus_error *reterr_error) {

        assert(u);
        assert(UNIT_VTABLE(u)->live_mount);

        if (!UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u))) {
                log_unit_debug(u, "Unit not active, cannot perform live mount.");
                return sd_bus_error_setf(
                                reterr_error,
                                BUS_ERROR_UNIT_INACTIVE,
                                "Live mounting '%s' on '%s' for unit '%s' cannot be scheduled: unit not active",
                                src,
                                dst,
                                u->id);
        }

        if (unit_active_state(u) == UNIT_REFRESHING) {
                log_unit_debug(u, "Unit already live mounting, refusing further requests.");
                return sd_bus_error_setf(
                                reterr_error,
                                BUS_ERROR_UNIT_BUSY,
                                "Live mounting '%s' on '%s' for unit '%s' cannot be scheduled: another live mount in progress",
                                src,
                                dst,
                                u->id);
        }

        if (u->job) {
                log_unit_debug(u, "Unit already has a job in progress, cannot live mount");
                return sd_bus_error_setf(
                                reterr_error,
                                BUS_ERROR_UNIT_BUSY,
                                "Live mounting '%s' on '%s' for unit '%s' cannot be scheduled: another operation in progress",
                                src,
                                dst,
                                u->id);
        }

        return UNIT_VTABLE(u)->live_mount(u, src, dst, message, flags, options, reterr_error);
}

static const char* const collect_mode_table[_COLLECT_MODE_MAX] = {
        [COLLECT_INACTIVE]           = "inactive",
        [COLLECT_INACTIVE_OR_FAILED] = "inactive-or-failed",
};

DEFINE_STRING_TABLE_LOOKUP(collect_mode, CollectMode);

Unit* unit_has_dependency(const Unit *u, UnitDependencyAtom atom, Unit *other) {
        Unit *i;

        assert(u);

        /* Checks if the unit has a dependency on 'other' with the specified dependency atom. If 'other' is
         * NULL checks if the unit has *any* dependency of that atom. Returns 'other' if found (or if 'other'
         * is NULL the first entry found), or NULL if not found. */

        UNIT_FOREACH_DEPENDENCY(i, u, atom)
                if (!other || other == i)
                        return i;

        return NULL;
}

int unit_get_dependency_array(const Unit *u, UnitDependencyAtom atom, Unit ***ret_array) {
        _cleanup_free_ Unit **array = NULL;
        size_t n = 0;
        Unit *other;

        assert(u);
        assert(ret_array);

        /* Gets a list of units matching a specific atom as array. This is useful when iterating through
         * dependencies while modifying them: the array is an "atomic snapshot" of sorts, that can be read
         * while the dependency table is continuously updated. */

        UNIT_FOREACH_DEPENDENCY(other, u, atom) {
                if (!GREEDY_REALLOC(array, n + 1))
                        return -ENOMEM;

                array[n++] = other;
        }

        *ret_array = TAKE_PTR(array);

        assert(n <= INT_MAX);
        return (int) n;
}

int unit_get_transitive_dependency_set(Unit *u, UnitDependencyAtom atom, Set **ret) {
        _cleanup_set_free_ Set *units = NULL, *queue = NULL;
        Unit *other;
        int r;

        assert(u);
        assert(ret);

        /* Similar to unit_get_dependency_array(), but also search the same dependency in other units. */

        do {
                UNIT_FOREACH_DEPENDENCY(other, u, atom) {
                        r = set_ensure_put(&units, NULL, other);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;
                        r = set_ensure_put(&queue, NULL, other);
                        if (r < 0)
                                return r;
                }
        } while ((u = set_steal_first(queue)));

        *ret = TAKE_PTR(units);
        return 0;
}

int unit_arm_timer(
                Unit *u,
                sd_event_source **source,
                bool relative,
                usec_t usec,
                sd_event_time_handler_t handler) {

        int r;

        assert(u);
        assert(source);
        assert(handler);

        if (*source) {
                if (usec == USEC_INFINITY)
                        return sd_event_source_set_enabled(*source, SD_EVENT_OFF);

                r = (relative ? sd_event_source_set_time_relative : sd_event_source_set_time)(*source, usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(*source, SD_EVENT_ONESHOT);
        }

        if (usec == USEC_INFINITY)
                return 0;

        r = (relative ? sd_event_add_time_relative : sd_event_add_time)(
                        u->manager->event,
                        source,
                        CLOCK_MONOTONIC,
                        usec, 0,
                        handler,
                        u);
        if (r < 0)
                return r;

        const char *d = strjoina(unit_type_to_string(u->type), "-timer");
        (void) sd_event_source_set_description(*source, d);

        return 0;
}

bool unit_passes_filter(Unit *u, char * const *states, char * const *patterns) {
        assert(u);

        if (!strv_isempty(states)) {
                char * const *unit_states = STRV_MAKE(
                                unit_load_state_to_string(u->load_state),
                                unit_active_state_to_string(unit_active_state(u)),
                                unit_sub_state_to_string(u));

                if (!strv_overlap(states, unit_states))
                        return false;
        }

        return strv_fnmatch_or_empty(patterns, u->id, FNM_NOESCAPE);
}

static int unit_get_nice(Unit *u) {
        ExecContext *ec;

        ec = unit_get_exec_context(u);
        return ec ? ec->nice : 0;
}

static uint64_t unit_get_cpu_weight(Unit *u) {
        CGroupContext *cc;

        cc = unit_get_cgroup_context(u);
        return cc ? cgroup_context_cpu_weight(cc, manager_state(u->manager)) : CGROUP_WEIGHT_DEFAULT;
}

int unit_get_exec_quota_stats(Unit *u, ExecContext *c, ExecDirectoryType dt, uint64_t *ret_usage, uint64_t *ret_limit) {
        int r;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *p = NULL, *pp = NULL;

        assert(u);
        assert(c);

        if (c->directories[dt].n_items == 0) {
                *ret_usage = UINT64_MAX;
                *ret_limit = UINT64_MAX;
                return 0;
        }

        ExecDirectoryItem *i = &c->directories[dt].items[0];
        p = path_join(u->manager->prefix[dt], i->path);
        if (!p)
                return log_oom_debug();

        if (exec_directory_is_private(c, dt)) {
                pp = path_join(u->manager->prefix[dt], "private", i->path);
                if (!pp)
                        return log_oom_debug();
        }

        const char *target_dir = pp ?: p;
        fd = open(target_dir, O_PATH | O_CLOEXEC | O_DIRECTORY);
        if (fd < 0)
                return log_unit_debug_errno(u, errno, "Failed to get exec quota stats: %m");

        uint32_t proj_id;
        r = read_fs_xattr_fd(fd, /* ret_xflags= */ NULL, &proj_id);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to get project ID for exec quota stats: %m");

        struct dqblk req;
        r = quota_query_proj_id(fd, proj_id, &req);
        if (r <= 0)
                return log_unit_debug_errno(u, r, "Failed to query project ID for exec quota stats: %m");

        *ret_usage = req.dqb_curspace;
        *ret_limit = req.dqb_bhardlimit * QIF_DQBLKSIZE;

        return r;
}

int unit_compare_priority(Unit *a, Unit *b) {
        int ret;

        ret = CMP(a->type, b->type);
        if (ret != 0)
                return -ret;

        ret = CMP(unit_get_cpu_weight(a), unit_get_cpu_weight(b));
        if (ret != 0)
                return -ret;

        ret = CMP(unit_get_nice(a), unit_get_nice(b));
        if (ret != 0)
                return ret;

        return strcmp(a->id, b->id);
}

const char* unit_log_field(const Unit *u) {
        return MANAGER_IS_SYSTEM(ASSERT_PTR(u)->manager) ? "UNIT=" : "USER_UNIT=";
}

const char* unit_invocation_log_field(const Unit *u) {
        return MANAGER_IS_SYSTEM(ASSERT_PTR(u)->manager) ? "INVOCATION_ID=" : "USER_INVOCATION_ID=";
}

const ActivationDetailsVTable * const activation_details_vtable[_UNIT_TYPE_MAX] = {
        [UNIT_PATH]  = &activation_details_path_vtable,
        [UNIT_TIMER] = &activation_details_timer_vtable,
};

ActivationDetails *activation_details_new(Unit *trigger_unit) {
        _cleanup_free_ ActivationDetails *details = NULL;

        assert(trigger_unit);
        assert(trigger_unit->type != _UNIT_TYPE_INVALID);
        assert(trigger_unit->id);

        details = malloc0(activation_details_vtable[trigger_unit->type]->object_size);
        if (!details)
                return NULL;

        *details = (ActivationDetails) {
                .n_ref = 1,
                .trigger_unit_type = trigger_unit->type,
        };

        details->trigger_unit_name = strdup(trigger_unit->id);
        if (!details->trigger_unit_name)
                return NULL;

        if (ACTIVATION_DETAILS_VTABLE(details)->init)
                ACTIVATION_DETAILS_VTABLE(details)->init(details, trigger_unit);

        return TAKE_PTR(details);
}

static ActivationDetails *activation_details_free(ActivationDetails *details) {
        if (!details)
                return NULL;

        if (ACTIVATION_DETAILS_VTABLE(details)->done)
                ACTIVATION_DETAILS_VTABLE(details)->done(details);

        free(details->trigger_unit_name);

        return mfree(details);
}

void activation_details_serialize(const ActivationDetails *details, FILE *f) {
        if (!details || details->trigger_unit_type == _UNIT_TYPE_INVALID)
                return;

        (void) serialize_item(f, "activation-details-unit-type", unit_type_to_string(details->trigger_unit_type));
        if (details->trigger_unit_name)
                (void) serialize_item(f, "activation-details-unit-name", details->trigger_unit_name);
        if (ACTIVATION_DETAILS_VTABLE(details)->serialize)
                ACTIVATION_DETAILS_VTABLE(details)->serialize(details, f);
}

int activation_details_deserialize(const char *key, const char *value, ActivationDetails **details) {
        int r;

        assert(key);
        assert(value);
        assert(details);

        if (!*details) {
                UnitType t;

                if (!streq(key, "activation-details-unit-type"))
                        return -EINVAL;

                t = unit_type_from_string(value);
                if (t < 0)
                        return t;

                /* The activation details vtable has defined ops only for path and timer units */
                if (!activation_details_vtable[t])
                        return -EINVAL;

                *details = malloc0(activation_details_vtable[t]->object_size);
                if (!*details)
                        return -ENOMEM;

                **details = (ActivationDetails) {
                        .n_ref = 1,
                        .trigger_unit_type = t,
                };

                return 0;
        }

        if (streq(key, "activation-details-unit-name")) {
                r = free_and_strdup(&(*details)->trigger_unit_name, value);
                if (r < 0)
                        return r;

                return 0;
        }

        if (ACTIVATION_DETAILS_VTABLE(*details)->deserialize)
                return ACTIVATION_DETAILS_VTABLE(*details)->deserialize(key, value, details);

        return -EINVAL;
}

int activation_details_append_env(const ActivationDetails *details, char ***strv) {
        int r = 0;

        assert(strv);

        if (!details)
                return 0;

        if (!isempty(details->trigger_unit_name)) {
                char *s = strjoin("TRIGGER_UNIT=", details->trigger_unit_name);
                if (!s)
                        return -ENOMEM;

                r = strv_consume(strv, TAKE_PTR(s));
                if (r < 0)
                        return r;
        }

        if (ACTIVATION_DETAILS_VTABLE(details)->append_env) {
                r = ACTIVATION_DETAILS_VTABLE(details)->append_env(details, strv);
                if (r < 0)
                        return r;
        }

        return r + !isempty(details->trigger_unit_name); /* Return the number of variables added to the env block */
}

int activation_details_append_pair(const ActivationDetails *details, char ***strv) {
        int r = 0;

        assert(strv);

        if (!details)
                return 0;

        if (!isempty(details->trigger_unit_name)) {
                r = strv_extend_many(strv, "trigger_unit", details->trigger_unit_name);
                if (r < 0)
                        return r;
        }

        if (ACTIVATION_DETAILS_VTABLE(details)->append_pair) {
                r = ACTIVATION_DETAILS_VTABLE(details)->append_pair(details, strv);
                if (r < 0)
                        return r;
        }

        return r + !isempty(details->trigger_unit_name); /* Return the number of pairs added to the strv */
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(ActivationDetails, activation_details, activation_details_free);

static const char* const unit_mount_dependency_type_table[_UNIT_MOUNT_DEPENDENCY_TYPE_MAX] = {
        [UNIT_MOUNT_WANTS]    = "WantsMountsFor",
        [UNIT_MOUNT_REQUIRES] = "RequiresMountsFor",
};

DEFINE_STRING_TABLE_LOOKUP(unit_mount_dependency_type, UnitMountDependencyType);

static const char* const oom_policy_table[_OOM_POLICY_MAX] = {
        [OOM_CONTINUE] = "continue",
        [OOM_STOP]     = "stop",
        [OOM_KILL]     = "kill",
};

DEFINE_STRING_TABLE_LOOKUP(oom_policy, OOMPolicy);

UnitDependency unit_mount_dependency_type_to_dependency_type(UnitMountDependencyType t) {
        switch (t) {

        case UNIT_MOUNT_WANTS:
                return UNIT_WANTS;

        case UNIT_MOUNT_REQUIRES:
                return UNIT_REQUIRES;

        default:
                assert_not_reached();
        }
}

int unit_queue_job_check_and_mangle_type(
                Unit *u,
                JobType *type, /* input and output */
                bool reload_if_possible,
                sd_bus_error *reterr_error) {

        JobType t;

        assert(u);
        assert(type);

        t = *type;

        if (reload_if_possible && unit_can_reload(u)) {
                if (t == JOB_RESTART)
                        t = JOB_RELOAD_OR_START;
                else if (t == JOB_TRY_RESTART)
                        t = JOB_TRY_RELOAD;
        }

        /* Our transaction logic allows units not properly loaded to be stopped. But if already dead
         * let's return clear error to caller. */
        if (t == JOB_STOP && UNIT_IS_LOAD_ERROR(u->load_state) && unit_active_state(u) == UNIT_INACTIVE)
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", u->id);

        if ((t == JOB_START && u->refuse_manual_start) ||
            (t == JOB_STOP && u->refuse_manual_stop) ||
            (IN_SET(t, JOB_RESTART, JOB_TRY_RESTART) && (u->refuse_manual_start || u->refuse_manual_stop)) ||
            (t == JOB_RELOAD_OR_START && job_type_collapse(t, u) == JOB_START && u->refuse_manual_start))
                return sd_bus_error_setf(reterr_error,
                                         BUS_ERROR_ONLY_BY_DEPENDENCY,
                                         "Operation refused, unit %s may be requested by dependency only (it is configured to refuse manual start/stop).",
                                         u->id);

        /* dbus-broker issues StartUnit for activation requests, and Type=dbus services automatically
         * gain dependency on dbus.socket. Therefore, if dbus has a pending stop job, the new start
         * job that pulls in dbus again would cause job type conflict. Let's avoid that by rejecting
         * job enqueuing early.
         *
         * Note that unlike signal_activation_request(), we can't use unit_inactive_or_pending()
         * here. StartUnit is a more generic interface, and thus users are allowed to use e.g. systemctl
         * to start Type=dbus services even when dbus is inactive. */
        if (t == JOB_START && u->type == UNIT_SERVICE && SERVICE(u)->type == SERVICE_DBUS)
                FOREACH_STRING(dbus_unit, SPECIAL_DBUS_SOCKET, SPECIAL_DBUS_SERVICE) {
                        Unit *dbus = manager_get_unit(u->manager, dbus_unit);
                        if (dbus && unit_stop_pending(dbus))
                                return sd_bus_error_setf(reterr_error,
                                                         BUS_ERROR_SHUTTING_DOWN,
                                                         "Operation for unit %s refused, D-Bus is shutting down.",
                                                         u->id);
                }

        *type = t;

        return 0;
}

int parse_unit_marker(const char *marker, unsigned *settings, unsigned *mask) {
        bool some_plus_minus = false, b = true;

        assert(marker);
        assert(settings);
        assert(mask);

        if (IN_SET(marker[0], '+', '-')) {
                b = marker[0] == '+';
                marker++;
                some_plus_minus = true;
        }

        UnitMarker m = unit_marker_from_string(marker);
        if (m < 0)
                return -EINVAL;

        /* When +- are not used, last one wins, so reset the bitmask before storing the new result */
        if (!some_plus_minus)
                *settings = 0;

        SET_FLAG(*settings, 1u << m, b);
        SET_FLAG(*mask, 1u << m, true);

        return some_plus_minus;
}

unsigned unit_normalize_markers(unsigned existing_markers, unsigned new_markers) {
        /* Follow the job merging logic: when new markers conflict with existing ones, the new marker
         * takes precedence and clears out conflicting existing markers. Then standard normalization
         * resolves any remaining conflicts. */

        /* New stop wins against all existing markers */
        if (BIT_SET(new_markers, UNIT_MARKER_NEEDS_STOP))
                CLEAR_BITS(existing_markers, UNIT_MARKER_NEEDS_RESTART, UNIT_MARKER_NEEDS_START, UNIT_MARKER_NEEDS_RELOAD);
        /* New start wins against existing stop */
        if (BIT_SET(new_markers, UNIT_MARKER_NEEDS_START))
                CLEAR_BIT(existing_markers, UNIT_MARKER_NEEDS_STOP);
        /* New restart wins against existing start and reload */
        if (BIT_SET(new_markers, UNIT_MARKER_NEEDS_RESTART))
                CLEAR_BITS(existing_markers, UNIT_MARKER_NEEDS_START, UNIT_MARKER_NEEDS_RELOAD);

        unsigned markers = existing_markers | new_markers;

        /* Standard normalization: reload loses against everything */
        if (BIT_SET(markers, UNIT_MARKER_NEEDS_RESTART) || BIT_SET(markers, UNIT_MARKER_NEEDS_START) || BIT_SET(markers, UNIT_MARKER_NEEDS_STOP))
                CLEAR_BIT(markers, UNIT_MARKER_NEEDS_RELOAD);
        /* Stop wins against restart and reload */
        if (BIT_SET(markers, UNIT_MARKER_NEEDS_STOP))
                CLEAR_BITS(markers, UNIT_MARKER_NEEDS_RESTART, UNIT_MARKER_NEEDS_RELOAD);
        /* Start wins against stop */
        if (BIT_SET(markers, UNIT_MARKER_NEEDS_START))
                CLEAR_BIT(markers, UNIT_MARKER_NEEDS_STOP);
        /* Restart wins against start */
        if (BITS_SET(markers, UNIT_MARKER_NEEDS_RESTART, UNIT_MARKER_NEEDS_START))
                CLEAR_BIT(markers, UNIT_MARKER_NEEDS_START);

        return markers;
}
