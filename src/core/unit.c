/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "sd-id128.h"
#include "sd-messages.h"

#include "all-units.h"
#include "alloc-util.h"
#include "bpf-firewall.h"
#include "bpf-foreign.h"
#include "bpf-socket-bind.h"
#include "bus-common-errors.h"
#include "bus-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "core-varlink.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "dropin.h"
#include "escape.h"
#include "execute.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "fileio.h"
#include "format-util.h"
#include "id128-util.h"
#include "install.h"
#include "io-util.h"
#include "label.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "macro.h"
#include "missing_audit.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "set.h"
#include "signal-util.h"
#include "sparse-endian.h"
#include "special.h"
#include "specifier.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "unit-name.h"
#include "unit.h"
#include "user-util.h"
#include "virt.h"
#if BPF_FRAMEWORK
#include "bpf-link.h"
#endif

/* Thresholds for logging at INFO level about resource consumption */
#define MENTIONWORTHY_CPU_NSEC (1 * NSEC_PER_SEC)
#define MENTIONWORTHY_IO_BYTES (1024 * 1024ULL)
#define MENTIONWORTHY_IP_BYTES (0ULL)

/* Thresholds for logging at INFO level about resource consumption */
#define NOTICEWORTHY_CPU_NSEC (10*60 * NSEC_PER_SEC) /* 10 minutes */
#define NOTICEWORTHY_IO_BYTES (10 * 1024 * 1024ULL)  /* 10 MB */
#define NOTICEWORTHY_IP_BYTES (128 * 1024 * 1024ULL) /* 128 MB */

const UnitVTable * const unit_vtable[_UNIT_TYPE_MAX] = {
        [UNIT_SERVICE] = &service_vtable,
        [UNIT_SOCKET] = &socket_vtable,
        [UNIT_TARGET] = &target_vtable,
        [UNIT_DEVICE] = &device_vtable,
        [UNIT_MOUNT] = &mount_vtable,
        [UNIT_AUTOMOUNT] = &automount_vtable,
        [UNIT_SWAP] = &swap_vtable,
        [UNIT_TIMER] = &timer_vtable,
        [UNIT_PATH] = &path_vtable,
        [UNIT_SLICE] = &slice_vtable,
        [UNIT_SCOPE] = &scope_vtable,
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
        u->unit_file_preset = -1;
        u->on_failure_job_mode = JOB_REPLACE;
        u->on_success_job_mode = JOB_FAIL;
        u->cgroup_control_inotify_wd = -1;
        u->cgroup_memory_inotify_wd = -1;
        u->job_timeout = USEC_INFINITY;
        u->job_running_timeout = USEC_INFINITY;
        u->ref_uid = UID_INVALID;
        u->ref_gid = GID_INVALID;
        u->cpu_usage_last = NSEC_INFINITY;
        u->cgroup_invalidated_mask |= CGROUP_MASK_BPF_FIREWALL;
        u->failure_action_exit_status = u->success_action_exit_status = -1;

        u->ip_accounting_ingress_map_fd = -1;
        u->ip_accounting_egress_map_fd = -1;
        for (CGroupIOAccountingMetric i = 0; i < _CGROUP_IO_ACCOUNTING_METRIC_MAX; i++)
                u->io_accounting_last[i] = UINT64_MAX;

        u->ipv4_allow_map_fd = -1;
        u->ipv6_allow_map_fd = -1;
        u->ipv4_deny_map_fd = -1;
        u->ipv6_deny_map_fd = -1;

        u->last_section_private = -1;

        u->start_ratelimit = (RateLimit) { m->default_start_limit_interval, m->default_start_limit_burst };
        u->auto_start_stop_ratelimit = (RateLimit) { 10 * USEC_PER_SEC, 16 };

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

                cc->cpu_accounting = u->manager->default_cpu_accounting;
                cc->io_accounting = u->manager->default_io_accounting;
                cc->blockio_accounting = u->manager->default_blockio_accounting;
                cc->memory_accounting = u->manager->default_memory_accounting;
                cc->tasks_accounting = u->manager->default_tasks_accounting;
                cc->ip_accounting = u->manager->default_ip_accounting;

                if (u->type != UNIT_SLICE)
                        cc->tasks_max = u->manager->default_tasks_max;
        }

        ec = unit_get_exec_context(u);
        if (ec) {
                exec_context_init(ec);

                if (MANAGER_IS_SYSTEM(u->manager))
                        ec->keyring_mode = EXEC_KEYRING_SHARED;
                else {
                        ec->keyring_mode = EXEC_KEYRING_INHERIT;

                        /* User manager might have its umask redefined by PAM or UMask=. In this
                         * case let the units it manages inherit this value by default. They can
                         * still tune this value through their own unit file */
                        (void) get_process_umask(getpid_cached(), &ec->umask);
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
        r = set_ensure_put(&u->aliases, &string_hash_ops, donated_name);
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
                                                    "instance is not set when adding name '%s': %m", text);

                r = unit_name_replace_instance(text, u->instance, &name);
                if (r < 0)
                        return log_unit_debug_errno(u, r,
                                                    "failed to build instance name from '%s': %m", text);
        } else {
                name = strdup(text);
                if (!name)
                        return -ENOMEM;
        }

        if (unit_has_name(u, name))
                return 0;

        if (hashmap_contains(u->manager->units, name))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EEXIST),
                                            "unit already exist when adding name '%s': %m", name);

        if (!unit_name_is_valid(name, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "name '%s' is invalid: %m", name);

        t = unit_name_to_type(name);
        if (t < 0)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "failed to derive unit type from name '%s': %m", name);

        if (u->type != _UNIT_TYPE_INVALID && t != u->type)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "unit type is illegal: u->type(%d) and t(%d) for name '%s': %m",
                                            u->type, t, name);

        r = unit_name_to_instance(name, &instance);
        if (r < 0)
                return log_unit_debug_errno(u, r, "failed to extract instance from name '%s': %m", name);

        if (instance && !unit_type_may_template(t))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL), "templates are not allowed for name '%s': %m", name);

        /* Ensure that this unit either has no instance, or that the instance matches. */
        if (u->type != _UNIT_TYPE_INVALID && !streq_ptr(u->instance, instance))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                            "cannot add name %s, the instances don't match (\"%s\" != \"%s\").",
                                            name, instance, u->instance);

        if (u->id && !unit_type_may_alias(t))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EEXIST),
                                            "cannot add name %s, aliases are not allowed for %s units.",
                                            name, unit_type_to_string(t));

        if (hashmap_size(u->manager->units) >= MANAGER_MAX_NAMES)
                return log_unit_warning_errno(u, SYNTHETIC_ERRNO(E2BIG), "cannot add name, manager has too many units: %m");

        /* Add name to the global hashmap first, because that's easier to undo */
        r = hashmap_put(u->manager->units, name, u);
        if (r < 0)
                return log_unit_debug_errno(u, r, "add unit to hashmap failed for name '%s': %m", text);

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

bool unit_may_gc(Unit *u) {
        UnitActiveState state;
        int r;

        assert(u);

        /* Checks whether the unit is ready to be unloaded for garbage collection.
         * Returns true when the unit may be collected, and false if there's some
         * reason to keep it loaded.
         *
         * References from other units are *not* checked here. Instead, this is done
         * in unit_gc_sweep(), but using markers to properly collect dependency loops.
         */

        if (u->job)
                return false;

        if (u->nop_job)
                return false;

        state = unit_active_state(u);

        /* If the unit is inactive and failed and no job is queued for it, then release its runtime resources */
        if (UNIT_IS_INACTIVE_OR_FAILED(state) &&
            UNIT_VTABLE(u)->release_resources)
                UNIT_VTABLE(u)->release_resources(u);

        if (u->perpetual)
                return false;

        if (sd_bus_track_count(u->bus_track) > 0)
                return false;

        /* But we keep the unit object around for longer when it is referenced or configured to not be gc'ed */
        switch (u->collect_mode) {

        case COLLECT_INACTIVE:
                if (state != UNIT_INACTIVE)
                        return false;

                break;

        case COLLECT_INACTIVE_OR_FAILED:
                if (!IN_SET(state, UNIT_INACTIVE, UNIT_FAILED))
                        return false;

                break;

        default:
                assert_not_reached("Unknown garbage collection mode");
        }

        if (u->cgroup_path) {
                /* If the unit has a cgroup, then check whether there's anything in it. If so, we should stay
                 * around. Units with active processes should never be collected. */

                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path);
                if (r < 0)
                        log_unit_debug_errno(u, r, "Failed to determine whether cgroup %s is empty: %m", empty_to_root(u->cgroup_path));
                if (r <= 0)
                        return false;
        }

        if (UNIT_VTABLE(u)->may_gc && !UNIT_VTABLE(u)->may_gc(u))
                return false;

        return true;
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

static void unit_clear_dependencies(Unit *u) {
        assert(u);

        /* Removes all dependencies configured on u and their reverse dependencies. */

        for (Hashmap *deps; (deps = hashmap_steal_first(u->dependencies));) {

                for (Unit *other; (other = hashmap_steal_first_key(deps));) {
                        Hashmap *other_deps;

                        HASHMAP_FOREACH(other_deps, other->dependencies)
                                hashmap_remove(other_deps, u);

                        unit_add_to_gc_queue(other);
                }

                hashmap_free(deps);
        }

        u->dependencies = hashmap_free(u->dependencies);
}

static void unit_remove_transient(Unit *u) {
        char **i;

        assert(u);

        if (!u->transient)
                return;

        if (u->fragment_path)
                (void) unlink(u->fragment_path);

        STRV_FOREACH(i, u->dropin_paths) {
                _cleanup_free_ char *p = NULL, *pp = NULL;

                p = dirname_malloc(*i); /* Get the drop-in directory from the drop-in file */
                if (!p)
                        continue;

                pp = dirname_malloc(p); /* Get the config directory from the drop-in directory */
                if (!pp)
                        continue;

                /* Only drop transient drop-ins */
                if (!path_equal(u->manager->lookup_paths.transient, pp))
                        continue;

                (void) unlink(*i);
                (void) rmdir(p);
        }
}

static void unit_free_requires_mounts_for(Unit *u) {
        assert(u);

        for (;;) {
                _cleanup_free_ char *path = NULL;

                path = hashmap_steal_first_key(u->requires_mounts_for);
                if (!path)
                        break;
                else {
                        char s[strlen(path) + 1];

                        PATH_FOREACH_PREFIX_MORE(s, path) {
                                char *y;
                                Set *x;

                                x = hashmap_get2(u->manager->units_requiring_mounts_for, s, (void**) &y);
                                if (!x)
                                        continue;

                                (void) set_remove(x, u);

                                if (set_isempty(x)) {
                                        (void) hashmap_remove(u->manager->units_requiring_mounts_for, y);
                                        free(y);
                                        set_free(x);
                                }
                        }
                }
        }

        u->requires_mounts_for = hashmap_free(u->requires_mounts_for);
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

        u->transient_file = safe_fclose(u->transient_file);

        if (!MANAGER_IS_RELOADING(u->manager))
                unit_remove_transient(u);

        bus_unit_send_removed_signal(u);

        unit_done(u);

        unit_dequeue_rewatch_pids(u);

        sd_bus_slot_unref(u->match_bus_slot);
        sd_bus_track_unref(u->bus_track);
        u->deserialized_refs = strv_free(u->deserialized_refs);
        u->pending_freezer_message = sd_bus_message_unref(u->pending_freezer_message);

        unit_free_requires_mounts_for(u);

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


        fdset_free(u->initial_socket_bind_link_fds);
#if BPF_FRAMEWORK
        bpf_link_free(u->ipv4_socket_bind_link);
        bpf_link_free(u->ipv6_socket_bind_link);
#endif

        unit_release_cgroup(u);

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

        bpf_firewall_close(u);

        hashmap_free(u->bpf_foreign_by_key);

        bpf_program_unref(u->bpf_device_control_installed);

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

        set_free_free(u->aliases);
        free(u->id);

        return mfree(u);
}

FreezerState unit_freezer_state(Unit *u) {
        assert(u);

        return u->freezer_state;
}

int unit_freezer_state_kernel(Unit *u, FreezerState *ret) {
        char *values[1] = {};
        int r;

        assert(u);

        r = cg_get_keyed_attribute(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, "cgroup.events",
                                   STRV_MAKE("frozen"), values);
        if (r < 0)
                return r;

        r = _FREEZER_STATE_INVALID;

        if (values[0])  {
                if (streq(values[0], "0"))
                        r = FREEZER_RUNNING;
                else if (streq(values[0], "1"))
                        r = FREEZER_FROZEN;
        }

        free(values[0]);
        *ret = r;

        return 0;
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
        other->aliases = set_free_free(other->aliases);

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
         * First make some room in the per dependency type hashmaps. Using the summed size of both unit's
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

static void unit_maybe_warn_about_dependency(
                Unit *u,
                const char *other_id,
                UnitDependency dependency) {

        assert(u);

        /* Only warn about some unit types */
        if (!IN_SET(dependency,
                    UNIT_CONFLICTS,
                    UNIT_CONFLICTED_BY,
                    UNIT_BEFORE,
                    UNIT_AFTER,
                    UNIT_ON_SUCCESS,
                    UNIT_ON_FAILURE,
                    UNIT_TRIGGERS,
                    UNIT_TRIGGERED_BY))
                return;

        if (streq_ptr(u->id, other_id))
                log_unit_warning(u, "Dependency %s=%s dropped", unit_dependency_to_string(dependency), u->id);
        else
                log_unit_warning(u, "Dependency %s=%s dropped, merged into %s", unit_dependency_to_string(dependency), strna(other_id), u->id);
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

static int unit_add_dependency_hashmap(
                Hashmap **dependencies,
                UnitDependency d,
                Unit *other,
                UnitDependencyMask origin_mask,
                UnitDependencyMask destination_mask) {

        Hashmap *per_type;
        int r;

        assert(dependencies);
        assert(other);
        assert(origin_mask < _UNIT_DEPENDENCY_MASK_FULL);
        assert(destination_mask < _UNIT_DEPENDENCY_MASK_FULL);
        assert(origin_mask > 0 || destination_mask > 0);

        /* Ensure the top-level dependency hashmap exists that maps UnitDependency → Hashmap(Unit* →
         * UnitDependencyInfo) */
        r = hashmap_ensure_allocated(dependencies, NULL);
        if (r < 0)
                return r;

        /* Acquire the inner hashmap, that maps Unit* → UnitDependencyInfo, for the specified dependency
         * type, and if it's missing allocate it and insert it. */
        per_type = hashmap_get(*dependencies, UNIT_DEPENDENCY_TO_PTR(d));
        if (!per_type) {
                per_type = hashmap_new(NULL);
                if (!per_type)
                        return -ENOMEM;

                r = hashmap_put(*dependencies, UNIT_DEPENDENCY_TO_PTR(d), per_type);
                if (r < 0) {
                        hashmap_free(per_type);
                        return r;
                }
        }

        return unit_per_dependency_type_hashmap_update(per_type, other, origin_mask, destination_mask);
}

static void unit_merge_dependencies(
                Unit *u,
                Unit *other) {

        int r;

        assert(u);
        assert(other);

        if (u == other)
                return;

        for (;;) {
                _cleanup_(hashmap_freep) Hashmap *other_deps = NULL;
                UnitDependencyInfo di_back;
                Unit *back;
                void *dt; /* Actually of type UnitDependency, except that we don't bother casting it here,
                           * since the hashmaps all want it as void pointer. */

                /* Let's focus on one dependency type at a time, that 'other' has defined. */
                other_deps = hashmap_steal_first_key_and_value(other->dependencies, &dt);
                if (!other_deps)
                        break; /* done! */

                /* Now iterate through all dependencies of this dependency type, of 'other'. We refer to the
                 * referenced units as 'back'. */
                HASHMAP_FOREACH_KEY(di_back.data, back, other_deps) {
                        Hashmap *back_deps;
                        void *back_dt;

                        if (back == u) {
                                /* This is a dependency pointing back to the unit we want to merge with?
                                 * Suppress it (but warn) */
                                unit_maybe_warn_about_dependency(u, other->id, UNIT_DEPENDENCY_FROM_PTR(dt));
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
                }

                /* Now all references towards 'other' of the current type 'dt' are corrected to point to
                 * 'u'. Lets's now move the deps of type 'dt' from 'other' to 'u'. First, let's try to move
                 * them per type wholesale. */
                r = hashmap_put(u->dependencies, dt, other_deps);
                if (r == -EEXIST) {
                        Hashmap *deps;

                        /* The target unit already has dependencies of this type, let's then merge this individually. */

                        assert_se(deps = hashmap_get(u->dependencies, dt));

                        for (;;) {
                                UnitDependencyInfo di_move;

                                /* Get first dep */
                                di_move.data = hashmap_steal_first_key_and_value(other_deps, (void**) &back);
                                if (!di_move.data)
                                        break; /* done */
                                if (back == u) {
                                        /* Would point back to us, ignore */
                                        unit_maybe_warn_about_dependency(u, other->id, UNIT_DEPENDENCY_FROM_PTR(dt));
                                        continue;
                                }

                                assert_se(unit_per_dependency_type_hashmap_update(deps, back, di_move.origin_mask, di_move.destination_mask) >= 0);
                        }
                } else {
                        assert_se(r >= 0);
                        TAKE_PTR(other_deps);

                        if (hashmap_remove(other_deps, u))
                                unit_maybe_warn_about_dependency(u, other->id, UNIT_DEPENDENCY_FROM_PTR(dt));
                }
        }

        other->dependencies = hashmap_free(other->dependencies);
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

        /* Merge names */
        r = unit_merge_names(u, other);
        if (r < 0)
                return r;

        /* Redirect all references */
        while (other->refs_by_target)
                unit_ref_set(other->refs_by_target, other->refs_by_target->source, u);

        /* Merge dependencies */
        unit_merge_dependencies(u, other);

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

        if (c->working_directory && !c->working_directory_missing_ok) {
                r = unit_require_mounts_for(u, c->working_directory, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        if (c->root_directory) {
                r = unit_require_mounts_for(u, c->root_directory, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        if (c->root_image) {
                r = unit_require_mounts_for(u, c->root_image, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                if (!u->manager->prefix[dt])
                        continue;

                char **dp;
                STRV_FOREACH(dp, c->directories[dt].paths) {
                        _cleanup_free_ char *p = NULL;

                        p = path_join(u->manager->prefix[dt], *dp);
                        if (!p)
                                return -ENOMEM;

                        r = unit_require_mounts_for(u, p, UNIT_DEPENDENCY_FILE);
                        if (r < 0)
                                return r;
                }
        }

        if (!MANAGER_IS_SYSTEM(u->manager))
                return 0;

        /* For the following three directory types we need write access, and /var/ is possibly on the root
         * fs. Hence order after systemd-remount-fs.service, to ensure things are writable. */
        if (!strv_isempty(c->directories[EXEC_DIRECTORY_STATE].paths) ||
            !strv_isempty(c->directories[EXEC_DIRECTORY_CACHE].paths) ||
            !strv_isempty(c->directories[EXEC_DIRECTORY_LOGS].paths)) {
                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_REMOUNT_FS_SERVICE, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        if (c->private_tmp) {

                /* FIXME: for now we make a special case for /tmp and add a weak dependency on
                 * tmp.mount so /tmp being masked is supported. However there's no reason to treat
                 * /tmp specifically and masking other mount units should be handled more
                 * gracefully too, see PR#16894. */
                r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_WANTS, "tmp.mount", true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;

                r = unit_require_mounts_for(u, "/var/tmp", UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;

                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_TMPFILES_SETUP_SERVICE, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        if (c->root_image) {
                /* We need to wait for /dev/loopX to appear when doing RootImage=, hence let's add an
                 * implicit dependency on udev */

                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_UDEVD_SERVICE, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        }

        if (!IN_SET(c->std_output,
                    EXEC_OUTPUT_JOURNAL, EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
                    EXEC_OUTPUT_KMSG, EXEC_OUTPUT_KMSG_AND_CONSOLE) &&
            !IN_SET(c->std_error,
                    EXEC_OUTPUT_JOURNAL, EXEC_OUTPUT_JOURNAL_AND_CONSOLE,
                    EXEC_OUTPUT_KMSG, EXEC_OUTPUT_KMSG_AND_CONSOLE) &&
            !c->log_namespace)
                return 0;

        /* If syslog or kernel logging is requested (or log namespacing is), make sure our own logging daemon
         * is run first. */

        if (c->log_namespace) {
                _cleanup_free_ char *socket_unit = NULL, *varlink_socket_unit = NULL;

                r = unit_name_build_from_type("systemd-journald", c->log_namespace, UNIT_SOCKET, &socket_unit);
                if (r < 0)
                        return r;

                r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_REQUIRES, socket_unit, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;

                r = unit_name_build_from_type("systemd-journald-varlink", c->log_namespace, UNIT_SOCKET, &varlink_socket_unit);
                if (r < 0)
                        return r;

                r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_REQUIRES, varlink_socket_unit, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        return r;
        } else
                r = unit_add_dependency_by_name(u, UNIT_AFTER, SPECIAL_JOURNALD_SOCKET, true, UNIT_DEPENDENCY_FILE);
        if (r < 0)
                return r;

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

        if (u->load_state == UNIT_STUB) {
                if (fragment_required)
                        return -ENOENT;

                u->load_state = UNIT_LOADED;
        }

        /* Load drop-in directory data. If u is an alias, we might be reloading the
         * target unit needlessly. But we cannot be sure which drops-ins have already
         * been loaded and which not, at least without doing complicated book-keeping,
         * so let's always reread all drop-ins. */
        r = unit_load_dropin(unit_follow_merge(u));
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
        Manager *m = u->manager;

        assert(u);

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
        if (slice)
                return unit_add_two_dependencies(u, UNIT_AFTER, UNIT_REQUIRES, slice, true, mask);

        if (unit_has_name(u, SPECIAL_ROOT_SLICE))
                return 0;

        return unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_REQUIRES, SPECIAL_ROOT_SLICE, true, mask);
}

static int unit_add_mount_dependencies(Unit *u) {
        UnitDependencyInfo di;
        const char *path;
        int r;

        assert(u);

        HASHMAP_FOREACH_KEY(di.data, path, u->requires_mounts_for) {
                char prefix[strlen(path) + 1];

                PATH_FOREACH_PREFIX_MORE(prefix, path) {
                        _cleanup_free_ char *p = NULL;
                        Unit *m;

                        r = unit_name_from_path(prefix, ".mount", &p);
                        if (IN_SET(r, -EINVAL, -ENAMETOOLONG))
                                continue; /* If the path cannot be converted to a mount unit name, then it's
                                           * not manageable as a unit by systemd, and hence we don't need a
                                           * dependency on it. Let's thus silently ignore the issue. */
                        if (r < 0)
                                return r;

                        m = manager_get_unit(u->manager, p);
                        if (!m) {
                                /* Make sure to load the mount unit if it exists. If so the dependencies on
                                 * this unit will be added later during the loading of the mount unit. */
                                (void) manager_load_unit_prepare(u->manager, p, NULL, NULL, &m);
                                continue;
                        }
                        if (m == u)
                                continue;

                        if (m->load_state != UNIT_LOADED)
                                continue;

                        r = unit_add_dependency(u, UNIT_AFTER, m, true, di.origin_mask);
                        if (r < 0)
                                return r;

                        if (m->fragment_path) {
                                r = unit_add_dependency(u, UNIT_REQUIRES, m, true, di.origin_mask);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

static int unit_add_oomd_dependencies(Unit *u) {
        CGroupContext *c;
        bool wants_oomd;
        int r;

        assert(u);

        if (!u->default_dependencies)
                return 0;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        wants_oomd = (c->moom_swap == MANAGED_OOM_KILL || c->moom_mem_pressure == MANAGED_OOM_KILL);
        if (!wants_oomd)
                return 0;

        r = unit_add_two_dependencies_by_name(u, UNIT_AFTER, UNIT_WANTS, "systemd-oomd.service", true, UNIT_DEPENDENCY_FILE);
        if (r < 0)
                return r;

        return 0;
}

static int unit_add_startup_units(Unit *u) {
        CGroupContext *c;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        if (c->startup_cpu_shares == CGROUP_CPU_SHARES_INVALID &&
            c->startup_io_weight == CGROUP_WEIGHT_INVALID &&
            c->startup_blockio_weight == CGROUP_BLKIO_WEIGHT_INVALID)
                return 0;

        return set_ensure_put(&u->manager->startup_units, NULL, u);
}

static int unit_validate_on_failure_job_mode(
                Unit *u,
                const char *job_mode_setting,
                JobMode job_mode,
                const char *dependency_name,
                UnitDependencyAtom atom) {

        Unit *other, *found = NULL;

        if (job_mode != JOB_ISOLATE)
                return 0;

        UNIT_FOREACH_DEPENDENCY(other, u, atom) {
                if (!found)
                        found = other;
                else if (found != other)
                        return log_unit_error_errno(
                                        u, SYNTHETIC_ERRNO(ENOEXEC),
                                        "More than one %s dependencies specified but %sisolate set. Refusing.",
                                        dependency_name, job_mode_setting);
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

                r = unit_validate_on_failure_job_mode(u, "OnSuccessJobMode=", u->on_success_job_mode, "OnSuccess=", UNIT_ATOM_ON_SUCCESS);
                if (r < 0)
                        goto fail;

                r = unit_validate_on_failure_job_mode(u, "OnFailureJobMode=", u->on_failure_job_mode, "OnFailure=", UNIT_ATOM_ON_FAILURE);
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
                                         u->manager->unit_log_field,
                                         u->id,
                                         u->manager->invocation_log_field,
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

        dual_timestamp_get(&u->condition_timestamp);

        r = manager_get_effective_environment(u->manager, &env);
        if (r < 0) {
                log_unit_error_errno(u, r, "Failed to determine effective environment: %m");
                u->condition_result = CONDITION_ERROR;
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

        dual_timestamp_get(&u->assert_timestamp);

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

void unit_status_printf(Unit *u, StatusType status_type, const char *status, const char *format, const char *ident) {
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

        emergency_action(u->manager, u->start_limit_action,
                         EMERGENCY_ACTION_IS_WATCHDOG|EMERGENCY_ACTION_WARN,
                         u->reboot_arg, -1, reason);

        return -ECANCELED;
}

bool unit_shall_confirm_spawn(Unit *u) {
        assert(u);

        if (manager_is_confirm_spawn_disabled(u->manager))
                return false;

        /* For some reasons units remaining in the same process group
         * as PID 1 fail to acquire the console even if it's not used
         * by any process. So skip the confirmation question for them. */
        return !unit_get_exec_context(u)->same_pgrp;
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
 *         -EALREADY:   Unit is already started.
 *         -ECOMM:      Condition failed
 *         -EAGAIN:     An operation is already in progress. Retry later.
 *
 * Errors that are real errors:
 *         -EBADR:      This unit type does not support starting.
 *         -ECANCELED:  Start limit hit, too many requests for now
 *         -EPROTO:     Assert failed
 *         -EINVAL:     Unit not loaded
 *         -EOPNOTSUPP: Unit type not supported
 *         -ENOLINK:    The necessary dependencies are not fulfilled.
 *         -ESTALE:     This unit has been started before and can't be started a second time
 *         -ENOENT:     This is a triggering unit and unit to trigger is not loaded
 */
int unit_start(Unit *u) {
        UnitActiveState state;
        Unit *following;

        assert(u);

        /* Check start rate limiting early so that failure conditions don't cause us to enter a busy loop. */
        if (UNIT_VTABLE(u)->test_start_limit) {
                int r = UNIT_VTABLE(u)->test_start_limit(u);
                if (r < 0)
                        return r;
        }

        /* If this is already started, then this will succeed. Note that this will even succeed if this unit
         * is not startable by the user. This is relied on to detect when we need to wait for units and when
         * waiting is finished. */
        state = unit_active_state(u);
        if (UNIT_IS_ACTIVE_OR_RELOADING(state))
                return -EALREADY;
        if (state == UNIT_MAINTENANCE)
                return -EAGAIN;

        /* Units that aren't loaded cannot be started */
        if (u->load_state != UNIT_LOADED)
                return -EINVAL;

        /* Refuse starting scope units more than once */
        if (UNIT_VTABLE(u)->once_only && dual_timestamp_is_set(&u->inactive_enter_timestamp))
                return -ESTALE;

        /* If the conditions failed, don't do anything at all. If we already are activating this call might
         * still be useful to speed up activation in case there is some hold-off time, but we don't want to
         * recheck the condition in that case. */
        if (state != UNIT_ACTIVATING &&
            !unit_test_condition(u))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(ECOMM), "Starting requested but condition failed. Not starting unit.");

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
         * dependencies might not be in effect anymore, due to a reload or due to a failed condition. */
        if (!unit_verify_deps(u))
                return -ENOLINK;

        /* Forward to the main object, if we aren't it. */
        following = unit_following(u);
        if (following) {
                log_unit_debug(u, "Redirecting start request from %s to %s.", u->id, following->id);
                return unit_start(following);
        }

        /* If it is stopped, but we cannot start it, then fail */
        if (!UNIT_VTABLE(u)->start)
                return -EBADR;

        /* We don't suppress calls to ->start() here when we are already starting, to allow this request to
         * be used as a "hurry up" call, for example when the unit is in some "auto restart" state where it
         * waits for a holdoff timer to elapse before it will start again. */

        unit_add_to_dbus_queue(u);
        unit_cgroup_freezer_action(u, FREEZER_THAW);

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

        if (!UNIT_VTABLE(u)->stop)
                return -EBADR;

        unit_add_to_dbus_queue(u);
        unit_cgroup_freezer_action(u, FREEZER_THAW);

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
                return -EAGAIN;

        if (state != UNIT_ACTIVE)
                return log_unit_warning_errno(u, SYNTHETIC_ERRNO(ENOEXEC), "Unit cannot be reloaded because it is inactive.");

        following = unit_following(u);
        if (following) {
                log_unit_debug(u, "Redirecting reload request from %s to %s.", u->id, following->id);
                return unit_reload(following);
        }

        unit_add_to_dbus_queue(u);

        if (!UNIT_VTABLE(u)->reload) {
                /* Unit doesn't have a reload function, but we need to propagate the reload anyway */
                unit_notify(u, unit_active_state(u), unit_active_state(u), 0);
                return 0;
        }

        unit_cgroup_freezer_action(u, FREEZER_THAW);

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
                        if (*ret_culprit)
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

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_RETROACTIVE_START_REPLACE) /* Requires= + BindsTo= */
                if (!unit_has_dependency(u, UNIT_ATOM_AFTER, other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_START, other, JOB_REPLACE, NULL, NULL, NULL);

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_RETROACTIVE_START_FAIL) /* Wants= */
                if (!unit_has_dependency(u, UNIT_ATOM_AFTER, other) &&
                    !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_START, other, JOB_FAIL, NULL, NULL, NULL);

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_RETROACTIVE_STOP_ON_START) /* Conflicts= (and inverse) */
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_STOP, other, JOB_REPLACE, NULL, NULL, NULL);
}

static void retroactively_stop_dependencies(Unit *u) {
        Unit *other;

        assert(u);
        assert(UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(u)));

        /* Pull down units which are bound to us recursively if enabled */
        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_RETROACTIVE_STOP_ON_STOP) /* BoundBy= */
                if (!UNIT_IS_INACTIVE_OR_DEACTIVATING(unit_active_state(other)))
                        manager_add_job(u->manager, JOB_STOP, other, JOB_REPLACE, NULL, NULL, NULL);
}

void unit_start_on_failure(
                Unit *u,
                const char *dependency_name,
                UnitDependencyAtom atom,
                JobMode job_mode) {

        bool logged = false;
        Unit *other;
        int r;

        assert(u);
        assert(dependency_name);
        assert(IN_SET(atom, UNIT_ATOM_ON_SUCCESS, UNIT_ATOM_ON_FAILURE));

        /* Act on OnFailure= and OnSuccess= dependencies */

        UNIT_FOREACH_DEPENDENCY(other, u, atom) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!logged) {
                        log_unit_info(u, "Triggering %s dependencies.", dependency_name);
                        logged = true;
                }

                r = manager_add_job(u->manager, JOB_START, other, job_mode, NULL, &error, NULL);
                if (r < 0)
                        log_unit_warning_errno(
                                        u, r, "Failed to enqueue %s job, ignoring: %s",
                                        dependency_name, bus_error_message(&error, r));
        }

        if (logged)
                log_unit_debug(u, "Triggering %s dependencies done.", dependency_name);
}

void unit_trigger_notify(Unit *u) {
        Unit *other;

        assert(u);

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_TRIGGERED_BY)
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
        struct iovec iovec[1 + _CGROUP_IP_ACCOUNTING_METRIC_MAX + _CGROUP_IO_ACCOUNTING_METRIC_MAX + 4];
        bool any_traffic = false, have_ip_accounting = false, any_io = false, have_io_accounting = false;
        _cleanup_free_ char *igress = NULL, *egress = NULL, *rr = NULL, *wr = NULL;
        int log_level = LOG_DEBUG; /* May be raised if resources consumed over a threshold */
        size_t n_message_parts = 0, n_iovec = 0;
        char* message_parts[1 + 2 + 2 + 1], *t;
        nsec_t nsec = NSEC_INFINITY;
        int r;
        const char* const ip_fields[_CGROUP_IP_ACCOUNTING_METRIC_MAX] = {
                [CGROUP_IP_INGRESS_BYTES]   = "IP_METRIC_INGRESS_BYTES",
                [CGROUP_IP_INGRESS_PACKETS] = "IP_METRIC_INGRESS_PACKETS",
                [CGROUP_IP_EGRESS_BYTES]    = "IP_METRIC_EGRESS_BYTES",
                [CGROUP_IP_EGRESS_PACKETS]  = "IP_METRIC_EGRESS_PACKETS",
        };
        const char* const io_fields[_CGROUP_IO_ACCOUNTING_METRIC_MAX] = {
                [CGROUP_IO_READ_BYTES]       = "IO_METRIC_READ_BYTES",
                [CGROUP_IO_WRITE_BYTES]      = "IO_METRIC_WRITE_BYTES",
                [CGROUP_IO_READ_OPERATIONS]  = "IO_METRIC_READ_OPERATIONS",
                [CGROUP_IO_WRITE_OPERATIONS] = "IO_METRIC_WRITE_OPERATIONS",
        };

        assert(u);

        /* Invoked whenever a unit enters failed or dead state. Logs information about consumed resources if resource
         * accounting was enabled for a unit. It does this in two ways: a friendly human readable string with reduced
         * information and the complete data in structured fields. */

        (void) unit_get_cpu_usage(u, &nsec);
        if (nsec != NSEC_INFINITY) {
                char buf[FORMAT_TIMESPAN_MAX] = "";

                /* Format the CPU time for inclusion in the structured log message */
                if (asprintf(&t, "CPU_USAGE_NSEC=%" PRIu64, nsec) < 0) {
                        r = log_oom();
                        goto finish;
                }
                iovec[n_iovec++] = IOVEC_MAKE_STRING(t);

                /* Format the CPU time for inclusion in the human language message string */
                format_timespan(buf, sizeof(buf), nsec / NSEC_PER_USEC, USEC_PER_MSEC);
                t = strjoin("consumed ", buf, " CPU time");
                if (!t) {
                        r = log_oom();
                        goto finish;
                }

                message_parts[n_message_parts++] = t;

                log_level = raise_level(log_level,
                                        nsec > NOTICEWORTHY_CPU_NSEC,
                                        nsec > MENTIONWORTHY_CPU_NSEC);
        }

        for (CGroupIOAccountingMetric k = 0; k < _CGROUP_IO_ACCOUNTING_METRIC_MAX; k++) {
                char buf[FORMAT_BYTES_MAX] = "";
                uint64_t value = UINT64_MAX;

                assert(io_fields[k]);

                (void) unit_get_io_accounting(u, k, k > 0, &value);
                if (value == UINT64_MAX)
                        continue;

                have_io_accounting = true;
                if (value > 0)
                        any_io = true;

                /* Format IO accounting data for inclusion in the structured log message */
                if (asprintf(&t, "%s=%" PRIu64, io_fields[k], value) < 0) {
                        r = log_oom();
                        goto finish;
                }
                iovec[n_iovec++] = IOVEC_MAKE_STRING(t);

                /* Format the IO accounting data for inclusion in the human language message string, but only
                 * for the bytes counters (and not for the operations counters) */
                if (k == CGROUP_IO_READ_BYTES) {
                        assert(!rr);
                        rr = strjoin("read ", format_bytes(buf, sizeof(buf), value), " from disk");
                        if (!rr) {
                                r = log_oom();
                                goto finish;
                        }
                } else if (k == CGROUP_IO_WRITE_BYTES) {
                        assert(!wr);
                        wr = strjoin("written ", format_bytes(buf, sizeof(buf), value), " to disk");
                        if (!wr) {
                                r = log_oom();
                                goto finish;
                        }
                }

                if (IN_SET(k, CGROUP_IO_READ_BYTES, CGROUP_IO_WRITE_BYTES))
                        log_level = raise_level(log_level,
                                                value > MENTIONWORTHY_IO_BYTES,
                                                value > NOTICEWORTHY_IO_BYTES);
        }

        if (have_io_accounting) {
                if (any_io) {
                        if (rr)
                                message_parts[n_message_parts++] = TAKE_PTR(rr);
                        if (wr)
                                message_parts[n_message_parts++] = TAKE_PTR(wr);

                } else {
                        char *k;

                        k = strdup("no IO");
                        if (!k) {
                                r = log_oom();
                                goto finish;
                        }

                        message_parts[n_message_parts++] = k;
                }
        }

        for (CGroupIPAccountingMetric m = 0; m < _CGROUP_IP_ACCOUNTING_METRIC_MAX; m++) {
                char buf[FORMAT_BYTES_MAX] = "";
                uint64_t value = UINT64_MAX;

                assert(ip_fields[m]);

                (void) unit_get_ip_accounting(u, m, &value);
                if (value == UINT64_MAX)
                        continue;

                have_ip_accounting = true;
                if (value > 0)
                        any_traffic = true;

                /* Format IP accounting data for inclusion in the structured log message */
                if (asprintf(&t, "%s=%" PRIu64, ip_fields[m], value) < 0) {
                        r = log_oom();
                        goto finish;
                }
                iovec[n_iovec++] = IOVEC_MAKE_STRING(t);

                /* Format the IP accounting data for inclusion in the human language message string, but only for the
                 * bytes counters (and not for the packets counters) */
                if (m == CGROUP_IP_INGRESS_BYTES) {
                        assert(!igress);
                        igress = strjoin("received ", format_bytes(buf, sizeof(buf), value), " IP traffic");
                        if (!igress) {
                                r = log_oom();
                                goto finish;
                        }
                } else if (m == CGROUP_IP_EGRESS_BYTES) {
                        assert(!egress);
                        egress = strjoin("sent ", format_bytes(buf, sizeof(buf), value), " IP traffic");
                        if (!egress) {
                                r = log_oom();
                                goto finish;
                        }
                }

                if (IN_SET(m, CGROUP_IP_INGRESS_BYTES, CGROUP_IP_EGRESS_BYTES))
                        log_level = raise_level(log_level,
                                                value > MENTIONWORTHY_IP_BYTES,
                                                value > NOTICEWORTHY_IP_BYTES);
        }

        /* This check is here because it is the earliest point following all possible log_level assignments. If
         * log_level is assigned anywhere after this point, move this check. */
        if (!unit_log_level_test(u, log_level)) {
                r = 0;
                goto finish;
        }

        if (have_ip_accounting) {
                if (any_traffic) {
                        if (igress)
                                message_parts[n_message_parts++] = TAKE_PTR(igress);
                        if (egress)
                                message_parts[n_message_parts++] = TAKE_PTR(egress);

                } else {
                        char *k;

                        k = strdup("no IP traffic");
                        if (!k) {
                                r = log_oom();
                                goto finish;
                        }

                        message_parts[n_message_parts++] = k;
                }
        }

        /* Is there any accounting data available at all? */
        if (n_iovec == 0) {
                r = 0;
                goto finish;
        }

        if (n_message_parts == 0)
                t = strjoina("MESSAGE=", u->id, ": Completed.");
        else {
                _cleanup_free_ char *joined = NULL;

                message_parts[n_message_parts] = NULL;

                joined = strv_join(message_parts, ", ");
                if (!joined) {
                        r = log_oom();
                        goto finish;
                }

                joined[0] = ascii_toupper(joined[0]);
                t = strjoina("MESSAGE=", u->id, ": ", joined, ".");
        }

        /* The following four fields we allocate on the stack or are static strings, we hence don't want to free them,
         * and hence don't increase n_iovec for them */
        iovec[n_iovec] = IOVEC_MAKE_STRING(t);
        iovec[n_iovec + 1] = IOVEC_MAKE_STRING("MESSAGE_ID=" SD_MESSAGE_UNIT_RESOURCES_STR);

        t = strjoina(u->manager->unit_log_field, u->id);
        iovec[n_iovec + 2] = IOVEC_MAKE_STRING(t);

        t = strjoina(u->manager->invocation_log_field, u->invocation_id_string);
        iovec[n_iovec + 3] = IOVEC_MAKE_STRING(t);

        log_unit_struct_iovec(u, log_level, iovec, n_iovec + 4);
        r = 0;

finish:
        for (size_t i = 0; i < n_message_parts; i++)
                free(message_parts[i]);

        for (size_t i = 0; i < n_iovec; i++)
                free(iovec[i].iov_base);

        return r;

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

        if (u->type != UNIT_SERVICE)
                return;

        /* Write audit record if we have just finished starting up */
        manager_send_unit_audit(u->manager, u, AUDIT_SERVICE_START, true);
        u->in_audit = true;
}

static void unit_emit_audit_stop(Unit *u, UnitActiveState state) {
        assert(u);

        if (u->type != UNIT_SERVICE)
                return;

        if (u->in_audit) {
                /* Write audit record if we have just finished shutting down */
                manager_send_unit_audit(u->manager, u, AUDIT_SERVICE_STOP, state == UNIT_INACTIVE);
                u->in_audit = false;
        } else {
                /* Hmm, if there was no start record written write it now, so that we always have a nice pair */
                manager_send_unit_audit(u->manager, u, AUDIT_SERVICE_START, state == UNIT_INACTIVE);

                if (state == UNIT_INACTIVE)
                        manager_send_unit_audit(u->manager, u, AUDIT_SERVICE_STOP, true);
        }
}

static bool unit_process_job(Job *j, UnitActiveState ns, UnitNotifyFlags flags) {
        bool unexpected = false;
        JobResult result;

        assert(j);

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
                        job_finish_and_invalidate(j, JOB_DONE, true, false);
                else if (j->state == JOB_RUNNING && ns != UNIT_ACTIVATING) {
                        unexpected = true;

                        if (UNIT_IS_INACTIVE_OR_FAILED(ns)) {
                                if (ns == UNIT_FAILED)
                                        result = JOB_FAILED;
                                else
                                        result = JOB_DONE;

                                job_finish_and_invalidate(j, result, true, false);
                        }
                }

                break;

        case JOB_RELOAD:
        case JOB_RELOAD_OR_START:
        case JOB_TRY_RELOAD:

                if (j->state == JOB_RUNNING) {
                        if (ns == UNIT_ACTIVE)
                                job_finish_and_invalidate(j, (flags & UNIT_NOTIFY_RELOAD_FAILURE) ? JOB_FAILED : JOB_DONE, true, false);
                        else if (!IN_SET(ns, UNIT_ACTIVATING, UNIT_RELOADING)) {
                                unexpected = true;

                                if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                                        job_finish_and_invalidate(j, ns == UNIT_FAILED ? JOB_FAILED : JOB_DONE, true, false);
                        }
                }

                break;

        case JOB_STOP:
        case JOB_RESTART:
        case JOB_TRY_RESTART:

                if (UNIT_IS_INACTIVE_OR_FAILED(ns))
                        job_finish_and_invalidate(j, JOB_DONE, true, false);
                else if (j->state == JOB_RUNNING && ns != UNIT_DEACTIVATING) {
                        unexpected = true;
                        job_finish_and_invalidate(j, JOB_FAILED, true, false);
                }

                break;

        default:
                assert_not_reached("Job type unknown");
        }

        return unexpected;
}

void unit_notify(Unit *u, UnitActiveState os, UnitActiveState ns, UnitNotifyFlags flags) {
        const char *reason;
        Manager *m;

        assert(u);
        assert(os < _UNIT_ACTIVE_STATE_MAX);
        assert(ns < _UNIT_ACTIVE_STATE_MAX);

        /* Note that this is called for all low-level state changes, even if they might map to the same high-level
         * UnitActiveState! That means that ns == os is an expected behavior here. For example: if a mount point is
         * remounted this function will be called too! */

        m = u->manager;

        /* Let's enqueue the change signal early. In case this unit has a job associated we want that this unit is in
         * the bus queue, so that any job change signal queued will force out the unit change signal first. */
        unit_add_to_dbus_queue(u);

        /* Update systemd-oomd on the property/state change */
        if (os != ns) {
                /* Always send an update if the unit is going into an inactive state so systemd-oomd knows to stop
                 * monitoring.
                 * Also send an update whenever the unit goes active; this is to handle a case where an override file
                 * sets one of the ManagedOOM*= properties to "kill", then later removes it. systemd-oomd needs to
                 * know to stop monitoring when the unit changes from "kill" -> "auto" on daemon-reload, but we don't
                 * have the information on the property. Thus, indiscriminately send an update. */
                if (UNIT_IS_INACTIVE_OR_FAILED(ns) || UNIT_IS_ACTIVE_OR_RELOADING(ns))
                        (void) manager_varlink_send_managed_oom_update(u);
        }

        /* Update timestamps for state changes */
        if (!MANAGER_IS_RELOADING(m)) {
                dual_timestamp_get(&u->state_change_timestamp);

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
                         (1u << UNIT_MARKER_NEEDS_RELOAD)|(1u << UNIT_MARKER_NEEDS_RESTART),
                         false);
                unit_prune_cgroup(u);
                unit_unlink_state_files(u);
        } else if (ns != os && ns == UNIT_RELOADING)
                SET_FLAG(u->markers, 1u << UNIT_MARKER_NEEDS_RELOAD, false);

        unit_update_on_console(u);

        if (!MANAGER_IS_RELOADING(m)) {
                bool unexpected;

                /* Let's propagate state changes to the job */
                if (u->job)
                        unexpected = unit_process_job(u->job, ns, flags);
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

                if (ns != os && ns == UNIT_FAILED) {
                        log_unit_debug(u, "Unit entered failed state.");

                        if (!(flags & UNIT_NOTIFY_WILL_AUTO_RESTART))
                                unit_start_on_failure(u, "OnFailure=", UNIT_ATOM_ON_FAILURE, u->on_failure_job_mode);
                }

                if (UNIT_IS_ACTIVE_OR_RELOADING(ns) && !UNIT_IS_ACTIVE_OR_RELOADING(os)) {
                        /* This unit just finished starting up */

                        unit_emit_audit_start(u);
                        manager_send_unit_plymouth(m, u);
                }

                if (UNIT_IS_INACTIVE_OR_FAILED(ns) && !UNIT_IS_INACTIVE_OR_FAILED(os)) {
                        /* This unit just stopped/failed. */

                        unit_emit_audit_stop(u, ns);
                        unit_log_resources(u);
                }

                if (ns == UNIT_INACTIVE && !IN_SET(os, UNIT_FAILED, UNIT_INACTIVE, UNIT_MAINTENANCE) &&
                    !(flags & UNIT_NOTIFY_WILL_AUTO_RESTART))
                        unit_start_on_failure(u, "OnSuccess=", UNIT_ATOM_ON_SUCCESS, u->on_success_job_mode);
        }

        manager_recheck_journal(m);
        manager_recheck_dbus(m);

        unit_trigger_notify(u);

        if (!MANAGER_IS_RELOADING(m)) {
                if (os != UNIT_FAILED && ns == UNIT_FAILED) {
                        reason = strjoina("unit ", u->id, " failed");
                        emergency_action(m, u->failure_action, 0, u->reboot_arg, unit_failure_action_exit_status(u), reason);
                } else if (!UNIT_IS_INACTIVE_OR_FAILED(os) && ns == UNIT_INACTIVE) {
                        reason = strjoina("unit ", u->id, " succeeded");
                        emergency_action(m, u->success_action, 0, u->reboot_arg, unit_success_action_exit_status(u), reason);
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
        }

        if (UNIT_IS_ACTIVE_OR_RELOADING(ns)) {
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

int unit_watch_pid(Unit *u, pid_t pid, bool exclusive) {
        int r;

        assert(u);
        assert(pid_is_valid(pid));

        /* Watch a specific PID */

        /* Caller might be sure that this PID belongs to this unit only. Let's take this
         * opportunity to remove any stalled references to this PID as they can be created
         * easily (when watching a process which is not our direct child). */
        if (exclusive)
                manager_unwatch_pid(u->manager, pid);

        r = set_ensure_allocated(&u->pids, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&u->manager->watch_pids, NULL);
        if (r < 0)
                return r;

        /* First try, let's add the unit keyed by "pid". */
        r = hashmap_put(u->manager->watch_pids, PID_TO_PTR(pid), u);
        if (r == -EEXIST)  {
                Unit **array;
                bool found = false;
                size_t n = 0;

                /* OK, the "pid" key is already assigned to a different unit. Let's see if the "-pid" key (which points
                 * to an array of Units rather than just a Unit), lists us already. */

                array = hashmap_get(u->manager->watch_pids, PID_TO_PTR(-pid));
                if (array)
                        for (; array[n]; n++)
                                if (array[n] == u)
                                        found = true;

                if (found) /* Found it already? if so, do nothing */
                        r = 0;
                else {
                        Unit **new_array;

                        /* Allocate a new array */
                        new_array = new(Unit*, n + 2);
                        if (!new_array)
                                return -ENOMEM;

                        memcpy_safe(new_array, array, sizeof(Unit*) * n);
                        new_array[n] = u;
                        new_array[n+1] = NULL;

                        /* Add or replace the old array */
                        r = hashmap_replace(u->manager->watch_pids, PID_TO_PTR(-pid), new_array);
                        if (r < 0) {
                                free(new_array);
                                return r;
                        }

                        free(array);
                }
        } else if (r < 0)
                return r;

        r = set_put(u->pids, PID_TO_PTR(pid));
        if (r < 0)
                return r;

        return 0;
}

void unit_unwatch_pid(Unit *u, pid_t pid) {
        Unit **array;

        assert(u);
        assert(pid_is_valid(pid));

        /* First let's drop the unit in case it's keyed as "pid". */
        (void) hashmap_remove_value(u->manager->watch_pids, PID_TO_PTR(pid), u);

        /* Then, let's also drop the unit, in case it's in the array keyed by -pid */
        array = hashmap_get(u->manager->watch_pids, PID_TO_PTR(-pid));
        if (array) {
                /* Let's iterate through the array, dropping our own entry */

                size_t m = 0;
                for (size_t n = 0; array[n]; n++)
                        if (array[n] != u)
                                array[m++] = array[n];
                array[m] = NULL;

                if (m == 0) {
                        /* The array is now empty, remove the entire entry */
                        assert_se(hashmap_remove(u->manager->watch_pids, PID_TO_PTR(-pid)) == array);
                        free(array);
                }
        }

        (void) set_remove(u->pids, PID_TO_PTR(pid));
}

void unit_unwatch_all_pids(Unit *u) {
        assert(u);

        while (!set_isempty(u->pids))
                unit_unwatch_pid(u, PTR_TO_PID(set_first(u->pids)));

        u->pids = set_free(u->pids);
}

static void unit_tidy_watch_pids(Unit *u) {
        pid_t except1, except2;
        void *e;

        assert(u);

        /* Cleans dead PIDs from our list */

        except1 = unit_main_pid(u);
        except2 = unit_control_pid(u);

        SET_FOREACH(e, u->pids) {
                pid_t pid = PTR_TO_PID(e);

                if (pid == except1 || pid == except2)
                        continue;

                if (!pid_is_unwaited(pid))
                        unit_unwatch_pid(u, pid);
        }
}

static int on_rewatch_pids_event(sd_event_source *s, void *userdata) {
        Unit *u = userdata;

        assert(s);
        assert(u);

        unit_tidy_watch_pids(u);
        unit_watch_all_pids(u);

        /* If the PID set is empty now, then let's finish this off. */
        unit_synthesize_cgroup_empty_event(u);

        return 0;
}

int unit_enqueue_rewatch_pids(Unit *u) {
        int r;

        assert(u);

        if (!u->cgroup_path)
                return -ENOENT;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return r;
        if (r > 0) /* On unified we can use proper notifications */
                return 0;

        /* Enqueues a low-priority job that will clean up dead PIDs from our list of PIDs to watch and subscribe to new
         * PIDs that might have appeared. We do this in a delayed job because the work might be quite slow, as it
         * involves issuing kill(pid, 0) on all processes we watch. */

        if (!u->rewatch_pids_event_source) {
                _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;

                r = sd_event_add_defer(u->manager->event, &s, on_rewatch_pids_event, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate event source for tidying watched PIDs: %m");

                r = sd_event_source_set_priority(s, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return log_error_errno(r, "Failed to adjust priority of event source for tidying watched PIDs: %m");

                (void) sd_event_source_set_description(s, "tidy-watch-pids");

                u->rewatch_pids_event_source = TAKE_PTR(s);
        }

        r = sd_event_source_set_enabled(u->rewatch_pids_event_source, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Failed to enable event source for tidying watched PIDs: %m");

        return 0;
}

void unit_dequeue_rewatch_pids(Unit *u) {
        int r;
        assert(u);

        if (!u->rewatch_pids_event_source)
                return;

        r = sd_event_source_set_enabled(u->rewatch_pids_event_source, SD_EVENT_OFF);
        if (r < 0)
                log_warning_errno(r, "Failed to disable event source for tidying watched PIDs, ignoring: %m");

        u->rewatch_pids_event_source = sd_event_source_disable_unref(u->rewatch_pids_event_source);
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
                assert_not_reached("Invalid job type");
        }
}

int unit_add_dependency(
                Unit *u,
                UnitDependency d,
                Unit *other,
                bool add_reference,
                UnitDependencyMask mask) {

        static const UnitDependency inverse_table[_UNIT_DEPENDENCY_MAX] = {
                [UNIT_REQUIRES] = UNIT_REQUIRED_BY,
                [UNIT_REQUISITE] = UNIT_REQUISITE_OF,
                [UNIT_WANTS] = UNIT_WANTED_BY,
                [UNIT_BINDS_TO] = UNIT_BOUND_BY,
                [UNIT_PART_OF] = UNIT_CONSISTS_OF,
                [UNIT_UPHOLDS] = UNIT_UPHELD_BY,
                [UNIT_REQUIRED_BY] = UNIT_REQUIRES,
                [UNIT_REQUISITE_OF] = UNIT_REQUISITE,
                [UNIT_WANTED_BY] = UNIT_WANTS,
                [UNIT_BOUND_BY] = UNIT_BINDS_TO,
                [UNIT_CONSISTS_OF] = UNIT_PART_OF,
                [UNIT_UPHELD_BY] = UNIT_UPHOLDS,
                [UNIT_CONFLICTS] = UNIT_CONFLICTED_BY,
                [UNIT_CONFLICTED_BY] = UNIT_CONFLICTS,
                [UNIT_BEFORE] = UNIT_AFTER,
                [UNIT_AFTER] = UNIT_BEFORE,
                [UNIT_ON_SUCCESS] = UNIT_ON_SUCCESS_OF,
                [UNIT_ON_SUCCESS_OF] = UNIT_ON_SUCCESS,
                [UNIT_ON_FAILURE] = UNIT_ON_FAILURE_OF,
                [UNIT_ON_FAILURE_OF] = UNIT_ON_FAILURE,
                [UNIT_TRIGGERS] = UNIT_TRIGGERED_BY,
                [UNIT_TRIGGERED_BY] = UNIT_TRIGGERS,
                [UNIT_PROPAGATES_RELOAD_TO] = UNIT_RELOAD_PROPAGATED_FROM,
                [UNIT_RELOAD_PROPAGATED_FROM] = UNIT_PROPAGATES_RELOAD_TO,
                [UNIT_PROPAGATES_STOP_TO] = UNIT_STOP_PROPAGATED_FROM,
                [UNIT_STOP_PROPAGATED_FROM] = UNIT_PROPAGATES_STOP_TO,
                [UNIT_JOINS_NAMESPACE_OF] = UNIT_JOINS_NAMESPACE_OF, /* symmetric! 👓 */
                [UNIT_REFERENCES] = UNIT_REFERENCED_BY,
                [UNIT_REFERENCED_BY] = UNIT_REFERENCES,
                [UNIT_IN_SLICE] = UNIT_SLICE_OF,
                [UNIT_SLICE_OF] = UNIT_IN_SLICE,
        };
        Unit *original_u = u, *original_other = other;
        UnitDependencyAtom a;
        int r;

        /* Helper to know whether sending a notification is necessary or not: if the dependency is already
         * there, no need to notify! */
        bool noop;

        assert(u);
        assert(d >= 0 && d < _UNIT_DEPENDENCY_MAX);
        assert(other);

        u = unit_follow_merge(u);
        other = unit_follow_merge(other);
        a = unit_dependency_to_atom(d);
        assert(a >= 0);

        /* We won't allow dependencies on ourselves. We will not consider them an error however. */
        if (u == other) {
                unit_maybe_warn_about_dependency(original_u, original_other->id, d);
                return 0;
        }

        /* Note that ordering a device unit after a unit is permitted since it allows to start its job
         * running timeout at a specific time. */
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

        r = unit_add_dependency_hashmap(&u->dependencies, d, other, mask, 0);
        if (r < 0)
                return r;
        noop = !r;

        if (inverse_table[d] != _UNIT_DEPENDENCY_INVALID && inverse_table[d] != d) {
                r = unit_add_dependency_hashmap(&other->dependencies, inverse_table[d], u, 0, mask);
                if (r < 0)
                        return r;
                if (r)
                        noop = false;
        }

        if (add_reference) {
                r = unit_add_dependency_hashmap(&u->dependencies, UNIT_REFERENCES, other, mask, 0);
                if (r < 0)
                        return r;
                if (r)
                        noop = false;

                r = unit_add_dependency_hashmap(&other->dependencies, UNIT_REFERENCED_BY, u, 0, mask);
                if (r < 0)
                        return r;
                if (r)
                        noop = false;
        }

        if (!noop)
                unit_add_to_dbus_queue(u);

        return 0;
}

int unit_add_two_dependencies(Unit *u, UnitDependency d, UnitDependency e, Unit *other, bool add_reference, UnitDependencyMask mask) {
        int r;

        assert(u);

        r = unit_add_dependency(u, d, other, add_reference, mask);
        if (r < 0)
                return r;

        return unit_add_dependency(u, e, other, add_reference, mask);
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

        r = manager_load_unit(u->manager, name, NULL, NULL, &other);
        if (r < 0)
                return r;

        return unit_add_two_dependencies(u, d, e, other, add_reference, mask);
}

int set_unit_path(const char *p) {
        /* This is mostly for debug purposes */
        if (setenv("SYSTEMD_UNIT_PATH", p, 1) < 0)
                return -errno;

        return 0;
}

char *unit_dbus_path(Unit *u) {
        assert(u);

        if (!u->id)
                return NULL;

        return unit_dbus_path_from_name(u->id);
}

char *unit_dbus_path_invocation_id(Unit *u) {
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

int unit_set_slice(Unit *u, Unit *slice, UnitDependencyMask mask) {
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
        if (UNIT_GET_SLICE(u) && u->cgroup_realized)
                return -EBUSY;

        r = unit_add_dependency(u, UNIT_IN_SLICE, slice, true, mask);
        if (r < 0)
                return r;

        return 1;
}

int unit_set_default_slice(Unit *u) {
        const char *slice_name;
        Unit *slice;
        int r;

        assert(u);

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

        return unit_set_slice(u, slice, UNIT_DEPENDENCY_FILE);
}

const char *unit_slice_name(Unit *u) {
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

static int signal_name_owner_changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *new_owner;
        Unit *u = userdata;
        int r;

        assert(message);
        assert(u);

        r = sd_bus_message_read(message, "sss", NULL, NULL, &new_owner);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (UNIT_VTABLE(u)->bus_name_owner_change)
                UNIT_VTABLE(u)->bus_name_owner_change(u, empty_to_null(new_owner));

        return 0;
}

static int get_name_owner_handler(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const sd_bus_error *e;
        const char *new_owner;
        Unit *u = userdata;
        int r;

        assert(message);
        assert(u);

        u->get_name_owner_slot = sd_bus_slot_unref(u->get_name_owner_slot);

        e = sd_bus_message_get_error(message);
        if (e) {
                if (!sd_bus_error_has_name(e, "org.freedesktop.DBus.Error.NameHasNoOwner"))
                        log_unit_error(u, "Unexpected error response from GetNameOwner(): %s", e->message);

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
        const char *match;
        int r;

        assert(u);
        assert(bus);
        assert(name);

        if (u->match_bus_slot || u->get_name_owner_slot)
                return -EBUSY;

        match = strjoina("type='signal',"
                         "sender='org.freedesktop.DBus',"
                         "path='/org/freedesktop/DBus',"
                         "interface='org.freedesktop.DBus',"
                         "member='NameOwnerChanged',"
                         "arg0='", name, "'");

        r = sd_bus_add_match_async(bus, &u->match_bus_slot, match, signal_name_owner_changed, NULL, u);
        if (r < 0)
                return r;

        r = sd_bus_call_method_async(
                        bus,
                        &u->get_name_owner_slot,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "GetNameOwner",
                        get_name_owner_handler,
                        u,
                        "s", name);
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
        int r = 0, q;
        char **i;

        assert(u);

        /* Make sure we don't enter a loop, when coldplugging recursively. */
        if (u->coldplugged)
                return 0;

        u->coldplugged = true;

        STRV_FOREACH(i, u->deserialized_refs) {
                q = bus_unit_track_add_name(u, *i);
                if (q < 0 && r >= 0)
                        r = q;
        }
        u->deserialized_refs = strv_free(u->deserialized_refs);

        if (UNIT_VTABLE(u)->coldplug) {
                q = UNIT_VTABLE(u)->coldplug(u);
                if (q < 0 && r >= 0)
                        r = q;
        }

        if (u->job) {
                q = job_coldplug(u->job);
                if (q < 0 && r >= 0)
                        r = q;
        }
        if (u->nop_job) {
                q = job_coldplug(u->nop_job);
                if (q < 0 && r >= 0)
                        r = q;
        }

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
        _cleanup_strv_free_ char **t = NULL;
        char **path;

        assert(u);

        /* For unit files, we allow masking… */
        if (fragment_mtime_newer(u->fragment_path, u->fragment_mtime,
                                 u->load_state == UNIT_MASKED))
                return true;

        /* Source paths should not be masked… */
        if (fragment_mtime_newer(u->source_path, u->source_mtime, false))
                return true;

        if (u->load_state == UNIT_LOADED)
                (void) unit_find_dropin_paths(u, &t);
        if (!strv_equal(u->dropin_paths, t))
                return true;

        /* … any drop-ins that are masked are simply omitted from the list. */
        STRV_FOREACH(path, u->dropin_paths)
                if (fragment_mtime_newer(*path, u->dropin_mtime, false))
                        return true;

        return false;
}

void unit_reset_failed(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->reset_failed)
                UNIT_VTABLE(u)->reset_failed(u);

        ratelimit_reset(&u->start_ratelimit);
        u->start_limit_hit = false;
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

        if (u->job &&
            IN_SET(u->job->type, JOB_START, JOB_RELOAD_OR_START, JOB_RESTART))
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

int unit_kill(Unit *u, KillWho w, int signo, sd_bus_error *error) {
        assert(u);
        assert(w >= 0 && w < _KILL_WHO_MAX);
        assert(SIGNAL_VALID(signo));

        if (!UNIT_VTABLE(u)->kill)
                return -EOPNOTSUPP;

        return UNIT_VTABLE(u)->kill(u, w, signo, error);
}

static Set *unit_pid_set(pid_t main_pid, pid_t control_pid) {
        _cleanup_set_free_ Set *pid_set = NULL;
        int r;

        pid_set = set_new(NULL);
        if (!pid_set)
                return NULL;

        /* Exclude the main/control pids from being killed via the cgroup */
        if (main_pid > 0) {
                r = set_put(pid_set, PID_TO_PTR(main_pid));
                if (r < 0)
                        return NULL;
        }

        if (control_pid > 0) {
                r = set_put(pid_set, PID_TO_PTR(control_pid));
                if (r < 0)
                        return NULL;
        }

        return TAKE_PTR(pid_set);
}

static int kill_common_log(pid_t pid, int signo, void *userdata) {
        _cleanup_free_ char *comm = NULL;
        Unit *u = userdata;

        assert(u);

        (void) get_process_comm(pid, &comm);
        log_unit_info(u, "Sending signal SIG%s to process " PID_FMT " (%s) on client request.",
                      signal_to_string(signo), pid, strna(comm));

        return 1;
}

int unit_kill_common(
                Unit *u,
                KillWho who,
                int signo,
                pid_t main_pid,
                pid_t control_pid,
                sd_bus_error *error) {

        int r = 0;
        bool killed = false;

        /* This is the common implementation for explicit user-requested killing of unit processes, shared by
         * various unit types. Do not confuse with unit_kill_context(), which is what we use when we want to
         * stop a service ourselves. */

        if (IN_SET(who, KILL_MAIN, KILL_MAIN_FAIL)) {
                if (main_pid < 0)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no main processes", unit_type_to_string(u->type));
                if (main_pid == 0)
                        return sd_bus_error_set_const(error, BUS_ERROR_NO_SUCH_PROCESS, "No main process to kill");
        }

        if (IN_SET(who, KILL_CONTROL, KILL_CONTROL_FAIL)) {
                if (control_pid < 0)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_PROCESS, "%s units have no control processes", unit_type_to_string(u->type));
                if (control_pid == 0)
                        return sd_bus_error_set_const(error, BUS_ERROR_NO_SUCH_PROCESS, "No control process to kill");
        }

        if (IN_SET(who, KILL_CONTROL, KILL_CONTROL_FAIL, KILL_ALL, KILL_ALL_FAIL))
                if (control_pid > 0) {
                        _cleanup_free_ char *comm = NULL;
                        (void) get_process_comm(control_pid, &comm);

                        if (kill(control_pid, signo) < 0) {
                                /* Report this failure both to the logs and to the client */
                                sd_bus_error_set_errnof(
                                                error, errno,
                                                "Failed to send signal SIG%s to control process " PID_FMT " (%s): %m",
                                                signal_to_string(signo), control_pid, strna(comm));
                                r = log_unit_warning_errno(
                                                u, errno,
                                                "Failed to send signal SIG%s to control process " PID_FMT " (%s) on client request: %m",
                                                signal_to_string(signo), control_pid, strna(comm));
                        } else {
                                log_unit_info(u, "Sent signal SIG%s to control process " PID_FMT " (%s) on client request.",
                                              signal_to_string(signo), control_pid, strna(comm));
                                killed = true;
                        }
                }

        if (IN_SET(who, KILL_MAIN, KILL_MAIN_FAIL, KILL_ALL, KILL_ALL_FAIL))
                if (main_pid > 0) {
                        _cleanup_free_ char *comm = NULL;
                        (void) get_process_comm(main_pid, &comm);

                        if (kill(main_pid, signo) < 0) {
                                if (r == 0)
                                        sd_bus_error_set_errnof(
                                                        error, errno,
                                                        "Failed to send signal SIG%s to main process " PID_FMT " (%s): %m",
                                                        signal_to_string(signo), main_pid, strna(comm));

                                r = log_unit_warning_errno(
                                                u, errno,
                                                "Failed to send signal SIG%s to main process " PID_FMT " (%s) on client request: %m",
                                                signal_to_string(signo), main_pid, strna(comm));
                        } else {
                                log_unit_info(u, "Sent signal SIG%s to main process " PID_FMT " (%s) on client request.",
                                              signal_to_string(signo), main_pid, strna(comm));
                                killed = true;
                        }
                }

        if (IN_SET(who, KILL_ALL, KILL_ALL_FAIL) && u->cgroup_path) {
                _cleanup_set_free_ Set *pid_set = NULL;
                int q;

                /* Exclude the main/control pids from being killed via the cgroup */
                pid_set = unit_pid_set(main_pid, control_pid);
                if (!pid_set)
                        return log_oom();

                q = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, signo, 0, pid_set, kill_common_log, u);
                if (q < 0) {
                        if (!IN_SET(q, -ESRCH, -ENOENT)) {
                                if (r == 0)
                                        sd_bus_error_set_errnof(
                                                        error, q,
                                                        "Failed to send signal SIG%s to auxiliary processes: %m",
                                                        signal_to_string(signo));

                                r = log_unit_warning_errno(
                                                u, q,
                                                "Failed to send signal SIG%s to auxiliary processes on client request: %m",
                                                signal_to_string(signo));
                        }
                } else
                        killed = true;
        }

        /* If the "fail" versions of the operation are requested, then complain if the set of processes we killed is empty */
        if (r == 0 && !killed && IN_SET(who, KILL_ALL_FAIL, KILL_CONTROL_FAIL, KILL_MAIN_FAIL))
                return sd_bus_error_set_const(error, BUS_ERROR_NO_SUCH_PROCESS, "No matching processes to kill");

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
        int r;

        assert(u);

        if (u->unit_file_state < 0 && u->fragment_path) {
                r = unit_file_get_state(
                                u->manager->unit_file_scope,
                                NULL,
                                u->id,
                                &u->unit_file_state);
                if (r < 0)
                        u->unit_file_state = UNIT_FILE_BAD;
        }

        return u->unit_file_state;
}

int unit_get_unit_file_preset(Unit *u) {
        assert(u);

        if (u->unit_file_preset < 0 && u->fragment_path)
                u->unit_file_preset = unit_file_query_preset(
                                u->manager->unit_file_scope,
                                NULL,
                                basename(u->fragment_path),
                                NULL);

        return u->unit_file_preset;
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
                        if (u->manager->rlimit[i] && !ec->rlimit[i]) {
                                ec->rlimit[i] = newdup(struct rlimit, u->manager->rlimit[i], 1);
                                if (!ec->rlimit[i])
                                        return -ENOMEM;
                        }

                if (MANAGER_IS_USER(u->manager) &&
                    !ec->working_directory) {

                        r = get_home_dir(&ec->working_directory);
                        if (r < 0)
                                return r;

                        /* Allow user services to run, even if the
                         * home directory is missing */
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

                        ec->private_tmp = true;
                        ec->remove_ipc = true;
                        ec->protect_system = PROTECT_SYSTEM_STRICT;
                        if (ec->protect_home == PROTECT_HOME_NO)
                                ec->protect_home = PROTECT_HOME_READ_ONLY;

                        /* Make sure this service can neither benefit from SUID/SGID binaries nor create
                         * them. */
                        ec->no_new_privileges = true;
                        ec->restrict_suid_sgid = true;
                }
        }

        cc = unit_get_cgroup_context(u);
        if (cc && ec) {

                if (ec->private_devices &&
                    cc->device_policy == CGROUP_DEVICE_POLICY_AUTO)
                        cc->device_policy = CGROUP_DEVICE_POLICY_CLOSED;

                if ((ec->root_image || !LIST_IS_EMPTY(ec->mount_images)) &&
                    (cc->device_policy != CGROUP_DEVICE_POLICY_AUTO || cc->device_allow)) {
                        const char *p;

                        /* When RootImage= or MountImages= is specified, the following devices are touched. */
                        FOREACH_STRING(p, "/dev/loop-control", "/dev/mapper/control") {
                                r = cgroup_add_device_allow(cc, p, "rw");
                                if (r < 0)
                                        return r;
                        }
                        FOREACH_STRING(p, "block-loop", "block-blkext", "block-device-mapper") {
                                r = cgroup_add_device_allow(cc, p, "rwm");
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
                        r = cgroup_add_device_allow(cc, "char-rtc", "r");
                        if (r < 0)
                                return r;
                }
        }

        return 0;
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

char* unit_escape_setting(const char *s, UnitWriteFlags flags, char **buf) {
        char *ret = NULL;

        if (!s)
                return NULL;

        /* Escapes the input string as requested. Returns the escaped string. If 'buf' is specified then the allocated
         * return buffer pointer is also written to *buf, except if no escaping was necessary, in which case *buf is
         * set to NULL, and the input pointer is returned as-is. This means the return value always contains a properly
         * escaped version, but *buf when passed only contains a pointer if an allocation was necessary. If *buf is
         * not specified, then the return value always needs to be freed. Callers can use this to optimize memory
         * allocations. */

        if (flags & UNIT_ESCAPE_SPECIFIERS) {
                ret = specifier_escape(s);
                if (!ret)
                        return NULL;

                s = ret;
        }

        if (flags & UNIT_ESCAPE_C) {
                char *a;

                a = cescape(s);
                free(ret);
                if (!a)
                        return NULL;

                ret = a;
        }

        if (buf) {
                *buf = ret;
                return ret ?: (char*) s;
        }

        return ret ?: strdup(s);
}

char* unit_concat_strv(char **l, UnitWriteFlags flags) {
        _cleanup_free_ char *result = NULL;
        size_t n = 0;
        char **i;

        /* Takes a list of strings, escapes them, and concatenates them. This may be used to format command lines in a
         * way suitable for ExecStart= stanzas */

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
                /* When this is a transient unit file in creation, then let's not create a new drop-in but instead
                 * write to the transient unit file. */
                fputs(data, u->transient_file);

                if (!endswith(data, "\n"))
                        fputc('\n', u->transient_file);

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
                r = set_put_strdup(&u->manager->unit_path_cache, p);
                if (r < 0)
                        return r;
        }

        r = write_string_file_atomic_label(q, wrapped);
        if (r < 0)
                return r;

        r = strv_push(&u->dropin_paths, q);
        if (r < 0)
                return r;
        q = NULL;

        strv_uniq(u->dropin_paths);

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

        RUN_WITH_UMASK(0022) {
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

static int log_kill(pid_t pid, int sig, void *userdata) {
        _cleanup_free_ char *comm = NULL;

        (void) get_process_comm(pid, &comm);

        /* Don't log about processes marked with brackets, under the assumption that these are temporary processes
           only, like for example systemd's own PAM stub process. */
        if (comm && comm[0] == '(')
                return 0;

        log_unit_notice(userdata,
                        "Killing process " PID_FMT " (%s) with signal SIG%s.",
                        pid,
                        strna(comm),
                        signal_to_string(sig));

        return 1;
}

static int operation_to_signal(const KillContext *c, KillOperation k, bool *noteworthy) {
        assert(c);

        switch (k) {

        case KILL_TERMINATE:
        case KILL_TERMINATE_AND_LOG:
                *noteworthy = false;
                return c->kill_signal;

        case KILL_RESTART:
                *noteworthy = false;
                return restart_kill_signal(c);

        case KILL_KILL:
                *noteworthy = true;
                return c->final_kill_signal;

        case KILL_WATCHDOG:
                *noteworthy = true;
                return c->watchdog_signal;

        default:
                assert_not_reached("KillOperation unknown");
        }
}

int unit_kill_context(
                Unit *u,
                KillContext *c,
                KillOperation k,
                pid_t main_pid,
                pid_t control_pid,
                bool main_pid_alien) {

        bool wait_for_exit = false, send_sighup;
        cg_kill_log_func_t log_func = NULL;
        int sig, r;

        assert(u);
        assert(c);

        /* Kill the processes belonging to this unit, in preparation for shutting the unit down.  Returns > 0
         * if we killed something worth waiting for, 0 otherwise. Do not confuse with unit_kill_common()
         * which is used for user-requested killing of unit processes. */

        if (c->kill_mode == KILL_NONE)
                return 0;

        bool noteworthy;
        sig = operation_to_signal(c, k, &noteworthy);
        if (noteworthy)
                log_func = log_kill;

        send_sighup =
                c->send_sighup &&
                IN_SET(k, KILL_TERMINATE, KILL_TERMINATE_AND_LOG) &&
                sig != SIGHUP;

        if (main_pid > 0) {
                if (log_func)
                        log_func(main_pid, sig, u);

                r = kill_and_sigcont(main_pid, sig);
                if (r < 0 && r != -ESRCH) {
                        _cleanup_free_ char *comm = NULL;
                        (void) get_process_comm(main_pid, &comm);

                        log_unit_warning_errno(u, r, "Failed to kill main process " PID_FMT " (%s), ignoring: %m", main_pid, strna(comm));
                } else {
                        if (!main_pid_alien)
                                wait_for_exit = true;

                        if (r != -ESRCH && send_sighup)
                                (void) kill(main_pid, SIGHUP);
                }
        }

        if (control_pid > 0) {
                if (log_func)
                        log_func(control_pid, sig, u);

                r = kill_and_sigcont(control_pid, sig);
                if (r < 0 && r != -ESRCH) {
                        _cleanup_free_ char *comm = NULL;
                        (void) get_process_comm(control_pid, &comm);

                        log_unit_warning_errno(u, r, "Failed to kill control process " PID_FMT " (%s), ignoring: %m", control_pid, strna(comm));
                } else {
                        wait_for_exit = true;

                        if (r != -ESRCH && send_sighup)
                                (void) kill(control_pid, SIGHUP);
                }
        }

        if (u->cgroup_path &&
            (c->kill_mode == KILL_CONTROL_GROUP || (c->kill_mode == KILL_MIXED && k == KILL_KILL))) {
                _cleanup_set_free_ Set *pid_set = NULL;

                /* Exclude the main/control pids from being killed via the cgroup */
                pid_set = unit_pid_set(main_pid, control_pid);
                if (!pid_set)
                        return -ENOMEM;

                r = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path,
                                      sig,
                                      CGROUP_SIGCONT|CGROUP_IGNORE_SELF,
                                      pid_set,
                                      log_func, u);
                if (r < 0) {
                        if (!IN_SET(r, -EAGAIN, -ESRCH, -ENOENT))
                                log_unit_warning_errno(u, r, "Failed to kill control group %s, ignoring: %m", empty_to_root(u->cgroup_path));

                } else if (r > 0) {

                        /* FIXME: For now, on the legacy hierarchy, we will not wait for the cgroup members to die if
                         * we are running in a container or if this is a delegation unit, simply because cgroup
                         * notification is unreliable in these cases. It doesn't work at all in containers, and outside
                         * of containers it can be confused easily by left-over directories in the cgroup — which
                         * however should not exist in non-delegated units. On the unified hierarchy that's different,
                         * there we get proper events. Hence rely on them. */

                        if (cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) > 0 ||
                            (detect_container() == 0 && !unit_cgroup_delegate(u)))
                                wait_for_exit = true;

                        if (send_sighup) {
                                set_free(pid_set);

                                pid_set = unit_pid_set(main_pid, control_pid);
                                if (!pid_set)
                                        return -ENOMEM;

                                (void) cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path,
                                                         SIGHUP,
                                                         CGROUP_IGNORE_SELF,
                                                         pid_set,
                                                         NULL, NULL);
                        }
                }
        }

        return wait_for_exit;
}

int unit_require_mounts_for(Unit *u, const char *path, UnitDependencyMask mask) {
        int r;

        assert(u);
        assert(path);

        /* Registers a unit for requiring a certain path and all its prefixes. We keep a hashtable of these
         * paths in the unit (from the path to the UnitDependencyInfo structure indicating how to the
         * dependency came to be). However, we build a prefix table for all possible prefixes so that new
         * appearing mount units can easily determine which units to make themselves a dependency of. */

        if (!path_is_absolute(path))
                return -EINVAL;

        if (hashmap_contains(u->requires_mounts_for, path)) /* Exit quickly if the path is already covered. */
                return 0;

        _cleanup_free_ char *p = strdup(path);
        if (!p)
                return -ENOMEM;

        /* Use the canonical form of the path as the stored key. We call path_is_normalized()
         * only after simplification, since path_is_normalized() rejects paths with '.'.
         * path_is_normalized() also verifies that the path fits in PATH_MAX. */
        path = path_simplify(p);

        if (!path_is_normalized(path))
                return -EPERM;

        UnitDependencyInfo di = {
                .origin_mask = mask
        };

        r = hashmap_ensure_put(&u->requires_mounts_for, &path_hash_ops, p, di.data);
        if (r < 0)
                return r;
        assert(r > 0);
        TAKE_PTR(p); /* path remains a valid pointer to the string stored in the hashmap */

        char prefix[strlen(path) + 1];
        PATH_FOREACH_PREFIX_MORE(prefix, path) {
                Set *x;

                x = hashmap_get(u->manager->units_requiring_mounts_for, prefix);
                if (!x) {
                        _cleanup_free_ char *q = NULL;

                        r = hashmap_ensure_allocated(&u->manager->units_requiring_mounts_for, &path_hash_ops);
                        if (r < 0)
                                return r;

                        q = strdup(prefix);
                        if (!q)
                                return -ENOMEM;

                        x = set_new(NULL);
                        if (!x)
                                return -ENOMEM;

                        r = hashmap_put(u->manager->units_requiring_mounts_for, q, x);
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
        ExecRuntime **rt;
        size_t offset;
        Unit *other;
        int r;

        offset = UNIT_VTABLE(u)->exec_runtime_offset;
        assert(offset > 0);

        /* Check if there already is an ExecRuntime for this unit? */
        rt = (ExecRuntime**) ((uint8_t*) u + offset);
        if (*rt)
                return 0;

        /* Try to get it from somebody else */
        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_JOINS_NAMESPACE_OF) {
                r = exec_runtime_acquire(u->manager, NULL, other->id, false, rt);
                if (r == 1)
                        return 1;
        }

        return exec_runtime_acquire(u->manager, unit_get_exec_context(u), u->id, true, rt);
}

int unit_setup_dynamic_creds(Unit *u) {
        ExecContext *ec;
        DynamicCreds *dcreds;
        size_t offset;

        assert(u);

        offset = UNIT_VTABLE(u)->dynamic_creds_offset;
        assert(offset > 0);
        dcreds = (DynamicCreds*) ((uint8_t*) u + offset);

        ec = unit_get_exec_context(u);
        assert(ec);

        if (!ec->dynamic_user)
                return 0;

        return dynamic_creds_acquire(dcreds, u->manager, ec->user, ec->group);
}

bool unit_type_supported(UnitType t) {
        if (_unlikely_(t < 0))
                return false;
        if (_unlikely_(t >= _UNIT_TYPE_MAX))
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

        r = dir_is_empty(where);
        if (r > 0 || r == -ENOTDIR)
                return;
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to check directory %s: %m", where);
                return;
        }

        log_unit_struct(u, LOG_NOTICE,
                        "MESSAGE_ID=" SD_MESSAGE_OVERMOUNTING_STR,
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Directory %s to mount over is not empty, mounting anyway.", where),
                        "WHERE=%s", where);
}

int unit_fail_if_noncanonical(Unit *u, const char* where) {
        _cleanup_free_ char *canonical_where = NULL;
        int r;

        assert(u);
        assert(where);

        r = chase_symlinks(where, NULL, CHASE_NONEXISTENT, &canonical_where, NULL);
        if (r < 0) {
                log_unit_debug_errno(u, r, "Failed to check %s for symlinks, ignoring: %m", where);
                return 0;
        }

        /* We will happily ignore a trailing slash (or any redundant slashes) */
        if (path_equal(where, canonical_where))
                return 0;

        /* No need to mention "." or "..", they would already have been rejected by unit_name_from_path() */
        log_unit_struct(u, LOG_ERR,
                        "MESSAGE_ID=" SD_MESSAGE_OVERMOUNTING_STR,
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Mount path %s is not canonical (contains a symlink).", where),
                        "WHERE=%s", where);

        return -ELOOP;
}

bool unit_is_pristine(Unit *u) {
        assert(u);

        /* Check if the unit already exists or is already around,
         * in a number of different ways. Note that to cater for unit
         * types such as slice, we are generally fine with units that
         * are marked UNIT_LOADED even though nothing was actually
         * loaded, as those unit types don't require a file on disk. */

        return !(!IN_SET(u->load_state, UNIT_NOT_FOUND, UNIT_LOADED) ||
                 u->fragment_path ||
                 u->source_path ||
                 !strv_isempty(u->dropin_paths) ||
                 u->job ||
                 u->merged_into);
}

pid_t unit_control_pid(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->control_pid)
                return UNIT_VTABLE(u)->control_pid(u);

        return 0;
}

pid_t unit_main_pid(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->main_pid)
                return UNIT_VTABLE(u)->main_pid(u);

        return 0;
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
        unit_unref_uid_internal(u, &u->ref_uid, destroy_now, manager_unref_uid);
}

static void unit_unref_gid(Unit *u, bool destroy_now) {
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

        p->confirm_spawn = manager_get_confirm_spawn(u->manager);
        p->cgroup_supported = u->manager->cgroup_supported;
        p->prefix = u->manager->prefix;
        SET_FLAG(p->flags, EXEC_PASS_LOG_UNIT|EXEC_CHOWN_DIRECTORIES, MANAGER_IS_SYSTEM(u->manager));

        /* Copy parameters from unit */
        p->cgroup_path = u->cgroup_path;
        SET_FLAG(p->flags, EXEC_CGROUP_DELEGATE, unit_cgroup_delegate(u));

        p->received_credentials = u->manager->received_credentials;

        return 0;
}

int unit_fork_helper_process(Unit *u, const char *name, pid_t *ret) {
        int r;

        assert(u);
        assert(ret);

        /* Forks off a helper process and makes sure it is a member of the unit's cgroup. Returns == 0 in the child,
         * and > 0 in the parent. The pid parameter is always filled in with the child's PID. */

        (void) unit_realize_cgroup(u);

        r = safe_fork(name, FORK_REOPEN_LOG, ret);
        if (r != 0)
                return r;

        (void) default_signals(SIGNALS_CRASH_HANDLER, SIGNALS_IGNORE);
        (void) ignore_signals(SIGPIPE);

        (void) prctl(PR_SET_PDEATHSIG, SIGTERM);

        if (u->cgroup_path) {
                r = cg_attach_everywhere(u->manager->cgroup_supported, u->cgroup_path, 0, NULL, NULL);
                if (r < 0) {
                        log_unit_error_errno(u, r, "Failed to join unit cgroup %s: %m", empty_to_root(u->cgroup_path));
                        _exit(EXIT_CGROUP);
                }
        }

        return 0;
}

int unit_fork_and_watch_rm_rf(Unit *u, char **paths, pid_t *ret_pid) {
        pid_t pid;
        int r;

        assert(u);
        assert(ret_pid);

        r = unit_fork_helper_process(u, "(sd-rmrf)", &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                int ret = EXIT_SUCCESS;
                char **i;

                STRV_FOREACH(i, paths) {
                        r = rm_rf(*i, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_MISSING_OK);
                        if (r < 0) {
                                log_error_errno(r, "Failed to remove '%s': %m", *i);
                                ret = EXIT_FAILURE;
                        }
                }

                _exit(ret);
        }

        r = unit_watch_pid(u, pid, true);
        if (r < 0)
                return r;

        *ret_pid = pid;
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
                r = xdg_user_runtime_dir(&user_path, "/systemd/units/invocation:");
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

        r = symlink_atomic_label(u->invocation_id_string, p);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to create invocation ID symlink %s: %m", p);

        u->exported_invocation_id = true;
        return 0;
}

static int unit_export_log_level_max(Unit *u, const ExecContext *c) {
        const char *p;
        char buf[2];
        int r;

        assert(u);
        assert(c);

        if (u->exported_log_level_max)
                return 0;

        if (c->log_level_max < 0)
                return 0;

        assert(c->log_level_max <= 7);

        buf[0] = '0' + c->log_level_max;
        buf[1] = 0;

        p = strjoina("/run/systemd/units/log-level-max:", u->id);
        r = symlink_atomic(buf, p);
        if (r < 0)
                return log_unit_debug_errno(u, r, "Failed to create maximum log level symlink %s: %m", p);

        u->exported_log_level_max = true;
        return 0;
}

static int unit_export_log_extra_fields(Unit *u, const ExecContext *c) {
        _cleanup_close_ int fd = -1;
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

        if (c->log_ratelimit_interval_usec == 0)
                return 0;

        p = strjoina("/run/systemd/units/log-rate-limit-interval:", u->id);

        if (asprintf(&buf, "%" PRIu64, c->log_ratelimit_interval_usec) < 0)
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

        if (c->log_ratelimit_burst == 0)
                return 0;

        p = strjoina("/run/systemd/units/log-rate-limit-burst:", u->id);

        if (asprintf(&buf, "%u", c->log_ratelimit_burst) < 0)
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
                (void) unit_export_log_level_max(u, c);
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

int unit_prepare_exec(Unit *u) {
        int r;

        assert(u);

        /* Load any custom firewall BPF programs here once to test if they are existing and actually loadable.
         * Fail here early since later errors in the call chain unit_realize_cgroup to cgroup_context_apply are ignored. */
        r = bpf_firewall_load_custom(u);
        if (r < 0)
                return r;

        /* Prepares everything so that we can fork of a process for this unit */

        (void) unit_realize_cgroup(u);

        if (u->reset_accounting) {
                (void) unit_reset_accounting(u);
                u->reset_accounting = false;
        }

        unit_export_state_files(u);

        r = unit_setup_exec_runtime(u);
        if (r < 0)
                return r;

        r = unit_setup_dynamic_creds(u);
        if (r < 0)
                return r;

        return 0;
}

static bool ignore_leftover_process(const char *comm) {
        return comm && comm[0] == '('; /* Most likely our own helper process (PAM?), ignore */
}

int unit_log_leftover_process_start(pid_t pid, int sig, void *userdata) {
        _cleanup_free_ char *comm = NULL;

        (void) get_process_comm(pid, &comm);

        if (ignore_leftover_process(comm))
                return 0;

        /* During start we print a warning */

        log_unit_warning(userdata,
                         "Found left-over process " PID_FMT " (%s) in control group while starting unit. Ignoring.\n"
                         "This usually indicates unclean termination of a previous run, or service implementation deficiencies.",
                         pid, strna(comm));

        return 1;
}

int unit_log_leftover_process_stop(pid_t pid, int sig, void *userdata) {
        _cleanup_free_ char *comm = NULL;

        (void) get_process_comm(pid, &comm);

        if (ignore_leftover_process(comm))
                return 0;

        /* During stop we only print an informational message */

        log_unit_info(userdata,
                      "Unit process " PID_FMT " (%s) remains running after unit stopped.",
                      pid, strna(comm));

        return 1;
}

int unit_warn_leftover_processes(Unit *u, cg_kill_log_func_t log_func) {
        assert(u);

        (void) unit_pick_cgroup_path(u);

        if (!u->cgroup_path)
                return 0;

        return cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, 0, 0, NULL, log_func, u);
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

const char *unit_label_path(const Unit *u) {
        const char *p;

        assert(u);

        /* Returns the file system path to use for MAC access decisions, i.e. the file to read the SELinux label off
         * when validating access checks. */

        p = u->source_path ?: u->fragment_path;
        if (!p)
                return NULL;

        /* If a unit is masked, then don't read the SELinux label of /dev/null, as that really makes no sense */
        if (null_or_empty_path(p) > 0)
                return NULL;

        return p;
}

int unit_pid_attachable(Unit *u, pid_t pid, sd_bus_error *error) {
        int r;

        assert(u);

        /* Checks whether the specified PID is generally good for attaching, i.e. a valid PID, not our manager itself,
         * and not a kernel thread either */

        /* First, a simple range check */
        if (!pid_is_valid(pid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Process identifier " PID_FMT " is not valid.", pid);

        /* Some extra safety check */
        if (pid == 1 || pid == getpid_cached())
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Process " PID_FMT " is a manager process, refusing.", pid);

        /* Don't even begin to bother with kernel threads */
        r = is_kernel_thread(pid);
        if (r == -ESRCH)
                return sd_bus_error_setf(error, SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN, "Process with ID " PID_FMT " does not exist.", pid);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to determine whether process " PID_FMT " is a kernel thread: %m", pid);
        if (r > 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Process " PID_FMT " is a kernel thread, refusing.", pid);

        return 0;
}

void unit_log_success(Unit *u) {
        assert(u);

        /* Let's show message "Deactivated successfully" in debug mode (when manager is user) rather than in info mode.
         * This message has low information value for regular users and it might be a bit overwhelming on a system with
         * a lot of devices. */
        log_unit_struct(u,
                        MANAGER_IS_USER(u->manager) ? LOG_DEBUG : LOG_INFO,
                        "MESSAGE_ID=" SD_MESSAGE_UNIT_SUCCESS_STR,
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Deactivated successfully."));
}

void unit_log_failure(Unit *u, const char *result) {
        assert(u);
        assert(result);

        log_unit_struct(u, LOG_WARNING,
                        "MESSAGE_ID=" SD_MESSAGE_UNIT_FAILURE_RESULT_STR,
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Failed with result '%s'.", result),
                        "UNIT_RESULT=%s", result);
}

void unit_log_skip(Unit *u, const char *result) {
        assert(u);
        assert(result);

        log_unit_struct(u, LOG_INFO,
                        "MESSAGE_ID=" SD_MESSAGE_UNIT_SKIPPED_STR,
                        LOG_UNIT_INVOCATION_ID(u),
                        LOG_UNIT_MESSAGE(u, "Skipped due to '%s'.", result),
                        "UNIT_RESULT=%s", result);
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
                        "MESSAGE_ID=" SD_MESSAGE_UNIT_PROCESS_EXIT_STR,
                        LOG_UNIT_MESSAGE(u, "%s exited, code=%s, status=%i/%s%s",
                                         kind,
                                         sigchld_code_to_string(code), status,
                                         strna(code == CLD_EXITED
                                               ? exit_status_to_string(status, EXIT_STATUS_FULL)
                                               : signal_to_string(status)),
                                         success ? " (success)" : ""),
                        "EXIT_CODE=%s", sigchld_code_to_string(code),
                        "EXIT_STATUS=%i", status,
                        "COMMAND=%s", strna(command),
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

void unit_destroy_runtime_data(Unit *u, const ExecContext *context) {
        assert(u);
        assert(context);

        if (context->runtime_directory_preserve_mode == EXEC_PRESERVE_NO ||
            (context->runtime_directory_preserve_mode == EXEC_PRESERVE_RESTART && !unit_will_restart(u)))
                exec_context_destroy_runtime_directory(context, u->manager->prefix[EXEC_DIRECTORY_RUNTIME]);

        exec_context_destroy_credentials(context, u->manager->prefix[EXEC_DIRECTORY_RUNTIME], u->id);
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
        if (!IN_SET(state, UNIT_INACTIVE))
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

bool unit_can_freeze(Unit *u) {
        assert(u);

        if (UNIT_VTABLE(u)->can_freeze)
                return UNIT_VTABLE(u)->can_freeze(u);

        return UNIT_VTABLE(u)->freeze;
}

void unit_frozen(Unit *u) {
        assert(u);

        u->freezer_state = FREEZER_FROZEN;

        bus_unit_send_pending_freezer_message(u);
}

void unit_thawed(Unit *u) {
        assert(u);

        u->freezer_state = FREEZER_RUNNING;

        bus_unit_send_pending_freezer_message(u);
}

static int unit_freezer_action(Unit *u, FreezerAction action) {
        UnitActiveState s;
        int (*method)(Unit*);
        int r;

        assert(u);
        assert(IN_SET(action, FREEZER_FREEZE, FREEZER_THAW));

        method = action == FREEZER_FREEZE ? UNIT_VTABLE(u)->freeze : UNIT_VTABLE(u)->thaw;
        if (!method || !cg_freezer_supported())
                return -EOPNOTSUPP;

        if (u->job)
                return -EBUSY;

        if (u->load_state != UNIT_LOADED)
                return -EHOSTDOWN;

        s = unit_active_state(u);
        if (s != UNIT_ACTIVE)
                return -EHOSTDOWN;

        if (IN_SET(u->freezer_state, FREEZER_FREEZING, FREEZER_THAWING))
                return -EALREADY;

        r = method(u);
        if (r <= 0)
                return r;

        return 1;
}

int unit_freeze(Unit *u) {
        return unit_freezer_action(u, FREEZER_FREEZE);
}

int unit_thaw(Unit *u) {
        return unit_freezer_action(u, FREEZER_THAW);
}

/* Wrappers around low-level cgroup freezer operations common for service and scope units */
int unit_freeze_vtable_common(Unit *u) {
        return unit_cgroup_freezer_action(u, FREEZER_FREEZE);
}

int unit_thaw_vtable_common(Unit *u) {
        return unit_cgroup_freezer_action(u, FREEZER_THAW);
}

static const char* const collect_mode_table[_COLLECT_MODE_MAX] = {
        [COLLECT_INACTIVE] = "inactive",
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
