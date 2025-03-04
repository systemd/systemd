/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "dbus-swap.h"
#include "dbus-unit.h"
#include "device-util.h"
#include "device.h"
#include "escape.h"
#include "exit-status.h"
#include "fd-util.h"
#include "format-util.h"
#include "fstab-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "swap.h"
#include "unit-name.h"
#include "unit.h"
#include "virt.h"

static const UnitActiveState state_translation_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD]                 = UNIT_INACTIVE,
        [SWAP_ACTIVATING]           = UNIT_ACTIVATING,
        [SWAP_ACTIVATING_DONE]      = UNIT_ACTIVE,
        [SWAP_ACTIVE]               = UNIT_ACTIVE,
        [SWAP_DEACTIVATING]         = UNIT_DEACTIVATING,
        [SWAP_DEACTIVATING_SIGTERM] = UNIT_DEACTIVATING,
        [SWAP_DEACTIVATING_SIGKILL] = UNIT_DEACTIVATING,
        [SWAP_FAILED]               = UNIT_FAILED,
        [SWAP_CLEANING]             = UNIT_MAINTENANCE,
};

static int swap_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);
static int swap_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int swap_process_proc_swaps(Manager *m);

static bool SWAP_STATE_WITH_PROCESS(SwapState state) {
        return IN_SET(state,
                      SWAP_ACTIVATING,
                      SWAP_ACTIVATING_DONE,
                      SWAP_DEACTIVATING,
                      SWAP_DEACTIVATING_SIGTERM,
                      SWAP_DEACTIVATING_SIGKILL,
                      SWAP_CLEANING);
}

static UnitActiveState swap_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SWAP(u)->state];
}

static const char *swap_sub_state_to_string(Unit *u) {
        assert(u);

        return swap_state_to_string(SWAP(u)->state);
}

static bool swap_may_gc(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));

        if (s->from_proc_swaps)
                return false;

        return true;
}

static bool swap_is_extrinsic(Unit *u) {
        assert(SWAP(u));

        return MANAGER_IS_USER(u->manager);
}

static void swap_unset_proc_swaps(Swap *s) {
        assert(s);

        if (!s->from_proc_swaps)
                return;

        s->parameters_proc_swaps.what = mfree(s->parameters_proc_swaps.what);
        s->from_proc_swaps = false;
}

static int swap_set_devnode(Swap *s, const char *devnode) {
        Hashmap *swaps;
        Swap *first;
        int r;

        assert(s);

        r = hashmap_ensure_allocated(&UNIT(s)->manager->swaps_by_devnode, &path_hash_ops);
        if (r < 0)
                return r;

        swaps = UNIT(s)->manager->swaps_by_devnode;

        if (s->devnode) {
                first = hashmap_get(swaps, s->devnode);

                LIST_REMOVE(same_devnode, first, s);
                if (first)
                        hashmap_replace(swaps, first->devnode, first);
                else
                        hashmap_remove(swaps, s->devnode);

                s->devnode = mfree(s->devnode);
        }

        if (devnode) {
                s->devnode = strdup(devnode);
                if (!s->devnode)
                        return -ENOMEM;

                first = hashmap_get(swaps, s->devnode);
                LIST_PREPEND(same_devnode, first, s);

                return hashmap_replace(swaps, first->devnode, first);
        }

        return 0;
}

static void swap_init(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));

        assert(u->load_state == UNIT_STUB);

        s->timeout_usec = u->manager->defaults.timeout_start_usec;

        s->exec_context.std_output = u->manager->defaults.std_output;
        s->exec_context.std_error = u->manager->defaults.std_error;

        s->control_pid = PIDREF_NULL;
        s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;

        u->ignore_on_isolate = true;
}

static void swap_unwatch_control_pid(Swap *s) {
        assert(s);
        unit_unwatch_pidref_done(UNIT(s), &s->control_pid);
}

static void swap_done(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));

        swap_unset_proc_swaps(s);
        swap_set_devnode(s, NULL);

        s->what = mfree(s->what);
        s->parameters_fragment.what = mfree(s->parameters_fragment.what);
        s->parameters_fragment.options = mfree(s->parameters_fragment.options);

        s->exec_runtime = exec_runtime_free(s->exec_runtime);

        exec_command_done_array(s->exec_command, _SWAP_EXEC_COMMAND_MAX);
        s->control_command = NULL;

        swap_unwatch_control_pid(s);

        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
}

static int swap_arm_timer(Swap *s, bool relative, usec_t usec) {
        assert(s);

        return unit_arm_timer(UNIT(s), &s->timer_event_source, relative, usec, swap_dispatch_timer);
}

static SwapParameters* swap_get_parameters(Swap *s) {
        assert(s);

        if (s->from_proc_swaps)
                return &s->parameters_proc_swaps;

        if (s->from_fragment)
                return &s->parameters_fragment;

        return NULL;
}

static int swap_add_device_dependencies(Swap *s) {
        UnitDependencyMask mask;
        SwapParameters *p;
        int r;

        assert(s);

        if (!s->what)
                return 0;

        p = swap_get_parameters(s);
        if (!p || !p->what)
                return 0;

        mask = s->from_proc_swaps ? UNIT_DEPENDENCY_PROC_SWAP : UNIT_DEPENDENCY_FILE;

        if (is_device_path(p->what)) {
                r = unit_add_node_dependency(UNIT(s), p->what, UNIT_REQUIRES, mask);
                if (r < 0)
                        return r;

                return unit_add_blockdev_dependency(UNIT(s), p->what, mask);
        }

        /* File based swap devices need to be ordered after systemd-remount-fs.service, since they might need
         * a writable file system. */
        return unit_add_dependency_by_name(UNIT(s), UNIT_AFTER, SPECIAL_REMOUNT_FS_SERVICE, true, mask);
}

static int swap_add_default_dependencies(Swap *s) {
        int r;

        assert(s);

        if (!UNIT(s)->default_dependencies)
                return 0;

        if (!MANAGER_IS_SYSTEM(UNIT(s)->manager))
                return 0;

        if (detect_container() > 0)
                return 0;

        /* swap units generated for the swap dev links are missing the
         * ordering dep against the swap target. */
        r = unit_add_dependency_by_name(UNIT(s), UNIT_BEFORE, SPECIAL_SWAP_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        return unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, true, UNIT_DEPENDENCY_DEFAULT);
}

static int swap_verify(Swap *s) {
        _cleanup_free_ char *e = NULL;
        int r;

        assert(s);
        assert(UNIT(s)->load_state == UNIT_LOADED);

        r = unit_name_from_path(s->what, ".swap", &e);
        if (r < 0)
                return log_unit_error_errno(UNIT(s), r, "Failed to generate unit name from path: %m");

        if (!unit_has_name(UNIT(s), e))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOEXEC), "Value of What= and unit name do not match, not loading.");

        return 0;
}

static int swap_load_devnode(Swap *s) {
        _cleanup_free_ char *p = NULL;
        struct stat st;
        int r;

        assert(s);

        if (stat(s->what, &st) < 0 || !S_ISBLK(st.st_mode))
                return 0;

        r = devname_from_stat_rdev(&st, &p);
        if (r < 0) {
                log_unit_full_errno(UNIT(s), r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                    "Failed to get device node for swap %s: %m", s->what);
                return 0;
        }

        return swap_set_devnode(s, p);
}

static int swap_add_extras(Swap *s) {
        int r;

        assert(s);

        if (UNIT(s)->fragment_path)
                s->from_fragment = true;

        if (!s->what) {
                if (s->parameters_fragment.what)
                        s->what = strdup(s->parameters_fragment.what);
                else if (s->parameters_proc_swaps.what)
                        s->what = strdup(s->parameters_proc_swaps.what);
                else {
                        r = unit_name_to_path(UNIT(s)->id, &s->what);
                        if (r < 0)
                                return r;
                }

                if (!s->what)
                        return -ENOMEM;
        }

        path_simplify(s->what);

        if (!UNIT(s)->description) {
                r = unit_set_description(UNIT(s), s->what);
                if (r < 0)
                        return r;
        }

        r = unit_add_mounts_for(UNIT(s), s->what, UNIT_DEPENDENCY_IMPLICIT, UNIT_MOUNT_REQUIRES);
        if (r < 0)
                return r;

        r = swap_add_device_dependencies(s);
        if (r < 0)
                return r;

        r = swap_load_devnode(s);
        if (r < 0)
                return r;

        r = unit_patch_contexts(UNIT(s));
        if (r < 0)
                return r;

        r = unit_add_exec_dependencies(UNIT(s), &s->exec_context);
        if (r < 0)
                return r;

        r = unit_set_default_slice(UNIT(s));
        if (r < 0)
                return r;

        r = swap_add_default_dependencies(s);
        if (r < 0)
                return r;

        return 0;
}

static int swap_load(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));
        int r;

        assert(u->load_state == UNIT_STUB);

        /* Load a .swap file */
        r = unit_load_fragment_and_dropin(u, /* fragment_required = */ !s->from_proc_swaps);

        /* Add in some extras, and do so either when we successfully loaded something or when /proc/swaps is
         * already active. */
        if (u->load_state == UNIT_LOADED || s->from_proc_swaps)
                RET_GATHER(r, swap_add_extras(s));

        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        return swap_verify(s);
}

static int swap_setup_unit(
                Manager *m,
                const char *what,
                const char *what_proc_swaps,
                int priority,
                bool set_flags) {

        _cleanup_(unit_freep) Unit *new_unit = NULL;
        _cleanup_free_ char *e = NULL;
        Unit *u;
        Swap *s;
        int r;

        assert(m);
        assert(what);
        assert(what_proc_swaps);

        r = unit_name_from_path(what, ".swap", &e);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name from path: %m");

        u = manager_get_unit(m, e);
        if (u) {
                s = ASSERT_PTR(SWAP(u));

                if (s->from_proc_swaps &&
                    !path_equal(s->parameters_proc_swaps.what, what_proc_swaps))
                        return log_unit_error_errno(u, SYNTHETIC_ERRNO(EEXIST),
                                                    "Swap appeared twice with different device paths %s and %s, refusing.",
                                                    s->parameters_proc_swaps.what, what_proc_swaps);
        } else {
                r = unit_new_for_name(m, sizeof(Swap), e, &new_unit);
                if (r < 0)
                        return log_warning_errno(r, "Failed to load swap unit '%s': %m", e);

                u = new_unit;
                s = ASSERT_PTR(SWAP(u));

                s->what = strdup(what);
                if (!s->what)
                        return log_oom();

                unit_add_to_load_queue(u);
        }

        SwapParameters *p = &s->parameters_proc_swaps;

        if (!p->what) {
                p->what = strdup(what_proc_swaps);
                if (!p->what)
                        return log_oom();
        }

        /* The unit is definitely around now, mark it as loaded if it was previously referenced but
         * could not be loaded. After all we can load it now, from the data in /proc/swaps. */
        if (UNIT_IS_LOAD_ERROR(u->load_state)) {
                u->load_state = UNIT_LOADED;
                u->load_error = 0;
        }

        if (set_flags) {
                s->is_active = true;
                s->just_activated = !s->from_proc_swaps;
        }

        s->from_proc_swaps = true;

        p->priority = priority;
        p->priority_set = true;

        unit_add_to_dbus_queue(u);
        TAKE_PTR(new_unit);

        return 0;
}

static void swap_process_new(Manager *m, const char *device, int prio, bool set_flags) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        const char *dn;
        struct stat st, st_link;
        int r;

        assert(m);

        if (swap_setup_unit(m, device, device, prio, set_flags) < 0)
                return;

        /* If this is a block device, then let's add duplicates for
         * all other names of this block device */
        if (stat(device, &st) < 0 || !S_ISBLK(st.st_mode))
                return;

        r = sd_device_new_from_stat_rdev(&d, &st);
        if (r < 0)
                return (void) log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                             "Failed to allocate device for swap %s: %m", device);

        /* Add the main device node */
        if (sd_device_get_devname(d, &dn) >= 0 && !streq(dn, device))
                (void) swap_setup_unit(m, dn, device, prio, set_flags);

        /* Add additional units for all symlinks */
        FOREACH_DEVICE_DEVLINK(d, devlink) {

                /* Don't bother with the /dev/block links */
                if (streq(devlink, device))
                        continue;

                if (path_startswith(devlink, "/dev/block/"))
                        continue;

                if (stat(devlink, &st_link) >= 0 &&
                    (!S_ISBLK(st_link.st_mode) ||
                     st_link.st_rdev != st.st_rdev))
                        continue;

                (void) swap_setup_unit(m, devlink, device, prio, set_flags);
        }
}

static void swap_set_state(Swap *s, SwapState state) {
        SwapState old_state;

        assert(s);

        if (s->state != state)
                bus_unit_send_pending_change_signal(UNIT(s), false);

        old_state = s->state;
        s->state = state;

        if (!SWAP_STATE_WITH_PROCESS(state)) {
                s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
                swap_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;
        }

        if (state != old_state)
                log_unit_debug(UNIT(s), "Changed %s -> %s", swap_state_to_string(old_state), swap_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state], /* reload_success = */ true);

        /* If there other units for the same device node have a job
           queued it might be worth checking again if it is runnable
           now. This is necessary, since swap_start() refuses
           operation with EAGAIN if there's already another job for
           the same device node queued. */
        LIST_FOREACH_OTHERS(same_devnode, other, s)
                if (UNIT(other)->job)
                        job_add_to_run_queue(UNIT(other)->job);
}

static int swap_coldplug(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));
        SwapState new_state = SWAP_DEAD;
        int r;

        assert(s->state == SWAP_DEAD);

        if (s->deserialized_state != s->state)
                new_state = s->deserialized_state;
        else if (s->from_proc_swaps)
                new_state = SWAP_ACTIVE;

        if (new_state == s->state)
                return 0;

        if (pidref_is_set(&s->control_pid) &&
            pidref_is_unwaited(&s->control_pid) > 0 &&
            SWAP_STATE_WITH_PROCESS(new_state)) {

                r = unit_watch_pidref(UNIT(s), &s->control_pid, /* exclusive= */ false);
                if (r < 0)
                        return r;

                r = swap_arm_timer(s, /* relative= */ false, usec_add(u->state_change_timestamp.monotonic, s->timeout_usec));
                if (r < 0)
                        return r;
        }

        if (!IN_SET(new_state, SWAP_DEAD, SWAP_FAILED))
                (void) unit_setup_exec_runtime(u);

        swap_set_state(s, new_state);
        return 0;
}

static void swap_dump(Unit *u, FILE *f, const char *prefix) {
        Swap *s = ASSERT_PTR(SWAP(u));
        SwapParameters *p;
        const char *prefix2;

        assert(f);

        prefix = strempty(prefix);
        prefix2 = strjoina(prefix, "\t");

        if (s->from_proc_swaps)
                p = &s->parameters_proc_swaps;
        else if (s->from_fragment)
                p = &s->parameters_fragment;
        else
                p = NULL;

        fprintf(f,
                "%sSwap State: %s\n"
                "%sResult: %s\n"
                "%sClean Result: %s\n"
                "%sWhat: %s\n"
                "%sFrom /proc/swaps: %s\n"
                "%sFrom fragment: %s\n"
                "%sExtrinsic: %s\n",
                prefix, swap_state_to_string(s->state),
                prefix, swap_result_to_string(s->result),
                prefix, swap_result_to_string(s->clean_result),
                prefix, s->what,
                prefix, yes_no(s->from_proc_swaps),
                prefix, yes_no(s->from_fragment),
                prefix, yes_no(swap_is_extrinsic(u)));

        if (s->devnode)
                fprintf(f, "%sDevice Node: %s\n", prefix, s->devnode);

        if (p)
                fprintf(f,
                        "%sPriority: %i\n"
                        "%sOptions: %s\n",
                        prefix, p->priority,
                        prefix, strempty(p->options));

        fprintf(f,
                "%sTimeoutSec: %s\n",
                prefix, FORMAT_TIMESPAN(s->timeout_usec, USEC_PER_SEC));

        if (pidref_is_set(&s->control_pid))
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, s->control_pid.pid);

        exec_context_dump(&s->exec_context, f, prefix);
        kill_context_dump(&s->kill_context, f, prefix);
        cgroup_context_dump(UNIT(s), f, prefix);

        for (SwapExecCommand c = 0; c < _SWAP_EXEC_COMMAND_MAX; c++) {
                if (!s->exec_command[c].argv)
                        continue;

                fprintf(f, "%s%s %s:\n",
                        prefix, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), swap_exec_command_to_string(c));

                exec_command_dump(s->exec_command + c, f, prefix2);
        }
}

static int swap_spawn(Swap *s, ExecCommand *c, PidRef *ret_pid) {
        _cleanup_(exec_params_shallow_clear) ExecParameters exec_params = EXEC_PARAMETERS_INIT(
                        EXEC_APPLY_SANDBOXING|EXEC_APPLY_CHROOT|EXEC_APPLY_TTY_STDIN);
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert(s);
        assert(c);
        assert(ret_pid);

        r = unit_prepare_exec(UNIT(s));
        if (r < 0)
                return r;

        r = swap_arm_timer(s, /* relative= */ true, s->timeout_usec);
        if (r < 0)
                return r;

        r = unit_set_exec_params(UNIT(s), &exec_params);
        if (r < 0)
                return r;

        /* Assume the label inherited from systemd as the fallback */
        exec_params.fallback_smack_process_label = NULL;

        r = exec_spawn(UNIT(s),
                       c,
                       &s->exec_context,
                       &exec_params,
                       s->exec_runtime,
                       &s->cgroup_context,
                       &pidref);
        if (r < 0)
                return r;

        r = unit_watch_pidref(UNIT(s), &pidref, /* exclusive= */ true);
        if (r < 0)
                return r;

        *ret_pid = TAKE_PIDREF(pidref);
        return 0;
}

static void swap_enter_dead(Swap *s, SwapResult f) {
        assert(s);

        if (s->result == SWAP_SUCCESS)
                s->result = f;

        unit_log_result(UNIT(s), s->result == SWAP_SUCCESS, swap_result_to_string(s->result));
        unit_warn_leftover_processes(UNIT(s), /* start = */ false);

        swap_set_state(s, s->result != SWAP_SUCCESS ? SWAP_FAILED : SWAP_DEAD);

        s->exec_runtime = exec_runtime_destroy(s->exec_runtime);

        unit_destroy_runtime_data(UNIT(s), &s->exec_context, /* destroy_runtime_dir = */ true);

        unit_unref_uid_gid(UNIT(s), true);
}

static void swap_enter_active(Swap *s, SwapResult f) {
        assert(s);

        if (s->result == SWAP_SUCCESS)
                s->result = f;

        swap_set_state(s, SWAP_ACTIVE);
}

static void swap_enter_dead_or_active(Swap *s, SwapResult f) {
        assert(s);

        if (s->from_proc_swaps) {
                swap_enter_active(s, f);

                LIST_FOREACH_OTHERS(same_devnode, other, s)
                        if (UNIT(other)->job)
                                swap_enter_dead_or_active(other, f);
        } else
                swap_enter_dead(s, f);
}

static int state_to_kill_operation(Swap *s, SwapState state) {
        if (state == SWAP_DEACTIVATING_SIGTERM) {
                if (unit_has_job_type(UNIT(s), JOB_RESTART))
                        return KILL_RESTART;
                else
                        return KILL_TERMINATE;
        }

        return KILL_KILL;
}

static void swap_enter_signal(Swap *s, SwapState state, SwapResult f) {
        int r;

        assert(s);

        if (s->result == SWAP_SUCCESS)
                s->result = f;

        r = unit_kill_context(UNIT(s), state_to_kill_operation(s, state));
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");
                goto fail;
        }

        if (r > 0) {
                r = swap_arm_timer(s, /* relative= */ true, s->timeout_usec);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                        goto fail;
                }

                swap_set_state(s, state);
        } else if (state == SWAP_DEACTIVATING_SIGTERM && s->kill_context.send_sigkill)
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGKILL, SWAP_SUCCESS);
        else
                swap_enter_dead_or_active(s, SWAP_SUCCESS);

        return;

fail:
        swap_enter_dead_or_active(s, SWAP_FAILURE_RESOURCES);
}

static void swap_enter_activating(Swap *s) {
        _cleanup_free_ char *opts = NULL;
        int r;

        assert(s);

        unit_warn_leftover_processes(UNIT(s), /* start = */ true);

        s->control_command_id = SWAP_EXEC_ACTIVATE;
        s->control_command = s->exec_command + SWAP_EXEC_ACTIVATE;

        if (s->from_fragment) {
                int priority = 0;

                r = fstab_find_pri(s->parameters_fragment.options, &priority);
                if (r < 0)
                        log_unit_warning_errno(UNIT(s), r, "Failed to parse swap priority \"%s\", ignoring: %m", s->parameters_fragment.options);
                else if (r > 0 && s->parameters_fragment.priority_set)
                        log_unit_warning(UNIT(s), "Duplicate swap priority configuration by Priority= and Options= fields.");

                if (r <= 0 && s->parameters_fragment.priority_set) {
                        if (s->parameters_fragment.options)
                                r = asprintf(&opts, "%s,pri=%i", s->parameters_fragment.options, s->parameters_fragment.priority);
                        else
                                r = asprintf(&opts, "pri=%i", s->parameters_fragment.priority);
                        if (r < 0) {
                                r = log_oom();
                                goto fail;
                        }
                }
        }

        r = exec_command_set(s->control_command, "/sbin/swapon", "--fixpgsz", NULL);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to initialize swapon command line: %m");
                goto fail;
        }

        if (s->parameters_fragment.options || opts) {
                r = exec_command_append(s->control_command, "-o",
                                opts ?: s->parameters_fragment.options, NULL);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to prepare swapon command line: %m");
                        goto fail;
                }
        }

        r = exec_command_append(s->control_command, s->what, NULL);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to prepare swapon command line: %m");
                goto fail;
        }

        swap_unwatch_control_pid(s);

        r = swap_spawn(s, s->control_command, &s->control_pid);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'swapon' task: %m");
                goto fail;
        }

        swap_set_state(s, SWAP_ACTIVATING);
        return;

fail:
        swap_enter_dead_or_active(s, SWAP_FAILURE_RESOURCES);
}

static void swap_enter_deactivating(Swap *s) {
        int r;

        assert(s);

        s->control_command_id = SWAP_EXEC_DEACTIVATE;
        s->control_command = s->exec_command + SWAP_EXEC_DEACTIVATE;

        r = exec_command_set(s->control_command,
                             "/sbin/swapoff",
                             s->what,
                             NULL);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to prepare swapoff command line: %m");
                goto fail;
        }

        swap_unwatch_control_pid(s);

        r = swap_spawn(s, s->control_command, &s->control_pid);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to spawn 'swapoff' task: %m");
                goto fail;
        }

        swap_set_state(s, SWAP_DEACTIVATING);
        return;

fail:
        swap_enter_dead_or_active(s, SWAP_FAILURE_RESOURCES);
}

static void swap_cycle_clear(Swap *s) {
        assert(s);

        s->result = SWAP_SUCCESS;
        exec_command_reset_status_array(s->exec_command, _SWAP_EXEC_COMMAND_MAX);

        if (s->cgroup_runtime)
                s->cgroup_runtime->reset_accounting = true;
}

static int swap_start(Unit *u) {
        Swap *s = SWAP(u);
        int r;

        assert(s);

        /* We cannot fulfill this request right now, try again later please! */
        if (IN_SET(s->state,
                   SWAP_DEACTIVATING,
                   SWAP_DEACTIVATING_SIGTERM,
                   SWAP_DEACTIVATING_SIGKILL,
                   SWAP_CLEANING))
                return -EAGAIN;

        /* Already on it! */
        if (s->state == SWAP_ACTIVATING)
                return 0;

        assert(IN_SET(s->state, SWAP_DEAD, SWAP_FAILED));

        if (detect_container() > 0)
                return -EPERM;

        /* If there's a job for another swap unit for the same node
         * running, then let's not dispatch this one for now, and wait
         * until that other job has finished. */
        LIST_FOREACH_OTHERS(same_devnode, other, s)
                if (UNIT(other)->job && UNIT(other)->job->state == JOB_RUNNING)
                        return -EAGAIN;

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        swap_cycle_clear(s);
        swap_enter_activating(s);
        return 1;
}

static int swap_stop(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));

        switch (s->state) {

        case SWAP_DEACTIVATING:
        case SWAP_DEACTIVATING_SIGTERM:
        case SWAP_DEACTIVATING_SIGKILL:
                /* Already on it */
                return 0;

        case SWAP_ACTIVATING:
        case SWAP_ACTIVATING_DONE:
                /* There's a control process pending, directly enter kill mode */
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGTERM, SWAP_SUCCESS);
                return 0;

        case SWAP_ACTIVE:
                if (detect_container() > 0)
                        return -EPERM;

                swap_enter_deactivating(s);
                return 1;

        case SWAP_CLEANING:
                /* If we are currently cleaning, then abort it, brutally. */
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGKILL, SWAP_SUCCESS);
                return 0;

        default:
                assert_not_reached();
        }
}

static int swap_serialize(Unit *u, FILE *f, FDSet *fds) {
        Swap *s = ASSERT_PTR(SWAP(u));

        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", swap_state_to_string(s->state));
        (void) serialize_item(f, "result", swap_result_to_string(s->result));
        (void) serialize_pidref(f, fds, "control-pid", &s->control_pid);

        if (s->control_command_id >= 0)
                (void) serialize_item(f, "control-command", swap_exec_command_to_string(s->control_command_id));

        return 0;
}

static int swap_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Swap *s = ASSERT_PTR(SWAP(u));

        assert(fds);

        if (streq(key, "state")) {
                SwapState state;

                state = swap_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        s->deserialized_state = state;
        } else if (streq(key, "result")) {
                SwapResult f;

                f = swap_result_from_string(value);
                if (f < 0)
                        log_unit_debug(u, "Failed to parse result value: %s", value);
                else if (f != SWAP_SUCCESS)
                        s->result = f;
        } else if (streq(key, "control-pid")) {

                if (!pidref_is_set(&s->control_pid))
                        (void) deserialize_pidref(fds, value, &s->control_pid);

        } else if (streq(key, "control-command")) {
                SwapExecCommand id;

                id = swap_exec_command_from_string(value);
                if (id < 0)
                        log_unit_debug(u, "Failed to parse exec-command value: %s", value);
                else {
                        s->control_command_id = id;
                        s->control_command = s->exec_command + id;
                }
        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

static void swap_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Swap *s = ASSERT_PTR(SWAP(u));
        SwapResult f;

        assert(pid >= 0);

        if (pid != s->control_pid.pid)
                return;

        /* Let's scan /proc/swaps before we process SIGCHLD. For the reasoning see the similar code in
         * mount.c */
        (void) swap_process_proc_swaps(u->manager);

        pidref_done(&s->control_pid);

        if (is_clean_exit(code, status, EXIT_CLEAN_COMMAND, NULL))
                f = SWAP_SUCCESS;
        else if (code == CLD_EXITED)
                f = SWAP_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = SWAP_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = SWAP_FAILURE_CORE_DUMP;
        else
                assert_not_reached();

        if (s->result == SWAP_SUCCESS)
                s->result = f;

        if (s->control_command) {
                exec_status_exit(&s->control_command->exec_status, &s->exec_context, pid, code, status);

                s->control_command = NULL;
                s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;
        }

        unit_log_process_exit(
                        u,
                        "Swap process",
                        swap_exec_command_to_string(s->control_command_id),
                        f == SWAP_SUCCESS,
                        code, status);

        switch (s->state) {

        case SWAP_ACTIVATING:
        case SWAP_ACTIVATING_DONE:

                if (f == SWAP_SUCCESS || s->from_proc_swaps)
                        swap_enter_active(s, f);
                else
                        swap_enter_dead(s, f);
                break;

        case SWAP_DEACTIVATING:
        case SWAP_DEACTIVATING_SIGKILL:
        case SWAP_DEACTIVATING_SIGTERM:

                swap_enter_dead_or_active(s, f);
                break;

        case SWAP_CLEANING:
                if (s->clean_result == SWAP_SUCCESS)
                        s->clean_result = f;

                swap_enter_dead(s, SWAP_SUCCESS);
                break;

        default:
                assert_not_reached();
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);
}

static int swap_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Swap *s = ASSERT_PTR(SWAP(userdata));

        assert(s->timer_event_source == source);

        switch (s->state) {

        case SWAP_ACTIVATING:
        case SWAP_ACTIVATING_DONE:
                log_unit_warning(UNIT(s), "Activation timed out. Stopping.");
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGTERM, SWAP_FAILURE_TIMEOUT);
                break;

        case SWAP_DEACTIVATING:
                log_unit_warning(UNIT(s), "Deactivation timed out. Stopping.");
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGTERM, SWAP_FAILURE_TIMEOUT);
                break;

        case SWAP_DEACTIVATING_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "Swap process timed out. Killing.");
                        swap_enter_signal(s, SWAP_DEACTIVATING_SIGKILL, SWAP_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "Swap process timed out. Skipping SIGKILL. Ignoring.");
                        swap_enter_dead_or_active(s, SWAP_FAILURE_TIMEOUT);
                }
                break;

        case SWAP_DEACTIVATING_SIGKILL:
                log_unit_warning(UNIT(s), "Swap process still around after SIGKILL. Ignoring.");
                swap_enter_dead_or_active(s, SWAP_FAILURE_TIMEOUT);
                break;

        case SWAP_CLEANING:
                log_unit_warning(UNIT(s), "Cleaning timed out. killing.");

                if (s->clean_result == SWAP_SUCCESS)
                        s->clean_result = SWAP_FAILURE_TIMEOUT;

                swap_enter_signal(s, SWAP_DEACTIVATING_SIGKILL, 0);
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int swap_load_proc_swaps(Manager *m, bool set_flags) {
        assert(m);

        rewind(m->proc_swaps);

        (void) fscanf(m->proc_swaps, "%*s %*s %*s %*s %*s\n");

        for (unsigned i = 1;; i++) {
                _cleanup_free_ char *dev = NULL, *d = NULL;
                int prio = 0, k;

                k = fscanf(m->proc_swaps,
                           "%ms "  /* device/file */
                           "%*s "  /* type of swap */
                           "%*s "  /* swap size */
                           "%*s "  /* used */
                           "%i\n", /* priority */
                           &dev, &prio);
                if (k != 2) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u, skipping.", i);
                        continue;
                }

                ssize_t l = cunescape(dev, UNESCAPE_RELAX, &d);
                if (l < 0)
                        return log_error_errno(l, "Failed to unescape device path: %m");

                device_found_node(m, d, DEVICE_FOUND_SWAP, DEVICE_FOUND_SWAP);

                (void) swap_process_new(m, d, prio, set_flags);
        }

        return 0;
}

static int swap_process_proc_swaps(Manager *m) {
        int r;

        assert(m);

        r = swap_load_proc_swaps(m, true);
        if (r < 0) {
                /* Reset flags, just in case, for late calls */
                LIST_FOREACH(units_by_type, u, m->units_by_type[UNIT_SWAP]) {
                        Swap *swap = SWAP(u);

                        assert(swap);

                        swap->is_active = swap->just_activated = false;
                }

                return 0;
        }

        manager_dispatch_load_queue(m);

        LIST_FOREACH(units_by_type, u, m->units_by_type[UNIT_SWAP]) {
                Swap *swap = SWAP(u);

                assert(swap);

                if (!swap->is_active) {

                        swap_unset_proc_swaps(swap);

                        switch (swap->state) {

                        case SWAP_ACTIVE:
                                /* This has just been deactivated */
                                swap_enter_dead(swap, SWAP_SUCCESS);
                                break;

                        default:
                                /* Fire again */
                                swap_set_state(swap, swap->state);
                                break;
                        }

                        if (swap->what)
                                device_found_node(m, swap->what, DEVICE_NOT_FOUND, DEVICE_FOUND_SWAP);

                } else if (swap->just_activated) {

                        /* New swap entry */

                        switch (swap->state) {

                        case SWAP_DEAD:
                        case SWAP_FAILED:
                                (void) unit_acquire_invocation_id(u);
                                swap_cycle_clear(swap);
                                swap_enter_active(swap, SWAP_SUCCESS);
                                break;

                        case SWAP_ACTIVATING:
                                swap_set_state(swap, SWAP_ACTIVATING_DONE);
                                break;

                        default:
                                /* Nothing really changed, but let's
                                 * issue an notification call
                                 * nonetheless, in case somebody is
                                 * waiting for this. */
                                swap_set_state(swap, swap->state);
                                break;
                        }
                }

                /* Reset the flags for later calls */
                swap->is_active = swap->just_activated = false;
        }

        return 1;
}

static int swap_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(revents & EPOLLPRI);

        return swap_process_proc_swaps(m);
}

static Unit* swap_following(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));
        Swap *first = NULL;

        /* If the user configured the swap through /etc/fstab or
         * a device unit, follow that. */

        if (s->from_fragment)
                return NULL;

        LIST_FOREACH_OTHERS(same_devnode, other, s)
                if (other->from_fragment)
                        return UNIT(other);

        /* Otherwise, make everybody follow the unit that's named after
         * the swap device in the kernel */

        if (streq_ptr(s->what, s->devnode))
                return NULL;

        LIST_FOREACH(same_devnode, other, s->same_devnode_next)
                if (streq_ptr(other->what, other->devnode))
                        return UNIT(other);

        LIST_FOREACH_BACKWARDS(same_devnode, other, s->same_devnode_prev) {
                if (streq_ptr(other->what, other->devnode))
                        return UNIT(other);

                first = other;
        }

        /* Fall back to the first on the list */
        return UNIT(first);
}

static int swap_following_set(Unit *u, Set **ret) {
        Swap *s = ASSERT_PTR(SWAP(u));
        _cleanup_set_free_ Set *set = NULL;
        int r;

        assert(ret);

        if (LIST_JUST_US(same_devnode, s)) {
                *ret = NULL;
                return 0;
        }

        set = set_new(NULL);
        if (!set)
                return -ENOMEM;

        LIST_FOREACH_OTHERS(same_devnode, other, s) {
                r = set_put(set, other);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(set);
        return 1;
}

static void swap_shutdown(Manager *m) {
        assert(m);

        m->swap_event_source = sd_event_source_disable_unref(m->swap_event_source);
        m->proc_swaps = safe_fclose(m->proc_swaps);
        m->swaps_by_devnode = hashmap_free(m->swaps_by_devnode);
}

static void swap_enumerate(Manager *m) {
        int r;

        assert(m);

        if (!m->proc_swaps) {
                m->proc_swaps = fopen("/proc/swaps", "re");
                if (!m->proc_swaps) {
                        if (errno == ENOENT)
                                log_debug_errno(errno, "Not swap enabled, skipping enumeration.");
                        else
                                log_warning_errno(errno, "Failed to open /proc/swaps, ignoring: %m");

                        return;
                }

                r = sd_event_add_io(m->event, &m->swap_event_source, fileno(m->proc_swaps), EPOLLPRI, swap_dispatch_io, m);
                if (r < 0) {
                        log_error_errno(r, "Failed to watch /proc/swaps: %m");
                        goto fail;
                }

                /* Dispatch this before we dispatch SIGCHLD, so that
                 * we always get the events from /proc/swaps before
                 * the SIGCHLD of /sbin/swapon. */
                r = sd_event_source_set_priority(m->swap_event_source, EVENT_PRIORITY_SWAP_TABLE);
                if (r < 0) {
                        log_error_errno(r, "Failed to change /proc/swaps priority: %m");
                        goto fail;
                }

                (void) sd_event_source_set_description(m->swap_event_source, "swap-proc");
        }

        r = swap_load_proc_swaps(m, false);
        if (r < 0)
                goto fail;

        return;

fail:
        swap_shutdown(m);
}

int swap_process_device_new(Manager *m, sd_device *dev) {
        _cleanup_free_ char *e = NULL;
        const char *dn;
        Unit *u;
        int r;

        assert(m);
        assert(dev);

        if (sd_device_get_devname(dev, &dn) < 0)
                return 0;

        r = unit_name_from_path(dn, ".swap", &e);
        if (r < 0) {
                log_debug_errno(r, "Cannot convert device name '%s' to unit name, ignoring: %m", dn);
                return 0;
        }

        u = manager_get_unit(m, e);
        if (u)
                r = swap_set_devnode(SWAP(u), dn);

        FOREACH_DEVICE_DEVLINK(dev, devlink) {
                _cleanup_free_ char *n = NULL;
                int q;

                q = unit_name_from_path(devlink, ".swap", &n);
                if (q == -EINVAL) /* If the name is not convertible to unit name, we can't manage it */
                        continue;
                if (q < 0)
                        return q;

                u = manager_get_unit(m, n);
                if (u) {
                        q = swap_set_devnode(SWAP(u), dn);
                        if (q < 0)
                                r = q;
                }
        }

        return r;
}

int swap_process_device_remove(Manager *m, sd_device *dev) {
        const char *dn;
        Swap *s;
        int r;

        r = sd_device_get_devname(dev, &dn);
        if (r < 0)
                return 0;

        r = 0;
        while ((s = hashmap_get(m->swaps_by_devnode, dn)))
                RET_GATHER(r, swap_set_devnode(s, NULL));

        return r;
}

static void swap_reset_failed(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));

        if (s->state == SWAP_FAILED)
                swap_set_state(s, SWAP_DEAD);

        s->result = SWAP_SUCCESS;
        s->clean_result = SWAP_SUCCESS;
}

static void swap_handoff_timestamp(
                Unit *u,
                const struct ucred *ucred,
                const dual_timestamp *ts) {

        Swap *s = ASSERT_PTR(SWAP(u));

        assert(ucred);
        assert(ts);

        if (s->control_pid.pid == ucred->pid && s->control_command) {
                exec_status_handoff(&s->control_command->exec_status, ucred, ts);
                unit_add_to_dbus_queue(u);
        }
}

static int swap_get_timeout(Unit *u, usec_t *timeout) {
        Swap *s = ASSERT_PTR(SWAP(u));
        usec_t t;
        int r;

        if (!s->timer_event_source)
                return 0;

        r = sd_event_source_get_time(s->timer_event_source, &t);
        if (r < 0)
                return r;
        if (t == USEC_INFINITY)
                return 0;

        *timeout = t;
        return 1;
}

static bool swap_supported(void) {
        static int supported = -1;

        /* If swap support is not available in the kernel, or we are
         * running in a container we don't support swap units, and any
         * attempts to starting one should fail immediately. */

        if (supported < 0)
                supported =
                        access("/proc/swaps", F_OK) >= 0 &&
                        detect_container() <= 0;

        return supported;
}

static PidRef* swap_control_pid(Unit *u) {
        return &ASSERT_PTR(SWAP(u))->control_pid;
}

static int swap_clean(Unit *u, ExecCleanMask mask) {
        Swap *s = ASSERT_PTR(SWAP(u));
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(mask != 0);

        if (s->state != SWAP_DEAD)
                return -EBUSY;

        r = exec_context_get_clean_directories(&s->exec_context, u->manager->prefix, mask, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l))
                return -EUNATCH;

        swap_unwatch_control_pid(s);
        s->clean_result = SWAP_SUCCESS;
        s->control_command = NULL;
        s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;

        r = swap_arm_timer(s, /* relative= */ true, s->exec_context.timeout_clean_usec);
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to install timer: %m");
                goto fail;
        }

        r = unit_fork_and_watch_rm_rf(u, l, &s->control_pid);
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to spawn cleaning task: %m");
                goto fail;
        }

        swap_set_state(s, SWAP_CLEANING);
        return 0;

fail:
        s->clean_result = SWAP_FAILURE_RESOURCES;
        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
        return r;
}

static int swap_can_clean(Unit *u, ExecCleanMask *ret) {
        Swap *s = ASSERT_PTR(SWAP(u));

        return exec_context_get_clean_mask(&s->exec_context, ret);
}

static int swap_can_start(Unit *u) {
        Swap *s = ASSERT_PTR(SWAP(u));
        int r;

        r = unit_test_start_limit(u);
        if (r < 0) {
                swap_enter_dead(s, SWAP_FAILURE_START_LIMIT_HIT);
                return r;
        }

        return 1;
}

int swap_get_priority(const Swap *s) {
        assert(s);

        if (s->from_proc_swaps && s->parameters_proc_swaps.priority_set)
                return s->parameters_proc_swaps.priority;

        if (s->from_fragment && s->parameters_fragment.priority_set)
                return s->parameters_fragment.priority;

        return -1;
}

const char* swap_get_options(const Swap *s) {
        assert(s);

        if (s->from_fragment)
                return s->parameters_fragment.options;

        return NULL;
}

static const char* const swap_exec_command_table[_SWAP_EXEC_COMMAND_MAX] = {
        [SWAP_EXEC_ACTIVATE]   = "ExecActivate",
        [SWAP_EXEC_DEACTIVATE] = "ExecDeactivate",
};

DEFINE_STRING_TABLE_LOOKUP(swap_exec_command, SwapExecCommand);

static const char* const swap_result_table[_SWAP_RESULT_MAX] = {
        [SWAP_SUCCESS]                 = "success",
        [SWAP_FAILURE_RESOURCES]       = "resources",
        [SWAP_FAILURE_TIMEOUT]         = "timeout",
        [SWAP_FAILURE_EXIT_CODE]       = "exit-code",
        [SWAP_FAILURE_SIGNAL]          = "signal",
        [SWAP_FAILURE_CORE_DUMP]       = "core-dump",
        [SWAP_FAILURE_START_LIMIT_HIT] = "start-limit-hit",
};

DEFINE_STRING_TABLE_LOOKUP(swap_result, SwapResult);

const UnitVTable swap_vtable = {
        .object_size = sizeof(Swap),
        .exec_context_offset = offsetof(Swap, exec_context),
        .cgroup_context_offset = offsetof(Swap, cgroup_context),
        .kill_context_offset = offsetof(Swap, kill_context),
        .exec_runtime_offset = offsetof(Swap, exec_runtime),
        .cgroup_runtime_offset = offsetof(Swap, cgroup_runtime),

        .sections =
                "Unit\0"
                "Swap\0"
                "Install\0",
        .private_section = "Swap",

        .can_fail = true,

        .init = swap_init,
        .load = swap_load,
        .done = swap_done,

        .coldplug = swap_coldplug,

        .dump = swap_dump,

        .start = swap_start,
        .stop = swap_stop,

        .clean = swap_clean,
        .can_clean = swap_can_clean,

        .get_timeout = swap_get_timeout,

        .serialize = swap_serialize,
        .deserialize_item = swap_deserialize_item,

        .active_state = swap_active_state,
        .sub_state_to_string = swap_sub_state_to_string,

        .will_restart = unit_will_restart_default,

        .may_gc = swap_may_gc,
        .is_extrinsic = swap_is_extrinsic,

        .sigchld_event = swap_sigchld_event,

        .reset_failed = swap_reset_failed,

        .notify_handoff_timestamp = swap_handoff_timestamp,

        .control_pid = swap_control_pid,

        .bus_set_property = bus_swap_set_property,
        .bus_commit_properties = bus_swap_commit_properties,

        .following = swap_following,
        .following_set = swap_following_set,

        .enumerate = swap_enumerate,
        .shutdown = swap_shutdown,
        .supported = swap_supported,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Activating swap %s...",
                        [1] = "Deactivating swap %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Activated swap %s.",
                        [JOB_FAILED]     = "Failed to activate swap %s.",
                        [JOB_TIMEOUT]    = "Timed out activating swap %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Deactivated swap %s.",
                        [JOB_FAILED]     = "Failed deactivating swap %s.",
                        [JOB_TIMEOUT]    = "Timed out deactivating swap %s.",
                },
        },

        .can_start = swap_can_start,

        .notify_plymouth = true,
};
