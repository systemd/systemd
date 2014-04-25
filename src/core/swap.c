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

#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <libudev.h>

#include "unit.h"
#include "swap.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "unit-name.h"
#include "dbus-swap.h"
#include "special.h"
#include "bus-errors.h"
#include "exit-status.h"
#include "def.h"
#include "path-util.h"
#include "virt.h"
#include "udev-util.h"

static const UnitActiveState state_translation_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = UNIT_INACTIVE,
        [SWAP_ACTIVATING] = UNIT_ACTIVATING,
        [SWAP_ACTIVATING_DONE] = UNIT_ACTIVE,
        [SWAP_ACTIVE] = UNIT_ACTIVE,
        [SWAP_DEACTIVATING] = UNIT_DEACTIVATING,
        [SWAP_ACTIVATING_SIGTERM] = UNIT_DEACTIVATING,
        [SWAP_ACTIVATING_SIGKILL] = UNIT_DEACTIVATING,
        [SWAP_DEACTIVATING_SIGTERM] = UNIT_DEACTIVATING,
        [SWAP_DEACTIVATING_SIGKILL] = UNIT_DEACTIVATING,
        [SWAP_FAILED] = UNIT_FAILED
};

static int swap_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);
static int swap_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata);

static void swap_unset_proc_swaps(Swap *s) {
        assert(s);

        if (!s->from_proc_swaps)
                return;

        free(s->parameters_proc_swaps.what);
        s->parameters_proc_swaps.what = NULL;

        s->from_proc_swaps = false;
}

static int swap_set_devnode(Swap *s, const char *devnode) {
        Hashmap *swaps;
        Swap *first;
        int r;

        assert(s);

        r = hashmap_ensure_allocated(&UNIT(s)->manager->swaps_by_devnode, string_hash_func, string_compare_func);
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

                free(s->devnode);
                s->devnode = NULL;
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
        Swap *s = SWAP(u);

        assert(s);
        assert(UNIT(s)->load_state == UNIT_STUB);

        s->timeout_usec = u->manager->default_timeout_start_usec;

        s->exec_context.std_output = u->manager->default_std_output;
        s->exec_context.std_error = u->manager->default_std_error;

        s->parameters_proc_swaps.priority = s->parameters_fragment.priority = -1;

        s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;

        u->ignore_on_isolate = true;
}

static void swap_unwatch_control_pid(Swap *s) {
        assert(s);

        if (s->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(s), s->control_pid);
        s->control_pid = 0;
}

static void swap_done(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        swap_unset_proc_swaps(s);
        swap_set_devnode(s, NULL);

        free(s->what);
        s->what = NULL;

        free(s->parameters_fragment.what);
        s->parameters_fragment.what = NULL;

        s->exec_runtime = exec_runtime_unref(s->exec_runtime);
        exec_command_done_array(s->exec_command, _SWAP_EXEC_COMMAND_MAX);
        s->control_command = NULL;

        swap_unwatch_control_pid(s);

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);
}

static int swap_arm_timer(Swap *s) {
        int r;

        assert(s);

        if (s->timeout_usec <= 0) {
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);
                return 0;
        }

        if (s->timer_event_source) {
                r = sd_event_source_set_time(s->timer_event_source, now(CLOCK_MONOTONIC) + s->timeout_usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(s->timer_event_source, SD_EVENT_ONESHOT);
        }

        return sd_event_add_time(
                        UNIT(s)->manager->event,
                        &s->timer_event_source,
                        CLOCK_MONOTONIC,
                        now(CLOCK_MONOTONIC) + s->timeout_usec, 0,
                        swap_dispatch_timer, s);
}

static int swap_add_device_links(Swap *s) {
        SwapParameters *p;

        assert(s);

        if (!s->what)
                return 0;

        if (s->from_fragment)
                p = &s->parameters_fragment;
        else
                return 0;

        if (is_device_path(s->what))
                return unit_add_node_link(UNIT(s), s->what, !p->noauto && UNIT(s)->manager->running_as == SYSTEMD_SYSTEM);
        else
                /* File based swap devices need to be ordered after
                 * systemd-remount-fs.service, since they might need a
                 * writable file system. */
                return unit_add_dependency_by_name(UNIT(s), UNIT_AFTER, SPECIAL_REMOUNT_FS_SERVICE, NULL, true);
}

static int swap_add_default_dependencies(Swap *s) {
        bool nofail = false, noauto = false;
        int r;

        assert(s);

        if (UNIT(s)->manager->running_as != SYSTEMD_SYSTEM)
                return 0;

        if (detect_container(NULL) > 0)
                return 0;

        r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, NULL, true);
        if (r < 0)
                return r;

        if (s->from_fragment) {
                SwapParameters *p = &s->parameters_fragment;

                nofail = p->nofail;
                noauto = p->noauto;
        }

        if (!noauto) {
                if (nofail)
                        r = unit_add_dependency_by_name_inverse(UNIT(s), UNIT_WANTS, SPECIAL_SWAP_TARGET, NULL, true);
                else
                        r = unit_add_two_dependencies_by_name_inverse(UNIT(s), UNIT_AFTER, UNIT_REQUIRES, SPECIAL_SWAP_TARGET, NULL, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int swap_verify(Swap *s) {
        bool b;
        _cleanup_free_ char *e = NULL;

        if (UNIT(s)->load_state != UNIT_LOADED)
                return 0;

        e = unit_name_from_path(s->what, ".swap");
        if (!e)
                return log_oom();

        b = unit_has_name(UNIT(s), e);
        if (!b) {
                log_error_unit(UNIT(s)->id, "%s: Value of \"What\" and unit name do not match, not loading.", UNIT(s)->id);
                return -EINVAL;
        }

        if (s->exec_context.pam_name && s->kill_context.kill_mode != KILL_CONTROL_GROUP) {
                log_error_unit(UNIT(s)->id, "%s has PAM enabled. Kill mode must be set to 'control-group'. Refusing to load.", UNIT(s)->id);
                return -EINVAL;
        }

        return 0;
}

static int swap_load_devnode(Swap *s) {
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        struct stat st;
        const char *p;

        assert(s);

        if (stat(s->what, &st) < 0 || !S_ISBLK(st.st_mode))
                return 0;

        d = udev_device_new_from_devnum(UNIT(s)->manager->udev, 'b', st.st_rdev);
        if (!d)
                return 0;

        p = udev_device_get_devnode(d);
        if (!p)
                return 0;

        return swap_set_devnode(s, p);
}

static int swap_load(Unit *u) {
        int r;
        Swap *s = SWAP(u);

        assert(s);
        assert(u->load_state == UNIT_STUB);

        /* Load a .swap file */
        r = unit_load_fragment_and_dropin_optional(u);
        if (r < 0)
                return r;

        if (u->load_state == UNIT_LOADED) {

                if (UNIT(s)->fragment_path)
                        s->from_fragment = true;

                if (!s->what) {
                        if (s->parameters_fragment.what)
                                s->what = strdup(s->parameters_fragment.what);
                        else if (s->parameters_proc_swaps.what)
                                s->what = strdup(s->parameters_proc_swaps.what);
                        else
                                s->what = unit_name_to_path(u->id);

                        if (!s->what)
                                return -ENOMEM;
                }

                path_kill_slashes(s->what);

                if (!UNIT(s)->description) {
                        r = unit_set_description(u, s->what);
                        if (r < 0)
                                return r;
                }

                r = unit_require_mounts_for(UNIT(s), s->what);
                if (r < 0)
                        return r;

                r = swap_add_device_links(s);
                if (r < 0)
                        return r;

                r = swap_load_devnode(s);
                if (r < 0)
                        return r;

                r = unit_patch_contexts(u);
                if (r < 0)
                        return r;

                r = unit_add_exec_dependencies(u, &s->exec_context);
                if (r < 0)
                        return r;

                r = unit_add_default_slice(u, &s->cgroup_context);
                if (r < 0)
                        return r;

                if (UNIT(s)->default_dependencies) {
                        r = swap_add_default_dependencies(s);
                        if (r < 0)
                                return r;
                }
        }

        return swap_verify(s);
}

static int swap_add_one(
                Manager *m,
                const char *what,
                const char *what_proc_swaps,
                int priority,
                bool noauto,
                bool nofail,
                bool set_flags) {

        _cleanup_free_ char *e = NULL;
        bool delete = false;
        Unit *u = NULL;
        int r;
        SwapParameters *p;

        assert(m);
        assert(what);
        assert(what_proc_swaps);

        e = unit_name_from_path(what, ".swap");
        if (!e)
                return log_oom();

        u = manager_get_unit(m, e);

        if (u &&
            SWAP(u)->from_proc_swaps &&
            !path_equal(SWAP(u)->parameters_proc_swaps.what, what_proc_swaps))
                return -EEXIST;

        if (!u) {
                delete = true;

                u = unit_new(m, sizeof(Swap));
                if (!u)
                        return log_oom();

                r = unit_add_name(u, e);
                if (r < 0)
                        goto fail;

                SWAP(u)->what = strdup(what);
                if (!SWAP(u)->what) {
                        r = log_oom();
                        goto fail;
                }

                unit_add_to_load_queue(u);
        } else
                delete = false;

        p = &SWAP(u)->parameters_proc_swaps;

        if (!p->what) {
                p->what = strdup(what_proc_swaps);
                if (!p->what) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (set_flags) {
                SWAP(u)->is_active = true;
                SWAP(u)->just_activated = !SWAP(u)->from_proc_swaps;
        }

        SWAP(u)->from_proc_swaps = true;

        p->priority = priority;
        p->noauto = noauto;
        p->nofail = nofail;

        unit_add_to_dbus_queue(u);

        return 0;

fail:
        log_warning_unit(e, "Failed to load swap unit: %s", strerror(-r));

        if (delete && u)
                unit_free(u);

        return r;
}

static int swap_process_new_swap(Manager *m, const char *device, int prio, bool set_flags) {
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;
        const char *dn;
        struct stat st;
        int r;

        assert(m);

        r = swap_add_one(m, device, device, prio, false, false, set_flags);
        if (r < 0)
                return r;

        /* If this is a block device, then let's add duplicates for
         * all other names of this block device */
        if (stat(device, &st) < 0 || !S_ISBLK(st.st_mode))
                return 0;

        d = udev_device_new_from_devnum(m->udev, 'b', st.st_rdev);
        if (!d)
                return 0;

        /* Add the main device node */
        dn = udev_device_get_devnode(d);
        if (dn && !streq(dn, device))
                swap_add_one(m, dn, device, prio, false, false, set_flags);

        /* Add additional units for all symlinks */
        first = udev_device_get_devlinks_list_entry(d);
        udev_list_entry_foreach(item, first) {
                const char *p;

                /* Don't bother with the /dev/block links */
                p = udev_list_entry_get_name(item);

                if (streq(p, device))
                        continue;

                if (path_startswith(p, "/dev/block/"))
                        continue;

                if (stat(p, &st) >= 0)
                        if (!S_ISBLK(st.st_mode) ||
                            st.st_rdev != udev_device_get_devnum(d))
                                continue;

                swap_add_one(m, p, device, prio, false, false, set_flags);
        }

        return r;
}

static void swap_set_state(Swap *s, SwapState state) {
        SwapState old_state;

        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != SWAP_ACTIVATING &&
            state != SWAP_ACTIVATING_SIGTERM &&
            state != SWAP_ACTIVATING_SIGKILL &&
            state != SWAP_ACTIVATING_DONE &&
            state != SWAP_DEACTIVATING &&
            state != SWAP_DEACTIVATING_SIGTERM &&
            state != SWAP_DEACTIVATING_SIGKILL) {
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);
                swap_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;
        }

        if (state != old_state)
                log_debug_unit(UNIT(s)->id,
                               "%s changed %s -> %s",
                               UNIT(s)->id,
                               swap_state_to_string(old_state),
                               swap_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state], true);
}

static int swap_coldplug(Unit *u) {
        Swap *s = SWAP(u);
        SwapState new_state = SWAP_DEAD;
        int r;

        assert(s);
        assert(s->state == SWAP_DEAD);

        if (s->deserialized_state != s->state)
                new_state = s->deserialized_state;
        else if (s->from_proc_swaps)
                new_state = SWAP_ACTIVE;

        if (new_state == s->state)
                return 0;

        if (new_state == SWAP_ACTIVATING ||
            new_state == SWAP_ACTIVATING_SIGTERM ||
            new_state == SWAP_ACTIVATING_SIGKILL ||
            new_state == SWAP_ACTIVATING_DONE ||
            new_state == SWAP_DEACTIVATING ||
            new_state == SWAP_DEACTIVATING_SIGTERM ||
            new_state == SWAP_DEACTIVATING_SIGKILL) {

                if (s->control_pid <= 0)
                        return -EBADMSG;

                r = unit_watch_pid(UNIT(s), s->control_pid);
                if (r < 0)
                        return r;

                r = swap_arm_timer(s);
                if (r < 0)
                        return r;
        }

        swap_set_state(s, new_state);
        return 0;
}

static void swap_dump(Unit *u, FILE *f, const char *prefix) {
        Swap *s = SWAP(u);
        SwapParameters *p;

        assert(s);
        assert(f);

        if (s->from_proc_swaps)
                p = &s->parameters_proc_swaps;
        else if (s->from_fragment)
                p = &s->parameters_fragment;
        else
                p = NULL;

        fprintf(f,
                "%sSwap State: %s\n"
                "%sResult: %s\n"
                "%sWhat: %s\n"
                "%sFrom /proc/swaps: %s\n"
                "%sFrom fragment: %s\n",
                prefix, swap_state_to_string(s->state),
                prefix, swap_result_to_string(s->result),
                prefix, s->what,
                prefix, yes_no(s->from_proc_swaps),
                prefix, yes_no(s->from_fragment));

        if (s->devnode)
                fprintf(f, "%sDevice Node: %s\n", prefix, s->devnode);

        if (p)
                fprintf(f,
                        "%sPriority: %i\n"
                        "%sNoAuto: %s\n"
                        "%sNoFail: %s\n",
                        prefix, p->priority,
                        prefix, yes_no(p->noauto),
                        prefix, yes_no(p->nofail));

        if (s->control_pid > 0)
                fprintf(f,
                        "%sControl PID: "PID_FMT"\n",
                        prefix, s->control_pid);

        exec_context_dump(&s->exec_context, f, prefix);
        kill_context_dump(&s->kill_context, f, prefix);
}

static int swap_spawn(Swap *s, ExecCommand *c, pid_t *_pid) {
        pid_t pid;
        int r;

        assert(s);
        assert(c);
        assert(_pid);

        unit_realize_cgroup(UNIT(s));

        r = unit_setup_exec_runtime(UNIT(s));
        if (r < 0)
                goto fail;

        r = swap_arm_timer(s);
        if (r < 0)
                goto fail;

        r = exec_spawn(c,
                       NULL,
                       &s->exec_context,
                       NULL, 0,
                       UNIT(s)->manager->environment,
                       true,
                       true,
                       true,
                       UNIT(s)->manager->confirm_spawn,
                       UNIT(s)->manager->cgroup_supported,
                       UNIT(s)->cgroup_path,
                       manager_get_runtime_prefix(UNIT(s)->manager),
                       UNIT(s)->id,
                       0,
                       NULL,
                       s->exec_runtime,
                       &pid);
        if (r < 0)
                goto fail;

        r = unit_watch_pid(UNIT(s), pid);
        if (r < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        return r;
}

static void swap_enter_dead(Swap *s, SwapResult f) {
        assert(s);

        if (f != SWAP_SUCCESS)
                s->result = f;

        exec_runtime_destroy(s->exec_runtime);
        s->exec_runtime = exec_runtime_unref(s->exec_runtime);

        exec_context_destroy_runtime_directory(&s->exec_context, manager_get_runtime_prefix(UNIT(s)->manager));

        swap_set_state(s, s->result != SWAP_SUCCESS ? SWAP_FAILED : SWAP_DEAD);
}

static void swap_enter_active(Swap *s, SwapResult f) {
        assert(s);

        if (f != SWAP_SUCCESS)
                s->result = f;

        swap_set_state(s, SWAP_ACTIVE);
}

static void swap_enter_signal(Swap *s, SwapState state, SwapResult f) {
        int r;

        assert(s);

        if (f != SWAP_SUCCESS)
                s->result = f;

        r = unit_kill_context(
                        UNIT(s),
                        &s->kill_context,
                        state != SWAP_ACTIVATING_SIGTERM && state != SWAP_DEACTIVATING_SIGTERM,
                        -1,
                        s->control_pid,
                        false);
        if (r < 0)
                goto fail;

        if (r > 0) {
                r = swap_arm_timer(s);
                if (r < 0)
                        goto fail;

                swap_set_state(s, state);
        } else if (state == SWAP_ACTIVATING_SIGTERM)
                swap_enter_signal(s, SWAP_ACTIVATING_SIGKILL, SWAP_SUCCESS);
        else if (state == SWAP_DEACTIVATING_SIGTERM)
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGKILL, SWAP_SUCCESS);
        else
                swap_enter_dead(s, SWAP_SUCCESS);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to kill processes: %s", UNIT(s)->id, strerror(-r));

        swap_enter_dead(s, SWAP_FAILURE_RESOURCES);
}

static void swap_enter_activating(Swap *s) {
        int r, priority;

        assert(s);

        s->control_command_id = SWAP_EXEC_ACTIVATE;
        s->control_command = s->exec_command + SWAP_EXEC_ACTIVATE;

        if (s->from_fragment)
                priority = s->parameters_fragment.priority;
        else
                priority = -1;

        if (priority >= 0) {
                char p[DECIMAL_STR_MAX(int)];

                sprintf(p, "%i", priority);

                r = exec_command_set(
                                s->control_command,
                                "/sbin/swapon",
                                "-p",
                                p,
                                s->what,
                                NULL);
        } else
                r = exec_command_set(
                                s->control_command,
                                "/sbin/swapon",
                                s->what,
                                NULL);

        if (r < 0)
                goto fail;

        swap_unwatch_control_pid(s);

        r = swap_spawn(s, s->control_command, &s->control_pid);
        if (r < 0)
                goto fail;

        swap_set_state(s, SWAP_ACTIVATING);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'swapon' task: %s",
                         UNIT(s)->id, strerror(-r));
        swap_enter_dead(s, SWAP_FAILURE_RESOURCES);
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
        if (r < 0)
                goto fail;

        swap_unwatch_control_pid(s);

        r = swap_spawn(s, s->control_command, &s->control_pid);
        if (r < 0)
                goto fail;

        swap_set_state(s, SWAP_DEACTIVATING);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to run 'swapoff' task: %s",
                         UNIT(s)->id, strerror(-r));
        swap_enter_active(s, SWAP_FAILURE_RESOURCES);
}

static int swap_start(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */

        if (s->state == SWAP_DEACTIVATING ||
            s->state == SWAP_DEACTIVATING_SIGTERM ||
            s->state == SWAP_DEACTIVATING_SIGKILL ||
            s->state == SWAP_ACTIVATING_SIGTERM ||
            s->state == SWAP_ACTIVATING_SIGKILL)
                return -EAGAIN;

        if (s->state == SWAP_ACTIVATING)
                return 0;

        assert(s->state == SWAP_DEAD || s->state == SWAP_FAILED);

        if (detect_container(NULL) > 0)
                return -EPERM;

        s->result = SWAP_SUCCESS;
        swap_enter_activating(s);
        return 0;
}

static int swap_stop(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        if (s->state == SWAP_DEACTIVATING ||
            s->state == SWAP_DEACTIVATING_SIGTERM ||
            s->state == SWAP_DEACTIVATING_SIGKILL ||
            s->state == SWAP_ACTIVATING_SIGTERM ||
            s->state == SWAP_ACTIVATING_SIGKILL)
                return 0;

        assert(s->state == SWAP_ACTIVATING ||
               s->state == SWAP_ACTIVATING_DONE ||
               s->state == SWAP_ACTIVE);

        if (detect_container(NULL) > 0)
                return -EPERM;

        swap_enter_deactivating(s);
        return 0;
}

static int swap_serialize(Unit *u, FILE *f, FDSet *fds) {
        Swap *s = SWAP(u);

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", swap_state_to_string(s->state));
        unit_serialize_item(u, f, "result", swap_result_to_string(s->result));

        if (s->control_pid > 0)
                unit_serialize_item_format(u, f, "control-pid", PID_FMT, s->control_pid);

        if (s->control_command_id >= 0)
                unit_serialize_item(u, f, "control-command", swap_exec_command_to_string(s->control_command_id));

        return 0;
}

static int swap_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Swap *s = SWAP(u);

        assert(s);
        assert(fds);

        if (streq(key, "state")) {
                SwapState state;

                state = swap_state_from_string(value);
                if (state < 0)
                        log_debug_unit(u->id, "Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;
        } else if (streq(key, "result")) {
                SwapResult f;

                f = swap_result_from_string(value);
                if (f < 0)
                        log_debug_unit(u->id, "Failed to parse result value %s", value);
                else if (f != SWAP_SUCCESS)
                        s->result = f;
        } else if (streq(key, "control-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_debug_unit(u->id, "Failed to parse control-pid value %s", value);
                else
                        s->control_pid = pid;

        } else if (streq(key, "control-command")) {
                SwapExecCommand id;

                id = swap_exec_command_from_string(value);
                if (id < 0)
                        log_debug_unit(u->id, "Failed to parse exec-command value %s", value);
                else {
                        s->control_command_id = id;
                        s->control_command = s->exec_command + id;
                }
        } else
                log_debug_unit(u->id, "Unknown serialization key '%s'", key);

        return 0;
}

_pure_ static UnitActiveState swap_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SWAP(u)->state];
}

_pure_ static const char *swap_sub_state_to_string(Unit *u) {
        assert(u);

        return swap_state_to_string(SWAP(u)->state);
}

_pure_ static bool swap_check_gc(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        return s->from_proc_swaps;
}

static void swap_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Swap *s = SWAP(u);
        SwapResult f;

        assert(s);
        assert(pid >= 0);

        if (pid != s->control_pid)
                return;

        s->control_pid = 0;

        if (is_clean_exit(code, status, NULL))
                f = SWAP_SUCCESS;
        else if (code == CLD_EXITED)
                f = SWAP_FAILURE_EXIT_CODE;
        else if (code == CLD_KILLED)
                f = SWAP_FAILURE_SIGNAL;
        else if (code == CLD_DUMPED)
                f = SWAP_FAILURE_CORE_DUMP;
        else
                assert_not_reached("Unknown code");

        if (f != SWAP_SUCCESS)
                s->result = f;

        if (s->control_command) {
                exec_status_exit(&s->control_command->exec_status, &s->exec_context, pid, code, status);

                s->control_command = NULL;
                s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;
        }

        log_full_unit(f == SWAP_SUCCESS ? LOG_DEBUG : LOG_NOTICE,
                      u->id,
                      "%s swap process exited, code=%s status=%i",
                      u->id, sigchld_code_to_string(code), status);

        switch (s->state) {

        case SWAP_ACTIVATING:
        case SWAP_ACTIVATING_DONE:
        case SWAP_ACTIVATING_SIGTERM:
        case SWAP_ACTIVATING_SIGKILL:

                if (f == SWAP_SUCCESS)
                        swap_enter_active(s, f);
                else
                        swap_enter_dead(s, f);
                break;

        case SWAP_DEACTIVATING:
        case SWAP_DEACTIVATING_SIGKILL:
        case SWAP_DEACTIVATING_SIGTERM:

                swap_enter_dead(s, f);
                break;

        default:
                assert_not_reached("Uh, control process died at wrong time.");
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);
}

static int swap_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Swap *s = SWAP(userdata);

        assert(s);
        assert(s->timer_event_source == source);

        switch (s->state) {

        case SWAP_ACTIVATING:
        case SWAP_ACTIVATING_DONE:
                log_warning_unit(UNIT(s)->id, "%s activation timed out. Stopping.", UNIT(s)->id);
                swap_enter_signal(s, SWAP_ACTIVATING_SIGTERM, SWAP_FAILURE_TIMEOUT);
                break;

        case SWAP_DEACTIVATING:
                log_warning_unit(UNIT(s)->id, "%s deactivation timed out. Stopping.", UNIT(s)->id);
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGTERM, SWAP_FAILURE_TIMEOUT);
                break;

        case SWAP_ACTIVATING_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_warning_unit(UNIT(s)->id, "%s activation timed out. Killing.", UNIT(s)->id);
                        swap_enter_signal(s, SWAP_ACTIVATING_SIGKILL, SWAP_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(UNIT(s)->id, "%s activation timed out. Skipping SIGKILL. Ignoring.", UNIT(s)->id);
                        swap_enter_dead(s, SWAP_FAILURE_TIMEOUT);
                }
                break;

        case SWAP_DEACTIVATING_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_warning_unit(UNIT(s)->id, "%s deactivation timed out. Killing.", UNIT(s)->id);
                        swap_enter_signal(s, SWAP_DEACTIVATING_SIGKILL, SWAP_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(UNIT(s)->id, "%s deactivation timed out. Skipping SIGKILL. Ignoring.", UNIT(s)->id);
                        swap_enter_dead(s, SWAP_FAILURE_TIMEOUT);
                }
                break;

        case SWAP_ACTIVATING_SIGKILL:
        case SWAP_DEACTIVATING_SIGKILL:
                log_warning_unit(UNIT(s)->id, "%s swap process still around after SIGKILL. Ignoring.", UNIT(s)->id);
                swap_enter_dead(s, SWAP_FAILURE_TIMEOUT);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

static int swap_load_proc_swaps(Manager *m, bool set_flags) {
        unsigned i;
        int r = 0;

        assert(m);

        rewind(m->proc_swaps);

        (void) fscanf(m->proc_swaps, "%*s %*s %*s %*s %*s\n");

        for (i = 1;; i++) {
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

                        log_warning("Failed to parse /proc/swaps:%u", i);
                        continue;
                }

                d = cunescape(dev);
                if (!d)
                        return -ENOMEM;

                k = swap_process_new_swap(m, d, prio, set_flags);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int swap_dispatch_io(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        Unit *u;
        int r;

        assert(m);
        assert(revents & EPOLLPRI);

        r = swap_load_proc_swaps(m, true);
        if (r < 0) {
                log_error("Failed to reread /proc/swaps: %s", strerror(-r));

                /* Reset flags, just in case, for late calls */
                LIST_FOREACH(units_by_type, u, m->units_by_type[UNIT_SWAP]) {
                        Swap *swap = SWAP(u);

                        swap->is_active = swap->just_activated = false;
                }

                return 0;
        }

        manager_dispatch_load_queue(m);

        LIST_FOREACH(units_by_type, u, m->units_by_type[UNIT_SWAP]) {
                Swap *swap = SWAP(u);

                if (!swap->is_active) {
                        /* This has just been deactivated */

                        swap_unset_proc_swaps(swap);

                        switch (swap->state) {

                        case SWAP_ACTIVE:
                                swap_enter_dead(swap, SWAP_SUCCESS);
                                break;

                        default:
                                /* Fire again */
                                swap_set_state(swap, swap->state);
                                break;
                        }

                } else if (swap->just_activated) {

                        /* New swap entry */

                        switch (swap->state) {

                        case SWAP_DEAD:
                        case SWAP_FAILED:
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

static Unit *swap_following(Unit *u) {
        Swap *s = SWAP(u);
        Swap *other, *first = NULL;

        assert(s);

        if (streq_ptr(s->what, s->devnode))
                return NULL;

        /* Make everybody follow the unit that's named after the swap
         * device in the kernel */

        LIST_FOREACH_AFTER(same_devnode, other, s)
                if (streq_ptr(other->what, other->devnode))
                        return UNIT(other);

        LIST_FOREACH_BEFORE(same_devnode, other, s) {
                if (streq_ptr(other->what, other->devnode))
                        return UNIT(other);

                first = other;
        }

        return UNIT(first);
}

static int swap_following_set(Unit *u, Set **_set) {
        Swap *s = SWAP(u), *other;
        Set *set;
        int r;

        assert(s);
        assert(_set);

        if (LIST_JUST_US(same_devnode, s)) {
                *_set = NULL;
                return 0;
        }

        set = set_new(NULL, NULL);
        if (!set)
                return -ENOMEM;

        LIST_FOREACH_AFTER(same_devnode, other, s) {
                r = set_put(set, other);
                if (r < 0)
                        goto fail;
        }

        LIST_FOREACH_BEFORE(same_devnode, other, s) {
                r = set_put(set, other);
                if (r < 0)
                        goto fail;
        }

        *_set = set;
        return 1;

fail:
        set_free(set);
        return r;
}

static void swap_shutdown(Manager *m) {
        assert(m);

        m->swap_event_source = sd_event_source_unref(m->swap_event_source);

        if (m->proc_swaps) {
                fclose(m->proc_swaps);
                m->proc_swaps = NULL;
        }

        hashmap_free(m->swaps_by_devnode);
        m->swaps_by_devnode = NULL;
}

static int swap_enumerate(Manager *m) {
        int r;

        assert(m);

        if (!m->proc_swaps) {
                m->proc_swaps = fopen("/proc/swaps", "re");
                if (!m->proc_swaps)
                        return errno == ENOENT ? 0 : -errno;

                r = sd_event_add_io(m->event, &m->swap_event_source, fileno(m->proc_swaps), EPOLLPRI, swap_dispatch_io, m);
                if (r < 0)
                        goto fail;

                /* Dispatch this before we dispatch SIGCHLD, so that
                 * we always get the events from /proc/swaps before
                 * the SIGCHLD of /sbin/swapon. */
                r = sd_event_source_set_priority(m->swap_event_source, -10);
                if (r < 0)
                        goto fail;
        }

        r = swap_load_proc_swaps(m, false);
        if (r < 0)
                goto fail;

        return 0;

fail:
        swap_shutdown(m);
        return r;
}

int swap_process_new_device(Manager *m, struct udev_device *dev) {
        struct udev_list_entry *item = NULL, *first = NULL;
        _cleanup_free_ char *e = NULL;
        const char *dn;
        Swap *s;
        int r = 0;

        assert(m);
        assert(dev);

        dn = udev_device_get_devnode(dev);
        if (!dn)
                return 0;

        e = unit_name_from_path(dn, ".swap");
        if (!e)
                return -ENOMEM;

        s = hashmap_get(m->units, e);
        if (s)
                r = swap_set_devnode(s, dn);

        first = udev_device_get_devlinks_list_entry(dev);
        udev_list_entry_foreach(item, first) {
                _cleanup_free_ char *n = NULL;

                n = unit_name_from_path(udev_list_entry_get_name(item), ".swap");
                if (!n)
                        return -ENOMEM;

                s = hashmap_get(m->units, n);
                if (s) {
                        int q;

                        q = swap_set_devnode(s, dn);
                        if (q < 0)
                                r = q;
                }
        }

        return r;
}

int swap_process_removed_device(Manager *m, struct udev_device *dev) {
        const char *dn;
        int r = 0;
        Swap *s;

        dn = udev_device_get_devnode(dev);
        if (!dn)
                return 0;

        while ((s = hashmap_get(m->swaps_by_devnode, dn))) {
                int q;

                q = swap_set_devnode(s, NULL);
                if (q < 0)
                        r = q;
        }

        return r;
}

static void swap_reset_failed(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        if (s->state == SWAP_FAILED)
                swap_set_state(s, SWAP_DEAD);

        s->result = SWAP_SUCCESS;
}

static int swap_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        return unit_kill_common(u, who, signo, -1, SWAP(u)->control_pid, error);
}

static int swap_get_timeout(Unit *u, uint64_t *timeout) {
        Swap *s = SWAP(u);
        int r;

        if (!s->timer_event_source)
                return 0;

        r = sd_event_source_get_time(s->timer_event_source, timeout);
        if (r < 0)
                return r;

        return 1;
}

static const char* const swap_state_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = "dead",
        [SWAP_ACTIVATING] = "activating",
        [SWAP_ACTIVATING_DONE] = "activating-done",
        [SWAP_ACTIVE] = "active",
        [SWAP_DEACTIVATING] = "deactivating",
        [SWAP_ACTIVATING_SIGTERM] = "activating-sigterm",
        [SWAP_ACTIVATING_SIGKILL] = "activating-sigkill",
        [SWAP_DEACTIVATING_SIGTERM] = "deactivating-sigterm",
        [SWAP_DEACTIVATING_SIGKILL] = "deactivating-sigkill",
        [SWAP_FAILED] = "failed"
};

DEFINE_STRING_TABLE_LOOKUP(swap_state, SwapState);

static const char* const swap_exec_command_table[_SWAP_EXEC_COMMAND_MAX] = {
        [SWAP_EXEC_ACTIVATE] = "ExecActivate",
        [SWAP_EXEC_DEACTIVATE] = "ExecDeactivate",
};

DEFINE_STRING_TABLE_LOOKUP(swap_exec_command, SwapExecCommand);

static const char* const swap_result_table[_SWAP_RESULT_MAX] = {
        [SWAP_SUCCESS] = "success",
        [SWAP_FAILURE_RESOURCES] = "resources",
        [SWAP_FAILURE_TIMEOUT] = "timeout",
        [SWAP_FAILURE_EXIT_CODE] = "exit-code",
        [SWAP_FAILURE_SIGNAL] = "signal",
        [SWAP_FAILURE_CORE_DUMP] = "core-dump"
};

DEFINE_STRING_TABLE_LOOKUP(swap_result, SwapResult);

const UnitVTable swap_vtable = {
        .object_size = sizeof(Swap),
        .exec_context_offset = offsetof(Swap, exec_context),
        .cgroup_context_offset = offsetof(Swap, cgroup_context),
        .kill_context_offset = offsetof(Swap, kill_context),
        .exec_runtime_offset = offsetof(Swap, exec_runtime),

        .sections =
                "Unit\0"
                "Swap\0"
                "Install\0",
        .private_section = "Swap",

        .no_alias = true,
        .no_instances = true,

        .init = swap_init,
        .load = swap_load,
        .done = swap_done,

        .coldplug = swap_coldplug,

        .dump = swap_dump,

        .start = swap_start,
        .stop = swap_stop,

        .kill = swap_kill,

        .get_timeout = swap_get_timeout,

        .serialize = swap_serialize,
        .deserialize_item = swap_deserialize_item,

        .active_state = swap_active_state,
        .sub_state_to_string = swap_sub_state_to_string,

        .check_gc = swap_check_gc,

        .sigchld_event = swap_sigchld_event,

        .reset_failed = swap_reset_failed,

        .bus_interface = "org.freedesktop.systemd1.Swap",
        .bus_vtable = bus_swap_vtable,
        .bus_set_property = bus_swap_set_property,
        .bus_commit_properties = bus_swap_commit_properties,

        .following = swap_following,
        .following_set = swap_following_set,

        .enumerate = swap_enumerate,
        .shutdown = swap_shutdown,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Activating swap %s...",
                        [1] = "Deactivating swap %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Activated swap %s.",
                        [JOB_FAILED]     = "Failed to activate swap %s.",
                        [JOB_DEPENDENCY] = "Dependency failed for %s.",
                        [JOB_TIMEOUT]    = "Timed out activating swap %s.",
                },
                .finished_stop_job = {
                        [JOB_DONE]       = "Deactivated swap %s.",
                        [JOB_FAILED]     = "Failed deactivating swap %s.",
                        [JOB_TIMEOUT]    = "Timed out deactivating swap %s.",
                },
        },
};
