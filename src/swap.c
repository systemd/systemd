/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

static const UnitActiveState state_translation_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = UNIT_INACTIVE,
        [SWAP_ACTIVATING] = UNIT_ACTIVATING,
        [SWAP_ACTIVE] = UNIT_ACTIVE,
        [SWAP_DEACTIVATING] = UNIT_DEACTIVATING,
        [SWAP_ACTIVATING_SIGTERM] = UNIT_DEACTIVATING,
        [SWAP_ACTIVATING_SIGKILL] = UNIT_DEACTIVATING,
        [SWAP_DEACTIVATING_SIGTERM] = UNIT_DEACTIVATING,
        [SWAP_DEACTIVATING_SIGKILL] = UNIT_DEACTIVATING,
        [SWAP_FAILED] = UNIT_FAILED
};

static void swap_unset_proc_swaps(Swap *s) {
        Swap *first;

        assert(s);

        if (!s->parameters_proc_swaps.what)
                return;

        /* Remove this unit from the chain of swaps which share the
         * same kernel swap device. */

        first = hashmap_get(s->meta.manager->swaps_by_proc_swaps, s->parameters_proc_swaps.what);
        LIST_REMOVE(Swap, same_proc_swaps, first, s);

        if (first)
                hashmap_remove_and_replace(s->meta.manager->swaps_by_proc_swaps, s->parameters_proc_swaps.what, first->parameters_proc_swaps.what, first);
        else
                hashmap_remove(s->meta.manager->swaps_by_proc_swaps, s->parameters_proc_swaps.what);

        free(s->parameters_proc_swaps.what);
        s->parameters_proc_swaps.what = NULL;
}

 static void swap_init(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);
        assert(s->meta.load_state == UNIT_STUB);

        s->timeout_usec = DEFAULT_TIMEOUT_USEC;

        exec_context_init(&s->exec_context);

        s->parameters_etc_fstab.priority = s->parameters_proc_swaps.priority = s->parameters_fragment.priority = -1;

        s->timer_watch.type = WATCH_INVALID;

        s->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
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

        free(s->what);
        s->what = NULL;

        free(s->parameters_etc_fstab.what);
        free(s->parameters_fragment.what);
        s->parameters_etc_fstab.what = s->parameters_fragment.what = NULL;

        exec_context_done(&s->exec_context);
        exec_command_done_array(s->exec_command, _SWAP_EXEC_COMMAND_MAX);
        s->control_command = NULL;

        swap_unwatch_control_pid(s);

        unit_unwatch_timer(u, &s->timer_watch);
}

int swap_add_one_mount_link(Swap *s, Mount *m) {
         int r;

        assert(s);
        assert(m);

        if (s->meta.load_state != UNIT_LOADED ||
            m->meta.load_state != UNIT_LOADED)
                return 0;

        if (is_device_path(s->what))
                return 0;

        if (!path_startswith(s->what, m->where))
                return 0;

        if ((r = unit_add_two_dependencies(UNIT(s), UNIT_AFTER, UNIT_REQUIRES, UNIT(m), true)) < 0)
                return r;

        return 0;
}

static int swap_add_mount_links(Swap *s) {
        Meta *other;
        int r;

        assert(s);

        LIST_FOREACH(units_per_type, other, s->meta.manager->units_per_type[UNIT_MOUNT])
                if ((r = swap_add_one_mount_link(s, (Mount*) other)) < 0)
                        return r;

        return 0;
}

static int swap_add_target_links(Swap *s) {
        Unit *tu;
        SwapParameters *p;
        int r;

        assert(s);

        if (s->from_fragment)
                p = &s->parameters_fragment;
        else if (s->from_etc_fstab)
                p = &s->parameters_etc_fstab;
        else
                return 0;

        if ((r = manager_load_unit(s->meta.manager, SPECIAL_SWAP_TARGET, NULL, NULL, &tu)) < 0)
                return r;

        if (!p->noauto &&
            (p->handle || s->meta.manager->swap_auto) &&
            s->from_etc_fstab &&
            s->meta.manager->running_as == MANAGER_SYSTEM)
                if ((r = unit_add_dependency(tu, UNIT_WANTS, UNIT(s), true)) < 0)
                        return r;

        return unit_add_dependency(UNIT(s), UNIT_BEFORE, tu, true);
}

static int swap_add_device_links(Swap *s) {
        SwapParameters *p;

        assert(s);

        if (!s->what)
                return 0;

        if (s->from_fragment)
                p = &s->parameters_fragment;
        else if (s->from_etc_fstab)
                p = &s->parameters_etc_fstab;
        else
                return 0;

        return unit_add_node_link(UNIT(s), s->what,
                                  !p->noauto && p->nofail &&
                                  s->meta.manager->running_as == MANAGER_SYSTEM);
}

static int swap_add_default_dependencies(Swap *s) {
        int r;

        assert(s);

        if (s->meta.manager->running_as == MANAGER_SYSTEM) {

                if ((r = unit_add_two_dependencies_by_name(UNIT(s), UNIT_BEFORE, UNIT_CONFLICTS, SPECIAL_UMOUNT_TARGET, NULL, true)) < 0)
                        return r;
        }

        return 0;
}

static int swap_verify(Swap *s) {
        bool b;
        char *e;

        if (s->meta.load_state != UNIT_LOADED)
                  return 0;

        if (!(e = unit_name_from_path(s->what, ".swap")))
                  return -ENOMEM;

        b = unit_has_name(UNIT(s), e);
        free(e);

        if (!b) {
                log_error("%s: Value of \"What\" and unit name do not match, not loading.\n", s->meta.id);
                return -EINVAL;
        }

        if (s->exec_context.pam_name && s->exec_context.kill_mode != KILL_CONTROL_GROUP) {
                log_error("%s has PAM enabled. Kill mode must be set to 'control-group'. Refusing.", s->meta.id);
                return -EINVAL;
        }

        return 0;
}

static int swap_load(Unit *u) {
        int r;
        Swap *s = SWAP(u);

        assert(s);
        assert(u->meta.load_state == UNIT_STUB);

        /* Load a .swap file */
        if ((r = unit_load_fragment_and_dropin_optional(u)) < 0)
                return r;

        if (u->meta.load_state == UNIT_LOADED) {

                if (s->meta.fragment_path)
                        s->from_fragment = true;

                if (!s->what) {
                        if (s->parameters_fragment.what)
                                s->what = strdup(s->parameters_fragment.what);
                        else if (s->parameters_etc_fstab.what)
                                s->what = strdup(s->parameters_etc_fstab.what);
                        else if (s->parameters_proc_swaps.what)
                                s->what = strdup(s->parameters_proc_swaps.what);
                        else
                                s->what = unit_name_to_path(u->meta.id);

                        if (!s->what)
                                return -ENOMEM;
                }

                path_kill_slashes(s->what);

                if (!s->meta.description)
                        if ((r = unit_set_description(u, s->what)) < 0)
                                return r;

                if ((r = swap_add_device_links(s)) < 0)
                        return r;

                if ((r = swap_add_mount_links(s)) < 0)
                        return r;

                if ((r = swap_add_target_links(s)) < 0)
                        return r;

                if ((r = unit_add_default_cgroup(u)) < 0)
                        return r;

                if (s->meta.default_dependencies)
                        if ((r = swap_add_default_dependencies(s)) < 0)
                                return r;
        }

        return swap_verify(s);
}

int swap_add_one(
                Manager *m,
                const char *what,
                const char *what_proc_swaps,
                int priority,
                bool noauto,
                bool nofail,
                bool handle,
                bool set_flags) {

        Unit *u = NULL;
        char *e = NULL, *wp = NULL;
        bool delete = false;
        int r;
        SwapParameters *p;

        assert(m);
        assert(what);

        if (!(e = unit_name_from_path(what, ".swap")))
                return -ENOMEM;

        u = manager_get_unit(m, e);

        if (what_proc_swaps &&
            u &&
            SWAP(u)->from_proc_swaps &&
            !path_equal(SWAP(u)->parameters_proc_swaps.what, what_proc_swaps))
                return -EEXIST;

        if (!u) {
                delete = true;

                if (!(u = unit_new(m))) {
                        free(e);
                        return -ENOMEM;
                }

                if ((r = unit_add_name(u, e)) < 0)
                        goto fail;

                if (!(SWAP(u)->what = strdup(what))) {
                        r = -ENOMEM;
                        goto fail;
                }

                unit_add_to_load_queue(u);
        } else
                delete = false;

        if (what_proc_swaps) {
                Swap *first;

                p = &SWAP(u)->parameters_proc_swaps;

                if (!p->what) {
                        if (!(wp = strdup(what_proc_swaps))) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        if (!m->swaps_by_proc_swaps)
                                if (!(m->swaps_by_proc_swaps = hashmap_new(string_hash_func, string_compare_func))) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                        free(p->what);
                        p->what = wp;

                        first = hashmap_get(m->swaps_by_proc_swaps, wp);
                        LIST_PREPEND(Swap, same_proc_swaps, first, SWAP(u));

                        if ((r = hashmap_replace(m->swaps_by_proc_swaps, wp, first)) < 0)
                                goto fail;
                }

                if (set_flags) {
                        SWAP(u)->is_active = true;
                        SWAP(u)->just_activated = !SWAP(u)->from_proc_swaps;
                }

                SWAP(u)->from_proc_swaps = true;

        } else {
                p = &SWAP(u)->parameters_etc_fstab;

                if (!(wp = strdup(what))) {
                        r = -ENOMEM;
                        goto fail;
                }

                free(p->what);
                p->what = wp;

                SWAP(u)->from_etc_fstab = true;
        }

        p->priority = priority;
        p->noauto = noauto;
        p->nofail = nofail;
        p->handle = handle;

        unit_add_to_dbus_queue(u);

        free(e);

        return 0;

fail:
        log_warning("Failed to load swap unit: %s", strerror(-r));

        free(wp);
        free(e);

        if (delete && u)
                unit_free(u);

        return r;
}

static int swap_process_new_swap(Manager *m, const char *device, int prio, bool set_flags) {
        struct stat st;
        int r = 0, k;

        assert(m);

        if (stat(device, &st) >= 0 && S_ISBLK(st.st_mode)) {
                struct udev_device *d;
                const char *dn;
                struct udev_list_entry *item = NULL, *first = NULL;

                /* So this is a proper swap device. Create swap units
                 * for all names this swap device is known under */

                if (!(d = udev_device_new_from_devnum(m->udev, 'b', st.st_rdev)))
                        return -ENOMEM;

                if ((dn = udev_device_get_devnode(d)))
                        r = swap_add_one(m, dn, device, prio, false, false, false, set_flags);

                /* Add additional units for all symlinks */
                first = udev_device_get_devlinks_list_entry(d);
                udev_list_entry_foreach(item, first) {
                        const char *p;

                        /* Don't bother with the /dev/block links */
                        p = udev_list_entry_get_name(item);

                        if (path_startswith(p, "/dev/block/"))
                                continue;

                        if (stat(p, &st) >= 0)
                                if ((!S_ISBLK(st.st_mode)) || st.st_rdev != udev_device_get_devnum(d))
                                        continue;

                        if ((k = swap_add_one(m, p, device, prio, false, false, false, set_flags)) < 0)
                                r = k;
                }

                udev_device_unref(d);
        }

        if ((k = swap_add_one(m, device, device, prio, false, false, false, set_flags)) < 0)
                r = k;

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
            state != SWAP_DEACTIVATING &&
            state != SWAP_DEACTIVATING_SIGTERM &&
            state != SWAP_DEACTIVATING_SIGKILL) {
                unit_unwatch_timer(UNIT(s), &s->timer_watch);
                swap_unwatch_control_pid(s);
                s->control_command = NULL;
                s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;
        }

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          s->meta.id,
                          swap_state_to_string(old_state),
                          swap_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state]);
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

        if (new_state != s->state) {

                if (new_state == SWAP_ACTIVATING ||
                    new_state == SWAP_ACTIVATING_SIGTERM ||
                    new_state == SWAP_ACTIVATING_SIGKILL ||
                    new_state == SWAP_DEACTIVATING ||
                    new_state == SWAP_DEACTIVATING_SIGTERM ||
                    new_state == SWAP_DEACTIVATING_SIGKILL) {

                        if (s->control_pid <= 0)
                                return -EBADMSG;

                        if ((r = unit_watch_pid(UNIT(s), s->control_pid)) < 0)
                                return r;

                        if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                                return r;
                }

                swap_set_state(s, new_state);
        }

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
                p = &s->parameters_etc_fstab;

        fprintf(f,
                "%sSwap State: %s\n"
                "%sWhat: %s\n"
                "%sPriority: %i\n"
                "%sNoAuto: %s\n"
                "%sNoFail: %s\n"
                "%sHandle: %s\n"
                "%sFrom /etc/fstab: %s\n"
                "%sFrom /proc/swaps: %s\n"
                "%sFrom fragment: %s\n",
                prefix, swap_state_to_string(s->state),
                prefix, s->what,
                prefix, p->priority,
                prefix, yes_no(p->noauto),
                prefix, yes_no(p->nofail),
                prefix, yes_no(p->handle),
                prefix, yes_no(s->from_etc_fstab),
                prefix, yes_no(s->from_proc_swaps),
                prefix, yes_no(s->from_fragment));

        if (s->control_pid > 0)
                fprintf(f,
                        "%sControl PID: %lu\n",
                        prefix, (unsigned long) s->control_pid);

        exec_context_dump(&s->exec_context, f, prefix);
}

static int swap_spawn(Swap *s, ExecCommand *c, pid_t *_pid) {
        pid_t pid;
        int r;

        assert(s);
        assert(c);
        assert(_pid);

        if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                goto fail;

        if ((r = exec_spawn(c,
                            NULL,
                            &s->exec_context,
                            NULL, 0,
                            s->meta.manager->environment,
                            true,
                            true,
                            true,
                            s->meta.manager->confirm_spawn,
                            s->meta.cgroup_bondings,
                            &pid)) < 0)
                goto fail;

        if ((r = unit_watch_pid(UNIT(s), pid)) < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        unit_unwatch_timer(UNIT(s), &s->timer_watch);

        return r;
}

static void swap_enter_dead(Swap *s, bool success) {
        assert(s);

        if (!success)
                s->failure = true;

        swap_set_state(s, s->failure ? SWAP_FAILED : SWAP_DEAD);
}

static void swap_enter_active(Swap *s, bool success) {
        assert(s);

        if (!success)
                s->failure = true;

        swap_set_state(s, SWAP_ACTIVE);
}

static void swap_enter_signal(Swap *s, SwapState state, bool success) {
        int r;
        Set *pid_set = NULL;
        bool wait_for_exit = false;

        assert(s);

        if (!success)
                s->failure = true;

        if (s->exec_context.kill_mode != KILL_NONE) {
                int sig = (state == SWAP_ACTIVATING_SIGTERM ||
                           state == SWAP_DEACTIVATING_SIGTERM) ? s->exec_context.kill_signal : SIGKILL;

                if (s->control_pid > 0) {
                        if (kill(s->exec_context.kill_mode == KILL_PROCESS_GROUP ?
                                 -s->control_pid :
                                 s->control_pid, sig) < 0 && errno != ESRCH)

                                log_warning("Failed to kill control process %li: %m", (long) s->control_pid);
                        else
                                wait_for_exit = true;
                }

                if (s->exec_context.kill_mode == KILL_CONTROL_GROUP) {

                        if (!(pid_set = set_new(trivial_hash_func, trivial_compare_func))) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        /* Exclude the control pid from being killed via the cgroup */
                        if (s->control_pid > 0)
                                if ((r = set_put(pid_set, LONG_TO_PTR(s->control_pid))) < 0)
                                        goto fail;

                        if ((r = cgroup_bonding_kill_list(s->meta.cgroup_bondings, sig, pid_set)) < 0) {
                                if (r != -EAGAIN && r != -ESRCH && r != -ENOENT)
                                        log_warning("Failed to kill control group: %s", strerror(-r));
                        } else if (r > 0)
                                wait_for_exit = true;

                        set_free(pid_set);
                }
        }

        if (wait_for_exit) {
                if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                        goto fail;

                swap_set_state(s, state);
        } else
                swap_enter_dead(s, true);

        return;

fail:
        log_warning("%s failed to kill processes: %s", s->meta.id, strerror(-r));

        swap_enter_dead(s, false);

        if (pid_set)
                set_free(pid_set);
}

static void swap_enter_activating(Swap *s) {
        int r, priority;

        assert(s);

        s->control_command_id = SWAP_EXEC_ACTIVATE;
        s->control_command = s->exec_command + SWAP_EXEC_ACTIVATE;

        if (s->from_fragment)
                priority = s->parameters_fragment.priority;
        else if (s->from_etc_fstab)
                priority = s->parameters_etc_fstab.priority;
        else
                priority = -1;

        if (priority >= 0) {
                char p[LINE_MAX];

                snprintf(p, sizeof(p), "%i", priority);
                char_array_0(p);

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

        if ((r = swap_spawn(s, s->control_command, &s->control_pid)) < 0)
                goto fail;

        swap_set_state(s, SWAP_ACTIVATING);

        return;

fail:
        log_warning("%s failed to run 'swapon' task: %s", s->meta.id, strerror(-r));
        swap_enter_dead(s, false);
}

static void swap_enter_deactivating(Swap *s, bool success) {
        int r;

        assert(s);

        if (!success)
                s->failure = true;

        s->control_command_id = SWAP_EXEC_DEACTIVATE;
        s->control_command = s->exec_command + SWAP_EXEC_DEACTIVATE;

        if ((r = exec_command_set(
                             s->control_command,
                             "/sbin/swapoff",
                             s->what,
                             NULL)) < 0)
                goto fail;

        swap_unwatch_control_pid(s);

        if ((r = swap_spawn(s, s->control_command, &s->control_pid)) < 0)
                goto fail;

        swap_set_state(s, SWAP_DEACTIVATING);

        return;

fail:
        log_warning("%s failed to run 'swapoff' task: %s", s->meta.id, strerror(-r));
        swap_enter_active(s, false);
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

        s->failure = false;
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
               s->state == SWAP_ACTIVE);

        swap_enter_deactivating(s, true);
        return 0;
}

static int swap_serialize(Unit *u, FILE *f, FDSet *fds) {
        Swap *s = SWAP(u);

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", swap_state_to_string(s->state));
        unit_serialize_item(u, f, "failure", yes_no(s->failure));

        if (s->control_pid > 0)
                unit_serialize_item_format(u, f, "control-pid", "%lu", (unsigned long) s->control_pid);

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

                if ((state = swap_state_from_string(value)) < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;
        } else if (streq(key, "failure")) {
                int b;

                if ((b = parse_boolean(value)) < 0)
                        log_debug("Failed to parse failure value %s", value);
                else
                        s->failure = b || s->failure;

        } else if (streq(key, "control-pid")) {
                pid_t pid;

                if (parse_pid(value, &pid) < 0)
                        log_debug("Failed to parse control-pid value %s", value);
                else
                        s->control_pid = pid;

        } else if (streq(key, "control-command")) {
                SwapExecCommand id;

                if ((id = swap_exec_command_from_string(value)) < 0)
                        log_debug("Failed to parse exec-command value %s", value);
                else {
                        s->control_command_id = id;
                        s->control_command = s->exec_command + id;
                }

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static UnitActiveState swap_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SWAP(u)->state];
}

static const char *swap_sub_state_to_string(Unit *u) {
        assert(u);

        return swap_state_to_string(SWAP(u)->state);
}

static bool swap_check_gc(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        return s->from_etc_fstab || s->from_proc_swaps;
}

static void swap_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Swap *s = SWAP(u);
        bool success;

        assert(s);
        assert(pid >= 0);

        if (pid != s->control_pid)
                return;

        s->control_pid = 0;

        success = is_clean_exit(code, status);
        s->failure = s->failure || !success;

        if (s->control_command) {
                exec_status_exit(&s->control_command->exec_status, pid, code, status, s->exec_context.utmp_id);
                s->control_command = NULL;
                s->control_command_id = _SWAP_EXEC_COMMAND_INVALID;
        }

        log_full(success ? LOG_DEBUG : LOG_NOTICE,
                 "%s swap process exited, code=%s status=%i", u->meta.id, sigchld_code_to_string(code), status);

        switch (s->state) {

        case SWAP_ACTIVATING:
        case SWAP_ACTIVATING_SIGTERM:
        case SWAP_ACTIVATING_SIGKILL:

                if (success)
                        swap_enter_active(s, true);
                else
                        swap_enter_dead(s, false);
                break;

        case SWAP_DEACTIVATING:
        case SWAP_DEACTIVATING_SIGKILL:
        case SWAP_DEACTIVATING_SIGTERM:

                if (success)
                        swap_enter_dead(s, true);
                else
                        swap_enter_dead(s, false);
                break;

        default:
                assert_not_reached("Uh, control process died at wrong time.");
        }

        /* Notify clients about changed exit status */
        unit_add_to_dbus_queue(u);

        /* Request a reload of /proc/swaps, so that following units
         * can follow our state change */
        u->meta.manager->request_reload = true;
}

static void swap_timer_event(Unit *u, uint64_t elapsed, Watch *w) {
        Swap *s = SWAP(u);

        assert(s);
        assert(elapsed == 1);
        assert(w == &s->timer_watch);

        switch (s->state) {

        case SWAP_ACTIVATING:
                log_warning("%s activation timed out. Stopping.", u->meta.id);
                swap_enter_signal(s, SWAP_ACTIVATING_SIGTERM, false);
                break;

        case SWAP_DEACTIVATING:
                log_warning("%s deactivation timed out. Stopping.", u->meta.id);
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGTERM, false);
                break;

        case SWAP_ACTIVATING_SIGTERM:
                log_warning("%s activation timed out. Killing.", u->meta.id);
                swap_enter_signal(s, SWAP_ACTIVATING_SIGKILL, false);
                break;

        case SWAP_DEACTIVATING_SIGTERM:
                log_warning("%s deactivation timed out. Killing.", u->meta.id);
                swap_enter_signal(s, SWAP_DEACTIVATING_SIGKILL, false);
                break;

        case SWAP_ACTIVATING_SIGKILL:
        case SWAP_DEACTIVATING_SIGKILL:
                log_warning("%s swap process still around after SIGKILL. Ignoring.", u->meta.id);
                swap_enter_dead(s, false);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

static int swap_load_proc_swaps(Manager *m, bool set_flags) {
        unsigned i;
        int r = 0;

        assert(m);

        rewind(m->proc_swaps);

        (void) fscanf(m->proc_swaps, "%*s %*s %*s %*s %*s\n");

        for (i = 1;; i++) {
                char *dev = NULL, *d;
                int prio = 0, k;

                if ((k = fscanf(m->proc_swaps,
                                "%ms "  /* device/file */
                                "%*s "  /* type of swap */
                                "%*s "  /* swap size */
                                "%*s "  /* used */
                                "%i\n", /* priority */
                                &dev, &prio)) != 2) {

                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u.", i);
                        free(dev);
                        continue;
                }

                d = cunescape(dev);
                free(dev);

                if (!d)
                        return -ENOMEM;

                k = swap_process_new_swap(m, d, prio, set_flags);
                free(d);

                if (k < 0)
                        r = k;
        }

        return r;
}

int swap_dispatch_reload(Manager *m) {
        /* This function should go as soon as the kernel properly notifies us */

        if (_likely_(!m->request_reload))
                return 0;

        m->request_reload = false;

        return swap_fd_event(m, EPOLLPRI);
}

int swap_fd_event(Manager *m, int events) {
        Meta *meta;
        int r;

        assert(m);
        assert(events & EPOLLPRI);

        if ((r == swap_load_proc_swaps(m, true)) < 0) {
                log_error("Failed to reread /proc/swaps: %s", strerror(-r));

                /* Reset flags, just in case, for late calls */
                LIST_FOREACH(units_per_type, meta, m->units_per_type[UNIT_SWAP]) {
                        Swap *swap = (Swap*) meta;

                        swap->is_active = swap->just_activated = false;
                }

                return 0;
        }

        manager_dispatch_load_queue(m);

        LIST_FOREACH(units_per_type, meta, m->units_per_type[UNIT_SWAP]) {
                Swap *swap = (Swap*) meta;

                if (!swap->is_active) {
                        /* This has just been deactivated */

                        swap->from_proc_swaps = false;
                        swap_unset_proc_swaps(swap);

                        switch (swap->state) {

                        case SWAP_ACTIVE:
                                swap_enter_dead(swap, true);
                                break;

                        default:
                                swap_set_state(swap, swap->state);
                                break;
                        }

                } else if (swap->just_activated) {

                        /* New swap entry */

                        switch (swap->state) {

                        case SWAP_DEAD:
                        case SWAP_FAILED:
                                swap_enter_active(swap, true);
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

        if (streq_ptr(s->what, s->parameters_proc_swaps.what))
                return NULL;

        /* Make everybody follow the unit that's named after the swap
         * device in the kernel */

        LIST_FOREACH_AFTER(same_proc_swaps, other, s)
                if (streq_ptr(other->what, other->parameters_proc_swaps.what))
                        return UNIT(other);

        LIST_FOREACH_BEFORE(same_proc_swaps, other, s) {
                if (streq_ptr(other->what, other->parameters_proc_swaps.what))
                        return UNIT(other);

                first = other;
        }

        return UNIT(first);
}

static void swap_shutdown(Manager *m) {
        assert(m);

        if (m->proc_swaps) {
                fclose(m->proc_swaps);
                m->proc_swaps = NULL;
        }

        hashmap_free(m->swaps_by_proc_swaps);
        m->swaps_by_proc_swaps = NULL;
}

static int swap_enumerate(Manager *m) {
        int r;
        struct epoll_event ev;
        assert(m);

        if (!m->proc_swaps) {
                if (!(m->proc_swaps = fopen("/proc/swaps", "re")))
                        return -errno;

                m->swap_watch.type = WATCH_SWAP;
                m->swap_watch.fd = fileno(m->proc_swaps);

                zero(ev);
                ev.events = EPOLLPRI;
                ev.data.ptr = &m->swap_watch;

                if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->swap_watch.fd, &ev) < 0)
                        return -errno;
        }

        /* We rely on mount.c to load /etc/fstab for us */

        if ((r = swap_load_proc_swaps(m, false)) < 0)
                swap_shutdown(m);

        return r;
}

static void swap_reset_failed(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        if (s->state == SWAP_FAILED)
                swap_set_state(s, SWAP_DEAD);

        s->failure = false;
}

static int swap_kill(Unit *u, KillWho who, KillMode mode, int signo, DBusError *error) {
        Swap *s = SWAP(u);
        int r = 0;
        Set *pid_set = NULL;

        assert(s);

        if (who == KILL_MAIN) {
                dbus_set_error(error, BUS_ERROR_NO_SUCH_PROCESS, "Swap units have no main processes");
                return -EINVAL;
        }

        if (s->control_pid <= 0 && who == KILL_CONTROL) {
                dbus_set_error(error, BUS_ERROR_NO_SUCH_PROCESS, "No control process to kill");
                return -ENOENT;
        }

        if (s->control_pid > 0)
                if (kill(mode == KILL_PROCESS_GROUP ? -s->control_pid : s->control_pid, signo) < 0)
                        r = -errno;

        if (mode == KILL_CONTROL_GROUP) {
                int q;

                if (!(pid_set = set_new(trivial_hash_func, trivial_compare_func)))
                        return -ENOMEM;

                /* Exclude the control pid from being killed via the cgroup */
                if (s->control_pid > 0)
                        if ((q = set_put(pid_set, LONG_TO_PTR(s->control_pid))) < 0) {
                                r = q;
                                goto finish;
                        }

                if ((q = cgroup_bonding_kill_list(s->meta.cgroup_bondings, signo, pid_set)) < 0)
                        if (r != -EAGAIN && r != -ESRCH && r != -ENOENT)
                                r = q;
        }

finish:
        if (pid_set)
                set_free(pid_set);

        return r;
}

static const char* const swap_state_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = "dead",
        [SWAP_ACTIVATING] = "activating",
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

const UnitVTable swap_vtable = {
        .suffix = ".swap",

        .no_alias = true,
        .no_instances = true,
        .no_isolate = true,
        .show_status = true,

        .init = swap_init,
        .load = swap_load,
        .done = swap_done,

        .coldplug = swap_coldplug,

        .dump = swap_dump,

        .start = swap_start,
        .stop = swap_stop,

        .kill = swap_kill,

        .serialize = swap_serialize,
        .deserialize_item = swap_deserialize_item,

        .active_state = swap_active_state,
        .sub_state_to_string = swap_sub_state_to_string,

        .check_gc = swap_check_gc,

        .sigchld_event = swap_sigchld_event,
        .timer_event = swap_timer_event,

        .reset_failed = swap_reset_failed,

        .bus_interface = "org.freedesktop.systemd1.Swap",
        .bus_message_handler = bus_swap_message_handler,
        .bus_invalidating_properties =  bus_swap_invalidating_properties,

        .following = swap_following,

        .enumerate = swap_enumerate,
        .shutdown = swap_shutdown
};
