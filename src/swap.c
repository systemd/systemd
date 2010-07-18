/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include "unit.h"
#include "swap.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "unit-name.h"
#include "dbus-swap.h"
#include "special.h"

static const UnitActiveState state_translation_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = UNIT_INACTIVE,
        [SWAP_ACTIVE] = UNIT_ACTIVE,
        [SWAP_MAINTENANCE] = UNIT_MAINTENANCE
};

static void swap_init(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);
        assert(s->meta.load_state == UNIT_STUB);

        s->parameters_etc_fstab.priority = s->parameters_proc_swaps.priority = s->parameters_fragment.priority = -1;
}

static void swap_done(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        free(s->what);
        free(s->parameters_etc_fstab.what);
        free(s->parameters_proc_swaps.what);
        free(s->parameters_fragment.what);
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

        if (!p->noauto && p->handle && s->meta.manager->running_as == MANAGER_SYSTEM)
                if ((r = unit_add_dependency(tu, UNIT_WANTS, UNIT(s), true)) < 0)
                        return r;

        return unit_add_dependency(UNIT(s), UNIT_BEFORE, tu, true);
}

static int swap_add_default_dependencies(Swap *s) {
        int r;

        assert(s);

        if (s->meta.manager->running_as == MANAGER_SYSTEM) {

                if ((r = unit_add_dependency_by_name(UNIT(s), UNIT_AFTER, SPECIAL_SYSINIT_TARGET, NULL, true)) < 0)
                        return r;

                /* Note that by default we don't disable swap devices
                 * on shutdown. i.e. there is no umount.target
                 * conflicts here. */
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

                if ((r = unit_add_node_link(u, s->what, u->meta.manager->running_as == MANAGER_SYSTEM)) < 0)
                        return r;

                if ((r = swap_add_mount_links(s)) < 0)
                        return r;

                if ((r = swap_add_target_links(s)) < 0)
                        return r;

                if (s->meta.default_dependencies)
                        if ((r = swap_add_default_dependencies(s)) < 0)
                                return r;
        }

        return swap_verify(s);
}

static int swap_find(Manager *m, const char *what, Unit **_u) {
        Unit *u;
        char *e;

        assert(m);
        assert(what);
        assert(_u);

        /* /proc/swaps and /etc/fstab might refer to this device by
         * different names (e.g. one by uuid, the other by the kernel
         * name), we hence need to look for all aliases we are aware
         * of for this device */

        if (!(e = unit_name_from_path(what, ".device")))
                return -ENOMEM;

        u = manager_get_unit(m, e);
        free(e);

        if (u) {
                Iterator i;
                const char *d;

                SET_FOREACH(d, u->meta.names, i) {
                        Unit *k;

                        if (!(e = unit_name_change_suffix(d, ".swap")))
                                return -ENOMEM;

                        k = manager_get_unit(m, e);
                        free(e);

                        if (k) {
                                *_u = k;
                                return 0;
                        }
                }
        }

        *_u = NULL;
        return 0;
}

int swap_add_one(
                Manager *m,
                const char *what,
                int priority,
                bool noauto,
                bool handle,
                bool from_proc_swaps) {
        Unit *u = NULL;
        char *e = NULL, *w = NULL;
        bool delete = false;
        int r;
        SwapParameters *p;

        assert(m);
        assert(what);

        if (!(e = unit_name_from_path(what, ".swap")))
                return -ENOMEM;

        if (!(u = manager_get_unit(m, e)))
                if ((r = swap_find(m, what, &u)) < 0)
                        goto fail;

        if (!u) {
                delete = true;

                if (!(u = unit_new(m))) {
                        free(e);
                        return -ENOMEM;
                }
        } else
                delete = false;

        if ((r = unit_add_name(u, e)) < 0)
                goto fail;

        if (!(w = strdup(what))) {
                r = -ENOMEM;
                goto fail;
        }

        if (from_proc_swaps) {
                p = &SWAP(u)->parameters_proc_swaps;
                SWAP(u)->from_proc_swaps = true;
        } else {
                p = &SWAP(u)->parameters_etc_fstab;
                SWAP(u)->from_etc_fstab = true;
        }

        free(p->what);
        p->what = w;

        p->priority = priority;
        p->noauto = noauto;
        p->handle = handle;

        if (delete)
                unit_add_to_load_queue(u);

        unit_add_to_dbus_queue(u);

        free(e);

        return 0;

fail:
        free(w);
        free(e);

        if (delete && u)
                unit_free(u);

        return r;
}

static void swap_set_state(Swap *s, SwapState state) {
        SwapState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

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

        assert(s);
        assert(s->state == SWAP_DEAD);

        if (s->deserialized_state != s->state)
                new_state = s->deserialized_state;
        else if (s->from_proc_swaps)
                new_state = SWAP_ACTIVE;

        if (new_state != s->state)
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
                p = &s->parameters_etc_fstab;

        fprintf(f,
                "%sSwap State: %s\n"
                "%sWhat: %s\n"
                "%sPriority: %i\n"
                "%sNoAuto: %s\n"
                "%sHandle: %s\n"
                "%sFrom /etc/fstab: %s\n"
                "%sFrom /proc/swaps: %s\n"
                "%sFrom fragment: %s\n",
                prefix, swap_state_to_string(s->state),
                prefix, s->what,
                prefix, p->priority,
                prefix, yes_no(p->noauto),
                prefix, yes_no(p->handle),
                prefix, yes_no(s->from_etc_fstab),
                prefix, yes_no(s->from_proc_swaps),
                prefix, yes_no(s->from_fragment));
}

static void swap_enter_dead(Swap *s, bool success) {
        assert(s);

        swap_set_state(s, success ? SWAP_MAINTENANCE : SWAP_DEAD);
}

static int swap_start(Unit *u) {
        Swap *s = SWAP(u);
        int priority = -1;
        int r;

        assert(s);
        assert(s->state == SWAP_DEAD || s->state == SWAP_MAINTENANCE);

        if (s->from_fragment)
                priority = s->parameters_fragment.priority;
        else if (s->from_etc_fstab)
                priority = s->parameters_etc_fstab.priority;

        r = swapon(s->what, (priority << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK);

        if (r < 0 && errno != EBUSY) {
                r = -errno;
                swap_enter_dead(s, false);
                return r;
        }

        swap_set_state(s, SWAP_ACTIVE);
        return 0;
}

static int swap_stop(Unit *u) {
        Swap *s = SWAP(u);
        int r;

        assert(s);

        assert(s->state == SWAP_ACTIVE);

        r = swapoff(s->what);
        swap_enter_dead(s, r >= 0 || errno == EINVAL);

        return 0;
}

static int swap_serialize(Unit *u, FILE *f, FDSet *fds) {
        Swap *s = SWAP(u);

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", swap_state_to_string(s->state));

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

static int swap_load_proc_swaps(Manager *m) {
        rewind(m->proc_swaps);

        (void) fscanf(m->proc_swaps, "%*s %*s %*s %*s %*s\n");

        for (;;) {
                char *dev = NULL, *d;
                int prio = 0, k;

                if ((k = fscanf(m->proc_swaps,
                                "%ms " /* device/file */
                                "%*s " /* type of swap */
                                "%*s " /* swap size */
                                "%*s " /* used */
                                "%i\n", /* priority */
                                &dev, &prio)) != 2) {

                        if (k == EOF)
                                break;

                        free(dev);
                        return -EBADMSG;
                }

                d = cunescape(dev);
                free(dev);

                if (!d)
                        return -ENOMEM;

                k = swap_add_one(m, d, prio, false, false, true);
                free(d);

                if (k < 0)
                        return k;
        }

        return 0;
}

static void swap_shutdown(Manager *m) {
        assert(m);

        if (m->proc_swaps) {
                fclose(m->proc_swaps);
                m->proc_swaps = NULL;
        }
}

static int swap_enumerate(Manager *m) {
        int r;
        assert(m);

        if (!m->proc_swaps)
                if (!(m->proc_swaps = fopen("/proc/swaps", "re")))
                        return -errno;

        if ((r = swap_load_proc_swaps(m)) < 0)
                swap_shutdown(m);

        return r;
}

static void swap_reset_maintenance(Unit *u) {
        Swap *s = SWAP(u);

        assert(s);

        if (s->state == SWAP_MAINTENANCE)
                swap_set_state(s, SWAP_DEAD);
}

static const char* const swap_state_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = "dead",
        [SWAP_ACTIVE] = "active",
        [SWAP_MAINTENANCE] = "maintenance"
};

DEFINE_STRING_TABLE_LOOKUP(swap_state, SwapState);

const UnitVTable swap_vtable = {
        .suffix = ".swap",

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

        .serialize = swap_serialize,
        .deserialize_item = swap_deserialize_item,

        .active_state = swap_active_state,
        .sub_state_to_string = swap_sub_state_to_string,

        .check_gc = swap_check_gc,

        .bus_message_handler = bus_swap_message_handler,

        .reset_maintenance = swap_reset_maintenance,

        .enumerate = swap_enumerate,
        .shutdown = swap_shutdown
};
