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

static const UnitActiveState state_translation_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = UNIT_INACTIVE,
        [SWAP_ACTIVE] = UNIT_ACTIVE,
        [SWAP_MAINTAINANCE] = UNIT_INACTIVE
};

static int swap_verify(Swap *s) {
        bool b;
        char *e;

        if (UNIT(s)->meta.load_state != UNIT_LOADED)
                  return 0;

        if (!(e = unit_name_from_path(s->what, ".swap")))
                  return -ENOMEM;

        b = unit_has_name(UNIT(s), e);
        free(e);

        if (!b) {
                log_error("%s: Value of \"What\" and unit name do not match, not loading.\n", UNIT(s)->meta.id);
                return -EINVAL;
        }
        return 0;
}

static int swap_add_target_links(Swap *s) {
        Manager *m = s->meta.manager;
        Unit *tu;
        int r;

        r = manager_load_unit(m, SPECIAL_SWAP_TARGET, NULL, &tu);
        if (r < 0)
                return r;

        if (!s->no_auto && (r = unit_add_dependency(tu, UNIT_WANTS, UNIT(s), true)) < 0)
                return r;

        return unit_add_dependency(UNIT(s), UNIT_BEFORE, tu, true);
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
                if (!s->what)
                        if (!(s->what = unit_name_to_path(u->meta.id)))
                                return -ENOMEM;

                path_kill_slashes(s->what);

                if ((r = mount_add_node_links(u, s->what)) < 0)
                        return r;

                if (!path_startswith(s->what, "/dev/"))
                        if ((r = mount_add_path_links(u, s->what, true)) < 0)
                                return r;

                if ((r = swap_add_target_links(s)) < 0)
                        return r;
        }

        return swap_verify(s);
}

int swap_add_one(Manager *m, const char *what, bool no_auto, int prio, bool from_proc_swaps) {
        Unit *u;
        char *e;
        bool delete;
        int r;

        if (!(e = unit_name_from_path(what, ".swap")))
                return -ENOMEM;

        if (!(u = manager_get_unit(m, e))) {
                delete = true;

                if (!(u = unit_new(m))) {
                        free(e);
                        return -ENOMEM;
                }

                r = unit_add_name(u, e);
                free(e);

                if (r < 0)
                        goto fail;

                if (!(SWAP(u)->what = strdup(what))) {
                        r = -ENOMEM;
                        goto fail;
                }

                if ((r = unit_set_description(u, what)) < 0)
                        goto fail;

                unit_add_to_load_queue(u);

                SWAP(u)->from_proc_swaps_only = from_proc_swaps;
        } else {
                if (SWAP(u)->from_proc_swaps_only && !from_proc_swaps)
                        SWAP(u)->from_proc_swaps_only = false;

                delete = false;
                free(e);
        }

        if (!from_proc_swaps)
                SWAP(u)->no_auto = no_auto;
        else
                SWAP(u)->found_in_proc_swaps = true;

        SWAP(u)->priority = prio;

        return 0;

fail:
        if (delete)
                unit_free(u);

        return 0;
}

static void swap_set_state(Swap *s, SwapState state) {
        SwapState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(s)->meta.id,
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
        else if (s->found_in_proc_swaps)
                new_state = SWAP_ACTIVE;

        if (new_state != s->state)
                swap_set_state(s, s->deserialized_state);

        return 0;
}

static void swap_dump(Unit *u, FILE *f, const char *prefix) {
        Swap *s = SWAP(u);

        assert(s);

        fprintf(f,
                "%sAutomount State: %s\n"
                "%sWhat: %s\n"
                "%sPriority: %i\n"
                "%sNoAuto: %s\n",
                prefix, swap_state_to_string(s->state),
                prefix, s->what,
                prefix, s->priority,
                prefix, yes_no(s->no_auto));
}

static void swap_enter_dead(Swap *s, bool success) {
        assert(s);

        swap_set_state(s, success ? SWAP_MAINTAINANCE : SWAP_DEAD);
}

static int swap_start(Unit *u) {
        Swap *s = SWAP(u);
        int r;

        assert(s);

        assert(s->state == SWAP_DEAD || s->state == SWAP_MAINTAINANCE);

        r = swapon(s->what, (s->priority << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK);

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

        return !s->from_proc_swaps_only || s->found_in_proc_swaps;
}

static int swap_load_proc_swaps(Manager *m) {
        Meta *meta;

        rewind(m->proc_swaps);
        fscanf(m->proc_self_mountinfo, "%*s %*s %*s %*s %*s\n");

        for (;;) {
                char *dev = NULL, *d;
                int prio = 0, k;

                k = fscanf(m->proc_self_mountinfo,
                           "%ms " /* device/file */
                           "%*s " /* type of swap */
                           "%*s " /* swap size */
                           "%*s " /* used */
                           "%d\n", /* priority */
                           &dev, &prio);

                if (k != 2) {
                        if (k == EOF)
                                k = 0;

                        free(dev);
                        return -EBADMSG;
                }
                if (!(d = cunescape(dev))) {
                        free(dev);
                        k = -ENOMEM;
                        return k;
                }

                k = swap_add_one(m, d, false, prio, true);
                free(dev);
                free(d);

                if (k < 0)
                        return k;
        }

        LIST_FOREACH(units_per_type, meta, m->units_per_type[UNIT_SWAP]) {
                Swap *s = (Swap*) meta;

                if (s->state != SWAP_DEAD && s->state != SWAP_ACTIVE)
                        continue;

                if ((s->state == SWAP_DEAD && !s->found_in_proc_swaps) ||
                    (s->state == SWAP_ACTIVE && s->found_in_proc_swaps))
                        continue;

                swap_set_state(s, s->found_in_proc_swaps ? SWAP_ACTIVE : SWAP_DEAD);

                /* Reset the flags for later calls */
                s->found_in_proc_swaps = false;
        }
}

static void swap_shutdown(Manager *m) {
        assert(m);

        if (m->proc_swaps) {
                fclose(m->proc_swaps);
                m->proc_swaps = NULL;
        }
}

static const char* const swap_state_table[_SWAP_STATE_MAX] = {
        [SWAP_DEAD] = "dead",
        [SWAP_ACTIVE] = "active",
        [SWAP_MAINTAINANCE] = "maintainance"
};

DEFINE_STRING_TABLE_LOOKUP(swap_state, SwapState);

static int swap_enumerate(Manager *m) {
        int r;
        assert(m);

        if (!m->proc_swaps &&
            !(m->proc_swaps = fopen("/proc/swaps", "er")))
                return -errno;

        if ((r = swap_load_proc_swaps(m)) < 0)
                swap_shutdown(m);

        return r;
}

const UnitVTable swap_vtable = {
        .suffix = ".swap",

        .no_alias = true,
        .no_instances = true,

        .load = swap_load,

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

        .shutdown = swap_shutdown,

        .enumerate = swap_enumerate
};
