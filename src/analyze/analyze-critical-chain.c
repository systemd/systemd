/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze-critical-chain.h"
#include "analyze-time-data.h"
#include "analyze.h"
#include "bus-error.h"
#include "copy.h"
#include "path-util.h"
#include "sort-util.h"
#include "special.h"
#include "static-destruct.h"
#include "strv.h"
#include "terminal-util.h"

static Hashmap *unit_times_hashmap = NULL;
STATIC_DESTRUCTOR_REGISTER(unit_times_hashmap, hashmap_freep);

static int list_dependencies_print(
                const char *name,
                unsigned level,
                unsigned branches,
                bool last,
                UnitTimes *times,
                BootTimes *boot) {

        for (unsigned i = level; i > 0; i--)
                printf("%s", special_glyph(branches & (1 << (i-1)) ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE));

        printf("%s", special_glyph(last ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH));

        if (times && times->activating >= boot->userspace_time) {
                if (timestamp_is_set(times->time))
                        printf("%s%s @%s +%s%s\n", ansi_highlight_red(), name,
                               FORMAT_TIMESPAN(times->activating - boot->userspace_time, USEC_PER_MSEC),
                               FORMAT_TIMESPAN(times->time, USEC_PER_MSEC), ansi_normal());
                else
                        printf("%s @%s\n", name, FORMAT_TIMESPAN(times->activated - boot->userspace_time, USEC_PER_MSEC));
        } else
                printf("%s\n", name);

        return 0;
}

static int list_dependencies_get_dependencies(sd_bus *bus, const char *name, char ***deps) {
        _cleanup_free_ char *path = NULL;

        assert(bus);
        assert(name);
        assert(deps);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return -ENOMEM;

        return bus_get_unit_property_strv(bus, path, "After", deps);
}

static int list_dependencies_compare(char *const *a, char *const *b) {
        usec_t usa = 0, usb = 0;
        UnitTimes *times;

        times = hashmap_get(unit_times_hashmap, *a);
        if (times)
                usa = times->activated;
        times = hashmap_get(unit_times_hashmap, *b);
        if (times)
                usb = times->activated;

        return CMP(usb, usa);
}

static bool times_in_range(const UnitTimes *times, const BootTimes *boot) {
        return times && times->activated > 0 && times->activated <= boot->finish_time;
}

static int list_dependencies_one(sd_bus *bus, const char *name, unsigned level, char ***units, unsigned branches) {
        _cleanup_strv_free_ char **deps = NULL;
        int r;
        usec_t service_longest = 0;
        int to_print = 0;
        UnitTimes *times;
        BootTimes *boot;

        if (strv_extend(units, name))
                return log_oom();

        r = list_dependencies_get_dependencies(bus, name, &deps);
        if (r < 0)
                return r;

        typesafe_qsort(deps, strv_length(deps), list_dependencies_compare);

        r = acquire_boot_times(bus, /* require_finished = */ true, &boot);
        if (r < 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (times_in_range(times, boot) && times->activated >= service_longest)
                        service_longest = times->activated;
        }

        if (service_longest == 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (times_in_range(times, boot) && service_longest - times->activated <= arg_fuzz)
                        to_print++;
        }

        if (!to_print)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (!times_in_range(times, boot) || service_longest - times->activated > arg_fuzz)
                        continue;

                to_print--;

                r = list_dependencies_print(*c, level, branches, to_print == 0, times, boot);
                if (r < 0)
                        return r;

                if (strv_contains(*units, *c)) {
                        r = list_dependencies_print("...", level + 1, (branches << 1) | (to_print ? 1 : 0),
                                                    true, NULL, boot);
                        if (r < 0)
                                return r;
                        continue;
                }

                r = list_dependencies_one(bus, *c, level + 1, units, (branches << 1) | (to_print ? 1 : 0));
                if (r < 0)
                        return r;

                if (to_print == 0)
                        break;
        }
        return 0;
}

static int list_dependencies(sd_bus *bus, const char *name) {
        _cleanup_strv_free_ char **units = NULL;
        UnitTimes *times;
        int r;
        const char *id;
        _cleanup_free_ char *path = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        BootTimes *boot;

        assert(bus);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "Id",
                        &error,
                        &reply,
                        "s");
        if (r < 0)
                return log_error_errno(r, "Failed to get ID: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &id);
        if (r < 0)
                return bus_log_parse_error(r);

        times = hashmap_get(unit_times_hashmap, id);

        r = acquire_boot_times(bus, /* require_finished = */ true, &boot);
        if (r < 0)
                return r;

        if (times) {
                if (times->time)
                        printf("%s%s +%s%s\n", ansi_highlight_red(), id,
                               FORMAT_TIMESPAN(times->time, USEC_PER_MSEC), ansi_normal());
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s\n", id,
                               FORMAT_TIMESPAN(times->activated - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s\n", id);
        }

        return list_dependencies_one(bus, name, 0, &units, 0);
}

int verb_critical_chain(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *times = NULL;
        int n, r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        n = acquire_time_data(bus, /* require_finished = */ true, &times);
        if (n <= 0)
                return n;

        for (UnitTimes *u = times; u->has_data; u++) {
                r = hashmap_ensure_put(&unit_times_hashmap, &string_hash_ops, u->name, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to add entry to hashmap: %m");
        }

        pager_open(arg_pager_flags);

        puts("The time when unit became active or started is printed after the \"@\" character.\n"
             "The time the unit took to start is printed after the \"+\" character.\n");

        if (argc > 1)
                STRV_FOREACH(name, strv_skip(argv, 1))
                        list_dependencies(bus, *name);
        else
                list_dependencies(bus, SPECIAL_DEFAULT_TARGET);

        return EXIT_SUCCESS;
}
