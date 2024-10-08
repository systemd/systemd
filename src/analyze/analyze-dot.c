/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-dot.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "glob-util.h"
#include "terminal-util.h"

static int graph_one_property(
                sd_bus *bus,
                const UnitInfo *u,
                const char *prop,
                const char *color,
                char **patterns,
                char **from_patterns,
                char **to_patterns) {

        _cleanup_strv_free_ char **units = NULL;
        bool match_patterns;
        int r;

        assert(bus);
        assert(u);
        assert(prop);
        assert(color);

        match_patterns = strv_fnmatch(patterns, u->id);

        if (!strv_isempty(from_patterns) && !match_patterns && !strv_fnmatch(from_patterns, u->id))
                return 0;

        r = bus_get_unit_property_strv(bus, u->unit_path, prop, &units);
        if (r < 0)
                return r;

        STRV_FOREACH(unit, units) {
                bool match_patterns2;

                match_patterns2 = strv_fnmatch(patterns, *unit);

                if (!strv_isempty(to_patterns) && !match_patterns2 && !strv_fnmatch(to_patterns, *unit))
                        continue;

                if (!strv_isempty(patterns) && !match_patterns && !match_patterns2)
                        continue;

                printf("\t\"%s\"->\"%s\" [color=\"%s\"];\n", u->id, *unit, color);
        }

        return 0;
}

static int graph_one(
                sd_bus *bus,
                const UnitInfo *u,
                char **patterns,
                char **from_patterns,
                char **to_patterns) {

        int r;

        assert(bus);
        assert(u);

        if (IN_SET(arg_dot, DEP_ORDER, DEP_ALL)) {
                r = graph_one_property(bus, u, "After", "green", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;
        }

        if (IN_SET(arg_dot, DEP_REQUIRE, DEP_ALL)) {
                r = graph_one_property(bus, u, "Requires", "black", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;

                r = graph_one_property(bus, u, "Requisite", "darkblue", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;

                r = graph_one_property(bus, u, "BindsTo", "gold", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;

                r = graph_one_property(bus, u, "Wants", "grey66", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;

                r = graph_one_property(bus, u, "Conflicts", "red", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int expand_patterns(sd_bus *bus, char **patterns, char ***ret) {
        _cleanup_strv_free_ char **expanded_patterns = NULL;
        int r;

        assert(bus);
        assert(ret);

        STRV_FOREACH(pattern, patterns) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_free_ char *unit = NULL, *unit_id = NULL;

                if (strv_extend(&expanded_patterns, *pattern) < 0)
                        return log_oom();

                if (string_is_glob(*pattern))
                        continue;

                unit = unit_dbus_path_from_name(*pattern);
                if (!unit)
                        return log_oom();

                r = sd_bus_get_property_string(
                                bus,
                                "org.freedesktop.systemd1",
                                unit,
                                "org.freedesktop.systemd1.Unit",
                                "Id",
                                &error,
                                &unit_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to get ID: %s", bus_error_message(&error, r));

                if (!streq(*pattern, unit_id))
                        if (strv_extend(&expanded_patterns, unit_id) < 0)
                                return log_oom();
        }

        *ret = TAKE_PTR(expanded_patterns); /* do not free */

        return 0;
}

int verb_dot(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **expanded_patterns = NULL;
        _cleanup_strv_free_ char **expanded_from_patterns = NULL;
        _cleanup_strv_free_ char **expanded_to_patterns = NULL;
        UnitInfo u;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        r = expand_patterns(bus, strv_skip(argv, 1), &expanded_patterns);
        if (r < 0)
                return r;

        r = expand_patterns(bus, arg_dot_from_patterns, &expanded_from_patterns);
        if (r < 0)
                return r;

        r = expand_patterns(bus, arg_dot_to_patterns, &expanded_to_patterns);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_systemd_mgr, "ListUnits", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        printf("digraph systemd {\n");

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {

                r = graph_one(bus, &u, expanded_patterns, expanded_from_patterns, expanded_to_patterns);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        printf("}\n");

        log_info("   Color legend: black     = Requires\n"
                 "                 dark blue = Requisite\n"
                 "                 gold      = BindsTo\n"
                 "                 dark grey = Wants\n"
                 "                 red       = Conflicts\n"
                 "                 green     = After\n");

        if (on_tty() && !arg_quiet)
                log_notice("-- You probably want to process this output with graphviz' dot tool.\n"
                           "-- Try a shell pipeline like 'systemd-analyze dot | dot -Tsvg > systemd.svg'!\n");

        return 0;
}
