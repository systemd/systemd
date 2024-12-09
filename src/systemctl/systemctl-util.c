/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/reboot.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "ask-password-agent.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"
#include "chase.h"
#include "dropin.h"
#include "env-util.h"
#include "exit-status.h"
#include "fs-util.h"
#include "glob-util.h"
#include "macro.h"
#include "path-util.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "process-util.h"
#include "reboot-util.h"
#include "set.h"
#include "stat-util.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"
#include "verbs.h"

static sd_bus *buses[_BUS_FOCUS_MAX] = {};

int acquire_bus_full(BusFocus focus, bool graceful, sd_bus **ret) {
        int r;

        assert(focus < _BUS_FOCUS_MAX);
        assert(ret);

        if (!IN_SET(arg_runtime_scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--global is not supported for this operation.");

        /* We only go directly to the manager, if we are using a local transport */
        if (!IN_SET(arg_transport, BUS_TRANSPORT_LOCAL, BUS_TRANSPORT_CAPSULE))
                focus = BUS_FULL;

        if (getenv_bool("SYSTEMCTL_FORCE_BUS") > 0)
                focus = BUS_FULL;

        if (!buses[focus]) {
                if (focus == BUS_MANAGER)
                        r = bus_connect_transport_systemd(arg_transport, arg_host, arg_runtime_scope, &buses[focus]);
                else
                        r = bus_connect_transport(arg_transport, arg_host, arg_runtime_scope, &buses[focus]);
                if (r < 0)
                        return bus_log_connect_full(graceful && focus == BUS_FULL && r == -ECONNREFUSED ? LOG_DEBUG : LOG_ERR,
                                                    r, arg_transport, arg_runtime_scope);

                (void) sd_bus_set_allow_interactive_authorization(buses[focus], arg_ask_password);
        }

        *ret = buses[focus];
        return 0;
}

void release_busses(void) {
        FOREACH_ARRAY(w, buses, _BUS_FOCUS_MAX)
                *w = sd_bus_flush_close_unref(*w);
}

void ask_password_agent_open_maybe(void) {
        /* Open the password agent as a child process if necessary */

        if (arg_dry_run)
                return;

        if (arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                return;

        ask_password_agent_open_if_enabled(arg_transport, arg_ask_password);
}

void polkit_agent_open_maybe(void) {
        /* Open the polkit agent as a child process if necessary */

        if (arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                return;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);
}

int translate_bus_error_to_exit_status(int r, const sd_bus_error *error) {
        assert(error);

        if (!sd_bus_error_is_set(error))
                return r;

        if (sd_bus_error_has_names(error, SD_BUS_ERROR_ACCESS_DENIED,
                                          BUS_ERROR_ONLY_BY_DEPENDENCY,
                                          BUS_ERROR_NO_ISOLATION,
                                          BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE))
                return EXIT_NOPERMISSION;

        if (sd_bus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT))
                return EXIT_NOTINSTALLED;

        if (sd_bus_error_has_names(error, BUS_ERROR_JOB_TYPE_NOT_APPLICABLE,
                                          SD_BUS_ERROR_NOT_SUPPORTED))
                return EXIT_NOTIMPLEMENTED;

        if (sd_bus_error_has_name(error, BUS_ERROR_LOAD_FAILED))
                return EXIT_NOTCONFIGURED;

        if (r != 0)
                return r;

        return EXIT_FAILURE;
}

int get_state_one_unit(sd_bus *bus, const char *unit, UnitActiveState *ret_active_state) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *buf = NULL, *dbus_path = NULL;
        UnitActiveState state;
        int r;

        assert(bus);
        assert(unit);
        assert(ret_active_state);

        dbus_path = unit_dbus_path_from_name(unit);
        if (!dbus_path)
                return log_oom();

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        dbus_path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveState",
                        &error,
                        &buf);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve unit state: %s", bus_error_message(&error, r));

        state = unit_active_state_from_string(buf);
        if (state < 0)
                return log_error_errno(state, "Invalid unit state '%s' for: %s", buf, unit);

        *ret_active_state = state;
        return 0;
}

int get_sub_state_one_unit(sd_bus *bus, const char *unit, char **ret_sub_state) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *sub_state = NULL, *dbus_path = NULL;
        int r;

        assert(bus);
        assert(unit);
        assert(ret_sub_state);

        dbus_path = unit_dbus_path_from_name(unit);
        if (!dbus_path)
                return log_oom();

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        dbus_path,
                        "org.freedesktop.systemd1.Unit",
                        "SubState",
                        &error,
                        &sub_state);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve unit sub state: %s", bus_error_message(&error, r));

        *ret_sub_state = TAKE_PTR(sub_state);
        return 0;
}

int get_unit_list(
                sd_bus *bus,
                const char *machine,
                char **patterns,
                UnitInfo **unit_infos,
                int c,
                sd_bus_message **ret_reply) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;
        bool fallback = false;

        assert(bus);
        assert(unit_infos);
        assert(ret_reply);

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitsByPatterns");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, arg_states);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, patterns);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0 && (sd_bus_error_has_names(&error, SD_BUS_ERROR_UNKNOWN_METHOD,
                                                     SD_BUS_ERROR_ACCESS_DENIED))) {
                /* Fallback to legacy ListUnitsFiltered method */
                fallback = true;
                log_debug_errno(r, "Failed to list units: %s Falling back to ListUnitsFiltered method.", bus_error_message(&error, r));
                m = sd_bus_message_unref(m);
                sd_bus_error_free(&error);

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitsFiltered");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, arg_states);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, 0, &error, &reply);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                UnitInfo u;

                r = bus_parse_unit_info(reply, &u);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                u.machine = machine;

                if (!output_show_unit(&u, fallback ? patterns : NULL))
                        continue;

                if (!GREEDY_REALLOC(*unit_infos, c+1))
                        return log_oom();

                (*unit_infos)[c++] = u;
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        *ret_reply = TAKE_PTR(reply);
        return c;
}

int expand_unit_names(
                sd_bus *bus,
                char * const *names,
                const char *suffix,
                char ***ret,
                bool *ret_expanded) {

        _cleanup_strv_free_ char **mangled = NULL, **globs = NULL;
        int r;

        assert(bus);
        assert(ret);

        STRV_FOREACH(name, names) {
                UnitNameMangle options = UNIT_NAME_MANGLE_GLOB | (arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN);
                char *t;

                r = unit_name_mangle_with_suffix(*name, NULL, options, suffix ?: ".service", &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle name: %m");

                if (string_is_glob(t))
                        r = strv_consume(&globs, t);
                else
                        r = strv_consume(&mangled, t);
                if (r < 0)
                        return log_oom();
        }

        /* Query the manager only if any of the names are a glob, since this is fairly expensive */
        bool expanded = !strv_isempty(globs);
        if (expanded) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_free_ UnitInfo *unit_infos = NULL;

                r = get_unit_list(bus, NULL, globs, &unit_infos, 0, &reply);
                if (r < 0)
                        return r;

                FOREACH_ARRAY(info, unit_infos, r)
                        if (strv_extend(&mangled, info->id) < 0)
                                return log_oom();
        }

        *ret = TAKE_PTR(mangled);
        if (ret_expanded)
                *ret_expanded = expanded;

        return 0;
}

int get_active_triggering_units(sd_bus *bus, const char *unit, bool ignore_masked, char ***ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **triggered_by = NULL, **active = NULL;
        _cleanup_free_ char *name = NULL, *dbus_path = NULL;
        int r;

        assert(bus);
        assert(unit);
        assert(ret);

        r = unit_name_mangle(unit, 0, &name);
        if (r < 0)
                return r;

        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE))
                goto skip;

        if (ignore_masked) {
                r = unit_is_masked(bus, name);
                if (r < 0)
                        return r;
                if (r > 0)
                        goto skip;
        }

        dbus_path = unit_dbus_path_from_name(name);
        if (!dbus_path)
                return -ENOMEM;

        r = sd_bus_get_property_strv(
                        bus,
                        "org.freedesktop.systemd1",
                        dbus_path,
                        "org.freedesktop.systemd1.Unit",
                        "TriggeredBy",
                        &error,
                        &triggered_by);
        if (r < 0)
                return log_debug_errno(r, "Failed to get TriggeredBy property of unit '%s': %s",
                                       name, bus_error_message(&error, r));

        STRV_FOREACH(i, triggered_by) {
                UnitActiveState active_state;

                r = get_state_one_unit(bus, *i, &active_state);
                if (r < 0)
                        return r;

                if (!IN_SET(active_state, UNIT_ACTIVE, UNIT_RELOADING, UNIT_REFRESHING))
                        continue;

                r = strv_extend(&active, *i);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(active);
        return 0;

skip:
        *ret = NULL;
        return 0;
}

void warn_triggering_units(sd_bus *bus, const char *unit, const char *operation, bool ignore_masked) {
        _cleanup_strv_free_ char **triggered_by = NULL;
        _cleanup_free_ char *joined = NULL;
        int r;

        assert(bus);
        assert(unit);
        assert(operation);

        r = get_active_triggering_units(bus, unit, ignore_masked, &triggered_by);
        if (r < 0) {
                if (r != -ENOENT) /* A linked unit might have disappeared after disabling */
                        log_warning_errno(r, "Failed to get triggering units for '%s', ignoring: %m", unit);
                return;
        }

        if (strv_isempty(triggered_by))
                return;

        joined = strv_join(triggered_by, ", ");
        if (!joined)
                return (void) log_oom();

        log_warning("%s '%s', but its triggering units are still active:\n"
                    "%s",
                    operation, unit, joined);
}

int need_daemon_reload(sd_bus *bus, const char *unit) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        int b, r;

        /* We ignore all errors here, since this is used to show a
         * warning only */

        /* We don't use unit_dbus_path_from_name() directly since we
         * don't want to load the unit if it isn't loaded. */

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnit", NULL, &reply, "s", unit);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return r;

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "NeedDaemonReload",
                        NULL,
                        'b', &b);
        if (r < 0)
                return r;

        return b;
}

void warn_unit_file_changed(const char *unit) {
        assert(unit);

        if (arg_no_warn)
                return;

        log_warning("Warning: The unit file, source configuration file or drop-ins of %s changed on disk. Run 'systemctl%s daemon-reload' to reload units.",
                    unit,
                    arg_runtime_scope == RUNTIME_SCOPE_SYSTEM ? "" : " --user");
}

int unit_file_find_path(LookupPaths *lp, const char *unit_name, char **ret_unit_path) {
        assert(lp);
        assert(unit_name);

        STRV_FOREACH(p, lp->search_path) {
                _cleanup_free_ char *path = NULL, *lpath = NULL;
                int r;

                path = path_join(*p, unit_name);
                if (!path)
                        return log_oom();

                r = chase(path, arg_root, 0, &lpath, NULL);
                if (r == -ENOENT)
                        continue;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_error_errno(r, "Failed to access path \"%s\": %m", path);

                if (ret_unit_path)
                        *ret_unit_path = TAKE_PTR(lpath);

                return 1;
        }

        if (ret_unit_path)
                *ret_unit_path = NULL;

        return 0;
}

int unit_find_paths(
                sd_bus *bus,
                const char *unit_name,
                LookupPaths *lp,
                bool force_client_side,
                Hashmap **cached_id_map,
                Hashmap **cached_name_map,
                char **ret_fragment_path,
                char ***ret_dropin_paths) {

        _cleanup_strv_free_ char **dropins = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        /**
         * Finds where the unit is defined on disk. Returns 0 if the unit is not found. Returns 1 if it is
         * found, and sets:
         *
         * - the path to the unit in *ret_frament_path, if it exists on disk,
         *
         * - and a strv of existing drop-ins in *ret_dropin_paths, if the arg is not NULL and any dropins
         *   were found.
         *
         * Returns -ERFKILL if the unit is masked, and -EKEYREJECTED if the unit file could not be loaded for
         * some reason (the latter only applies if we are going through the service manager). As special
         * exception it won't log for these two error cases.
         */

        assert(unit_name);
        assert(ret_fragment_path);
        assert(lp);

        /* Go via the bus to acquire the path, unless we are explicitly told not to, or when the unit name is a template */
        if (!force_client_side &&
            !install_client_side() &&
            !unit_name_is_valid(unit_name, UNIT_NAME_TEMPLATE)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_free_ char *load_state = NULL, *dbus_path = NULL;

                dbus_path = unit_dbus_path_from_name(unit_name);
                if (!dbus_path)
                        return log_oom();

                r = sd_bus_get_property_string(
                                bus,
                                "org.freedesktop.systemd1",
                                dbus_path,
                                "org.freedesktop.systemd1.Unit",
                                "LoadState",
                                &error,
                                &load_state);
                if (r < 0)
                        return log_error_errno(r, "Failed to get LoadState: %s", bus_error_message(&error, r));

                if (streq(load_state, "masked"))
                        return -ERFKILL; /* special case: no logging */
                if (streq(load_state, "not-found")) {
                        r = 0;
                        goto finish;
                }
                if (!STR_IN_SET(load_state, "loaded", "bad-setting"))
                        return -EKEYREJECTED; /* special case: no logging */

                r = sd_bus_get_property_string(
                                bus,
                                "org.freedesktop.systemd1",
                                dbus_path,
                                "org.freedesktop.systemd1.Unit",
                                "FragmentPath",
                                &error,
                                &path);
                if (r < 0)
                        return log_error_errno(r, "Failed to get FragmentPath: %s", bus_error_message(&error, r));

                if (ret_dropin_paths) {
                        r = sd_bus_get_property_strv(
                                        bus,
                                        "org.freedesktop.systemd1",
                                        dbus_path,
                                        "org.freedesktop.systemd1.Unit",
                                        "DropInPaths",
                                        &error,
                                        &dropins);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get DropInPaths: %s", bus_error_message(&error, r));
                }
        } else {
                const char *_path;
                _cleanup_set_free_free_ Set *names = NULL;

                if (!*cached_name_map) {
                        r = unit_file_build_name_map(lp, NULL, cached_id_map, cached_name_map, NULL);
                        if (r < 0)
                                return r;
                }

                r = unit_file_find_fragment(*cached_id_map, *cached_name_map, unit_name, &_path, &names);
                if (r < 0)
                        return log_error_errno(r, "Failed to find fragment for '%s': %m", unit_name);

                if (_path) {
                        path = strdup(_path);
                        if (!path)
                                return log_oom();
                }

                if (ret_dropin_paths) {
                        r = unit_file_find_dropin_paths(arg_root, lp->search_path, NULL,
                                                        ".d", ".conf",
                                                        NULL, names, &dropins);
                        if (r < 0)
                                return r;
                }
        }

 finish:
        if (isempty(path)) {
                *ret_fragment_path = NULL;
                r = 0;
        } else {
                *ret_fragment_path = TAKE_PTR(path);
                r = 1;
        }

        if (ret_dropin_paths) {
                if (!strv_isempty(dropins)) {
                        *ret_dropin_paths = TAKE_PTR(dropins);
                        r = 1;
                } else
                        *ret_dropin_paths = NULL;
        }

        if (r == 0 && !arg_force)
                log_error("No files found for %s.", unit_name);

        return r;
}

static int unit_find_template_path(
                const char *unit_name,
                LookupPaths *lp,
                char **ret_fragment_path,
                char **ret_template) {

        _cleanup_free_ char *t = NULL, *f = NULL;
        int r;

        /* Returns 1 if a fragment was found, 0 if not found, negative on error. */

        r = unit_file_find_path(lp, unit_name, &f);
        if (r < 0)
                return r;
        if (r > 0) {
                if (ret_fragment_path)
                        *ret_fragment_path = TAKE_PTR(f);
                if (ret_template)
                        *ret_template = NULL;
                return r; /* found a real unit */
        }

        r = unit_name_template(unit_name, &t);
        if (r == -EINVAL) {
                if (ret_fragment_path)
                        *ret_fragment_path = NULL;
                if (ret_template)
                        *ret_template = NULL;

                return 0; /* not a template, does not exist */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine template name: %m");

        r = unit_file_find_path(lp, t, ret_fragment_path);
        if (r < 0)
                return r;

        if (ret_template)
                *ret_template = r > 0 ? TAKE_PTR(t) : NULL;

        return r;
}

int unit_is_masked(sd_bus *bus, const char *unit) {
        _cleanup_free_ char *load_state = NULL;
        int r;

        assert(bus);
        assert(unit);

        if (unit_name_is_valid(unit, UNIT_NAME_TEMPLATE)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *state;

                r = bus_call_method(bus, bus_systemd_mgr, "GetUnitFileState", &error, &reply, "s", unit);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get UnitFileState for '%s': %s",
                                               unit, bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "s", &state);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                return STR_IN_SET(state, "masked", "masked-runtime");
        }

        r = unit_load_state(bus, unit, &load_state);
        if (r < 0)
                return r;

        return streq(load_state, "masked");
}

int unit_exists(LookupPaths *lp, const char *unit) {
        typedef struct UnitStateInfo {
                const char *load_state;
                const char *active_state;
        } UnitStateInfo;

        static const struct bus_properties_map property_map[] = {
                { "LoadState",   "s", NULL, offsetof(UnitStateInfo, load_state)   },
                { "ActiveState", "s", NULL, offsetof(UnitStateInfo, active_state) },
                {},
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *path = NULL;
        UnitStateInfo info = {};
        sd_bus *bus;
        int r;

        if (unit_name_is_valid(unit, UNIT_NAME_TEMPLATE))
                return unit_find_template_path(unit, lp, NULL, NULL);

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        r = bus_map_all_properties(bus, "org.freedesktop.systemd1", path, property_map, 0, &error, &m, &info);
        if (r < 0)
                return log_error_errno(r, "Failed to get properties: %s", bus_error_message(&error, r));

        return !streq_ptr(info.load_state, "not-found") || !streq_ptr(info.active_state, "inactive");
}

int append_unit_dependencies(sd_bus *bus, char **names, char ***ret) {
        _cleanup_strv_free_ char **with_deps = NULL;

        assert(bus);
        assert(ret);

        STRV_FOREACH(name, names) {
                char **deps;

                if (strv_extend(&with_deps, *name) < 0)
                        return log_oom();

                (void) unit_get_dependencies(bus, *name, &deps);

                if (strv_extend_strv_consume(&with_deps, deps, /* filter_duplicates = */ true) < 0)
                        return log_oom();
        }

        *ret = TAKE_PTR(with_deps);

        return 0;
}

int maybe_extend_with_unit_dependencies(sd_bus *bus, char ***list) {
        _cleanup_strv_free_ char **list_with_deps = NULL;
        int r;

        assert(bus);
        assert(list);

        if (!arg_with_dependencies)
                return 0;

        r = append_unit_dependencies(bus, *list, &list_with_deps);
        if (r < 0)
                return log_error_errno(r, "Failed to append unit dependencies: %m");

        return strv_free_and_replace(*list, list_with_deps);
}

int unit_get_dependencies(sd_bus *bus, const char *name, char ***ret) {
        _cleanup_strv_free_ char **deps = NULL;

        static const struct bus_properties_map map[_DEPENDENCY_MAX][7] = {
                [DEPENDENCY_FORWARD] = {
                        { "Requires",    "as", NULL, 0 },
                        { "Requisite",   "as", NULL, 0 },
                        { "Wants",       "as", NULL, 0 },
                        { "ConsistsOf",  "as", NULL, 0 },
                        { "BindsTo",     "as", NULL, 0 },
                        { "Upholds",     "as", NULL, 0 },
                        {}
                },
                [DEPENDENCY_REVERSE] = {
                        { "RequiredBy",  "as", NULL, 0 },
                        { "RequisiteOf", "as", NULL, 0 },
                        { "WantedBy",    "as", NULL, 0 },
                        { "PartOf",      "as", NULL, 0 },
                        { "BoundBy",     "as", NULL, 0 },
                        { "UpheldBy",    "as", NULL, 0 },
                        {}
                },
                [DEPENDENCY_AFTER] = {
                        { "After",       "as", NULL, 0 },
                        {}
                },
                [DEPENDENCY_BEFORE] = {
                        { "Before",      "as", NULL, 0 },
                        {}
                },
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *dbus_path = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(ret);

        dbus_path = unit_dbus_path_from_name(name);
        if (!dbus_path)
                return log_oom();

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.systemd1",
                                   dbus_path,
                                   map[arg_dependency],
                                   BUS_MAP_STRDUP,
                                   &error,
                                   NULL,
                                   &deps);
        if (r < 0)
                return log_error_errno(r, "Failed to get properties of %s: %s", name, bus_error_message(&error, r));

        strv_uniq(deps); /* Sometimes a unit might have multiple deps on the other unit,
                          * but we still want to show it just once. */
        *ret = TAKE_PTR(deps);

        return 0;
}

const char* unit_type_suffix(const char *unit) {
        const char *dot;

        dot = strrchr(unit, '.');
        if (!dot)
                return "";

        return dot + 1;
}

bool output_show_unit(const UnitInfo *u, char **patterns) {
        assert(u);

        if (!strv_fnmatch_or_empty(patterns, u->id, FNM_NOESCAPE))
                return false;

        if (arg_types && !strv_contains(arg_types, unit_type_suffix(u->id)))
                return false;

        if (arg_all)
                return true;

        /* Note that '--all' is not purely a state filter, but also a filter that hides units that "follow"
         * other units (which is used for device units that appear under different names). */
        if (!isempty(u->following))
                return false;

        if (!strv_isempty(arg_states))
                return true;

        /* By default show all units except the ones in inactive state and with no pending job */
        if (u->job_id > 0)
                return true;

        if (streq(u->active_state, "inactive"))
                return false;

        return true;
}

bool install_client_side(void) {
        /* Decides when to execute enable/disable/... operations client-side rather than server-side. */

        if (running_in_chroot_or_offline())
                return true;

        if (sd_booted() <= 0)
                return true;

        if (!isempty(arg_root))
                return true;

        if (arg_runtime_scope == RUNTIME_SCOPE_GLOBAL)
                return true;

        /* Unsupported environment variable, mostly for debugging purposes */
        if (getenv_bool("SYSTEMCTL_INSTALL_CLIENT_SIDE") > 0)
                return true;

        return false;
}

int output_table(Table *table) {
        int r;

        assert(table);

        if (OUTPUT_MODE_IS_JSON(arg_output))
                r = table_print_json(table, NULL, output_mode_to_json_format_flags(arg_output) | SD_JSON_FORMAT_COLOR_AUTO);
        else
                r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

bool show_preset_for_state(UnitFileState state) {
        /* Don't show preset state in those unit file states, it'll only confuse users. */
        return !IN_SET(state,
                       UNIT_FILE_ALIAS,
                       UNIT_FILE_STATIC,
                       UNIT_FILE_GENERATED,
                       UNIT_FILE_TRANSIENT);
}

UnitFileFlags unit_file_flags_from_args(void) {
        return (arg_runtime ? UNIT_FILE_RUNTIME : 0) |
               (arg_force   ? UNIT_FILE_FORCE   : 0);
}

int mangle_names(const char *operation, char * const *original_names, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(operation);
        assert(ret);

        STRV_FOREACH(name, original_names) {
                char *mangled;

                if (is_path(*name))
                        /* When enabling units qualified path names are OK, too, hence allow them explicitly. */
                        r = path_make_absolute_cwd(*name, &mangled);
                else
                        r = unit_name_mangle_with_suffix(*name, operation,
                                                         arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN,
                                                         ".service", &mangled);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle unit name or path '%s': %m", *name);

                if (strv_consume(&l, mangled) < 0)
                        return log_oom();
        }

        *ret = TAKE_PTR(l);

        return 0;
}

int halt_now(enum action a) {
        /* The kernel will automatically flush ATA disks and suchlike on reboot(), but the file systems need
         * to be synced explicitly in advance. */
        if (!arg_no_sync && !arg_dry_run)
                sync();

        /* Make sure C-A-D is handled by the kernel from this point on... */
        if (!arg_dry_run)
                (void) reboot(RB_ENABLE_CAD);

        switch (a) {

        case ACTION_HALT:
                if (!arg_quiet)
                        log_info("Halting.");
                if (arg_dry_run)
                        return 0;
                (void) reboot(RB_HALT_SYSTEM);
                return -errno;

        case ACTION_POWEROFF:
                if (!arg_quiet)
                        log_info("Powering off.");
                if (arg_dry_run)
                        return 0;
                (void) reboot(RB_POWER_OFF);
                return -errno;

        case ACTION_KEXEC:
        case ACTION_REBOOT:
                return reboot_with_parameter(REBOOT_FALLBACK |
                                             (arg_quiet ? 0 : REBOOT_LOG) |
                                             (arg_dry_run ? REBOOT_DRY_RUN : 0));

        default:
                assert_not_reached();
        }
}

int get_unit_by_pid(sd_bus *bus, pid_t pid, char **ret_unit, char **ret_path) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(pid >= 0); /* 0 is accepted by GetUnitByPID for querying our own process. */

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPID", &error, &reply, "u", (uint32_t) pid);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_UNIT_FOR_PID))
                        return log_error_errno(r, "%s", bus_error_message(&error, r));

                return log_error_errno(r,
                                       "Failed to get unit that PID " PID_FMT " belongs to: %s",
                                       pid > 0 ? pid : getpid_cached(),
                                       bus_error_message(&error, r));
        }

        _cleanup_free_ char *u = NULL, *p = NULL;
        const char *path;

        r = sd_bus_message_read_basic(reply, 'o', &path);
        if (r < 0)
                return bus_log_parse_error(r);

        if (ret_unit) {
                r = unit_name_from_dbus_path(path, &u);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to extract unit name from D-Bus object path '%s': %m",
                                               path);
        }

        if (ret_path) {
                p = strdup(path);
                if (!p)
                        return log_oom();
        }

        if (ret_unit)
                *ret_unit = TAKE_PTR(u);
        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return 0;
}

static int get_unit_by_pidfd(sd_bus *bus, const PidRef *pid, char **ret_unit, char **ret_path) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(pidref_is_set(pid));

        if (pid->fd < 0)
                return -EOPNOTSUPP;

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPIDFD", &error, &reply, "h", pid->fd);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
                        return -EOPNOTSUPP;

                if (sd_bus_error_has_names(&error, BUS_ERROR_NO_UNIT_FOR_PID, BUS_ERROR_NO_SUCH_PROCESS))
                        return log_error_errno(r, "%s", bus_error_message(&error, r));

                return log_error_errno(r,
                                       "Failed to get unit that PID " PID_FMT " belongs to: %s",
                                       pid->pid, bus_error_message(&error, r));
        }

        _cleanup_free_ char *u = NULL, *p = NULL;
        const char *path, *unit;

        r = sd_bus_message_read(reply, "os", &path, &unit);
        if (r < 0)
                return bus_log_parse_error(r);

        if (ret_unit) {
                u = strdup(unit);
                if (!u)
                        return log_oom();
        }

        if (ret_path) {
                p = strdup(path);
                if (!p)
                        return log_oom();
        }

        if (ret_unit)
                *ret_unit = TAKE_PTR(u);
        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return 0;
}

int lookup_unit_by_pidref(sd_bus *bus, pid_t pid, char **ret_unit, char **ret_path) {
        int r;

        assert(bus);
        assert(pid >= 0); /* 0 means our own process */

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return get_unit_by_pid(bus, pid, ret_unit, ret_path);

        static bool use_pidfd = true;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        r = pidref_set_pid(&pidref, pid);
        if (r < 0)
                return log_error_errno(r,
                                       r == -ESRCH ?
                                       "PID " PID_FMT " doesn't exist or is already gone." :
                                       "Failed to create reference to PID " PID_FMT ": %m",
                                       pid);

        if (use_pidfd) {
                r = get_unit_by_pidfd(bus, &pidref, ret_unit, ret_path);
                if (r != -EOPNOTSUPP)
                        return r;

                use_pidfd = false;
                log_debug_errno(r, "Unable to look up process using pidfd, falling back to pid.");
        }

        _cleanup_free_ char *u = NULL, *p = NULL;

        r = get_unit_by_pid(bus, pidref.pid, ret_unit ? &u : NULL, ret_path ? &p : NULL);
        if (r < 0)
                return r;

        r = pidref_verify(&pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to verify our reference to PID " PID_FMT ": %m", pidref.pid);

        if (ret_unit)
                *ret_unit = TAKE_PTR(u);
        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return 0;
}
