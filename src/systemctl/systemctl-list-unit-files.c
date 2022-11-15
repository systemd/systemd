/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "sort-util.h"
#include "systemctl-list-unit-files.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"

static int compare_unit_file_list(const UnitFileList *a, const UnitFileList *b) {
        const char *d1, *d2;

        d1 = strrchr(a->path, '.');
        d2 = strrchr(b->path, '.');

        if (d1 && d2) {
                int r;

                r = strcasecmp(d1, d2);
                if (r != 0)
                        return r;
        }

        return strcasecmp(basename(a->path), basename(b->path));
}

static bool output_show_unit_file(const UnitFileList *u, char **states, char **patterns) {
        assert(u);

        if (!strv_fnmatch_or_empty(patterns, basename(u->path), FNM_NOESCAPE))
                return false;

        if (!strv_isempty(arg_types)) {
                const char *dot;

                dot = strrchr(u->path, '.');
                if (!dot)
                        return false;

                if (!strv_contains(arg_types, dot+1))
                        return false;
        }

        if (!strv_isempty(states) &&
            !strv_contains(states, unit_file_state_to_string(u->state)))
                return false;

        return true;
}

static int output_unit_file_list(const UnitFileList *units, unsigned c) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(unit_file_presets_freep) UnitFilePresets presets = {};
        int r;

        table = table_new("unit file", "state", "preset");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        for (const UnitFileList *u = units; u < units + c; u++) {
                const char *on_underline = NULL, *on_unit_color = NULL, *id;
                bool underline;

                underline = u + 1 < units + c &&
                        !streq(unit_type_suffix(u->path), unit_type_suffix((u + 1)->path));

                if (underline)
                        on_underline = ansi_underline();

                if (IN_SET(u->state,
                           UNIT_FILE_MASKED,
                           UNIT_FILE_MASKED_RUNTIME,
                           UNIT_FILE_DISABLED,
                           UNIT_FILE_BAD))
                        on_unit_color = underline ? ansi_highlight_red_underline() : ansi_highlight_red();
                else if (IN_SET(u->state,
                                UNIT_FILE_ENABLED,
                                UNIT_FILE_ALIAS))
                        on_unit_color = underline ? ansi_highlight_green_underline() : ansi_highlight_green();
                else
                        on_unit_color = on_underline;

                id = basename(u->path);

                r = table_add_many(table,
                                   TABLE_STRING, id,
                                   TABLE_SET_BOTH_COLORS, strempty(on_underline),
                                   TABLE_STRING, unit_file_state_to_string(u->state),
                                   TABLE_SET_BOTH_COLORS, strempty(on_unit_color));
                if (r < 0)
                        return table_log_add_error(r);

                if (show_preset_for_state(u->state)) {
                        const char *unit_preset_str, *on_preset_color;

                        r = unit_file_query_preset(arg_scope, arg_root, id, &presets);
                        if (r < 0) {
                                unit_preset_str = "n/a";
                                on_preset_color = underline ? on_underline : ansi_normal();
                        } else if (r == 0) {
                                unit_preset_str = "disabled";
                                on_preset_color = underline ? ansi_highlight_red_underline() : ansi_highlight_red();
                        } else {
                                unit_preset_str = "enabled";
                                on_preset_color = underline ? ansi_highlight_green_underline() : ansi_highlight_green();
                        }

                        r = table_add_many(table,
                                           TABLE_STRING, unit_preset_str,
                                           TABLE_SET_BOTH_COLORS, strempty(on_preset_color));
                } else
                        r = table_add_many(table,
                                           TABLE_EMPTY,
                                           TABLE_SET_BOTH_COLORS, underline ? ansi_grey_underline() : ansi_grey());
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0)
                printf("\n%u unit files listed.\n", c);

        return 0;
}

int verb_list_unit_files(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ UnitFileList *units = NULL;
        unsigned c = 0;
        const char *state;
        char *path;
        int r;
        bool fallback = false;

        if (install_client_side()) {
                Hashmap *h;
                UnitFileList *u;
                unsigned n_units;

                h = hashmap_new(&string_hash_ops);
                if (!h)
                        return log_oom();

                r = unit_file_get_list(arg_scope, arg_root, h, arg_states, strv_skip(argv, 1));
                if (r < 0) {
                        unit_file_list_free(h);
                        return log_error_errno(r, "Failed to get unit file list: %m");
                }

                n_units = hashmap_size(h);

                units = new(UnitFileList, n_units ?: 1); /* avoid malloc(0) */
                if (!units) {
                        unit_file_list_free(h);
                        return log_oom();
                }

                HASHMAP_FOREACH(u, h) {
                        if (!output_show_unit_file(u, NULL, NULL))
                                continue;

                        units[c++] = *u;
                        free(u);
                }

                assert(c <= n_units);
                hashmap_free(h);

                r = 0;
        } else {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                sd_bus *bus;

                r = acquire_bus(BUS_MANAGER, &bus);
                if (r < 0)
                        return r;

                r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitFilesByPatterns");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append_strv(m, arg_states);
                if (r < 0)
                        return bus_log_create_error(r);

                if (arg_with_dependencies) {
                        _cleanup_strv_free_ char **names_with_deps = NULL;

                        r = append_unit_dependencies(bus, strv_skip(argv, 1), &names_with_deps);
                        if (r < 0)
                                return log_error_errno(r, "Failed to append unit dependencies: %m");

                        r = sd_bus_message_append_strv(m, names_with_deps);
                        if (r < 0)
                                return bus_log_create_error(r);
                } else {
                        r = sd_bus_message_append_strv(m, strv_skip(argv, 1));
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_call(bus, m, 0, &error, &reply);
                if (r < 0 && sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
                        /* Fallback to legacy ListUnitFiles method */
                        fallback = true;
                        log_debug_errno(r, "Failed to list unit files: %s Falling back to ListUnitsFiles method.", bus_error_message(&error, r));
                        m = sd_bus_message_unref(m);
                        sd_bus_error_free(&error);

                        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitFiles");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, 0, &error, &reply);
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to list unit files: %s", bus_error_message(&error, r));

                r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ss)");
                if (r < 0)
                        return bus_log_parse_error(r);

                while ((r = sd_bus_message_read(reply, "(ss)", &path, &state)) > 0) {

                        if (!GREEDY_REALLOC(units, c + 1))
                                return log_oom();

                        units[c] = (struct UnitFileList) {
                                path,
                                unit_file_state_from_string(state)
                        };

                        if (output_show_unit_file(&units[c],
                            fallback ? arg_states : NULL,
                            fallback ? strv_skip(argv, 1) : NULL))
                                c++;

                }
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        pager_open(arg_pager_flags);

        typesafe_qsort(units, c, compare_unit_file_list);
        r = output_unit_file_list(units, c);
        if (r < 0)
                return r;

        if (install_client_side())
                for (UnitFileList *unit = units; unit < units + c; unit++)
                        free(unit->path);

        if (c == 0)
                return -ENOENT;

        return 0;
}
