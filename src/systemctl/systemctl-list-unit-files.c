/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ansi-color.h"
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

static const char* preset_action_to_color(PresetAction action, bool underline) {
        assert(action >= 0);

        switch (action) {
        case PRESET_ENABLE:
                return underline ? ansi_highlight_green_underline() : ansi_highlight_green();
        case PRESET_DISABLE:
                return underline ? ansi_highlight_red_underline() : ansi_highlight_red();
        case PRESET_IGNORE:
                return underline ? ansi_highlight_yellow_underline() : ansi_highlight_yellow();
        default:
                return NULL;
        }
}

static int output_unit_file_list(const UnitFileList *units, unsigned c) {
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_(unit_file_presets_done) UnitFilePresets presets = {};
        int r;

        table = table_new("unit file", "state", "preset");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        FOREACH_ARRAY(u, units, c) {
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
                        const char *on_preset_color = underline ? on_underline : ansi_normal();

                        r = unit_file_query_preset(arg_runtime_scope, arg_root, id, &presets);
                        if (r >= 0)
                                on_preset_color = preset_action_to_color(r, underline);

                        r = table_add_many(table,
                                           TABLE_STRING, strna(preset_action_past_tense_to_string(r)),
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
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        _cleanup_free_ UnitFileList *units = NULL;
        unsigned c = 0;
        int r;

        if (install_client_side()) {
                unsigned n_units;

                r = unit_file_get_list(arg_runtime_scope, arg_root, arg_states, strv_skip(argv, 1), &h);
                if (r < 0)
                        return log_error_errno(r, "Failed to get unit file list: %m");

                n_units = hashmap_size(h);

                units = new(UnitFileList, n_units);
                if (!units)
                        return log_oom();

                UnitFileList *u;
                HASHMAP_FOREACH(u, h) {
                        if (!output_show_unit_file(u, NULL, NULL))
                                continue;

                        units[c++] = *u;
                }

                assert(c <= n_units);
        } else {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *path, *state;
                bool fallback = false;
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
                } else
                        r = sd_bus_message_append_strv(m, strv_skip(argv, 1));
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, 0, &error, &reply);
                if (r < 0 && sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
                        /* Fallback to legacy ListUnitFiles method */
                        log_debug_errno(r, "Unable to list unit files through ListUnitFilesByPatterns, falling back to ListUnitsFiles method.");

                        fallback = true;
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

                        units[c] = (UnitFileList) {
                                .path = (char*) path,
                                .state = unit_file_state_from_string(state),
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

        if (c == 0)
                return -ENOENT;

        return 0;
}
