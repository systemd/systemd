/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-login.h"

#include "bus-error.h"
#include "format-table.h"
#include "locale-util.h"
#include "set.h"
#include "sort-util.h"
#include "systemctl-list-units.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"

static void message_set_freep(Set **set) {
        set_free_with_destructor(*set, sd_bus_message_unref);
}

static int get_unit_list_recursive(
                sd_bus *bus,
                char **patterns,
                UnitInfo **ret_unit_infos,
                Set **ret_replies,
                char ***ret_machines) {

        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(message_set_freep) Set *replies;
        sd_bus_message *reply;
        int c, r;

        assert(bus);
        assert(ret_replies);
        assert(ret_unit_infos);
        assert(ret_machines);

        replies = set_new(NULL);
        if (!replies)
                return log_oom();

        c = get_unit_list(bus, NULL, patterns, &unit_infos, 0, &reply);
        if (c < 0)
                return c;

        r = set_put(replies, reply);
        if (r < 0) {
                sd_bus_message_unref(reply);
                return log_oom();
        }

        if (arg_recursive) {
                _cleanup_strv_free_ char **machines = NULL;
                char **i;

                r = sd_get_machine_names(&machines);
                if (r < 0)
                        return log_error_errno(r, "Failed to get machine names: %m");

                STRV_FOREACH(i, machines) {
                        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *container = NULL;
                        int k;

                        r = sd_bus_open_system_machine(&container, *i);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to connect to container %s, ignoring: %m", *i);
                                continue;
                        }

                        k = get_unit_list(container, *i, patterns, &unit_infos, c, &reply);
                        if (k < 0)
                                return k;

                        c = k;

                        r = set_put(replies, reply);
                        if (r < 0) {
                                sd_bus_message_unref(reply);
                                return log_oom();
                        }
                }

                *ret_machines = TAKE_PTR(machines);
        } else
                *ret_machines = NULL;

        *ret_unit_infos = TAKE_PTR(unit_infos);
        *ret_replies = TAKE_PTR(replies);

        return c;
}

static int output_units_list(const UnitInfo *unit_infos, unsigned c) {
        _cleanup_(table_unrefp) Table *table = NULL;
        unsigned job_count = 0;
        int r;

        table = table_new("", "unit", "load", "active", "sub", "job", "description");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_plain) {
                /* Hide the 'glyph' column when --plain is requested */
                r = table_hide_column_from_display(table, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to hide column: %m");
        }
        if (arg_full)
                table_set_width(table, 0);

        (void) table_set_empty_string(table, "-");

        for (const UnitInfo *u = unit_infos; unit_infos && (size_t) (u - unit_infos) < c; u++) {
                _cleanup_free_ char *j = NULL;
                const char *on_underline = "", *on_loaded = "", *on_active = "";
                const char *on_circle = "", *id;
                bool circle = false, underline = false;

                if (u + 1 < unit_infos + c &&
                    !streq(unit_type_suffix(u->id), unit_type_suffix((u + 1)->id))) {
                        on_underline = ansi_underline();
                        underline = true;
                }

                if (STR_IN_SET(u->load_state, "error", "not-found", "bad-setting", "masked") && !arg_plain) {
                        on_circle = underline ? ansi_highlight_yellow_underline() : ansi_highlight_yellow();
                        circle = true;
                        on_loaded = underline ? ansi_highlight_red_underline() : ansi_highlight_red();
                } else if (streq(u->active_state, "failed") && !arg_plain) {
                        on_circle = underline ? ansi_highlight_red_underline() : ansi_highlight_red();
                        circle = true;
                        on_active = underline ? ansi_highlight_red_underline() : ansi_highlight_red();
                } else {
                        on_circle = on_underline;
                        on_active = on_underline;
                        on_loaded = on_underline;
                }

                if (u->machine) {
                        j = strjoin(u->machine, ":", u->id);
                        if (!j)
                                return log_oom();

                        id = j;
                } else
                        id = u->id;

                r = table_add_many(table,
                                   TABLE_STRING, circle ? special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE) : " ",
                                   TABLE_SET_BOTH_COLORS, on_circle,
                                   TABLE_STRING, id,
                                   TABLE_SET_BOTH_COLORS, on_active,
                                   TABLE_STRING, u->load_state,
                                   TABLE_SET_BOTH_COLORS, on_loaded,
                                   TABLE_STRING, u->active_state,
                                   TABLE_SET_BOTH_COLORS, on_active,
                                   TABLE_STRING, u->sub_state,
                                   TABLE_SET_BOTH_COLORS, on_active,
                                   TABLE_STRING, u->job_id ? u->job_type: "",
                                   TABLE_SET_BOTH_COLORS, on_underline,
                                   TABLE_STRING, u->description,
                                   TABLE_SET_BOTH_COLORS, on_underline);
                if (r < 0)
                        return table_log_add_error(r);

                if (u->job_id != 0)
                        job_count++;
        }

        if (job_count == 0) {
                /* There's no data in the JOB column, so let's hide it */
                r = table_hide_column_from_display(table, 5);
                if (r < 0)
                        return log_error_errno(r, "Failed to hide column: %m");
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0) {
                const char *on, *off;
                size_t records = table_get_rows(table) - 1;

                if (records > 0) {
                        puts("\n"
                             "LOAD   = Reflects whether the unit definition was properly loaded.\n"
                             "ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n"
                             "SUB    = The low-level unit activation state, values depend on unit type.");
                        if (job_count > 0)
                                puts("JOB    = Pending job for the unit.\n");
                        on = ansi_highlight();
                        off = ansi_normal();
                } else {
                        on = ansi_highlight_red();
                        off = ansi_normal();
                }

                if (arg_all || strv_contains(arg_states, "inactive"))
                        printf("%s%zu loaded units listed.%s\n"
                               "To show all installed unit files use 'systemctl list-unit-files'.\n",
                               on, records, off);
                else if (!arg_states)
                        printf("%s%zu loaded units listed.%s Pass --all to see loaded but inactive units, too.\n"
                               "To show all installed unit files use 'systemctl list-unit-files'.\n",
                               on, records, off);
                else
                        printf("%zu loaded units listed.\n", records);
        }

        return 0;
}

int list_units(int argc, char *argv[], void *userdata) {
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_strv_free_ char **machines = NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        (void) pager_open(arg_pager_flags);

        if (arg_with_dependencies) {
                _cleanup_strv_free_ char **names = NULL;

                r = append_unit_dependencies(bus, strv_skip(argv, 1), &names);
                if (r < 0)
                        return r;

                r = get_unit_list_recursive(bus, names, &unit_infos, &replies, &machines);
                if (r < 0)
                        return r;
        } else {
                r = get_unit_list_recursive(bus, strv_skip(argv, 1), &unit_infos, &replies, &machines);
                if (r < 0)
                        return r;
        }

        typesafe_qsort(unit_infos, r, unit_info_compare);
        return output_units_list(unit_infos, r);
}

static int get_triggered_units(
                sd_bus *bus,
                const char* path,
                char*** ret) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(path);
        assert(ret);

        r = sd_bus_get_property_strv(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "Triggers",
                        &error,
                        ret);
        if (r < 0)
                return log_error_errno(r, "Failed to determine triggers: %s", bus_error_message(&error, r));

        return 0;
}

static int get_listening(
                sd_bus *bus,
                const char* unit_path,
                char*** listening) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *type, *path;
        int r, n = 0;

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        unit_path,
                        "org.freedesktop.systemd1.Socket",
                        "Listen",
                        &error,
                        &reply,
                        "a(ss)");
        if (r < 0)
                return log_error_errno(r, "Failed to get list of listening sockets: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ss)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ss)", &type, &path)) > 0) {

                r = strv_extend(listening, type);
                if (r < 0)
                        return log_oom();

                r = strv_extend(listening, path);
                if (r < 0)
                        return log_oom();

                n++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return n;
}

struct socket_info {
        const char *machine;
        const char* id;

        char* type;
        char* path;

        /* Note: triggered is a list here, although it almost certainly will always be one
         * unit. Nevertheless, dbus API allows for multiple values, so let's follow that. */
        char** triggered;

        /* The strv above is shared. free is set only in the first one. */
        bool own_triggered;
};

static int socket_info_compare(const struct socket_info *a, const struct socket_info *b) {
        int r;

        assert(a);
        assert(b);

        r = strcasecmp_ptr(a->machine, b->machine);
        if (r != 0)
                return r;

        r = strcmp(a->path, b->path);
        if (r != 0)
                return r;

        return strcmp(a->type, b->type);
}

static int output_sockets_list(struct socket_info *socket_infos, unsigned cs) {
        _cleanup_(table_unrefp) Table *table = NULL;
        const char *on, *off;
        int r;

        table = table_new("listen", "type", "unit", "activates");
        if (!table)
                return log_oom();

        if (!arg_show_types) {
                /* Hide the second (TYPE) column */
                r = table_set_display(table, (size_t) 0, (size_t) 2, (size_t) 3);
                if (r < 0)
                        return log_error_errno(r, "Failed to set columns to display: %m");
        }

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        (void) table_set_empty_string(table, "-");

        if (cs) {
                for (struct socket_info *s = socket_infos; s < socket_infos + cs; s++) {
                        _cleanup_free_ char *j = NULL;
                        const char *path;

                        if (s->machine) {
                                j = strjoin(s->machine, ":", s->path);
                                if (!j)
                                        return log_oom();
                                path = j;
                        } else
                                path = s->path;

                        r = table_add_many(table,
                                           TABLE_STRING, path,
                                           TABLE_STRING, s->type,
                                           TABLE_STRING, s->id);
                        if (r < 0)
                                return table_log_add_error(r);

                        if (strv_isempty(s->triggered))
                                r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                        else if (strv_length(s->triggered) == 1)
                                r = table_add_cell(table, NULL, TABLE_STRING, s->triggered[0]);
                        else
                                /* This should never happen, currently our socket units can only trigger a
                                 * single unit. But let's handle this anyway, who knows what the future
                                 * brings? */
                                r = table_add_cell(table, NULL, TABLE_STRV, s->triggered);
                        if (r < 0)
                                return table_log_add_error(r);

                }

                on = ansi_highlight();
                off = ansi_normal();
        } else {
                on = ansi_highlight_red();
                off = ansi_normal();
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0) {
                printf("\n%s%u sockets listed.%s\n", on, cs, off);
                if (!arg_all)
                        printf("Pass --all to see loaded but inactive sockets, too.\n");
        }

        return 0;
}

int list_sockets(int argc, char *argv[], void *userdata) {
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_strv_free_ char **machines = NULL;
        _cleanup_strv_free_ char **sockets_with_suffix = NULL;
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_free_ struct socket_info *socket_infos = NULL;
        unsigned cs = 0;
        size_t size = 0;
        int r, n;
        sd_bus *bus;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        (void) pager_open(arg_pager_flags);

        r = expand_unit_names(bus, strv_skip(argv, 1), ".socket", &sockets_with_suffix, NULL);
        if (r < 0)
                return r;

        if (argc == 1 || sockets_with_suffix) {
                n = get_unit_list_recursive(bus, sockets_with_suffix, &unit_infos, &replies, &machines);
                if (n < 0)
                        return n;

                for (const UnitInfo *u = unit_infos; u < unit_infos + n; u++) {
                        _cleanup_strv_free_ char **listening = NULL, **triggered = NULL;
                        int c;

                        if (!endswith(u->id, ".socket"))
                                continue;

                        r = get_triggered_units(bus, u->unit_path, &triggered);
                        if (r < 0)
                                goto cleanup;

                        c = get_listening(bus, u->unit_path, &listening);
                        if (c < 0) {
                                r = c;
                                goto cleanup;
                        }

                        if (!GREEDY_REALLOC(socket_infos, size, cs + c)) {
                                r = log_oom();
                                goto cleanup;
                        }

                        for (int i = 0; i < c; i++)
                                socket_infos[cs + i] = (struct socket_info) {
                                        .machine = u->machine,
                                        .id = u->id,
                                        .type = listening[i*2],
                                        .path = listening[i*2 + 1],
                                        .triggered = triggered,
                                        .own_triggered = i==0,
                                };

                        /* from this point on we will cleanup those socket_infos */
                        cs += c;
                        free(listening);
                        listening = triggered = NULL; /* avoid cleanup */
                }

                typesafe_qsort(socket_infos, cs, socket_info_compare);
        }

        output_sockets_list(socket_infos, cs);

 cleanup:
        assert(cs == 0 || socket_infos);
        for (struct socket_info *s = socket_infos; s < socket_infos + cs; s++) {
                free(s->type);
                free(s->path);
                if (s->own_triggered)
                        strv_free(s->triggered);
        }

        return r;
}

static int get_next_elapse(
                sd_bus *bus,
                const char *path,
                dual_timestamp *next) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        dual_timestamp t;
        int r;

        assert(bus);
        assert(path);
        assert(next);

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Timer",
                        "NextElapseUSecMonotonic",
                        &error,
                        't',
                        &t.monotonic);
        if (r < 0)
                return log_error_errno(r, "Failed to get next elapse time: %s", bus_error_message(&error, r));

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Timer",
                        "NextElapseUSecRealtime",
                        &error,
                        't',
                        &t.realtime);
        if (r < 0)
                return log_error_errno(r, "Failed to get next elapse time: %s", bus_error_message(&error, r));

        *next = t;
        return 0;
}

static int get_last_trigger(
                sd_bus *bus,
                const char *path,
                usec_t *last) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(path);
        assert(last);

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Timer",
                        "LastTriggerUSec",
                        &error,
                        't',
                        last);
        if (r < 0)
                return log_error_errno(r, "Failed to get last trigger time: %s", bus_error_message(&error, r));

        return 0;
}

struct timer_info {
        const char* machine;
        const char* id;
        usec_t next_elapse;
        usec_t last_trigger;
        char** triggered;
};

static int timer_info_compare(const struct timer_info *a, const struct timer_info *b) {
        int r;

        assert(a);
        assert(b);

        r = strcasecmp_ptr(a->machine, b->machine);
        if (r != 0)
                return r;

        r = CMP(a->next_elapse, b->next_elapse);
        if (r != 0)
                return r;

        return strcmp(a->id, b->id);
}

static int output_timers_list(struct timer_info *timer_infos, unsigned n) {
        _cleanup_(table_unrefp) Table *table = NULL;
        const char *on, *off;
        int r;

        assert(timer_infos || n == 0);

        table = table_new("next", "left", "last", "passed", "unit", "activates");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        (void) table_set_empty_string(table, "-");

        for (struct timer_info *t = timer_infos; t < timer_infos + n; t++) {
                _cleanup_free_ char *j = NULL, *activates = NULL;
                const char *unit;

                if (t->machine) {
                        j = strjoin(t->machine, ":", t->id);
                        if (!j)
                                return log_oom();
                        unit = j;
                } else
                        unit = t->id;

                activates = strv_join(t->triggered, ", ");
                if (!activates)
                        return log_oom();

                r = table_add_many(table,
                                   TABLE_TIMESTAMP, t->next_elapse,
                                   TABLE_TIMESTAMP_RELATIVE, t->next_elapse,
                                   TABLE_TIMESTAMP, t->last_trigger,
                                   TABLE_TIMESTAMP_RELATIVE, t->last_trigger,
                                   TABLE_STRING, unit,
                                   TABLE_STRING, activates);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (n > 0) {
                on = ansi_highlight();
                off = ansi_normal();
        } else {
                on = ansi_highlight_red();
                off = ansi_normal();
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0) {
                printf("\n%s%u timers listed.%s\n", on, n, off);
                if (!arg_all)
                        printf("Pass --all to see loaded but inactive timers, too.\n");
        }

        return 0;
}

usec_t calc_next_elapse(dual_timestamp *nw, dual_timestamp *next) {
        usec_t next_elapse;

        assert(nw);
        assert(next);

        if (timestamp_is_set(next->monotonic)) {
                usec_t converted;

                if (next->monotonic > nw->monotonic)
                        converted = nw->realtime + (next->monotonic - nw->monotonic);
                else
                        converted = nw->realtime - (nw->monotonic - next->monotonic);

                if (timestamp_is_set(next->realtime))
                        next_elapse = MIN(converted, next->realtime);
                else
                        next_elapse = converted;

        } else
                next_elapse = next->realtime;

        return next_elapse;
}

int list_timers(int argc, char *argv[], void *userdata) {
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_strv_free_ char **machines = NULL;
        _cleanup_strv_free_ char **timers_with_suffix = NULL;
        _cleanup_free_ struct timer_info *timer_infos = NULL;
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        size_t size = 0;
        int n, c = 0;
        dual_timestamp nw;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        (void) pager_open(arg_pager_flags);

        r = expand_unit_names(bus, strv_skip(argv, 1), ".timer", &timers_with_suffix, NULL);
        if (r < 0)
                return r;

        if (argc == 1 || timers_with_suffix) {
                n = get_unit_list_recursive(bus, timers_with_suffix, &unit_infos, &replies, &machines);
                if (n < 0)
                        return n;

                dual_timestamp_get(&nw);

                for (const UnitInfo *u = unit_infos; u < unit_infos + n; u++) {
                        _cleanup_strv_free_ char **triggered = NULL;
                        dual_timestamp next = DUAL_TIMESTAMP_NULL;
                        usec_t m, last = 0;

                        if (!endswith(u->id, ".timer"))
                                continue;

                        r = get_triggered_units(bus, u->unit_path, &triggered);
                        if (r < 0)
                                goto cleanup;

                        r = get_next_elapse(bus, u->unit_path, &next);
                        if (r < 0)
                                goto cleanup;

                        get_last_trigger(bus, u->unit_path, &last);

                        if (!GREEDY_REALLOC(timer_infos, size, c+1)) {
                                r = log_oom();
                                goto cleanup;
                        }

                        m = calc_next_elapse(&nw, &next);

                        timer_infos[c++] = (struct timer_info) {
                                .machine = u->machine,
                                .id = u->id,
                                .next_elapse = m,
                                .last_trigger = last,
                                .triggered = TAKE_PTR(triggered),
                        };
                }

                typesafe_qsort(timer_infos, c, timer_info_compare);
        }

        output_timers_list(timer_infos, c);

 cleanup:
        for (struct timer_info *t = timer_infos; t < timer_infos + c; t++)
                strv_free(t->triggered);

        return r;
}
