/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-login.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "format-table.h"
#include "locale-util.h"
#include "path-util.h"
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
                Set **ret_replies) {

        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int c, r;

        assert(bus);
        assert(ret_replies);
        assert(ret_unit_infos);

        replies = set_new(NULL);
        if (!replies)
                return log_oom();

        c = get_unit_list(bus, NULL, patterns, &unit_infos, 0, &reply);
        if (c < 0)
                return c;

        r = set_put(replies, reply);
        if (r < 0)
                return log_oom();
        TAKE_PTR(reply);

        if (arg_recursive) {
                _cleanup_strv_free_ char **machines = NULL;

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
                        if (r < 0)
                                return log_oom();
                        TAKE_PTR(reply);
                }
        }

        *ret_unit_infos = TAKE_PTR(unit_infos);
        *ret_replies = TAKE_PTR(replies);

        return c;
}

static void output_legend(const char *type, size_t n_items) {
        const char *on, *off;

        assert(type);

        on = n_items > 0 ? ansi_highlight() : ansi_highlight_red();
        off = ansi_normal();

        printf("\n%s%zu %ss listed.%s\n", on, n_items, type, off);
        if (!arg_all)
                printf("Pass --all to see loaded but inactive %ss, too.\n", type);
}

static int table_add_triggered(Table *table, char **triggered) {
        assert(table);

        if (strv_isempty(triggered))
                return table_add_cell(table, NULL, TABLE_EMPTY, NULL);
        else if (strv_length(triggered) == 1)
                return table_add_cell(table, NULL, TABLE_STRING, triggered[0]);
        else
                /* This should never happen, currently our socket units can only trigger a
                 * single unit. But let's handle this anyway, who knows what the future
                 * brings? */
                return table_add_cell(table, NULL, TABLE_STRV, triggered);
}

static char *format_unit_id(const char *unit, const char *machine) {
        assert(unit);

        return machine ? strjoin(machine, ":", unit) : strdup(unit);
}

static int output_units_list(const UnitInfo *unit_infos, size_t c) {
        _cleanup_(table_unrefp) Table *table = NULL;
        size_t job_count = 0;
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

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        for (const UnitInfo *u = unit_infos; unit_infos && (size_t) (u - unit_infos) < c; u++) {
                _cleanup_free_ char *id = NULL;
                const char *on_underline = "", *on_loaded = "", *on_active = "", *on_circle = "";
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

                id = format_unit_id(u->id, u->machine);
                if (!id)
                        return log_oom();

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
                }

                on = records > 0 ? ansi_highlight() : ansi_highlight_red();
                off = ansi_normal();

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

int verb_list_units(int argc, char *argv[], void *userdata) {
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(message_set_freep) Set *replies = NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        if (arg_with_dependencies) {
                _cleanup_strv_free_ char **names = NULL;

                r = append_unit_dependencies(bus, strv_skip(argv, 1), &names);
                if (r < 0)
                        return r;

                r = get_unit_list_recursive(bus, names, &unit_infos, &replies);
                if (r < 0)
                        return r;
        } else {
                r = get_unit_list_recursive(bus, strv_skip(argv, 1), &unit_infos, &replies);
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

struct socket_info {
        const char *machine;
        const char* id;

        char* type;
        char* path;

        /* Note: triggered is a list here, although it almost certainly will always be one
         * unit. Nevertheless, dbus API allows for multiple values, so let's follow that. */
        char** triggered;
};

struct socket_infos {
        struct socket_info *sockets;
        size_t n_sockets;
};

static void socket_infos_done(struct socket_infos *ss) {
        assert(ss);
        assert(ss->sockets || ss->n_sockets == 0);

        for (size_t i = 0; i < ss->n_sockets; i++) {
                struct socket_info *s = &ss->sockets[i];

                free(s->type);
                free(s->path);
                strv_free(s->triggered);
        }

        free(ss->sockets);
}

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

static int socket_info_add(
                sd_bus *bus,
                struct socket_infos *ss,
                const UnitInfo *u) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **triggered = NULL;
        const char *type, *path;
        int r;

        assert(bus);
        assert(ss);
        assert(u);

        if (!endswith(u->id, ".socket"))
                return 0;;

        r = get_triggered_units(bus, u->unit_path, &triggered);
        if (r < 0)
                return r;

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        u->unit_path,
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
                _cleanup_free_ char *type_dup = NULL, *path_dup = NULL;
                _cleanup_strv_free_ char **triggered_dup;

                type_dup = strdup(type);
                if (!type_dup)
                        return log_oom();

                path_dup = strdup(path);
                if (!path_dup)
                        return log_oom();

                triggered_dup = strv_copy(triggered);
                if (!triggered_dup)
                        return log_oom();

                if (!GREEDY_REALLOC(ss->sockets, ss->n_sockets + 1))
                        return log_oom();

                ss->sockets[ss->n_sockets++] = (struct socket_info) {
                        .machine = u->machine,
                        .id = u->id,
                        .type = TAKE_PTR(type_dup),
                        .path = TAKE_PTR(path_dup),
                        .triggered = TAKE_PTR(triggered_dup),
                };
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static int output_sockets_list(const struct socket_infos *ss) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(ss);
        assert(ss->sockets || ss->n_sockets == 0);

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

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        for (const struct socket_info *s = ss->sockets; s < ss->sockets + ss->n_sockets; s++) {
                _cleanup_free_ char *unit = NULL;

                unit = format_unit_id(s->id, s->machine);
                if (!unit)
                        return log_oom();

                r = table_add_many(table,
                                        TABLE_STRING, s->path,
                                        TABLE_STRING, s->type,
                                        TABLE_STRING, unit);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_triggered(table, s->triggered);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0)
                output_legend("socket", ss->n_sockets);

        return 0;
}

int verb_list_sockets(int argc, char *argv[], void *userdata) {
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_strv_free_ char **sockets_with_suffix = NULL;
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(socket_infos_done) struct socket_infos socket_infos = {};
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        r = expand_unit_names(bus, strv_skip(argv, 1), ".socket", &sockets_with_suffix, NULL);
        if (r < 0)
                return r;

        if (argc == 1 || sockets_with_suffix) {
                int n;

                n = get_unit_list_recursive(bus, sockets_with_suffix, &unit_infos, &replies);
                if (n < 0)
                        return n;

                for (const UnitInfo *u = unit_infos; u < unit_infos + n; u++) {
                        r = socket_info_add(bus, &socket_infos, u);
                        if (r < 0)
                                return r;
                }
        }

        typesafe_qsort(socket_infos.sockets, socket_infos.n_sockets, socket_info_compare);
        output_sockets_list(&socket_infos);

        return 0;
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

struct timer_infos {
        struct timer_info *timers;
        size_t n_timers;
};

static void timer_infos_done(struct timer_infos *ts) {
        assert(ts);
        assert(ts->timers || ts->n_timers == 0);

        for (size_t i = 0; i < ts->n_timers; i++)
                strv_free(ts->timers[i].triggered);

        free(ts->timers);
}

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

static int output_timers_list(const struct timer_infos *ts) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(ts);
        assert(ts->timers || ts->n_timers == 0);

        table = table_new("next", "left", "last", "passed", "unit", "activates");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        for (const struct timer_info *t = ts->timers; t < ts->timers + ts->n_timers; t++) {
                _cleanup_free_ char *unit = NULL;

                unit = format_unit_id(t->id, t->machine);
                if (!unit)
                        return log_oom();

                r = table_add_many(table,
                                   TABLE_TIMESTAMP, t->next_elapse,
                                   TABLE_TIMESTAMP_RELATIVE, t->next_elapse,
                                   TABLE_TIMESTAMP, t->last_trigger,
                                   TABLE_TIMESTAMP_RELATIVE, t->last_trigger,
                                   TABLE_STRING, unit);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_triggered(table, t->triggered);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0)
                output_legend("timer", ts->n_timers);

        return 0;
}

usec_t calc_next_elapse(const dual_timestamp *nw, const dual_timestamp *next) {
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

static int add_timer_info(
                sd_bus *bus,
                struct timer_infos *ts,
                const UnitInfo *u,
                const dual_timestamp *nw) {

        _cleanup_strv_free_ char **triggered = NULL;
        dual_timestamp next = DUAL_TIMESTAMP_NULL;
        usec_t m, last = 0;
        int r;

        assert(bus);
        assert(ts);
        assert(u);
        assert(nw);

        if (!endswith(u->id, ".timer"))
                return 0;

        r = get_triggered_units(bus, u->unit_path, &triggered);
        if (r < 0)
                return r;

        r = get_next_elapse(bus, u->unit_path, &next);
        if (r < 0)
                return r;

        r = get_last_trigger(bus, u->unit_path, &last);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(ts->timers, ts->n_timers + 1))
                return log_oom();

        m = calc_next_elapse(nw, &next);

        ts->timers[ts->n_timers++] = (struct timer_info) {
                .machine = u->machine,
                .id = u->id,
                .next_elapse = m,
                .last_trigger = last,
                .triggered = TAKE_PTR(triggered),
        };

        return 0;
}

int verb_list_timers(int argc, char *argv[], void *userdata) {
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_strv_free_ char **timers_with_suffix = NULL;
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(timer_infos_done) struct timer_infos timer_infos = {};
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        r = expand_unit_names(bus, strv_skip(argv, 1), ".timer", &timers_with_suffix, NULL);
        if (r < 0)
                return r;

        if (argc == 1 || timers_with_suffix) {
                dual_timestamp nw;
                int n;

                n = get_unit_list_recursive(bus, timers_with_suffix, &unit_infos, &replies);
                if (n < 0)
                        return n;

                dual_timestamp_get(&nw);

                for (const UnitInfo *u = unit_infos; u < unit_infos + n; u++) {
                        r = add_timer_info(bus, &timer_infos, u, &nw);
                        if (r < 0)
                                return r;
                }
        }

        typesafe_qsort(timer_infos.timers, timer_infos.n_timers, timer_info_compare);
        output_timers_list(&timer_infos);

        return 0;
}

struct automount_info {
        const char *machine;
        const char *id;
        char *what;
        char *where;
        usec_t timeout_idle_usec;
        bool mounted;
};

struct automount_infos {
        struct automount_info *infos;
        size_t n_infos;
};

static void automount_infos_done(struct automount_infos *as) {
        assert(as);
        assert(as->infos || as->n_infos == 0);

        for (size_t i = 0; i < as->n_infos; i++) {
                struct automount_info *a = &as->infos[i];

                free(a->what);
                free(a->where);
        }

        free(as->infos);
}

static int automount_info_compare(const struct automount_info *a, const struct automount_info *b) {
        int r;

        assert(a);
        assert(b);

        r = strcasecmp_ptr(a->machine, b->machine);
        if (r != 0)
                return r;

        return path_compare(a->where, b->where);
}

static int automount_info_add(
                sd_bus* bus,
                struct automount_infos *as,
                const UnitInfo *info) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *mount = NULL, *mount_path = NULL, *where = NULL, *what = NULL, *state = NULL;
        usec_t timeout_idle_usec;
        BusLocator locator;
        int r;

        assert(bus);
        assert(as);
        assert(info);

        if (!endswith(info->id, ".automount"))
                return 0;

        locator = (BusLocator) {
                .destination = "org.freedesktop.systemd1",
                .path = info->unit_path,
                .interface = "org.freedesktop.systemd1.Automount",
        };

        r = bus_get_property_string(bus, &locator, "Where", &error, &where);
        if (r < 0)
                return log_error_errno(r, "Failed to get automount target: %s", bus_error_message(&error, r));

        r = bus_get_property_trivial(bus, &locator, "TimeoutIdleUSec", &error, 't', &timeout_idle_usec);
        if (r < 0)
                return log_error_errno(r, "Failed to get idle timeout: %s", bus_error_message(&error, r));

        r = unit_name_from_path(where, ".mount", &mount);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name from path: %m");

        mount_path = unit_dbus_path_from_name(mount);
        if (!mount_path)
                return log_oom();

        locator.path = mount_path;
        locator.interface = "org.freedesktop.systemd1.Mount";

        r = bus_get_property_string(bus, &locator, "What", &error, &what);
        if (r < 0)
                return log_error_errno(r, "Failed to get mount source: %s", bus_error_message(&error, r));

        locator.interface = "org.freedesktop.systemd1.Unit";

        r = bus_get_property_string(bus, &locator, "ActiveState", &error, &state);
        if (r < 0)
                return log_error_errno(r, "Failed to get mount state: %s", bus_error_message(&error, r));

        if (!GREEDY_REALLOC(as->infos, as->n_infos + 1))
                return log_oom();

        as->infos[as->n_infos++] = (struct automount_info) {
                .machine = info->machine,
                .id = info->id,
                .what = TAKE_PTR(what),
                .where = TAKE_PTR(where),
                .timeout_idle_usec = timeout_idle_usec,
                .mounted = streq_ptr(state, "active"),
        };

        return 0;
}

static int output_automounts_list(const struct automount_infos *as) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(as);
        assert(as->infos || as->n_infos == 0);

        table = table_new("what", "where", "mounted", "idle timeout", "unit");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        for (struct automount_info *info = as->infos; info < as->infos + as->n_infos; info++) {
                _cleanup_free_ char *unit = NULL;

                unit = format_unit_id(info->id, info->machine);
                if (!unit)
                        return log_oom();

                r = table_add_many(table,
                                   TABLE_STRING, info->what,
                                   TABLE_STRING, info->where,
                                   TABLE_BOOLEAN, info->mounted,
                                   TABLE_TIMESPAN_MSEC, info->timeout_idle_usec,
                                   TABLE_STRING, unit);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0)
                output_legend("automount", as->n_infos);

        return 0;
}

int verb_list_automounts(int argc, char *argv[], void *userdata) {
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_strv_free_ char **automounts = NULL;
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(automount_infos_done) struct automount_infos as = {};
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        r = expand_unit_names(bus, strv_skip(argv, 1), ".automount", &automounts, NULL);
        if (r < 0)
                return r;

        if (argc == 1 || automounts) {
                int n;

                n = get_unit_list_recursive(bus, automounts, &unit_infos, &replies);
                if (n < 0)
                        return n;

                for (const UnitInfo *u = unit_infos; u < unit_infos + n; u++) {
                        r = automount_info_add(bus, &as, u);
                        if (r < 0)
                                return r;
                }

        }

        typesafe_qsort(as.infos, as.n_infos, automount_info_compare);
        output_automounts_list(&as);

        return 0;
}

struct path_info {
        const char *machine;
        const char *id;

        char *path;
        char *condition;

        /* Note: triggered is a list here, although it almost certainly will always be one
         * unit. Nevertheless, dbus API allows for multiple values, so let's follow that. */
        char** triggered;
};

struct path_infos {
        size_t count;
        struct path_info *items;
};

static int path_info_compare(const struct path_info *a, const struct path_info *b) {
        int r;

        assert(a);
        assert(b);

        r = strcasecmp_ptr(a->machine, b->machine);
        if (r != 0)
                return r;

        r = path_compare(a->path, b->path);
        if (r != 0)
                return r;

        r = strcmp(a->condition, b->condition);
        if (r != 0)
                return r;

        return strcasecmp_ptr(a->id, b->id);
}

static void path_infos_done(struct path_infos *ps) {
        assert(ps);
        assert(ps->items || ps->count == 0);

        for (struct path_info *p = ps->items; p < ps->items + ps->count; p++) {
                free(p->condition);
                free(p->path);
                strv_free(p->triggered);
        }

        free(ps->items);
}

static int get_paths(sd_bus *bus, const char *unit_path, char ***ret_conditions, char ***ret_paths) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **conditions = NULL, **paths = NULL;
        const char *condition, *path;
        int r, n = 0;

        assert(bus);
        assert(unit_path);
        assert(ret_conditions);
        assert(ret_paths);

        r = sd_bus_get_property(bus,
                                "org.freedesktop.systemd1",
                                unit_path,
                                "org.freedesktop.systemd1.Path",
                                "Paths",
                                &error,
                                &reply,
                                "a(ss)");
        if (r < 0)
                return log_error_errno(r, "Failed to get paths: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ss)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ss)", &condition, &path)) > 0) {
                if (strv_extend(&conditions, condition) < 0)
                        return log_oom();

                if (strv_extend(&paths, path) < 0)
                        return log_oom();

                n++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        *ret_conditions = TAKE_PTR(conditions);
        *ret_paths = TAKE_PTR(paths);

        return n;
}

static int output_paths_list(struct path_infos *ps) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(ps);
        assert(ps->items || ps->count == 0);

        table = table_new("path", "condition", "unit", "activates");
        if (!table)
                return log_oom();

        table_set_header(table, arg_legend != 0);
        if (arg_full)
                table_set_width(table, 0);

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        for (struct path_info *p = ps->items; p < ps->items + ps->count; p++) {
                _cleanup_free_ char *unit = NULL;

                unit = format_unit_id(p->id, p->machine);
                if (!unit)
                        return log_oom();

                r = table_add_many(table,
                                   TABLE_STRING, p->path,
                                   TABLE_STRING, p->condition,
                                   TABLE_STRING, unit);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_triggered(table, p->triggered);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = output_table(table);
        if (r < 0)
                return r;

        if (arg_legend != 0)
                output_legend("path", ps->count);

        return 0;
}

int verb_list_paths(int argc, char *argv[], void *userdata) {
        _cleanup_(message_set_freep) Set *replies = NULL;
        _cleanup_strv_free_ char **units = NULL;
        _cleanup_free_ UnitInfo *unit_infos = NULL;
        _cleanup_(path_infos_done) struct path_infos path_infos = {};
        int r, n;
        sd_bus *bus;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        r = expand_unit_names(bus, strv_skip(argv, 1), ".path", &units, NULL);
        if (r < 0)
                return r;

        if (argc == 1 || units) {
                n = get_unit_list_recursive(bus, units, &unit_infos, &replies);
                if (n < 0)
                        return n;

                for (const UnitInfo *u = unit_infos; u < unit_infos + n; u++) {
                        _cleanup_strv_free_ char **conditions = NULL, **paths = NULL, **triggered = NULL;
                        int c;

                        if (!endswith(u->id, ".path"))
                                continue;

                        r = get_triggered_units(bus, u->unit_path, &triggered);
                        if (r < 0)
                                return r;

                        c = get_paths(bus, u->unit_path, &conditions, &paths);
                        if (c < 0)
                                return c;

                        if (!GREEDY_REALLOC(path_infos.items, path_infos.count + c))
                                return log_oom();

                        for (int i = c - 1; i >= 0; i--) {
                                char **t;

                                t = strv_copy(triggered);
                                if (!t)
                                        return log_oom();

                                path_infos.items[path_infos.count++] = (struct path_info) {
                                        .machine = u->machine,
                                        .id = u->id,
                                        .condition = TAKE_PTR(conditions[i]),
                                        .path = TAKE_PTR(paths[i]),
                                        .triggered = t,
                                };
                        }
                }

                typesafe_qsort(path_infos.items, path_infos.count, path_info_compare);
        }

        output_paths_list(&path_infos);

        return 0;
}
