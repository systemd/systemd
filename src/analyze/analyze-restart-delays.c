/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-restart-delays.h"
#include "analyze-verify-util.h"
#include "bus-error.h"
#include "bus-map-properties.h"
#include "bus-util.h"
#include "exit-status.h"
#include "format-table.h"
#include "json-util.h"
#include "manager.h"
#include "pager.h"
#include "ratelimit.h"
#include "service.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-name.h"

/* The table has a row for each step, and start_limit_hit() checks the start limit once for each step. With
 * RestartSteps= close to UINT_MAX, the table grows until memory runs out. */
#define RESTART_STEPS_MAX 10000U

typedef struct RestartSettings {
        char *id;
        char *load_state;
        char *restart;
        bool restart_forced;
        usec_t restart_usec;
        unsigned restart_steps;
        usec_t restart_max_delay_usec;
        usec_t start_limit_interval_usec;
        unsigned start_limit_burst;
} RestartSettings;

static void restart_settings_done(RestartSettings *rs) {
        assert(rs);

        rs->id = mfree(rs->id);
        rs->load_state = mfree(rs->load_state);
        rs->restart = mfree(rs->restart);
}

static usec_t restart_delay(const RestartSettings *rs, unsigned n) {
        assert(rs);

        return service_restart_usec_nth(rs->restart_usec, rs->restart_max_delay_usec, rs->restart_steps, n);
}

/* Returns the number of the restart after which every restart waits the same delay. */
static unsigned restart_growth(const RestartSettings *rs) {
        assert(rs);

        if (!service_restart_backoff_enabled(rs->restart_usec, rs->restart_max_delay_usec, rs->restart_steps))
                return 1;

        assert(rs->restart_steps <= RESTART_STEPS_MAX);
        return rs->restart_steps + 1;
}

/* Returns the number of the restart that the start limit rejects, or 0 if the start limit never rejects a
 * restart. The time of the rejected restart is relative to the first start of the unit. */
static uint64_t start_limit_hit(const RestartSettings *rs, usec_t *ret_usec) {
        assert(rs);
        assert(ret_usec);

        *ret_usec = USEC_INFINITY;

        RateLimit rl = {
                .interval = rs->start_limit_interval_usec,
                .burst = rs->start_limit_burst,
        };

        if (!ratelimit_configured(&rl))
                return 0;

        /* ratelimit_below_at() treats a window that begins at 0 as unset, so let's start the clock at 1. The
         * service manager checks the start limit for the first start of the unit too. */
        usec_t ts = 1;
        assert_se(ratelimit_below_at(&rl, ts));

        unsigned growth = restart_growth(rs);
        for (unsigned n = 1; n <= growth; n++) {
                ts = usec_add(ts, restart_delay(rs, n));
                if (!ratelimit_below_at(&rl, ts)) {
                        *ret_usec = ts - 1;
                        return n;
                }
        }

        /* Every further restart waits d, and no earlier restart waited longer than d. If
         * StartLimitIntervalSec= is at least StartLimitBurst= times d, the current window of the start limit
         * contains the restart that the start limit rejects. If StartLimitIntervalSec= is shorter, no
         * window contains more than StartLimitBurst= restarts that are d apart, and the start limit never
         * rejects a restart. */
        usec_t d = restart_delay(rs, growth + 1);
        usec_t end = ratelimit_end(&rl);
        uint64_t in_window = d == 0 || end == USEC_INFINITY ? UINT64_MAX : (end - ts) / d;
        uint64_t left = rl.burst - rl.num;
        if (in_window <= left)
                return 0;

        usec_t p;
        *ret_usec = MUL_SAFE(&p, left + 1, d) ? usec_add(ts, p) - 1 : USEC_INFINITY;
        return growth + left + 1;
}

static int show_never_restarted(const RestartSettings *rs, const char *setting) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(rs);
        assert(setting);

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                printf("%s has %s, so the service manager never restarts it.\n", rs->id, setting);
                return 0;
        }

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("unit", rs->id),
                        SD_JSON_BUILD_PAIR("restarts", SD_JSON_BUILD_EMPTY_ARRAY));
        if (r < 0)
                return log_oom();

        return sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
}

static int show_restart_delays(const RestartSettings *rs, bool *printed) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *jrestarts = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        const char *never_restarted = NULL;
        usec_t total = 0, hit_usec;
        uint64_t hit;
        int r;

        assert(rs);
        assert(printed);

        /* The service manager never arms the restart timer for an infinite delay. */
        if (rs->restart_usec == USEC_INFINITY)
                never_restarted = "RestartSec=infinity";
        else if (streq_ptr(rs->restart, "no") && !rs->restart_forced)
                never_restarted = "Restart=no";

        if (!never_restarted && rs->restart_steps > RESTART_STEPS_MAX &&
            service_restart_backoff_enabled(rs->restart_usec, rs->restart_max_delay_usec, rs->restart_steps))
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                       "%s has RestartSteps=%u, refusing to show more than %u steps.",
                                       rs->id, rs->restart_steps, RESTART_STEPS_MAX);

        if (*printed && !sd_json_format_enabled(arg_json_format_flags))
                putchar('\n');
        *printed = true;

        if (never_restarted)
                return show_never_restarted(rs, never_restarted);

        table = table_new("restart", "delay", "total");
        if (!table)
                return log_oom();

        (void) table_set_align_percent(table, TABLE_HEADER_CELL(0), 100);
        (void) table_set_align_percent(table, TABLE_HEADER_CELL(1), 100);
        (void) table_set_align_percent(table, TABLE_HEADER_CELL(2), 100);

        unsigned growth = restart_growth(rs);
        usec_t further = restart_delay(rs, growth + 1);
        hit = start_limit_hit(rs, &hit_usec);

        for (unsigned n = 1; n <= growth && (hit == 0 || n <= hit); n++) {
                usec_t d = restart_delay(rs, n);

                total = usec_add(total, d);

                r = table_add_many(
                                table,
                                TABLE_UINT, n,
                                TABLE_TIMESPAN_MSEC, d,
                                TABLE_TIMESPAN_MSEC, total);
                if (r < 0)
                        return table_log_add_error(r);

                r = sd_json_variant_append_arraybo(
                                &jrestarts,
                                SD_JSON_BUILD_PAIR_UNSIGNED("restart", n),
                                SD_JSON_BUILD_PAIR_UNSIGNED("delayUSec", d),
                                SD_JSON_BUILD_PAIR_UNSIGNED("totalUSec", total));
                if (r < 0)
                        return log_oom();
        }

        if (sd_json_format_enabled(arg_json_format_flags)) {
                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("unit", rs->id),
                                SD_JSON_BUILD_PAIR_VARIANT("restarts", jrestarts),
                                SD_JSON_BUILD_PAIR_UNSIGNED("furtherDelayUSec", further),
                                JSON_BUILD_PAIR_CONDITION_UNSIGNED(hit > 0, "startLimitHitRestart", hit),
                                JSON_BUILD_PAIR_CONDITION_UNSIGNED(hit > 0, "startLimitHitUSec", hit_usec));
                if (r < 0)
                        return log_oom();

                return sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
        }

        r = table_print_with_pager(table, SD_JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
        if (r < 0)
                return r;

        if (hit > growth)
                printf("\nEvery further restart waits %s.", FORMAT_TIMESPAN(further, USEC_PER_MSEC));

        if (hit > 0)
                printf("%sThe start limit rejects restart %" PRIu64 ", %s after the first start, and %s enters "
                       "the failed state.\n",
                       hit > growth ? " " : "\n",
                       hit,
                       FORMAT_TIMESPAN(hit_usec, USEC_PER_MSEC),
                       rs->id);
        else
                printf("\nEvery further restart waits %s. The start limit never rejects a restart, so the service "
                       "manager restarts %s indefinitely.\n",
                       FORMAT_TIMESPAN(further, USEC_PER_MSEC),
                       rs->id);

        return 0;
}

static int map_restart_force_exit_status(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        bool *forced = ASSERT_PTR(userdata);
        const void *status, *signal;
        size_t n_status, n_signal;
        int r;

        assert(m);

        r = sd_bus_message_enter_container(m, 'r', "aiai");
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(m, 'i', &status, &n_status);
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(m, 'i', &signal, &n_signal);
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        *forced = n_status > 0 || n_signal > 0;
        return 0;
}

static int restart_delays_online(sd_bus *bus, const char *arg, bool *printed) {
        static const struct bus_properties_map map[] = {
                { "Id",                     "s",      NULL,                          offsetof(RestartSettings, id)                        },
                { "LoadState",              "s",      NULL,                          offsetof(RestartSettings, load_state)                },
                { "Restart",                "s",      NULL,                          offsetof(RestartSettings, restart)                   },
                { "RestartForceExitStatus", "(aiai)", map_restart_force_exit_status, offsetof(RestartSettings, restart_forced)            },
                { "RestartUSec",            "t",      NULL,                          offsetof(RestartSettings, restart_usec)              },
                { "RestartSteps",           "u",      NULL,                          offsetof(RestartSettings, restart_steps)             },
                { "RestartMaxDelayUSec",    "t",      NULL,                          offsetof(RestartSettings, restart_max_delay_usec)    },
                { "StartLimitIntervalUSec", "t",      NULL,                          offsetof(RestartSettings, start_limit_interval_usec) },
                { "StartLimitBurst",        "u",      NULL,                          offsetof(RestartSettings, start_limit_burst)         },
                {},
        };
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(restart_settings_done) RestartSettings rs = {};
        _cleanup_free_ char *unit = NULL, *path = NULL;
        int r;

        assert(bus);
        assert(arg);
        assert(printed);

        r = unit_name_mangle_with_suffix(arg, NULL, UNIT_NAME_MANGLE_WARN, ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle name '%s': %m", arg);

        if (!endswith(unit, ".service"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unit %s is not a service unit.", unit);

        if (unit_name_is_valid(unit, UNIT_NAME_TEMPLATE)) {
                _cleanup_free_ char *instance = NULL;

                r = unit_name_replace_instance(unit, arg_instance, &instance);
                if (r < 0)
                        return log_error_errno(r, "Failed to instantiate unit '%s': %m", unit);

                free_and_replace(unit, instance);
        }

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        map,
                        BUS_MAP_STRDUP,
                        &error,
                        NULL,
                        &rs);
        if (r < 0)
                return log_error_errno(r, "Failed to get properties of %s: %s", unit, bus_error_message(&error, r));

        if (streq_ptr(rs.load_state, "not-found"))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Unit %s not found.", unit);
        if (streq_ptr(rs.load_state, "masked"))
                return log_error_errno(SYNTHETIC_ERRNO(ERFKILL), "Unit %s is masked.", unit);
        if (!streq_ptr(rs.load_state, "loaded"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unit %s is not loaded properly.", unit);

        return show_restart_delays(&rs, printed);
}

static int restart_delays_offline(char **filenames) {
        _cleanup_(manager_freep) Manager *m = NULL;
        bool printed = false;
        int r, ret = 0;

        r = verify_set_unit_path(filenames);
        if (r < 0)
                return log_error_errno(r, "Failed to set unit load path: %m");

        r = manager_new(arg_runtime_scope,
                        MANAGER_TEST_RUN_MINIMAL |
                        MANAGER_TEST_RUN_ENV_GENERATORS |
                        MANAGER_TEST_RUN_IGNORE_DEPENDENCIES |
                        MANAGER_TEST_DONT_OPEN_EXECUTOR |
                        arg_generators * MANAGER_TEST_RUN_GENERATORS,
                        &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        r = manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, /* named_listen_fds= */ NULL, arg_root);
        if (r < 0)
                return r;

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *prepared = NULL;
                Unit *u;

                r = verify_prepare_filename(*filename, &prepared);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to prepare filename %s: %m", *filename));
                        continue;
                }

                r = manager_load_startable_unit_or_warn(m, /* name= */ NULL, prepared, LOG_ERR, &u);
                if (r < 0) {
                        RET_GATHER(ret, r);
                        continue;
                }

                Service *s = SERVICE(u);
                if (!s) {
                        RET_GATHER(ret, log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unit %s is not a service unit.", u->id));
                        continue;
                }

                _cleanup_(restart_settings_done) RestartSettings rs = {
                        .id = strdup(u->id),
                        .restart = strdup(service_restart_to_string(s->restart)),
                        .restart_forced = !exit_status_set_is_empty(&s->restart_force_status),
                        .restart_usec = s->restart_usec,
                        .restart_steps = s->restart_steps,
                        .restart_max_delay_usec = s->restart_max_delay_usec,
                        .start_limit_interval_usec = u->start_ratelimit.interval,
                        .start_limit_burst = u->start_ratelimit.burst,
                };
                if (!rs.id || !rs.restart)
                        return log_oom();

                RET_GATHER(ret, show_restart_delays(&rs, &printed));
        }

        return ret;
}

int verb_restart_delays(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        char **units = strv_skip(argv, 1);
        bool printed = false;
        int r, ret = 0;

        if (!arg_offline) {
                r = acquire_bus(&bus, NULL);
                if (r < 0)
                        return bus_log_connect_error(r, arg_transport, arg_runtime_scope);
        }

        pager_open(arg_pager_flags);

        if (arg_offline)
                return restart_delays_offline(units);

        STRV_FOREACH(unit, units)
                RET_GATHER(ret, restart_delays_online(bus, *unit, &printed));

        return ret;
}
