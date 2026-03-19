/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "hashmap.h"
#include "manager.h"
#include "metrics.h"
#include "service.h"
#include "unit-def.h"
#include "unit.h"
#include "varlink-metrics.h"

static int active_timestamp_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *enter_fields = NULL;
        r = sd_json_buildo(&enter_fields, SD_JSON_BUILD_PAIR_STRING("event", "enter"));
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *exit_fields = NULL;
        r = sd_json_buildo(&exit_fields, SD_JSON_BUILD_PAIR_STRING("event", "exit"));
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->active_enter_timestamp.realtime,
                                enter_fields);
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->active_exit_timestamp.realtime,
                                exit_fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int inactive_exit_timestamp_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->inactive_exit_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int state_change_timestamp_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->state_change_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int status_errno_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                (uint64_t) SERVICE(unit)->status_errno,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int unit_active_state_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_string(
                                context,
                                unit->id,
                                unit_active_state_to_string(unit_active_state(unit)),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int unit_load_state_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_string(
                                context,
                                unit->id,
                                unit_load_state_to_string(unit->load_state),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int nrestarts_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                context, unit->id, SERVICE(unit)->n_restarts, /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_by_type_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        for (UnitType type = 0; type < _UNIT_TYPE_MAX; type++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                uint64_t counter = 0;

                LIST_FOREACH(units_by_type, _u, manager->units_by_type[type])
                        counter++;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", unit_type_to_string(type)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                /* object= */ NULL,
                                counter,
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_by_state_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t counters[_UNIT_ACTIVE_STATE_MAX] = {};
        Unit *unit;
        char *key;
        int r;

        assert(context);

        /* TODO need a rework probably with state counter */
        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                counters[unit_active_state(unit)]++;
        }

        for (UnitActiveState state = 0; state < _UNIT_ACTIVE_STATE_MAX; state++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("state", unit_active_state_to_string(state)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                /* object= */ NULL,
                                counters[state],
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int jobs_queued_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(context);

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        hashmap_size(manager->jobs),
                        /* fields= */ NULL);
}

static int system_state_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(context);

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        manager_state_to_string(manager_state(manager)),
                        /* fields= */ NULL);
}

static int units_by_load_state_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t counters[_UNIT_LOAD_STATE_MAX] = {};
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                counters[unit->load_state]++;
        }

        for (UnitLoadState state = 0; state < _UNIT_LOAD_STATE_MAX; state++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("load_state", unit_load_state_to_string(state)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                /* object= */ NULL,
                                counters[state],
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t count = 0;
        Unit *unit;
        char *key;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                count++;
        }

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        count,
                        /* fields= */ NULL);
}

static const MetricFamily metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ActiveTimestamp",
                .description = "Per unit metric: timestamp of active state transitions in microseconds; 0 indicates the transition has not occurred",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = active_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InactiveExitTimestamp",
                .description = "Per unit metric: timestamp when the unit last exited the inactive state in microseconds; 0 indicates the transition has not occurred",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = inactive_exit_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "JobsQueued",
                .description = "Number of jobs currently queued",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = jobs_queued_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "NRestarts",
                .description = "Per unit metric: number of restarts",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = nrestarts_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "StateChangeTimestamp",
                .description = "Per unit metric: timestamp of the last state change in microseconds; 0 indicates no state change has occurred",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = state_change_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "StatusErrno",
                .description = "Per service metric: errno status of the service",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = status_errno_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SystemState",
                .description = "Overall system state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = system_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitActiveState",
                .description = "Per unit metric: active state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = unit_active_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitLoadState",
                .description = "Per unit metric: load state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = unit_load_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByLoadStateTotal",
                .description = "Total number of units by load state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_by_load_state_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByStateTotal",
                .description = "Total number of units of different state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_by_state_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByTypeTotal",
                .description = "Total number of units of different types",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_by_type_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsTotal",
                .description = "Total number of units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_total_build_json,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
