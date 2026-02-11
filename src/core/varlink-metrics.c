/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "manager.h"
#include "metrics.h"
#include "service.h"
#include "unit-def.h"
#include "unit.h"
#include "varlink-metrics.h"

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
        UnitActiveState counters[_UNIT_ACTIVE_STATE_MAX] = {};
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

const MetricFamily metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
         .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "nRestarts",
         .description = "Per unit metric: number of restarts",
         .type = METRIC_FAMILY_TYPE_COUNTER,
         .generate = nrestarts_build_json,
        },
        {
         .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "unitActiveState",
         .description = "Per unit metric: active state",
         .type = METRIC_FAMILY_TYPE_STRING,
         .generate = unit_active_state_build_json,
        },
        {
         .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "unitLoadState",
         .description = "Per unit metric: load state",
         .type = METRIC_FAMILY_TYPE_STRING,
         .generate = unit_load_state_build_json,
        },
        {
         .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "unitsByStateTotal",
         .description = "Total number of units of different state",
         .type = METRIC_FAMILY_TYPE_GAUGE,
         .generate = units_by_state_total_build_json,
        },
        {
         .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "unitsByTypeTotal",
         .description = "Total number of units of different types",
         .type = METRIC_FAMILY_TYPE_GAUGE,
         .generate = units_by_type_total_build_json,
        },
        {}
};

int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
