/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "hashmap.h"
#include "install.h"
#include "json-util.h"
#include "manager.h"
#include "metrics.h"
#include "service.h"
#include "unit.h"
#include "unit-def.h"
#include "varlink-metrics.h"

static int iterate_over_units(sd_varlink *link, const MetricFamily *mf, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        int r;

        assert(link);
        assert(mf);

        HASHMAP_FOREACH(unit, manager->units) {
                r = metric_build_body_json_one(link, mf, unit->id, unit);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int metric_fill_unit_active_state(sd_json_variant **v, void *userdata) {
        Unit *unit = ASSERT_PTR(userdata);
        return metric_set_value_string(v, unit_active_state_to_string(unit_active_state(unit)));
}

static int metric_fill_unit_load_state(sd_json_variant **v, void *userdata) {
        Unit *unit = ASSERT_PTR(userdata);
        return metric_set_value_string(v, unit_load_state_to_string(unit->load_state));
}

static int iterate_over_services(sd_varlink *link, const MetricFamily *mf, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(mf);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_body_json_one(link, mf, unit->id, unit);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int metric_fill_service_nrestarts(sd_json_variant **v, void *userdata) {
        Unit *unit = ASSERT_PTR(userdata);
        return metric_set_value_unsigned(v, SERVICE(unit)->n_restarts);
}

static int units_by_type_total_build_json(sd_varlink *link, const MetricFamily *mf, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        for (UnitType type = 0; type < _UNIT_TYPE_MAX; type++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *value = NULL;
                uint64_t counter = 0;

                LIST_FOREACH(units_by_type, _u, manager->units_by_type[type])
                        counter++;

                r = sd_json_variant_new_unsigned(&value, counter);
                if (r < 0)
                        return r;

                r = metric_build_full_json_one(
                                link,
                                mf,
                                /* object= */ NULL,
                                value,
                                STRV_MAKE("type", unit_type_to_string(type)));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_by_state_total_build_json(sd_varlink *link, const MetricFamily *mf, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        UnitActiveState counters[_UNIT_ACTIVE_STATE_MAX] = {};
        Unit *unit;
        int r;

        assert(link);
        assert(mf);

        /* TODO need a rework probably with state counter */
        HASHMAP_FOREACH(unit, manager->units)
                counters[unit_active_state(unit)]++;

        for (UnitActiveState state = 0; state < _UNIT_ACTIVE_STATE_MAX; state++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *value = NULL;
                r = sd_json_variant_new_unsigned(&value, counters[state]);
                if (r < 0)
                        return r;

                r = metric_build_full_json_one(
                                link,
                                mf,
                                /* object= */ NULL,
                                value,
                                STRV_MAKE("state", unit_active_state_to_string(state)));
                if (r < 0)
                        return r;
        }

        return 0;
}

const MetricFamily metric_family_table[] = {
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "unit_active_state",
                .description = "Per unit metric: active state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .iterate_cb = iterate_over_units,
                .fill_metric_cb = metric_fill_unit_active_state,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "unit_load_state",
                .description = "Per unit metric: load state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .iterate_cb = iterate_over_units,
                .fill_metric_cb = metric_fill_unit_load_state,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "nrestarts",
                .description = "Per unit metric: number of restarts",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .iterate_cb = iterate_over_services,
                .fill_metric_cb = metric_fill_service_nrestarts,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "units_by_type_total",
                .description = "Total number of units of different types",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .iterate_cb = units_by_type_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "units_by_state_total",
                .description = "Total number of units of different state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .iterate_cb = units_by_state_total_build_json,
        },
        {}
};

int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
