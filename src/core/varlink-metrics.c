/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "hashmap.h"
#include "manager.h"
#include "metrics.h"
#include "service.h"
#include "string-util.h"
#include "unit-def.h"
#include "unit.h"
#include "varlink-metrics.h"
#include "version.h"

typedef enum ManagerMetric {
        MANAGER_METRIC_ACTIVE_TIMESTAMP,
        MANAGER_METRIC_INACTIVE_EXIT_TIMESTAMP,
        MANAGER_METRIC_STATE_CHANGE_TIMESTAMP,
        MANAGER_METRIC_UNIT_ACTIVE_STATE,
        MANAGER_METRIC_UNIT_LOAD_STATE,
        MANAGER_METRIC_JOBS_QUEUED,
        MANAGER_METRIC_N_RESTARTS,
        MANAGER_METRIC_STATUS_ERRNO,
        MANAGER_METRIC_UNITS_BY_LOAD_STATE_TOTAL,
        MANAGER_METRIC_UNITS_BY_STATE_TOTAL,
        MANAGER_METRIC_UNITS_BY_TYPE_TOTAL,
        MANAGER_METRIC_UNITS_TOTAL,
        MANAGER_METRIC_RELOAD_COUNT,
        MANAGER_METRIC_SYSTEM_STATE,
        MANAGER_METRIC_VERSION,
        _MANAGER_METRIC_MAX,
        _MANAGER_METRIC_INVALID = -EINVAL,
} ManagerMetric;

static const MetricFamily metric_family_table[_MANAGER_METRIC_MAX + 1];

static int unit_metrics_build_json(
                sd_varlink *vl,
                Unit *unit,
                sd_json_variant *enter_fields,
                sd_json_variant *exit_fields) {

        int r;

        assert(vl);
        assert(unit);

        r = metric_build_send_unsigned(
                        metric_family_table + MANAGER_METRIC_ACTIVE_TIMESTAMP,
                        vl,
                        unit->id,
                        unit->active_enter_timestamp.realtime,
                        enter_fields);
        if (r < 0)
                return r;

        r = metric_build_send_unsigned(
                        metric_family_table + MANAGER_METRIC_ACTIVE_TIMESTAMP,
                        vl,
                        unit->id,
                        unit->active_exit_timestamp.realtime,
                        exit_fields);
        if (r < 0)
                return r;

        r = metric_build_send_unsigned(
                        metric_family_table + MANAGER_METRIC_INACTIVE_EXIT_TIMESTAMP,
                        vl,
                        unit->id,
                        unit->inactive_exit_timestamp.realtime,
                        /* fields= */ NULL);
        if (r < 0)
                return r;

        r = metric_build_send_unsigned(
                        metric_family_table + MANAGER_METRIC_STATE_CHANGE_TIMESTAMP,
                        vl,
                        unit->id,
                        unit->state_change_timestamp.realtime,
                        /* fields= */ NULL);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *sub_state_fields = NULL;
        r = sd_json_buildo(&sub_state_fields, SD_JSON_BUILD_PAIR_STRING("sub_state", unit_sub_state_to_string(unit)));
        if (r < 0)
                return r;

        r = metric_build_send_string(
                        metric_family_table + MANAGER_METRIC_UNIT_ACTIVE_STATE,
                        vl,
                        unit->id,
                        unit_active_state_to_string(unit_active_state(unit)),
                        sub_state_fields);
        if (r < 0)
                return r;

        return metric_build_send_string(
                        metric_family_table + MANAGER_METRIC_UNIT_LOAD_STATE,
                        vl,
                        unit->id,
                        unit_load_state_to_string(unit->load_state),
                        /* fields= */ NULL);
}

static int units_metrics_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(mf);
        assert(vl);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *enter_fields = NULL, *exit_fields = NULL;
        r = sd_json_buildo(&enter_fields, SD_JSON_BUILD_PAIR_STRING("event", "enter"));
        if (r < 0)
                return r;

        r = sd_json_buildo(&exit_fields, SD_JSON_BUILD_PAIR_STRING("event", "exit"));
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* Ignore aliases. */
                if (key != unit->id)
                        continue;

                r = unit_metrics_build_json(vl, unit, enter_fields, exit_fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int service_metrics_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(mf);
        assert(vl);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                Service *service = SERVICE(unit);

                r = metric_build_send_unsigned(
                                metric_family_table + MANAGER_METRIC_N_RESTARTS,
                                vl,
                                unit->id,
                                service->n_restarts,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                metric_family_table + MANAGER_METRIC_STATUS_ERRNO,
                                vl,
                                unit->id,
                                (uint64_t) service->status_errno,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_totals_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t by_type[_UNIT_TYPE_MAX] = {}, by_state[_UNIT_ACTIVE_STATE_MAX] = {},
                 by_load_state[_UNIT_LOAD_STATE_MAX] = {}, total = 0;
        Unit *unit;
        char *key;
        int r;

        assert(mf);
        assert(vl);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* Ignore aliases. */
                if (key != unit->id)
                        continue;

                by_type[unit->type]++;
                by_state[unit_active_state(unit)]++;
                by_load_state[unit->load_state]++;
                total++;
        }

        for (UnitLoadState state = 0; state < _UNIT_LOAD_STATE_MAX; state++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *load_state_fields = NULL;

                r = sd_json_buildo(&load_state_fields, SD_JSON_BUILD_PAIR_STRING("load_state", unit_load_state_to_string(state)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                metric_family_table + MANAGER_METRIC_UNITS_BY_LOAD_STATE_TOTAL,
                                vl,
                                /* object= */ NULL,
                                by_load_state[state],
                                load_state_fields);
                if (r < 0)
                        return r;
        }

        for (UnitActiveState state = 0; state < _UNIT_ACTIVE_STATE_MAX; state++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *active_state_fields = NULL;

                r = sd_json_buildo(&active_state_fields, SD_JSON_BUILD_PAIR_STRING("state", unit_active_state_to_string(state)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                metric_family_table + MANAGER_METRIC_UNITS_BY_STATE_TOTAL,
                                vl,
                                /* object= */ NULL,
                                by_state[state],
                                active_state_fields);
                if (r < 0)
                        return r;
        }

        for (UnitType type = 0; type < _UNIT_TYPE_MAX; type++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *type_fields = NULL;

                r = sd_json_buildo(&type_fields, SD_JSON_BUILD_PAIR_STRING("type", unit_type_to_string(type)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                metric_family_table + MANAGER_METRIC_UNITS_BY_TYPE_TOTAL,
                                vl,
                                /* object= */ NULL,
                                by_type[type],
                                type_fields);
                if (r < 0)
                        return r;
        }

        return metric_build_send_unsigned(
                        metric_family_table + MANAGER_METRIC_UNITS_TOTAL,
                        vl,
                        /* object= */ NULL,
                        total,
                        /* fields= */ NULL);
}

static int jobs_queued_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(mf && mf->name);
        assert(vl);

        return metric_build_send_unsigned(
                        mf,
                        vl,
                        /* object= */ NULL,
                        hashmap_size(manager->jobs),
                        /* fields= */ NULL);
}

static int reload_count_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(mf && mf->name);
        assert(vl);

        return metric_build_send_unsigned(
                        mf,
                        vl,
                        /* object= */ NULL,
                        manager->reload_count,
                        /* fields= */ NULL);
}

static int system_state_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(mf && mf->name);
        assert(vl);

        return metric_build_send_string(
                        mf,
                        vl,
                        /* object= */ NULL,
                        manager_state_to_string(manager_state(manager)),
                        /* fields= */ NULL);
}

static int version_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        assert(mf && mf->name);
        assert(vl);

        return metric_build_send_string(
                        mf,
                        vl,
                        /* object= */ NULL,
                        GIT_VERSION,
                        /* fields= */ NULL);
}

/* Single source of truth for all manager timestamp metrics, driving both List (the values) and Describe
 * (the schema advertised below). The .description is prefixed with "CLOCK_REALTIME "/"CLOCK_MONOTONIC " on
 * emission; firmware, loader and kernel have no meaningful monotonic value (a pre-kernel offset or zero),
 * hence they only expose the .Realtime metric (with_monotonic=false). */
static const struct {
        const char *name;
        bool with_monotonic;
        const char *description;
} manager_timestamp_metrics[_MANAGER_TIMESTAMP_MAX] = {
        [MANAGER_TIMESTAMP_FIRMWARE] = {
                .name = "FirmwareTimestamp",
                .with_monotonic = false,
                .description = "microseconds at which the firmware began execution (CLOCK_MONOTONIC is a pre-kernel offset, not reported)",
        },
        [MANAGER_TIMESTAMP_LOADER] = {
                .name = "LoaderTimestamp",
                .with_monotonic = false,
                .description = "microseconds at which the boot loader began execution (CLOCK_MONOTONIC is a pre-kernel offset, not reported)",
        },
        [MANAGER_TIMESTAMP_KERNEL] = {
                .name = "KernelTimestamp",
                .with_monotonic = false,
                .description = "microseconds at which the kernel started (CLOCK_MONOTONIC == 0)",
        },
        [MANAGER_TIMESTAMP_INITRD] = {
                .name = "InitRDTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the initrd began execution",
        },
        [MANAGER_TIMESTAMP_USERSPACE] = {
                .name = "UserspaceTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which userspace was reached",
        },
        [MANAGER_TIMESTAMP_FINISH] = {
                .name = "FinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which userspace finished booting",
        },
        [MANAGER_TIMESTAMP_SECURITY_START] = {
                .name = "SecurityStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager started uploading security policies to the kernel",
        },
        [MANAGER_TIMESTAMP_SECURITY_FINISH] = {
                .name = "SecurityFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager finished uploading security policies to the kernel",
        },
        [MANAGER_TIMESTAMP_GENERATORS_START] = {
                .name = "GeneratorsStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager started executing generators",
        },
        [MANAGER_TIMESTAMP_GENERATORS_FINISH] = {
                .name = "GeneratorsFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager finished executing generators",
        },
        [MANAGER_TIMESTAMP_UNITS_LOAD_START] = {
                .name = "UnitsLoadStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager first started loading units",
        },
        [MANAGER_TIMESTAMP_UNITS_LOAD_FINISH] = {
                .name = "UnitsLoadFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager first finished loading units",
        },
        [MANAGER_TIMESTAMP_UNITS_LOAD] = {
                .name = "UnitsLoadTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager last started loading units",
        },
        [MANAGER_TIMESTAMP_INITRD_SECURITY_START] = {
                .name = "InitRDSecurityStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager started uploading security policies to the kernel in the initrd",
        },
        [MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH] = {
                .name = "InitRDSecurityFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager finished uploading security policies to the kernel in the initrd",
        },
        [MANAGER_TIMESTAMP_INITRD_GENERATORS_START] = {
                .name = "InitRDGeneratorsStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager started executing generators in the initrd",
        },
        [MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH] = {
                .name = "InitRDGeneratorsFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager finished executing generators in the initrd",
        },
        [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START] = {
                .name = "InitRDUnitsLoadStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager first started loading units in the initrd",
        },
        [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH] = {
                .name = "InitRDUnitsLoadFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which the manager first finished loading units in the initrd",
        },
        [MANAGER_TIMESTAMP_SHUTDOWN_START] = {
                .name = "ShutdownStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which shutdown began, i.e. units started to be stopped",
        },
        [MANAGER_TIMESTAMP_SHUTDOWN_FINISH] = {
                .name = "ShutdownFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which all units finished stopping during shutdown",
        },
        [MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_START] = {
                .name = "PreviousShutdownStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which shutdown began during the previous boot, i.e. units started to be stopped, if available (e.g.: kexec or soft-reboot)",
        },
        [MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_FINISH] = {
                .name = "PreviousShutdownFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which all units finished stopping during the shutdown of the previous boot, if available (e.g.: kexec or soft-reboot)",
        },
        [MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_LATE_START] = {
                .name = "PreviousShutdownLateStartTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which systemd-shutdown began execution during the previous boot, restored from the LUO payload after a kexec-based live update",
        },
        [MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_LATE_FINISH] = {
                .name = "PreviousShutdownLateFinishTimestamp",
                .with_monotonic = true,
                .description = "microseconds at which systemd-shutdown was about to kexec into the current kernel during the previous boot, restored from the LUO payload after a kexec-based live update",
        },
};

static int manager_timestamps_build_json(sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(vl);

        FOREACH_ELEMENT(i, manager_timestamp_metrics) {
                if (!i->name)
                        continue;

                const dual_timestamp *t = manager->timestamps + (i - manager_timestamp_metrics);

                if (timestamp_is_set(t->realtime)) {
                        _cleanup_free_ char *name = strjoin(METRIC_IO_SYSTEMD_MANAGER_PREFIX, i->name, ".Realtime");
                        if (!name)
                                return -ENOMEM;

                        r = metric_build_send_unsigned(
                                        &(const MetricFamily) { .name = name },
                                        vl,
                                        /* object= */ NULL,
                                        t->realtime,
                                        /* fields= */ NULL);
                        if (r < 0)
                                return r;
                }

                if (i->with_monotonic && timestamp_is_set(t->monotonic)) {
                        _cleanup_free_ char *name = strjoin(METRIC_IO_SYSTEMD_MANAGER_PREFIX, i->name, ".Monotonic");
                        if (!name)
                                return -ENOMEM;

                        r = metric_build_send_unsigned(
                                        &(const MetricFamily) { .name = name },
                                        vl,
                                        /* object= */ NULL,
                                        t->monotonic,
                                        /* fields= */ NULL);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int manager_timestamps_describe(sd_varlink *link) {
        int r;

        assert(link);

        FOREACH_ELEMENT(i, manager_timestamp_metrics) {
                if (!i->name)
                        continue;

                _cleanup_free_ char *rt_name = strjoin(METRIC_IO_SYSTEMD_MANAGER_PREFIX, i->name, ".Realtime");
                _cleanup_free_ char *rt_description = strjoin("CLOCK_REALTIME ", i->description);
                if (!rt_name || !rt_description)
                        return -ENOMEM;

                r = metric_family_describe(
                                &(const MetricFamily) {
                                        .name = rt_name,
                                        .description = rt_description,
                                        .type = METRIC_FAMILY_TYPE_GAUGE,
                                },
                                link);
                if (r < 0)
                        return r;

                if (i->with_monotonic) {
                        _cleanup_free_ char *mt_name = strjoin(METRIC_IO_SYSTEMD_MANAGER_PREFIX, i->name, ".Monotonic");
                        _cleanup_free_ char *mt_description = strjoin("CLOCK_MONOTONIC ", i->description);
                        if (!mt_name || !mt_description)
                                return -ENOMEM;

                        r = metric_family_describe(
                                        &(const MetricFamily) {
                                                .name = mt_name,
                                                .description = mt_description,
                                                .type = METRIC_FAMILY_TYPE_GAUGE,
                                        },
                                        link);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static const MetricFamily metric_family_table[_MANAGER_METRIC_MAX + 1] = {
        /* Keep metrics grouped by generator. */
        [MANAGER_METRIC_ACTIVE_TIMESTAMP] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ActiveTimestamp",
                .description = "Per unit metric: timestamp of active state transitions in microseconds; 0 indicates the transition has not occurred",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_metrics_build_json,
        },
        [MANAGER_METRIC_INACTIVE_EXIT_TIMESTAMP] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InactiveExitTimestamp",
                .description = "Per unit metric: timestamp when the unit last exited the inactive state in microseconds; 0 indicates the transition has not occurred",
                .type = METRIC_FAMILY_TYPE_GAUGE,
        },
        [MANAGER_METRIC_STATE_CHANGE_TIMESTAMP] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "StateChangeTimestamp",
                .description = "Per unit metric: timestamp of the last state change in microseconds; 0 indicates no state change has occurred",
                .type = METRIC_FAMILY_TYPE_GAUGE,
        },
        [MANAGER_METRIC_UNIT_ACTIVE_STATE] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitActiveState",
                .description = "Per unit metric: active state, with the type-specific sub state",
                .type = METRIC_FAMILY_TYPE_STRING,
        },
        [MANAGER_METRIC_UNIT_LOAD_STATE] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitLoadState",
                .description = "Per unit metric: load state",
                .type = METRIC_FAMILY_TYPE_STRING,
        },
        /* Keep those ↑ grouped with units_metrics_build_json(). */
        [MANAGER_METRIC_JOBS_QUEUED] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "JobsQueued",
                .description = "Number of jobs currently queued",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = jobs_queued_build_json,
        },
        [MANAGER_METRIC_N_RESTARTS] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "NRestarts",
                .description = "Per unit metric: number of restarts",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = service_metrics_build_json,
        },
        [MANAGER_METRIC_STATUS_ERRNO] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "StatusErrno",
                .description = "Per service metric: errno status of the service",
                .type = METRIC_FAMILY_TYPE_GAUGE,
        },
        /* Keep those ↑ grouped with service_metrics_build_json(). */
        [MANAGER_METRIC_UNITS_BY_LOAD_STATE_TOTAL] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByLoadStateTotal",
                .description = "Total number of units by load state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_totals_build_json,
        },
        [MANAGER_METRIC_UNITS_BY_STATE_TOTAL] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByStateTotal",
                .description = "Total number of units of different state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
        },
        [MANAGER_METRIC_UNITS_BY_TYPE_TOTAL] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByTypeTotal",
                .description = "Total number of units of different types",
                .type = METRIC_FAMILY_TYPE_GAUGE,
        },
        [MANAGER_METRIC_UNITS_TOTAL] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsTotal",
                .description = "Total number of units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
        },
        /* Keep those ↑ grouped with units_totals_build_json(). */
        [MANAGER_METRIC_RELOAD_COUNT] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ReloadCount",
                .description = "Number of successful manager reloads since startup; resets across daemon-reexec",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = reload_count_build_json,
        },
        [MANAGER_METRIC_SYSTEM_STATE] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SystemState",
                .description = "Overall system state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = system_state_build_json,
        },
        [MANAGER_METRIC_VERSION] = {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "Version",
                .description = "Version of systemd",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = version_build_json,
        },
        [_MANAGER_METRIC_MAX] = {},
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        r = metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
        if (r < 0)
                return r;

        return manager_timestamps_describe(link);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        r = metrics_method_list(metric_family_table, link, parameters, flags, userdata);
        if (r < 0)
                return r;

        return manager_timestamps_build_json(link, userdata);
}
