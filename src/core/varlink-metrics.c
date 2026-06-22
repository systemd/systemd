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

static int active_timestamp_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(mf && mf->name);
        assert(vl);

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
                                mf,
                                vl,
                                unit->id,
                                unit->active_enter_timestamp.realtime,
                                enter_fields);
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                mf,
                                vl,
                                unit->id,
                                unit->active_exit_timestamp.realtime,
                                exit_fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int inactive_exit_timestamp_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(mf && mf->name);
        assert(vl);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                mf,
                                vl,
                                unit->id,
                                unit->inactive_exit_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
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

static int manager_timestamps_build_json(sd_varlink *vl, void *userdata) {
        static const struct {
                const char *name;
                ManagerTimestamp timestamp;
                bool with_monotonic;
        } timestamp_metrics[] = {
                { "FinishTimestamp",                     MANAGER_TIMESTAMP_FINISH,                        true  },
                { "FirmwareTimestamp",                   MANAGER_TIMESTAMP_FIRMWARE,                      false },
                { "GeneratorsFinishTimestamp",           MANAGER_TIMESTAMP_GENERATORS_FINISH,             true  },
                { "GeneratorsStartTimestamp",            MANAGER_TIMESTAMP_GENERATORS_START,              true  },
                { "InitRDGeneratorsFinishTimestamp",     MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH,      true  },
                { "InitRDGeneratorsStartTimestamp",      MANAGER_TIMESTAMP_INITRD_GENERATORS_START,       true  },
                { "InitRDSecurityFinishTimestamp",       MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH,        true  },
                { "InitRDSecurityStartTimestamp",        MANAGER_TIMESTAMP_INITRD_SECURITY_START,         true  },
                { "InitRDTimestamp",                     MANAGER_TIMESTAMP_INITRD,                        true  },
                { "InitRDUnitsLoadFinishTimestamp",      MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH,      true  },
                { "InitRDUnitsLoadStartTimestamp",       MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START,       true  },
                { "KernelTimestamp",                     MANAGER_TIMESTAMP_KERNEL,                        false },
                { "LoaderTimestamp",                     MANAGER_TIMESTAMP_LOADER,                        false },
                { "PreviousShutdownFinishTimestamp",     MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_FINISH,      true  },
                { "PreviousShutdownLateFinishTimestamp", MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_LATE_FINISH, true  },
                { "PreviousShutdownLateStartTimestamp",  MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_LATE_START,  true  },
                { "PreviousShutdownStartTimestamp",      MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_START,       true  },
                { "SecurityFinishTimestamp",             MANAGER_TIMESTAMP_SECURITY_FINISH,               true  },
                { "SecurityStartTimestamp",              MANAGER_TIMESTAMP_SECURITY_START,                true  },
                { "ShutdownFinishTimestamp",             MANAGER_TIMESTAMP_SHUTDOWN_FINISH,               true  },
                { "ShutdownStartTimestamp",              MANAGER_TIMESTAMP_SHUTDOWN_START,                true  },
                { "UnitsLoadFinishTimestamp",            MANAGER_TIMESTAMP_UNITS_LOAD_FINISH,             true  },
                { "UnitsLoadStartTimestamp",             MANAGER_TIMESTAMP_UNITS_LOAD_START,              true  },
                { "UnitsLoadTimestamp",                  MANAGER_TIMESTAMP_UNITS_LOAD,                    true  },
                { "UserspaceTimestamp",                  MANAGER_TIMESTAMP_USERSPACE,                     true  },
        };

        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(vl);

        /* Single generator for all manager timestamp metrics: emits <name>.Realtime and, when the
         * timestamp carries a meaningful monotonic value, <name>.Monotonic (firmware/loader/kernel don't,
         * as their CLOCK_MONOTONIC is a pre-kernel offset or zero). Kept in sync with the *Timestamp.*
         * describe entries in metric_family_table below. */
        FOREACH_ELEMENT(i, timestamp_metrics) {
                const dual_timestamp *t = manager->timestamps + i->timestamp;

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

static int state_change_timestamp_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(mf && mf->name);
        assert(vl);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                mf,
                                vl,
                                unit->id,
                                unit->state_change_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int status_errno_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(mf && mf->name);
        assert(vl);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                mf,
                                vl,
                                unit->id,
                                (uint64_t) SERVICE(unit)->status_errno,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int unit_active_state_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(mf && mf->name);
        assert(vl);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_string(
                                mf,
                                vl,
                                unit->id,
                                unit_active_state_to_string(unit_active_state(unit)),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int unit_load_state_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(mf && mf->name);
        assert(vl);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_string(
                                mf,
                                vl,
                                unit->id,
                                unit_load_state_to_string(unit->load_state),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int nrestarts_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(mf && mf->name);
        assert(vl);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                mf,
                                vl,
                                unit->id,
                                SERVICE(unit)->n_restarts,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
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

static int units_by_type_total_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(mf && mf->name);
        assert(vl);

        for (UnitType type = 0; type < _UNIT_TYPE_MAX; type++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                uint64_t counter = 0;

                LIST_FOREACH(units_by_type, _u, manager->units_by_type[type])
                        counter++;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", unit_type_to_string(type)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                mf,
                                vl,
                                /* object= */ NULL,
                                counter,
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_by_state_total_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t counters[_UNIT_ACTIVE_STATE_MAX] = {};
        Unit *unit;
        char *key;
        int r;

        assert(mf && mf->name);
        assert(vl);

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
                                mf,
                                vl,
                                /* object= */ NULL,
                                counters[state],
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
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

static int units_by_load_state_total_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t counters[_UNIT_LOAD_STATE_MAX] = {};
        Unit *unit;
        char *key;
        int r;

        assert(mf && mf->name);
        assert(vl);

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
                                mf,
                                vl,
                                /* object= */ NULL,
                                counters[state],
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_total_build_json(const MetricFamily *mf, sd_varlink *vl, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t count = 0;
        Unit *unit;
        char *key;

        assert(mf && mf->name);
        assert(vl);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                count++;
        }

        return metric_build_send_unsigned(
                        mf,
                        vl,
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
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "FinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which userspace finished booting",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "FinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which userspace finished booting",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "FirmwareTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the firmware began execution (CLOCK_MONOTONIC is a pre-kernel offset, not reported)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager finished executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InactiveExitTimestamp",
                .description = "Per unit metric: timestamp when the unit last exited the inactive state in microseconds; 0 indicates the transition has not occurred",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = inactive_exit_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDGeneratorsFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager finished executing generators in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDGeneratorsFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished executing generators in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDGeneratorsStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started executing generators in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDGeneratorsStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started executing generators in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager finished uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the initrd began execution",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the initrd began execution",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager first finished loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first finished loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager first started loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first started loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "JobsQueued",
                .description = "Number of jobs currently queued",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = jobs_queued_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "KernelTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the kernel started (CLOCK_MONOTONIC == 0)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "LoaderTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the boot loader began execution (CLOCK_MONOTONIC is a pre-kernel offset, not reported)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "NRestarts",
                .description = "Per unit metric: number of restarts",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = nrestarts_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which all units finished stopping during the shutdown of the previous boot, if available (e.g.: kexec or soft-reboot)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which all units finished stopping during the shutdown of the previous boot, if available (e.g.: kexec or soft-reboot)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which systemd-shutdown was about to kexec into the current kernel during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which systemd-shutdown was about to kexec into the current kernel during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which systemd-shutdown began execution during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which systemd-shutdown began execution during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which shutdown began during the previous boot, i.e. units started to be stopped, if available (e.g.: kexec or soft-reboot)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which shutdown began during the previous boot, i.e. units started to be stopped, if available (e.g.: kexec or soft-reboot)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ReloadCount",
                .description = "Number of successful manager reloads since startup; resets across daemon-reexec",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = reload_count_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SecurityFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager finished uploading security policies to the kernel",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SecurityFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished uploading security policies to the kernel",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SecurityStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started uploading security policies to the kernel",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SecurityStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started uploading security policies to the kernel",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which all units finished stopping during shutdown",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which all units finished stopping during shutdown",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which shutdown began, i.e. units started to be stopped",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which shutdown began, i.e. units started to be stopped",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
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
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager first finished loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first finished loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager first started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager last started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager last started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsTotal",
                .description = "Total number of units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UserspaceTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which userspace was reached",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UserspaceTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which userspace was reached",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "Version",
                .description = "Version of systemd",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = version_build_json,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        r = metrics_method_list(metric_family_table, link, parameters, flags, userdata);
        if (r < 0)
                return r;

        return manager_timestamps_build_json(link, userdata);
}
