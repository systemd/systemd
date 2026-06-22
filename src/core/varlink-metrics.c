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

static int manager_timestamp_build_json(
                const MetricFamily *mf,
                sd_varlink *vl,
                const dual_timestamp *t,
                bool with_monotonic) {

        int r;

        assert(mf && mf->name);
        assert(vl);
        assert(t);

        if (timestamp_is_set(t->realtime)) {
                r = metric_build_send_unsigned(
                                mf,  /* the .Realtime metric family entry */
                                vl,
                                /* object= */ NULL,
                                t->realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        if (with_monotonic && timestamp_is_set(t->monotonic)) {
                assert(endswith(mf[1].name, ".Monotonic"));
                r = metric_build_send_unsigned(
                                mf + 1,  /* the .Monotonic sibling is the next entry */
                                vl,
                                /* object= */ NULL,
                                t->monotonic,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Per-timestamp metric callbacks. Each callback emits the timestamp's .Realtime value; for
 * with_monotonic the .Monotonic value is emitted from the immediately following table entry (whose
 * .generate is NULL), see manager_timestamp_build_json(). Firmware/loader/kernel report only .Realtime:
 * their CLOCK_MONOTONIC is either 0 (kernel) or a pre-kernel offset (firmware/loader), neither of which is
 * a meaningful absolute monotonic timestamp. */
#define DEFINE_MANAGER_TIMESTAMP_METRIC(func, ts, with_monotonic)                                       \
        static int func(const MetricFamily *mf, sd_varlink *vl, void *userdata) {                       \
                Manager *manager = ASSERT_PTR(userdata);                                                \
                return manager_timestamp_build_json(mf, vl, &manager->timestamps[ts], (with_monotonic)); \
        }

DEFINE_MANAGER_TIMESTAMP_METRIC(firmware_timestamp_build_json,                      MANAGER_TIMESTAMP_FIRMWARE,                      false);
DEFINE_MANAGER_TIMESTAMP_METRIC(loader_timestamp_build_json,                        MANAGER_TIMESTAMP_LOADER,                        false);
DEFINE_MANAGER_TIMESTAMP_METRIC(kernel_timestamp_build_json,                        MANAGER_TIMESTAMP_KERNEL,                        false);
DEFINE_MANAGER_TIMESTAMP_METRIC(initrd_timestamp_build_json,                        MANAGER_TIMESTAMP_INITRD,                        true);
DEFINE_MANAGER_TIMESTAMP_METRIC(userspace_timestamp_build_json,                     MANAGER_TIMESTAMP_USERSPACE,                     true);
DEFINE_MANAGER_TIMESTAMP_METRIC(finish_timestamp_build_json,                        MANAGER_TIMESTAMP_FINISH,                        true);
DEFINE_MANAGER_TIMESTAMP_METRIC(security_start_timestamp_build_json,                MANAGER_TIMESTAMP_SECURITY_START,                true);
DEFINE_MANAGER_TIMESTAMP_METRIC(security_finish_timestamp_build_json,               MANAGER_TIMESTAMP_SECURITY_FINISH,               true);
DEFINE_MANAGER_TIMESTAMP_METRIC(generators_start_timestamp_build_json,              MANAGER_TIMESTAMP_GENERATORS_START,              true);
DEFINE_MANAGER_TIMESTAMP_METRIC(generators_finish_timestamp_build_json,             MANAGER_TIMESTAMP_GENERATORS_FINISH,             true);
DEFINE_MANAGER_TIMESTAMP_METRIC(units_load_start_timestamp_build_json,              MANAGER_TIMESTAMP_UNITS_LOAD_START,              true);
DEFINE_MANAGER_TIMESTAMP_METRIC(units_load_finish_timestamp_build_json,             MANAGER_TIMESTAMP_UNITS_LOAD_FINISH,             true);
DEFINE_MANAGER_TIMESTAMP_METRIC(units_load_timestamp_build_json,                    MANAGER_TIMESTAMP_UNITS_LOAD,                    true);
DEFINE_MANAGER_TIMESTAMP_METRIC(initrd_security_start_timestamp_build_json,         MANAGER_TIMESTAMP_INITRD_SECURITY_START,         true);
DEFINE_MANAGER_TIMESTAMP_METRIC(initrd_security_finish_timestamp_build_json,        MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH,        true);
DEFINE_MANAGER_TIMESTAMP_METRIC(initrd_generators_start_timestamp_build_json,       MANAGER_TIMESTAMP_INITRD_GENERATORS_START,       true);
DEFINE_MANAGER_TIMESTAMP_METRIC(initrd_generators_finish_timestamp_build_json,      MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH,      true);
DEFINE_MANAGER_TIMESTAMP_METRIC(initrd_units_load_start_timestamp_build_json,       MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START,       true);
DEFINE_MANAGER_TIMESTAMP_METRIC(initrd_units_load_finish_timestamp_build_json,      MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH,      true);
DEFINE_MANAGER_TIMESTAMP_METRIC(shutdown_start_timestamp_build_json,                MANAGER_TIMESTAMP_SHUTDOWN_START,                true);
DEFINE_MANAGER_TIMESTAMP_METRIC(shutdown_finish_timestamp_build_json,               MANAGER_TIMESTAMP_SHUTDOWN_FINISH,               true);
DEFINE_MANAGER_TIMESTAMP_METRIC(previous_shutdown_start_timestamp_build_json,       MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_START,       true);
DEFINE_MANAGER_TIMESTAMP_METRIC(previous_shutdown_finish_timestamp_build_json,      MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_FINISH,      true);
DEFINE_MANAGER_TIMESTAMP_METRIC(previous_shutdown_late_start_timestamp_build_json,  MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_LATE_START,  true);
DEFINE_MANAGER_TIMESTAMP_METRIC(previous_shutdown_late_finish_timestamp_build_json, MANAGER_TIMESTAMP_PREVIOUS_SHUTDOWN_LATE_FINISH, true);

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
                .generate = finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "FinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which userspace finished booting",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "FirmwareTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the firmware began execution (CLOCK_MONOTONIC is a pre-kernel offset, not reported)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = firmware_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager finished executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = generators_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with generators_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = generators_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "GeneratorsStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started executing generators",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with generators_start_timestamp_build_json(). */
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
                .generate = initrd_generators_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDGeneratorsFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished executing generators in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with initrd_generators_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDGeneratorsStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started executing generators in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = initrd_generators_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDGeneratorsStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started executing generators in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with initrd_generators_start_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager finished uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = initrd_security_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with initrd_security_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = initrd_security_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDSecurityStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started uploading security policies to the kernel in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with initrd_security_start_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the initrd began execution",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = initrd_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the initrd began execution",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with initrd_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager first finished loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = initrd_units_load_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first finished loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with initrd_units_load_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager first started loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = initrd_units_load_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InitRDUnitsLoadStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first started loading units in the initrd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with initrd_units_load_start_timestamp_build_json(). */
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
                .generate = kernel_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "LoaderTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the boot loader began execution (CLOCK_MONOTONIC is a pre-kernel offset, not reported)",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = loader_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "NRestarts",
                .description = "Per unit metric: number of restarts",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = nrestarts_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which all units finished stopping during the shutdown of the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = previous_shutdown_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which all units finished stopping during the shutdown of the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with previous_shutdown_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which systemd-shutdown was about to kexec into the current kernel during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = previous_shutdown_late_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which systemd-shutdown was about to kexec into the current kernel during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with previous_shutdown_late_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which systemd-shutdown began execution during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = previous_shutdown_late_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownLateStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which systemd-shutdown began execution during the previous boot, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with previous_shutdown_late_start_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which shutdown began during the previous boot, i.e. units started to be stopped, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = previous_shutdown_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "PreviousShutdownStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which shutdown began during the previous boot, i.e. units started to be stopped, restored from the LUO payload after a kexec-based live update",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with previous_shutdown_start_timestamp_build_json(). */
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
                .generate = security_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SecurityFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager finished uploading security policies to the kernel",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with security_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SecurityStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager started uploading security policies to the kernel",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = security_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SecurityStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager started uploading security policies to the kernel",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with security_start_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownFinishTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which all units finished stopping during shutdown",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = shutdown_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which all units finished stopping during shutdown",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with shutdown_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which shutdown began, i.e. units started to be stopped",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = shutdown_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ShutdownStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which shutdown began, i.e. units started to be stopped",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with shutdown_start_timestamp_build_json(). */
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
                .generate = units_load_finish_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadFinishTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first finished loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with units_load_finish_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadStartTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager first started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_load_start_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadStartTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager first started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with units_load_start_timestamp_build_json(). */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadTimestamp.Realtime",
                .description = "CLOCK_REALTIME microseconds at which the manager last started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_load_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsLoadTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which the manager last started loading units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with units_load_timestamp_build_json(). */
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
                .generate = userspace_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UserspaceTimestamp.Monotonic",
                .description = "CLOCK_MONOTONIC microseconds at which userspace was reached",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        /* Keep those ↑ in sync with userspace_timestamp_build_json(). */
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
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
