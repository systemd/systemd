/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "strv.h"
#include "time-util.h"

typedef enum SleepOperation {
        SLEEP_SUSPEND,
        SLEEP_HIBERNATE,
        SLEEP_HYBRID_SLEEP,
        _SLEEP_OPERATION_CONFIG_MAX,
        /* The operations above require configuration for mode and state. The ones below are "combined"
         * operations that use config from those individual operations. */

        SLEEP_SUSPEND_THEN_HIBERNATE,

        _SLEEP_OPERATION_MAX,
        _SLEEP_OPERATION_INVALID = -EINVAL,
} SleepOperation;

const char* sleep_operation_to_string(SleepOperation s) _const_;
SleepOperation sleep_operation_from_string(const char *s) _pure_;

static inline bool SLEEP_OPERATION_IS_HIBERNATION(SleepOperation operation) {
        return IN_SET(operation, SLEEP_HIBERNATE, SLEEP_HYBRID_SLEEP);
}

typedef struct SleepConfig {
        bool allow[_SLEEP_OPERATION_MAX];

        char **states[_SLEEP_OPERATION_CONFIG_MAX];
        char **modes[_SLEEP_OPERATION_CONFIG_MAX];  /* Power mode after writing hibernation image (/sys/power/disk) */
        char **mem_modes;                           /* /sys/power/mem_sleep */

        usec_t hibernate_delay_usec;
        bool hibernate_on_ac_power;
        usec_t suspend_estimation_usec;
} SleepConfig;

SleepConfig* sleep_config_free(SleepConfig *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(SleepConfig*, sleep_config_free);

int parse_sleep_config(SleepConfig **sleep_config);

static inline bool SLEEP_NEEDS_MEM_SLEEP(const SleepConfig *sc, SleepOperation operation) {
        assert(sc);
        assert(operation >= 0 && operation < _SLEEP_OPERATION_CONFIG_MAX);

        /* As per https://docs.kernel.org/admin-guide/pm/sleep-states.html#basic-sysfs-interfaces-for-system-suspend-and-hibernation,
         * /sys/power/mem_sleep is honored if /sys/power/state is set to "mem" (common for suspend)
         * or /sys/power/disk is set to "suspend" (hybrid-sleep). */

        return strv_contains(sc->states[operation], "mem") ||
               strv_contains(sc->modes[operation], "suspend");
}

typedef enum SleepSupport {
        SLEEP_SUPPORTED,
        SLEEP_DISABLED,                    /* Disabled in SleepConfig.allow */
        SLEEP_NOT_CONFIGURED,              /* SleepConfig.states is not configured */
        SLEEP_STATE_OR_MODE_NOT_SUPPORTED, /* SleepConfig.states/modes are not supported by kernel */
        SLEEP_RESUME_NOT_SUPPORTED,
        SLEEP_RESUME_DEVICE_MISSING,       /* resume= is specified, but the device cannot be found in /proc/swaps */
        SLEEP_RESUME_MISCONFIGURED,        /* resume= is not set yet resume_offset= is configured */
        SLEEP_NOT_ENOUGH_SWAP_SPACE,
        SLEEP_ALARM_NOT_SUPPORTED,         /* CLOCK_BOOTTIME_ALARM is unsupported by kernel (only used by s2h) */
} SleepSupport;

int sleep_supported_full(SleepOperation operation, SleepSupport *ret_support);
static inline int sleep_supported(SleepOperation operation) {
        return sleep_supported_full(operation, NULL);
}

/* Only for test-sleep-config */
int sleep_state_supported(char * const *states);
int sleep_mode_supported(const char *path, char * const *modes);
