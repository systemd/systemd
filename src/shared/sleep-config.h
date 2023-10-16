/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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

typedef struct SleepConfig {
        bool allow[_SLEEP_OPERATION_MAX];

        char **states[_SLEEP_OPERATION_CONFIG_MAX];
        char **modes[_SLEEP_OPERATION_CONFIG_MAX]; /* Power mode after writing hibernation image */

        usec_t hibernate_delay_usec;
        usec_t suspend_estimation_usec;
} SleepConfig;

SleepConfig* sleep_config_free(SleepConfig *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(SleepConfig*, sleep_config_free);

int parse_sleep_config(SleepConfig **sleep_config);

typedef enum SleepSupport {
        SLEEP_SUPPORTED,
        SLEEP_DISABLED,                    /* Disabled in SleepConfig.allow */
        SLEEP_NOT_CONFIGURED,              /* SleepConfig.states is not configured */
        SLEEP_STATE_OR_MODE_NOT_SUPPORTED, /* SleepConfig.states/modes are not supported by kernel */
        SLEEP_NOT_ENOUGH_SWAP_SPACE,
        SLEEP_ALARM_NOT_SUPPORTED,         /* CLOCK_BOOTTIME_ALARM is unsupported by kernel (only used by s2h) */
} SleepSupport;

int sleep_supported_full(SleepOperation operation, SleepSupport *ret_support);
static inline int sleep_supported(SleepOperation operation) {
        return sleep_supported_full(operation, NULL);
}

/* Only for test-sleep-config */
int sleep_state_supported(char **states);
int sleep_mode_supported(char **modes);
