/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "time-util.h"

#define DEFAULT_SUSPEND_ESTIMATION_USEC (1 * USEC_PER_HOUR)

typedef enum SleepOperation {
        SLEEP_SUSPEND,
        SLEEP_HIBERNATE,
        SLEEP_HYBRID_SLEEP,
        SLEEP_SUSPEND_THEN_HIBERNATE,
        _SLEEP_OPERATION_MAX,
        _SLEEP_OPERATION_INVALID = -EINVAL,
} SleepOperation;

typedef struct SleepConfig {
        bool allow[_SLEEP_OPERATION_MAX];
        char **modes[_SLEEP_OPERATION_MAX];
        char **states[_SLEEP_OPERATION_MAX];
        usec_t hibernate_delay_usec;
        usec_t suspend_estimation_usec;
} SleepConfig;

SleepConfig* free_sleep_config(SleepConfig *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(SleepConfig*, free_sleep_config);

int parse_sleep_config(SleepConfig **sleep_config);

int can_sleep(SleepOperation operation);
int can_sleep_disk(char **types);
int can_sleep_state(char **types);

const char* sleep_operation_to_string(SleepOperation s) _const_;
SleepOperation sleep_operation_from_string(const char *s) _pure_;
