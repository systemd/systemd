/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "time-util.h"

#define DEFAULT_SUSPEND_ESTIMATION_USEC (1 * USEC_PER_HOUR)

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
        char **modes[_SLEEP_OPERATION_CONFIG_MAX];
        char **states[_SLEEP_OPERATION_CONFIG_MAX];

        usec_t hibernate_delay_usec;
        usec_t suspend_estimation_usec;
} SleepConfig;

SleepConfig* sleep_config_free(SleepConfig *sc);
DEFINE_TRIVIAL_CLEANUP_FUNC(SleepConfig*, sleep_config_free);

typedef enum SwapType {
        SWAP_BLOCK,
        SWAP_FILE,
        _SWAP_TYPE_MAX,
        _SWAP_TYPE_INVALID = -EINVAL,
} SwapType;

/* entry in /proc/swaps */
typedef struct SwapEntry {
        char *path;
        SwapType type;
        uint64_t size;
        uint64_t used;
        int priority;
} SwapEntry;

SwapEntry* swap_entry_free(SwapEntry *se);
DEFINE_TRIVIAL_CLEANUP_FUNC(SwapEntry*, swap_entry_free);

/*
 * represents values for /sys/power/resume & /sys/power/resume_offset
 * and the matching /proc/swap entry.
 */
typedef struct HibernateLocation {
        dev_t devno;
        uint64_t offset; /* in memory pages */
        SwapEntry *swap;
} HibernateLocation;

HibernateLocation* hibernate_location_free(HibernateLocation *hl);
DEFINE_TRIVIAL_CLEANUP_FUNC(HibernateLocation*, hibernate_location_free);

int read_fiemap(int fd, struct fiemap **ret);
int parse_sleep_config(SleepConfig **sleep_config);
int find_hibernate_location(HibernateLocation **ret_hibernate_location);
int write_resume_config(dev_t devno, uint64_t offset, const char *device);

int can_sleep(SleepOperation operation);
int can_sleep_disk(char **types);
int can_sleep_state(char **types);
int check_wakeup_type(void);
