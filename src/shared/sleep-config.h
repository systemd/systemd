/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fiemap.h>

#include "hashmap.h"
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

/* entry in /proc/swaps */
typedef struct SwapEntry {
        char *device;
        char *type;
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
        uint64_t offset;
        SwapEntry *swap;
} HibernateLocation;

HibernateLocation* hibernate_location_free(HibernateLocation *hl);
DEFINE_TRIVIAL_CLEANUP_FUNC(HibernateLocation*, hibernate_location_free);

int read_fiemap(int fd, struct fiemap **ret);
int parse_sleep_config(SleepConfig **sleep_config);
int find_hibernate_location(HibernateLocation **ret_hibernate_location);

int can_sleep(SleepOperation operation);
int can_sleep_disk(char **types);
int can_sleep_state(char **types);
int battery_is_discharging_and_low(void);
int get_total_suspend_interval(Hashmap *last_capacity, usec_t *ret);
int fetch_batteries_capacity_by_name(Hashmap **ret_current_capacity);
int get_capacity_by_name(Hashmap *capacities_by_name, const char *name);
int estimate_battery_discharge_rate_per_hour(
                Hashmap *last_capacity,
                Hashmap *current_capacity,
                usec_t before_timestamp,
                usec_t after_timestamp);
int check_wakeup_type(void);
int battery_trip_point_alarm_exists(void);

const char* sleep_operation_to_string(SleepOperation s) _const_;
SleepOperation sleep_operation_from_string(const char *s) _pure_;
