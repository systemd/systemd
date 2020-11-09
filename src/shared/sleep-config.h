/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fiemap.h>
#include "time-util.h"

typedef struct SleepConfig {
        bool allow_suspend;         /* AllowSuspend */
        bool allow_hibernate;       /* AllowHibernation */
        bool allow_s2h;             /* AllowSuspendThenHibernate */
        bool allow_hybrid_sleep;    /* AllowHybridSleep */

        char **suspend_modes;       /* SuspendMode */
        char **suspend_states;      /* SuspendState */
        char **hibernate_modes;     /* HibernateMode */
        char **hibernate_states;    /* HibernateState */
        char **hybrid_modes;        /* HybridSleepMode */
        char **hybrid_states;       /* HybridSleepState */

        usec_t hibernate_delay_sec; /* HibernateDelaySec */
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

int sleep_settings(const char *verb, const SleepConfig *sleep_config, bool *ret_allow, char ***ret_modes, char ***ret_states);

int read_fiemap(int fd, struct fiemap **ret);
int parse_sleep_config(SleepConfig **sleep_config);
int find_hibernate_location(HibernateLocation **ret_hibernate_location);

int can_sleep(const char *verb);
int can_sleep_disk(char **types);
int can_sleep_state(char **types);
