/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fiemap.h>
#include <sys/types.h>

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
int find_hibernate_location(HibernateLocation **ret_hibernate_location);
int write_resume_config(dev_t devno, uint64_t offset, const char *device);
bool enough_swap_for_hibernation(void);
