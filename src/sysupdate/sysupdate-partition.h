/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/types.h>

#include "sd-id128.h"

#include "fdisk-util.h"
#include "macro.h"

typedef struct PartitionInfo PartitionInfo;

typedef enum PartitionChange {
        PARTITION_FLAGS           = 1 << 0,
        PARTITION_NO_AUTO         = 1 << 1,
        PARTITION_READ_ONLY       = 1 << 2,
        PARTITION_GROWFS          = 1 << 3,
        PARTITION_UUID            = 1 << 4,
        PARTITION_LABEL           = 1 << 5,
        _PARTITION_CHANGE_MAX     = (1 << 6) - 1, /* all of the above */
        _PARTITION_CHANGE_INVALID = -EINVAL,
} PartitionChange;

struct PartitionInfo {
        size_t partno;
        uint64_t start, size;
        uint64_t flags;
        sd_id128_t type, uuid;
        char *label;
        char *device; /* Note that this might point to some non-existing path in case we operate on a loopback file */
        bool no_auto:1;
        bool read_only:1;
        bool growfs:1;
};

#define PARTITION_INFO_NULL                     \
        {                                       \
                .partno = SIZE_MAX,             \
                .start = UINT64_MAX,            \
                .size = UINT64_MAX,             \
        }

void partition_info_destroy(PartitionInfo *p);

int read_partition_info(struct fdisk_context *c, struct fdisk_table *t, size_t i, PartitionInfo *ret);

int find_suitable_partition(const char *device, uint64_t space, sd_id128_t *partition_type, PartitionInfo *ret);
int patch_partition(const char *device, const PartitionInfo *info, PartitionChange change);
