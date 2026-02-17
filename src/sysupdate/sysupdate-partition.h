/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "sysupdate-forward.h"

typedef enum PartitionChange {
        PARTITION_FLAGS           = 1 << 0,
        PARTITION_NO_AUTO         = 1 << 1,
        PARTITION_READ_ONLY       = 1 << 2,
        PARTITION_GROWFS          = 1 << 3,
        PARTITION_UUID            = 1 << 4,
        PARTITION_LABEL           = 1 << 5,
        PARTITION_TYPE            = 1 << 6,
        _PARTITION_CHANGE_MAX     = (1 << 7) - 1, /* all of the above */
        _PARTITION_CHANGE_INVALID = -EINVAL,
} PartitionChange;

typedef struct PartitionInfo {
        size_t partno;
        uint64_t start, size;
        uint64_t flags;
        sd_id128_t type, uuid;
        char *label;
        char *device; /* Note that this might point to some non-existing path in case we operate on a loopback file */
        bool no_auto;
        bool read_only;
        bool growfs;
} PartitionInfo;

#define PARTITION_INFO_NULL                     \
        {                                       \
                .partno = SIZE_MAX,             \
                .start = UINT64_MAX,            \
                .size = UINT64_MAX,             \
        }

void partition_info_destroy(PartitionInfo *p);
int partition_info_copy(PartitionInfo *dest, const PartitionInfo *src);

int read_partition_info(struct fdisk_context *c, struct fdisk_table *t, size_t i, PartitionInfo *ret);

int gpt_partition_type_uuid_for_sysupdate_partial(sd_id128_t type, sd_id128_t *ret);
int gpt_partition_type_uuid_for_sysupdate_pending(sd_id128_t type, sd_id128_t *ret);

int find_suitable_partition(const char *device, uint64_t space, sd_id128_t *partition_type, PartitionInfo *ret);
int patch_partition(const char *device, const PartitionInfo *info, PartitionChange change);
