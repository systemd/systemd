/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "sysupdate-forward.h"
#include "sysupdate-partition.h"

typedef struct InstanceMetadata {
        /* Various bits of metadata for each instance, that is either derived from the filename/GPT label or
         * from metadata of the file/partition itself */
        char *version;
        sd_id128_t partition_uuid;
        bool partition_uuid_set;
        uint64_t partition_flags;          /* GPT partition flags */
        bool partition_flags_set;
        usec_t mtime;
        mode_t mode;
        uint64_t size;                     /* uncompressed size of the file */
        uint64_t tries_done, tries_left;   /* for boot assessment counters */
        int no_auto;
        int read_only;
        int growfs;
        uint8_t sha256sum[32];             /* SHA256 sum of the download (i.e. compressed) file */
        bool sha256sum_set;
} InstanceMetadata;

#define INSTANCE_METADATA_NULL                  \
        {                                       \
                .mtime = USEC_INFINITY,         \
                .mode = MODE_INVALID,           \
                .size = UINT64_MAX,             \
                .tries_done = UINT64_MAX,       \
                .tries_left = UINT64_MAX,       \
                .no_auto = -1,                  \
                .read_only = -1,                \
                .growfs = -1,                   \
        }

struct Instance {
        /* A pointer back to the resource this belongs to */
        Resource *resource;

        /* Metadata of this version */
        InstanceMetadata metadata;

        /* Where we found the instance */
        char *path;  /* includes the `.sysupdate.partial.` (etc.) prefix, if applicable */
        PartitionInfo partition_info;

        bool is_partial;
        bool is_pending;
};

void instance_metadata_destroy(InstanceMetadata *m);

int instance_new(Resource *rr, const char *path, const InstanceMetadata *f, Instance **ret);
Instance *instance_free(Instance *i);

DEFINE_TRIVIAL_CLEANUP_FUNC(Instance*, instance_free);
