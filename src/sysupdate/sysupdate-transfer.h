/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

/* Forward declare this type so that the headers below can use it */
typedef struct Transfer Transfer;

#include "sysupdate-partition.h"
#include "sysupdate-resource.h"
#include "sysupdate.h"

struct Transfer {
        char *id;

        char *min_version;
        char **protected_versions;
        char *current_symlink;
        bool verify;

        char **features;
        char **requisite_features;
        bool enabled;

        Resource source, target;

        uint64_t instances_max;
        bool remove_temporary;

        char **changelog;
        char **appstream;

        /* When creating a new partition/file, optionally override these attributes explicitly */
        sd_id128_t partition_uuid;
        bool partition_uuid_set;
        uint64_t partition_flags;
        bool partition_flags_set;
        mode_t mode;
        uint64_t tries_left, tries_done;
        int no_auto;
        int read_only;
        int growfs;

        /* If we create a new file/dir/subvol in the fs, the temporary and final path we create it under, as well as the read-only flag for it */
        char *temporary_path;
        char *final_path;
        int install_read_only;

        /* If we write to a partition in a partition table, the metrics of it */
        PartitionInfo partition_info;
        PartitionChange partition_change;

        Context *context;
};

typedef int (*TransferProgress)(const Transfer *t, const Instance *inst, unsigned percentage);

Transfer* transfer_new(Context *ctx);
Transfer* transfer_free(Transfer *t);
DEFINE_TRIVIAL_CLEANUP_FUNC(Transfer*, transfer_free);

int transfer_read_definition(Transfer *t, const char *path, const char **dirs, Hashmap *features);

int transfer_resolve_paths(Transfer *t, const char *root, const char *node);

int transfer_vacuum(Transfer *t, uint64_t space, const char *extra_protected_version);

int transfer_acquire_instance(Transfer *t, Instance *i, TransferProgress cb, void *userdata);

int transfer_install_instance(Transfer *t, Instance *i, const char *root);
