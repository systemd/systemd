/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "sysupdate-forward.h"
#include "sysupdate-partition.h"
#include "sysupdate-resource.h"

typedef struct Transfer {
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
        char *temporary_partial_path;
        char *temporary_pending_path;
        char *final_path;
        int install_read_only;

        /* If we write to a partition in a partition table, the metrics of it */
        PartitionInfo partition_info;
        PartitionChange partition_change;
        char *final_partition_label;
        char *temporary_partial_partition_label;
        char *temporary_pending_partition_label;

        Context *context;
} Transfer;

typedef int (*TransferProgress)(const Transfer *t, const Instance *inst, unsigned percentage);

Transfer* transfer_new(Context *ctx);
Transfer* transfer_free(Transfer *t);
DEFINE_TRIVIAL_CLEANUP_FUNC(Transfer*, transfer_free);

int transfer_read_definition(Transfer *t, const char *path, const char **dirs, Hashmap *features);

int transfer_resolve_paths(Transfer *t, const char *root, const char *node);

int transfer_vacuum(Transfer *t, uint64_t space, const char *extra_protected_version);

int transfer_compute_temporary_paths(Transfer *t, Instance *i, InstanceMetadata *f);
int transfer_acquire_instance(Transfer *t, Instance *i, InstanceMetadata *f, TransferProgress cb, void *userdata);
int transfer_process_partial_and_pending_instance(Transfer *t, Instance *i);

int transfer_install_instance(Transfer *t, Instance *i, const char *root);
