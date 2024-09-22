/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.repart.h"
#include "sd-varlink-idl.h"

/* NOTE: This API was intentionally designed to be the minimum needed by known clients. With Varlink, you can
 *       always add more functionality, but removing functionality would be backwards incompatible. If
 *       something you need is missing, PRs implementing it will be welcome! */

static SD_VARLINK_DEFINE_ENUM_TYPE(
                EmptyMode,
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks without an existing partition table"),
                SD_VARLINK_DEFINE_ENUM_VALUE(refuse),
                SD_VARLINK_FIELD_COMMENT("Create a new partition table if one doesn't already exist on disk"),
                SD_VARLINK_DEFINE_ENUM_VALUE(allow),
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks with an existing partition table, and create a new table if none exists."),
                SD_VARLINK_DEFINE_ENUM_VALUE(require),
                SD_VARLINK_FIELD_COMMENT("Always create a new partition table, potentially overwriting an existing table. Use with great care, this has the effect of erasing the disk."),
                SD_VARLINK_DEFINE_ENUM_VALUE(force),
                SD_VARLINK_FIELD_COMMENT("Create a new loopback file of specified size at the specified device node path."),
                SD_VARLINK_DEFINE_ENUM_VALUE(create));

static SD_VARLINK_DEFINE_METHOD(
                Check,
                SD_VARLINK_FIELD_COMMENT("The path to the target block device's node. The client should use the target's by-diskseq symlink if possible."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, 0),
                /* Known-missing: node isn't optional, since there's no reason for an OS installer to operate on its own host system */
                SD_VARLINK_FIELD_COMMENT("Paths to folders containing static definition files to be used by the client. Note that this is NOT intended for dynamically-generated definitions created by code."),
                SD_VARLINK_DEFINE_INPUT(definition_paths, SD_VARLINK_STRING, SD_VARLINK_ARRAY),
                /* Known-missing: A field for code-generated definitions. This shouldn't be hard to impl,
                 * just tedious: you'd need to define a Varlink type for a Partition definition (following the
                 * format of the config file) and then implement the parsing for it. Also, then make definition_paths
                 * nullable. */
                SD_VARLINK_FIELD_COMMENT("Controls how to handle disks that lack a partition table (i.e. are empty)."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(empty_mode, EmptyMode, 0),
                /* Known-missing: Repart's copy_from functionality */
                /* Known-missing: An output field describing what the partition layout would look like if the
                 * image were to be deployed. */);

static SD_VARLINK_DEFINE_ENUM_TYPE(
                EmptyMode,
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks without an existing partition table"),
                SD_VARLINK_DEFINE_ENUM_VALUE(refuse),
                SD_VARLINK_FIELD_COMMENT("Create a new partition table if one doesn't already exist on disk"),
                SD_VARLINK_DEFINE_ENUM_VALUE(allow),
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks with an existing partition table, and create a new table if none exists."),
                SD_VARLINK_DEFINE_ENUM_VALUE(require),
                SD_VARLINK_FIELD_COMMENT("Always create a new partition table, potentially overwriting an existing table. Use with great care, this has the effect of erasing the disk."),
                SD_VARLINK_DEFINE_ENUM_VALUE(force),
                SD_VARLINK_FIELD_COMMENT("Create a new loopback file of specified size at the specified device node path."),
                SD_VARLINK_DEFINE_ENUM_VALUE(create));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PartitionProgress,
                SD_VARLINK_FIELD_COMMENT("The current step being performed by the partitioner")
                );

static SD_VARLINK_DEFINE_METHOD(
                Partition,
                /* Note: the inputs here are parsed through the same code paths as Check(), so make sure that
                 * the arguments that are shared would be parsed the same way. */
                SD_VARLINK_FIELD_COMMENT("The path to the target block device's node. The client should use the target's by-diskseq symlink if possible."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Paths to folders containing static definition files to be used by the client. Note that this is NOT intended for dynamically-generated definitions created by code."),
                SD_VARLINK_DEFINE_INPUT(definition_paths, SD_VARLINK_STRING, SD_VARLINK_ARRAY),
                /* Knowwn-missing: dynamic code-generated definitions. */
                SD_VARLINK_FIELD_COMMENT("Controls how to handle disks that lack a partition table (i.e. are empty)."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(empty_mode, EmptyMode, 0),
                SD_VARLINK_FIELD_COMMENT("Used to report progress information back to the client."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(progress, PartitionProgress, SD_VARLINK_NULLABLE)
                /* Known-missing: An output field describing the final layout of the disk */);

static SD_VARLINK_DEFINE_ERROR(
                DiskTooSmall,
                SD_VARLINK_FIELD_COMMENT("The minimum required size of the disk to fit the specified image",
                SD_VARLINK_DEFINE_FIELD(min_size, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ERROR(
                InsufficientFreeSpace,
                SD_VARLINK_FIELD_COMMENT("An estimate of the amount of usable free space on disk. It's actually the size of the largest contiguous free area."),
                SD_VARLINK_DEFINE_FIELD(estimated_free, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The minimum required amount of free space to fit the image.",
                SD_VARLINK_DEFINE_FIELD(min_required, SD_VARLINK_INT, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Repart,
                "io.systemd.Repart",
                SD_VARLINK_INTERFACE_COMMENT("APIs for declaratively re-partitioning disks. Most useful for OS installers. This API is intentionally designed to be the minimum necessary for known clients, so if you need some functionality that's missing PRs are welcome!");

                SD_VARLINK_SYMBOL_COMMENT("Behaviors for disks that are completely empty (i.e. don't have a partition table yet)"),
                &vl_type_EmptyMode,

                SD_VARLINK_SYMBOL_COMMENT("Checks if an image will fit on a given target disk."),
                &vl_method_Check,
                SD_VARLINK_SYMBOL_COMMENT("Deploy an image onto a given target disk."),
                &vl_method_Partition,

                SD_VARLINK_SYMBOL_COMMENT("The target disk is too small to fit the partition table!"),
                &vl_error_DiskTooSmall,
                SD_VARLINK_SYMBOL_COMMENT(""),
                &vl_error_WontFit);
