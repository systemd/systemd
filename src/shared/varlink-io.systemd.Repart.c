/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.repart.h"
#include "sd-varlink-idl.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                EmptyMode,
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks without an existing partition table"),
                SD_VARLINK_DEFINE_ENUM_VALUE(refuse),
                SD_VARLINK_FIELD_COMMENT("Create a new partition table if one doesn't already exist on disk"),
                SD_VARLINK_DEFINE_ENUM_VALUE(allow),
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks with an existing partition table, and create a new table if none exists"),
                SD_VARLINK_DEFINE_ENUM_VALUE(require),
                SD_VARLINK_FIELD_COMMENT("Always create a new partition table, potentially overwriting an existing table"),
                SD_VARLINK_DEFINE_ENUM_VALUE(force));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Configuration,
                SD_VARLINK_FIELD_COMMENT("The block device or regular file to operate on. If possible, clients should prefer to use by-diskseq symlinks for block devices"),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Paths to folders that contain static definition files")
                SD_VARLINK_DEFINE_INPUT(static_definitions, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Controls how to handle disks that lack a partition table (i.e. are empty)"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(empty_mode, EmptyMode, 0));

static SD_VARLINK_DEFINE_METHOD(
                Check,
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(config, Configuration, 0));

static SD_VARLINK_DEFINE_METHOD(
                Partition,
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(config, Configuration, 0),
                SD_VARLINK_FIELD_COMMENT("Overall percentage of completion for this operation"),
                SD_VARLINK_DEFINE_OUTPUT(progress_percent, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(
                DiskTooSmall,
                SD_VARLINK_FIELD_COMMENT("The minimum required size of the disk to fit the specified image",
                SD_VARLINK_DEFINE_FIELD(min_size, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ERROR(
                InsufficientFreeSpace,
                SD_VARLINK_FIELD_COMMENT("An estimate of the amount of usable free space on disk."),
                SD_VARLINK_DEFINE_FIELD(estimated_free, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The minimum required amount of free space to fit the image."),
                SD_VARLINK_DEFINE_FIELD(min_required, SD_VARLINK_INT, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Repart,
                "io.systemd.Repart",
                SD_VARLINK_INTERFACE_COMMENT("API for declaratively re-partitioning disks using systemd-repart"),

                SD_VARLINK_SYMBOL_COMMENT("Behaviors for disks that are completely empty (i.e. don't have a partition table yet)"),
                &vl_type_EmptyMode,
                SD_VARLINK_SYMBOL_COMMENT("The configuration to operate on"),
                &vl_type_Configuration,

                SD_VARLINK_SYMBOL_COMMENT("Checks if an image will fit on a given target disk."),
                &vl_method_Check,
                SD_VARLINK_SYMBOL_COMMENT("Deploy an image onto a given target disk."),
                &vl_method_Partition,

                SD_VARLINK_SYMBOL_COMMENT("The target disk is too small to fit the requested partitions."),
                &vl_error_DiskTooSmall,
                SD_VARLINK_SYMBOL_COMMENT("The target disk has insufficient free space to fit the requested partitions."),
                &vl_error_InsufficientFreeSpace);
