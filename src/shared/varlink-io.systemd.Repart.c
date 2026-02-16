/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.Repart.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ProgressPhase,
                SD_VARLINK_DEFINE_ENUM_VALUE(loading_definitions),
                SD_VARLINK_DEFINE_ENUM_VALUE(loading_table),
                SD_VARLINK_DEFINE_ENUM_VALUE(opening_copy_block_sources),
                SD_VARLINK_DEFINE_ENUM_VALUE(acquiring_partition_labels),
                SD_VARLINK_DEFINE_ENUM_VALUE(minimizing),
                SD_VARLINK_DEFINE_ENUM_VALUE(placing),
                SD_VARLINK_DEFINE_ENUM_VALUE(wiping_disk),
                SD_VARLINK_DEFINE_ENUM_VALUE(wiping_partition),
                SD_VARLINK_DEFINE_ENUM_VALUE(copying_partition),
                SD_VARLINK_DEFINE_ENUM_VALUE(formatting_partition),
                SD_VARLINK_DEFINE_ENUM_VALUE(adjusting_partition),
                SD_VARLINK_DEFINE_ENUM_VALUE(writing_table),
                SD_VARLINK_DEFINE_ENUM_VALUE(rereading_table));

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

static SD_VARLINK_DEFINE_METHOD_FULL(
                Run,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Full path to the block device node to operate on. If omitted, dryRun must be true, in which case the minimal disk size is determined."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Decides whether to install the OS in addition to what is already on it, or if it shall be erased."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(empty, EmptyMode, 0),
                SD_VARLINK_FIELD_COMMENT("If true this will ponder if the installation would fit, but does not actually write anything to disk. Must be set to false to actually make changes."),
                SD_VARLINK_DEFINE_INPUT(dryRun, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The seed value to derive partition and file system UUIDs from"),
                SD_VARLINK_DEFINE_INPUT(seed, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to directory containing definition files."),
                SD_VARLINK_DEFINE_INPUT(definitions, SD_VARLINK_STRING, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("If true, automatically defer creation of all partitions whose label is \"empty\"."),
                SD_VARLINK_DEFINE_INPUT(deferPartitionsEmpty, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, automatically defer creation of all partitions which are marked for factory reset."),
                SD_VARLINK_DEFINE_INPUT(deferPartitionsFactoryReset, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("In dry-run mode returns the minimal disk size required."),
                SD_VARLINK_DEFINE_OUTPUT(minimalSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("In dry-run mode returns the size of the selected block device."),
                SD_VARLINK_DEFINE_OUTPUT(currentSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, a phase identifier is sent in progress updates."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(phase, ProgressPhase, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, an object identifier string is sent in progress updates."),
                SD_VARLINK_DEFINE_OUTPUT(object, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, a progress percentrage (specific to the work done for the specified phase+object is sent in progress updates."),
                SD_VARLINK_DEFINE_OUTPUT(progress, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListCandidateDevices,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Control whether to include the root disk of the currently booted OS in the list. Defaults to false, i.e. the root disk is included."),
                SD_VARLINK_DEFINE_INPUT(ignoreRoot, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Control whether to include block devices with zero size in the list, i.e. typically block devices without any inserted medium. Defaults to false, i.e. empty block devices are included."),
                SD_VARLINK_DEFINE_INPUT(ignoreEmpty, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The device node path of the block device."),
                SD_VARLINK_DEFINE_OUTPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("List of symlinks pointing to the device node, if any."),
                SD_VARLINK_DEFINE_OUTPUT(symlinks, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The Linux kernel disk sequence number identifying the medium."),
                SD_VARLINK_DEFINE_OUTPUT(diskseq, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The size of the block device in bytes."),
                SD_VARLINK_DEFINE_OUTPUT(sizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The device vendor string if known"),
                SD_VARLINK_DEFINE_OUTPUT(vendor, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The device model string if known"),
                SD_VARLINK_DEFINE_OUTPUT(model, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The subsystem the block device belongs to if known"),
                SD_VARLINK_DEFINE_OUTPUT(subsystem, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));


static SD_VARLINK_DEFINE_ERROR(NoCandidateDevices);
static SD_VARLINK_DEFINE_ERROR(ConflictingDiskLabelPresent);
static SD_VARLINK_DEFINE_ERROR(
                InsufficientFreeSpace,
                SD_VARLINK_FIELD_COMMENT("Minimal size of the disk required for the installation."),
                SD_VARLINK_DEFINE_FIELD(minimalSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Additional free space needed on the selected disk."),
                SD_VARLINK_DEFINE_FIELD(needFreeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Size of the selected block device."),
                SD_VARLINK_DEFINE_FIELD(currentSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(
                DiskTooSmall,
                SD_VARLINK_FIELD_COMMENT("Minimal size of the disk required for the installation."),
                SD_VARLINK_DEFINE_FIELD(minimalSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Actual size of the selected block device."),
                SD_VARLINK_DEFINE_FIELD(currentSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Repart,
                "io.systemd.Repart",
                SD_VARLINK_INTERFACE_COMMENT("API for declaratively re-partitioning disks using systemd-repart."),

                SD_VARLINK_SYMBOL_COMMENT("Behaviors for disks that are completely empty (i.e. don't have a partition table yet)"),
                &vl_type_EmptyMode,
                SD_VARLINK_SYMBOL_COMMENT("Progress phase identifiers. Note that we might add more phases here, and thus identifiers. Frontends can choose to display the phase to the user in some human readable form, or not do that, but if they do it and they receive a notification for a so far unknown phase, they should just ignore it."),
                &vl_type_ProgressPhase,

                SD_VARLINK_SYMBOL_COMMENT("Invoke the actual repartitioning operation, either in dry-run mode or for real. If invoked with 'more' enabled will report progress, otherwise will just report completion."),
                &vl_method_Run,
                SD_VARLINK_SYMBOL_COMMENT("An incompatible disk label present, and not told to erase it."),
                &vl_error_ConflictingDiskLabelPresent,
                SD_VARLINK_SYMBOL_COMMENT("The target disk has insufficient free space to fit all requested partitions. (But the disk would fit, if emptied.)"),
                &vl_error_InsufficientFreeSpace,
                SD_VARLINK_SYMBOL_COMMENT("The target disk is too small to fit the installation. (Regardless if emptied or not.)"),
                &vl_error_DiskTooSmall,

                SD_VARLINK_SYMBOL_COMMENT("Return a list of candidate block devices, i.e. that support partition scanning and other requirements for successful operation."),
                &vl_method_ListCandidateDevices,
                SD_VARLINK_SYMBOL_COMMENT("Not a single candidate block device could be found."),
                &vl_error_NoCandidateDevices);
