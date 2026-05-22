/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.Sysinstall.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ProgressPhase,

                SD_VARLINK_DEFINE_ENUM_VALUE(validate_block_device),
                SD_VARLINK_DEFINE_ENUM_VALUE(load_credentials),
                SD_VARLINK_DEFINE_ENUM_VALUE(encrypt_credentials),

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
                SD_VARLINK_DEFINE_ENUM_VALUE(rereading_table),

                SD_VARLINK_DEFINE_ENUM_VALUE(mount_partitions),
                SD_VARLINK_DEFINE_ENUM_VALUE(install_kernel),
                SD_VARLINK_DEFINE_ENUM_VALUE(install_bootloader),
                SD_VARLINK_DEFINE_ENUM_VALUE(unmount_partitions));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Run,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Full path to the block device node to operate on. If omitted, dryRun must be true, in which case the minimal disk size is determined."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true this will ponder if the installation would fit on the block device and report a summary. It does not actually write anything to disk. Must be set to false to actually install the OS to the block device."),
                SD_VARLINK_DEFINE_INPUT(dryRun, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Path to directory containing definition files."),
                SD_VARLINK_DEFINE_INPUT(definitions, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, fully erase the target block device."),
                SD_VARLINK_DEFINE_INPUT(erase, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("If true, this modifies EFI variables."),
                SD_VARLINK_DEFINE_INPUT(variables, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The path to a kernel image, if missing the current kernel is used."),
                SD_VARLINK_DEFINE_INPUT(kernelImage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),


                SD_VARLINK_FIELD_COMMENT("If true, copy current locale to target system"),
                SD_VARLINK_DEFINE_INPUT(copyLocale, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, copy current keymap to target system"),
                SD_VARLINK_DEFINE_INPUT(copyKeymap, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, copy current timezone to target system"),
                SD_VARLINK_DEFINE_INPUT(copyTimezone, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("A list of credentials with literal value in format 'ID:VALUE' to be installed on the new system."),
                SD_VARLINK_DEFINE_INPUT(setCredentials, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A list of credentials to be loaded in format 'ID:PATH' to be installed on the new system."),
                SD_VARLINK_DEFINE_INPUT(loadCredentials, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("In dry mode returns the minimal disk size required."),
                SD_VARLINK_DEFINE_OUTPUT(minimalSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("In dry mode returns the current allocated size of the selected block device."),
                SD_VARLINK_DEFINE_OUTPUT(currentSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, a phase identifier is sent in progress updates."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(phase, ProgressPhase, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, an object identifier string is sent in progress updates."),
                SD_VARLINK_DEFINE_OUTPUT(object, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, a progress percentage (specific to the work done for the specified phase+object is sent in progress updates)."),
                SD_VARLINK_DEFINE_OUTPUT(progress, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ListCandidateDevices,
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
                io_systemd_Sysinstall,
                "io.systemd.Sysinstall",
                SD_VARLINK_INTERFACE_COMMENT("API for installing the OS to another block device."),

                SD_VARLINK_SYMBOL_COMMENT("Progress phase identifiers. Note that we might add more phases here, and thus identifiers. Frontends can choose to display the phase to the user in some human readable form, or not do that, but if they do it and they receive a notification for a so far unknown phase, they should just ignore it."),
                &vl_type_ProgressPhase,

                SD_VARLINK_SYMBOL_COMMENT("Invoke the actual installation of the OS. If invoked with 'more' enabled will report progress, otherwise will just report completion."),
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
