/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.SysInstall.h"
#include "varlink-io.systemd.Repart.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ProgressPhase,

                SD_VARLINK_DEFINE_ENUM_VALUE(load_credentials),
                SD_VARLINK_DEFINE_ENUM_VALUE(encrypt_credentials),
                SD_VARLINK_DEFINE_ENUM_VALUE(install_partitions),
                SD_VARLINK_DEFINE_ENUM_VALUE(mount_partitions),
                SD_VARLINK_DEFINE_ENUM_VALUE(install_kernel),
                SD_VARLINK_DEFINE_ENUM_VALUE(install_bootloader),
                SD_VARLINK_DEFINE_ENUM_VALUE(unmount_partitions));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                DeviceFit,

                SD_VARLINK_DEFINE_ENUM_VALUE(enough_free_space),
                SD_VARLINK_DEFINE_ENUM_VALUE(insufficent_free_space),
                SD_VARLINK_DEFINE_ENUM_VALUE(disk_too_small),
                SD_VARLINK_DEFINE_ENUM_VALUE(conflicting_disk_label_present));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Credential,
                SD_VARLINK_FIELD_COMMENT("The id of the credential."),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The value, either a literal or a path if load is set to true."),
                SD_VARLINK_DEFINE_FIELD(value, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("If true, the value is used as path to load the credential from."),
                SD_VARLINK_DEFINE_FIELD(load, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Run,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Full path to the block device node to operate on."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Path to directory containing definition files."),
                SD_VARLINK_DEFINE_INPUT(definitions, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, fully erase the target block device."),
                SD_VARLINK_DEFINE_INPUT(erase, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("If true, EFI variables are modified to register the installed boot loader in the firmware's boot options database."),
                SD_VARLINK_DEFINE_INPUT(variables, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The path to a kernel image, if missing the current kernel is dedected and used."),
                SD_VARLINK_DEFINE_INPUT(kernelImage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("If true, the current locale is copied to target system"),
                SD_VARLINK_DEFINE_INPUT(copyLocale, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, the current keymap is copied to target system"),
                SD_VARLINK_DEFINE_INPUT(copyKeymap, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, the current timezone is copied to target system"),
                SD_VARLINK_DEFINE_INPUT(copyTimezone, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("A list of credentials to be installed to target system."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(credentials, Credential, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, a phase identifier is sent in progress updates."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(phase, ProgressPhase, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, an object identifier string is sent in progress updates."),
                SD_VARLINK_DEFINE_OUTPUT(object, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, a progress percentage (specific to the work done for the specified phase+object is sent in progress updates)."),
                SD_VARLINK_DEFINE_OUTPUT(progress, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListCandidateDevices,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Path to directory containing definition files, used to evaluate the fit of the target OS for each block device."),
                SD_VARLINK_DEFINE_INPUT(definitions, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, keep the call open after the initial enumeration and stream live add/remove notifications as block-subsystem uevents arrive. The end of the initial enumeration is marked by exactly one notification with action='ready' and no other fields. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(subscribe, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Discriminator field. Only set in subscribe mode. 'add' carries the full device record, 'remove' carries only node, 'ready' carries no other fields and is sent once after the initial enumeration."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(action, BlockDeviceAction, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The device node path of the block device."),
                SD_VARLINK_DEFINE_OUTPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("List of symlinks pointing to the device node, if any."),
                SD_VARLINK_DEFINE_OUTPUT(symlinks, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The Linux kernel disk sequence number identifying the medium."),
                SD_VARLINK_DEFINE_OUTPUT(diskseq, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The size of the block device in bytes."),
                SD_VARLINK_DEFINE_OUTPUT(sizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The device vendor string if known."),
                SD_VARLINK_DEFINE_OUTPUT(vendor, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The device model string if known."),
                SD_VARLINK_DEFINE_OUTPUT(model, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The subsystem the block device belongs to if known."),
                SD_VARLINK_DEFINE_OUTPUT(subsystem, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The fit indicating whether the OS would have enough available space on the device."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(fit, DeviceFit, 0),
                SD_VARLINK_FIELD_COMMENT("Minimal size of the disk required for the installation."),
                SD_VARLINK_DEFINE_OUTPUT(minimalSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Additional free space needed for the installation."),
                SD_VARLINK_DEFINE_OUTPUT(needFreeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Current allocated size of this block device."),
                SD_VARLINK_DEFINE_OUTPUT(currentSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoCandidateDevices);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_SysInstall,
                "io.systemd.SysInstall",
                SD_VARLINK_INTERFACE_COMMENT("API for installing the OS to another block device."),

                SD_VARLINK_SYMBOL_COMMENT("Progress phase identifiers. Note that we might add more phases here, and thus identifiers. Frontends can choose to display the phase to the user in some human readable form, or not do that, but if they do it and they receive a notification for a so far unknown phase, they should just ignore it."),
                &vl_type_ProgressPhase,

                SD_VARLINK_SYMBOL_COMMENT("Description about the fit of an OS on a block device."),
                &vl_type_DeviceFit,

                SD_VARLINK_SYMBOL_COMMENT("Discriminator on streamed ListCandidateDevices replies in subscribe mode."),
                &vl_type_BlockDeviceAction,

                SD_VARLINK_SYMBOL_COMMENT("A credential to install to target OS."),
                &vl_type_Credential,

                SD_VARLINK_SYMBOL_COMMENT("Invoke the actual installation of the OS. If invoked with 'more' enabled will report progress, otherwise will just report completion."),
                &vl_method_Run,

                SD_VARLINK_SYMBOL_COMMENT("Return a list of candidate block devices, i.e. that support partition scanning and other requirements for successful operation."),
                &vl_method_ListCandidateDevices,
                SD_VARLINK_SYMBOL_COMMENT("Not a single candidate block device could be found."),
                &vl_error_NoCandidateDevices);
