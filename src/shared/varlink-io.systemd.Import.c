/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Import.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ImageClass,
                SD_VARLINK_FIELD_COMMENT("An image to boot as a system on baremetal, in a VM or as a container"),
                SD_VARLINK_DEFINE_ENUM_VALUE(machine),
                SD_VARLINK_FIELD_COMMENT("An portable service image"),
                SD_VARLINK_DEFINE_ENUM_VALUE(portable),
                SD_VARLINK_FIELD_COMMENT("A system extension image"),
                SD_VARLINK_DEFINE_ENUM_VALUE(sysext),
                SD_VARLINK_FIELD_COMMENT("A configuration extension image"),
                SD_VARLINK_DEFINE_ENUM_VALUE(confext));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                RemoteType,
                SD_VARLINK_FIELD_COMMENT("Raw binary disk images, typically in a GPT envelope"),
                SD_VARLINK_DEFINE_ENUM_VALUE(raw),
                SD_VARLINK_FIELD_COMMENT("A tarball, optionally compressed"),
                SD_VARLINK_DEFINE_ENUM_VALUE(tar));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                TransferType,
                SD_VARLINK_FIELD_COMMENT("A local import of a tarball"),
                SD_VARLINK_DEFINE_ENUM_VALUE(import_tar),
                SD_VARLINK_FIELD_COMMENT("A local import of a raw disk image"),
                SD_VARLINK_DEFINE_ENUM_VALUE(import_raw),
                SD_VARLINK_FIELD_COMMENT("A local import of a file system tree"),
                SD_VARLINK_DEFINE_ENUM_VALUE(import_fs),
                SD_VARLINK_FIELD_COMMENT("A local export of a tarball"),
                SD_VARLINK_DEFINE_ENUM_VALUE(export_tar),
                SD_VARLINK_FIELD_COMMENT("A local export of a raw disk image"),
                SD_VARLINK_DEFINE_ENUM_VALUE(export_raw),
                SD_VARLINK_FIELD_COMMENT("A download of a tarball"),
                SD_VARLINK_DEFINE_ENUM_VALUE(pull_tar),
                SD_VARLINK_FIELD_COMMENT("A download of a raw disk image"),
                SD_VARLINK_DEFINE_ENUM_VALUE(pull_raw));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ImageVerify,
                SD_VARLINK_FIELD_COMMENT("No verification"),
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_FIELD_COMMENT("Verify that downloads match checksum file (SHA256SUMS), but do not check signature of checksum file"),
                SD_VARLINK_DEFINE_ENUM_VALUE(checksum),
                SD_VARLINK_FIELD_COMMENT("Verify that downloads match checksum file (SHA256SUMS), and check signature of checksum file."),
                SD_VARLINK_DEFINE_ENUM_VALUE(signature));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                LogMessage,
                SD_VARLINK_FIELD_COMMENT("The log message"),
                SD_VARLINK_DEFINE_FIELD(message, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The priority of the log message, using the BSD syslog priority levels"),
                SD_VARLINK_DEFINE_FIELD(priority, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListTransfers,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Image class to filter by"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A unique numeric identifier for the ongoing transfer"),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The type of transfer"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, TransferType, 0),
                SD_VARLINK_FIELD_COMMENT("The remote URL"),
                SD_VARLINK_DEFINE_OUTPUT(remote, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The local image name"),
                SD_VARLINK_DEFINE_OUTPUT(local, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The class of the image"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(class, ImageClass, 0),
                SD_VARLINK_FIELD_COMMENT("Progress in percent"),
                SD_VARLINK_DEFINE_OUTPUT(percent, SD_VARLINK_FLOAT, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Pull,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("The remote URL to download from"),
                SD_VARLINK_DEFINE_INPUT(remote, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The local image name to download to"),
                SD_VARLINK_DEFINE_INPUT(local, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The type of the resource"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(type, RemoteType, 0),
                SD_VARLINK_FIELD_COMMENT("The image class"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, 0),
                SD_VARLINK_FIELD_COMMENT("The whether and how thoroughly to verify the download before installing it locally. Defaults to 'signature'."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(verify, ImageVerify, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, an existing image by the local name is deleted. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(force, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to make the image read-only after downloading. Defaults ot false."),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to keep a pristine copy of the download separate from the locally installed image. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(keepDownload, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("A progress update, as percent value"),
                SD_VARLINK_DEFINE_OUTPUT(progress, SD_VARLINK_FLOAT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A log message about the ongoing transfer"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(log, LogMessage, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The numeric ID of this download"),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(AlreadyInProgress);
static SD_VARLINK_DEFINE_ERROR(TransferCancelled);
static SD_VARLINK_DEFINE_ERROR(TransferFailed);
static SD_VARLINK_DEFINE_ERROR(NoTransfers);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Import,
                "io.systemd.Import",
                SD_VARLINK_SYMBOL_COMMENT("Describes the class of images"),
                &vl_type_ImageClass,
                SD_VARLINK_SYMBOL_COMMENT("Describes the type of a images to transfer"),
                &vl_type_RemoteType,
                SD_VARLINK_SYMBOL_COMMENT("Describes the type of a transfer"),
                &vl_type_TransferType,
                SD_VARLINK_SYMBOL_COMMENT("Describes whether and how thoroughly to verify the download before installing it locally"),
                &vl_type_ImageVerify,
                SD_VARLINK_SYMBOL_COMMENT("Structure for log messages associated with a transfer operation"),
                &vl_type_LogMessage,
                SD_VARLINK_SYMBOL_COMMENT("List ongoing transfers, or query details about specific transfers"),
                &vl_method_ListTransfers,
                SD_VARLINK_SYMBOL_COMMENT("Download a .tar or .raw file. This must be called with the 'more' flag enabled. It will immediately return the numeric ID of the transfer, and then follow up with progress and log message updates, until the transfer is complete."),
                &vl_method_Pull,
                SD_VARLINK_SYMBOL_COMMENT("A transfer for the specified file is already ongoing"),
                &vl_error_AlreadyInProgress,
                SD_VARLINK_SYMBOL_COMMENT("The transfer has been cancelled on user request"),
                &vl_error_TransferCancelled,
                SD_VARLINK_SYMBOL_COMMENT("The transfer failed"),
                &vl_error_TransferFailed,
                SD_VARLINK_SYMBOL_COMMENT("No currently ongoing transfer"),
                &vl_error_NoTransfers);
