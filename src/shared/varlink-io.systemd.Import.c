/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Import.h"

static VARLINK_DEFINE_ENUM_TYPE(
                ImageClass,
                VARLINK_FIELD_COMMENT("An image to boot as a system on baremetal, in a VM or as a container"),
                VARLINK_DEFINE_ENUM_VALUE(machine),
                VARLINK_FIELD_COMMENT("An portable service image"),
                VARLINK_DEFINE_ENUM_VALUE(portable),
                VARLINK_FIELD_COMMENT("A system extension image"),
                VARLINK_DEFINE_ENUM_VALUE(sysext),
                VARLINK_FIELD_COMMENT("A configuration extension image"),
                VARLINK_DEFINE_ENUM_VALUE(confext));

static VARLINK_DEFINE_ENUM_TYPE(
                RemoteType,
                VARLINK_FIELD_COMMENT("Raw binary disk images, typically in a GPT envelope"),
                VARLINK_DEFINE_ENUM_VALUE(raw),
                VARLINK_FIELD_COMMENT("A tarball, optionally compressed"),
                VARLINK_DEFINE_ENUM_VALUE(tar));

static VARLINK_DEFINE_ENUM_TYPE(
                TransferType,
                VARLINK_FIELD_COMMENT("A local import of a tarball"),
                VARLINK_DEFINE_ENUM_VALUE(import_tar),
                VARLINK_FIELD_COMMENT("A local import of a raw disk image"),
                VARLINK_DEFINE_ENUM_VALUE(import_raw),
                VARLINK_FIELD_COMMENT("A local import of a file system tree"),
                VARLINK_DEFINE_ENUM_VALUE(import_fs),
                VARLINK_FIELD_COMMENT("A local export of a tarball"),
                VARLINK_DEFINE_ENUM_VALUE(export_tar),
                VARLINK_FIELD_COMMENT("A local export of a raw disk image"),
                VARLINK_DEFINE_ENUM_VALUE(export_raw),
                VARLINK_FIELD_COMMENT("A download of a tarball"),
                VARLINK_DEFINE_ENUM_VALUE(pull_tar),
                VARLINK_FIELD_COMMENT("A download of a raw disk image"),
                VARLINK_DEFINE_ENUM_VALUE(pull_raw));

static VARLINK_DEFINE_ENUM_TYPE(
                ImageVerify,
                VARLINK_FIELD_COMMENT("No verification"),
                VARLINK_DEFINE_ENUM_VALUE(no),
                VARLINK_FIELD_COMMENT("Verify that downloads match checksum file (SHA256SUMS), but do not check signature of checksum file"),
                VARLINK_DEFINE_ENUM_VALUE(checksum),
                VARLINK_FIELD_COMMENT("Verify that downloads match checksum file (SHA256SUMS), and check signature of checksum file."),
                VARLINK_DEFINE_ENUM_VALUE(signature));

static VARLINK_DEFINE_STRUCT_TYPE(
                LogMessage,
                VARLINK_FIELD_COMMENT("The log message"),
                VARLINK_DEFINE_FIELD(message, VARLINK_STRING, 0),
                VARLINK_FIELD_COMMENT("The priority of the log message, using the BSD syslog priority levels"),
                VARLINK_DEFINE_FIELD(priority, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                ListTransfers,
                VARLINK_FIELD_COMMENT("Image class to filter by"),
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("A unique numeric identifier for the ongoing transfer"),
                VARLINK_DEFINE_OUTPUT(id, VARLINK_INT, 0),
                VARLINK_FIELD_COMMENT("The type of transfer"),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(type, TransferType, 0),
                VARLINK_FIELD_COMMENT("The remote URL"),
                VARLINK_DEFINE_OUTPUT(remote, VARLINK_STRING, 0),
                VARLINK_FIELD_COMMENT("The local image name"),
                VARLINK_DEFINE_OUTPUT(local, VARLINK_STRING, 0),
                VARLINK_FIELD_COMMENT("The class of the image"),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(class, ImageClass, 0),
                VARLINK_FIELD_COMMENT("Progress in percent"),
                VARLINK_DEFINE_OUTPUT(percent, VARLINK_FLOAT, 0));

static VARLINK_DEFINE_METHOD(
                Pull,
                VARLINK_FIELD_COMMENT("The remote URL to download from"),
                VARLINK_DEFINE_INPUT(remote, VARLINK_STRING, 0),
                VARLINK_FIELD_COMMENT("The local image name to download to"),
                VARLINK_DEFINE_INPUT(local, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The type of the resource"),
                VARLINK_DEFINE_INPUT_BY_TYPE(type, RemoteType, 0),
                VARLINK_FIELD_COMMENT("The image class"),
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, 0),
                VARLINK_FIELD_COMMENT("The whether and how thoroughly to verify the download before installing it locally. Defauts to 'signature'."),
                VARLINK_DEFINE_INPUT_BY_TYPE(verify, ImageVerify, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("If true, an existing image by the local name is deleted. Defaults to false."),
                VARLINK_DEFINE_INPUT(force, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Whether to make the image read-only after downloading. Defaults ot false."),
                VARLINK_DEFINE_INPUT(readOnly, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Whether to keep a pristine copy of the download separate from the locally installed image. Defaults to false."),
                VARLINK_DEFINE_INPUT(keepDownload, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Whether to permit interactive authentication. Defaults to false."),
                VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("A progress update, as percent value"),
                VARLINK_DEFINE_OUTPUT(progress, VARLINK_FLOAT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("A log message about the ongoing transfer"),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(log, LogMessage, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The numeric ID of this download"),
                VARLINK_DEFINE_OUTPUT(id, VARLINK_INT, VARLINK_NULLABLE));

static VARLINK_DEFINE_ERROR(AlreadyInProgress);
static VARLINK_DEFINE_ERROR(TransferCancelled);
static VARLINK_DEFINE_ERROR(TransferFailed);
static VARLINK_DEFINE_ERROR(NoTransfers);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Import,
                "io.systemd.Import",
                VARLINK_SYMBOL_COMMENT("Describes the class of images"),
                &vl_type_ImageClass,
                VARLINK_SYMBOL_COMMENT("Describes the type of a images to transfer"),
                &vl_type_RemoteType,
                VARLINK_SYMBOL_COMMENT("Describes the type of a transfer"),
                &vl_type_TransferType,
                VARLINK_SYMBOL_COMMENT("Describes whether and how thoroughly to verify the download before installing it locally"),
                &vl_type_ImageVerify,
                VARLINK_SYMBOL_COMMENT("Structure for log messages associated with a transfer operation"),
                &vl_type_LogMessage,
                VARLINK_SYMBOL_COMMENT("List ongoing transfers, or query details about specific transfers"),
                &vl_method_ListTransfers,
                VARLINK_SYMBOL_COMMENT("Download a .tar or .raw file. This must be called with the 'more' flag enabled. It will immediately return the numeric ID of the transfer, and then follow up with progress and log message updates, until the transfer is complete."),
                &vl_method_Pull,
                VARLINK_SYMBOL_COMMENT("A transfer for the specified file is already ongoing"),
                &vl_error_AlreadyInProgress,
                VARLINK_SYMBOL_COMMENT("The transfer has been cancelled on user request"),
                &vl_error_TransferCancelled,
                VARLINK_SYMBOL_COMMENT("The transfer failed"),
                &vl_error_TransferFailed,
                VARLINK_SYMBOL_COMMENT("No currently ongoing transfer"),
                &vl_error_NoTransfers);
