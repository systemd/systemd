/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.MountFileSystem.h"

static VARLINK_DEFINE_ENUM_TYPE(
                PartitionDesignator,
                VARLINK_DEFINE_ENUM_VALUE(root),
                VARLINK_DEFINE_ENUM_VALUE(usr),
                VARLINK_DEFINE_ENUM_VALUE(home),
                VARLINK_DEFINE_ENUM_VALUE(srv),
                VARLINK_DEFINE_ENUM_VALUE(esp),
                VARLINK_DEFINE_ENUM_VALUE(xbootldr),
                VARLINK_DEFINE_ENUM_VALUE(swap),
                VARLINK_DEFINE_ENUM_VALUE(root_verity),
                VARLINK_DEFINE_ENUM_VALUE(usr_verity),
                VARLINK_DEFINE_ENUM_VALUE(root_verity_sig),
                VARLINK_DEFINE_ENUM_VALUE(usr_verity_sig),
                VARLINK_DEFINE_ENUM_VALUE(tmp),
                VARLINK_DEFINE_ENUM_VALUE(var));

static VARLINK_DEFINE_STRUCT_TYPE(
                PartitionInfo,
                VARLINK_DEFINE_FIELD(designator, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(writable, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(growFileSystem, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(partitionNumber, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(architecture, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(partitionUuid, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(fileSystemType, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(partitionLabel, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(size, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(offset, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(mountFileDescriptor, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                MountImage,
                VARLINK_DEFINE_INPUT(imageFileDescriptor, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(readOnly, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(growFileSystems, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(password, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(imagePolicy, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(partitions, PartitionInfo, VARLINK_ARRAY),
                VARLINK_DEFINE_OUTPUT(imagePolicy, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(imageSize, VARLINK_INT, 0),
                VARLINK_DEFINE_OUTPUT(sectorSize, VARLINK_INT, 0),
                VARLINK_DEFINE_OUTPUT(imageName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(imageUuid, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_ERROR(IncompatibleImage);
static VARLINK_DEFINE_ERROR(MultipleRootPartitionsFound);
static VARLINK_DEFINE_ERROR(RootPartitionNotFound);
static VARLINK_DEFINE_ERROR(DeniedByImagePolicy);

VARLINK_DEFINE_INTERFACE(
                io_systemd_MountFileSystem,
                "io.systemd.MountFileSystem",
                &vl_type_PartitionDesignator,
                &vl_type_PartitionInfo,
                &vl_method_MountImage,
                &vl_error_IncompatibleImage,
                &vl_error_MultipleRootPartitionsFound,
                &vl_error_RootPartitionNotFound,
                &vl_error_DeniedByImagePolicy);
