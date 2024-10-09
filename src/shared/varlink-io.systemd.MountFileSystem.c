/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.MountFileSystem.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                PartitionDesignator,
                SD_VARLINK_DEFINE_ENUM_VALUE(root),
                SD_VARLINK_DEFINE_ENUM_VALUE(usr),
                SD_VARLINK_DEFINE_ENUM_VALUE(home),
                SD_VARLINK_DEFINE_ENUM_VALUE(srv),
                SD_VARLINK_DEFINE_ENUM_VALUE(esp),
                SD_VARLINK_DEFINE_ENUM_VALUE(xbootldr),
                SD_VARLINK_DEFINE_ENUM_VALUE(swap),
                SD_VARLINK_DEFINE_ENUM_VALUE(root_verity),
                SD_VARLINK_DEFINE_ENUM_VALUE(usr_verity),
                SD_VARLINK_DEFINE_ENUM_VALUE(root_verity_sig),
                SD_VARLINK_DEFINE_ENUM_VALUE(usr_verity_sig),
                SD_VARLINK_DEFINE_ENUM_VALUE(tmp),
                SD_VARLINK_DEFINE_ENUM_VALUE(var));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PartitionInfo,
                SD_VARLINK_DEFINE_FIELD(designator, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(writable, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(growFileSystem, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(partitionNumber, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(architecture, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(partitionUuid, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(fileSystemType, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(partitionLabel, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(size, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(offset, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(mountFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                MountImage,
                SD_VARLINK_DEFINE_INPUT(imageFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(growFileSystems, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(password, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(imagePolicy, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(partitions, PartitionInfo, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(imagePolicy, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(imageSize, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_OUTPUT(sectorSize, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_OUTPUT(imageName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(imageUuid, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(IncompatibleImage);
static SD_VARLINK_DEFINE_ERROR(MultipleRootPartitionsFound);
static SD_VARLINK_DEFINE_ERROR(RootPartitionNotFound);
static SD_VARLINK_DEFINE_ERROR(DeniedByImagePolicy);
static SD_VARLINK_DEFINE_ERROR(KeyNotFound);
static SD_VARLINK_DEFINE_ERROR(VerityFailure);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_MountFileSystem,
                "io.systemd.MountFileSystem",
                &vl_type_PartitionDesignator,
                &vl_type_PartitionInfo,
                &vl_method_MountImage,
                &vl_error_IncompatibleImage,
                &vl_error_MultipleRootPartitionsFound,
                &vl_error_RootPartitionNotFound,
                &vl_error_DeniedByImagePolicy,
                &vl_error_KeyNotFound,
                &vl_error_VerityFailure);
