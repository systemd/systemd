/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Volumes.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                VolumeType,
                SD_VARLINK_FIELD_COMMENT("Block device volumes, only block addressable"),
                SD_VARLINK_DEFINE_ENUM_VALUE(blk),
                SD_VARLINK_FIELD_COMMENT("Regular file volumes, byte addressable"),
                SD_VARLINK_DEFINE_ENUM_VALUE(reg),
                SD_VARLINK_FIELD_COMMENT("POSIX file system volumes, path/offset addressable"),
                SD_VARLINK_DEFINE_ENUM_VALUE(dir));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                CreateMode,
                SD_VARLINK_FIELD_COMMENT("Open if exists already, create if missing"),
                SD_VARLINK_DEFINE_ENUM_VALUE(any),
                SD_VARLINK_FIELD_COMMENT("Create if missing, fail if exists already"),
                SD_VARLINK_DEFINE_ENUM_VALUE(new),
                SD_VARLINK_FIELD_COMMENT("Open if exists already, fail if missing"),
                SD_VARLINK_DEFINE_ENUM_VALUE(open));

static SD_VARLINK_DEFINE_METHOD(
                Acquire,
                SD_VARLINK_FIELD_COMMENT("The name of the volume to acquire"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Determines whether to open or create a volume"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(createMode, CreateMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The template to use when creating a new volume"),
                SD_VARLINK_DEFINE_INPUT(template, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Controls read/write access to the volume. If false and the volume cannot be opened in writable mode the call will fail. If null volume will be acquired in writable mode of possible, read-only otherwise."),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Dictates what kind of volume to request. Some volumes can be acquired either as regular file or as block device. In all other cases if this value doesn't match the volume type, the request will fail."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(requestAs, VolumeType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The size of the volume, if one is created. Has no effect of no volume is created."),
                SD_VARLINK_DEFINE_INPUT(createSize, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Returns an index into the file descriptor table of this reply, pointing to the file descriptor to the volume. Must be an opened file descriptor, not an O_PATH."),
                SD_VARLINK_DEFINE_OUTPUT(fileDescriptorIndex, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The volume type, i.e. ultimately the inode type of the returned file descriptor"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, VolumeType, 0),
                SD_VARLINK_FIELD_COMMENT("Whether volume has been opened in read-only mode"),
                SD_VARLINK_DEFINE_OUTPUT(readOnly, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Specifies a shell glob to filter enumeration by"),
                SD_VARLINK_DEFINE_INPUT(matchName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The volume's primary name"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Additional names"),
                SD_VARLINK_DEFINE_OUTPUT(aliases, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The type of the volume"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, VolumeType, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the volume is read-only."),
                SD_VARLINK_DEFINE_OUTPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Size in bytes, if known"),
                SD_VARLINK_DEFINE_OUTPUT(sizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Used bytes, if known"),
                SD_VARLINK_DEFINE_OUTPUT(usedBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListTemplates,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Specifies a shell glob to filter enumeration by"),
                SD_VARLINK_DEFINE_INPUT(matchName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The template's name"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The type of the volumes defined by this template"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, VolumeType, 0));

static SD_VARLINK_DEFINE_ERROR(NoSuchVolume);
static SD_VARLINK_DEFINE_ERROR(VolumeExists);
static SD_VARLINK_DEFINE_ERROR(NoSuchTemplate);
static SD_VARLINK_DEFINE_ERROR(TypeNotSupported);
static SD_VARLINK_DEFINE_ERROR(InvalidRequestAs);
static SD_VARLINK_DEFINE_ERROR(BadTemplate);
static SD_VARLINK_DEFINE_ERROR(CreateNotSupported);
static SD_VARLINK_DEFINE_ERROR(CreateSizeRequired);
static SD_VARLINK_DEFINE_ERROR(ReadOnlyVolume);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Volumes,
                "io.systemd.Volumes",
                SD_VARLINK_INTERFACE_COMMENT("Volume Acquisition API"),
                SD_VARLINK_SYMBOL_COMMENT("Encodes three classes of volumes. This follows the kernel's nomenclature for inode types, i.e. reg, dir, blk."),
                &vl_type_VolumeType,
                SD_VARLINK_SYMBOL_COMMENT("Determines whether to open existing or create a new volume."),
                &vl_type_CreateMode,
                SD_VARLINK_SYMBOL_COMMENT("Acquires a file descriptor for a volume."),
                &vl_method_Acquire,
                SD_VARLINK_SYMBOL_COMMENT("Lists available volumes."),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("Lists available templates."),
                &vl_method_ListTemplates,
                SD_VARLINK_SYMBOL_COMMENT("No volume under the specified name exists."),
                &vl_error_NoSuchVolume,
                SD_VARLINK_SYMBOL_COMMENT("A volume under the specified name already exists."),
                &vl_error_VolumeExists,
                SD_VARLINK_SYMBOL_COMMENT("No template under the specified name exists."),
                &vl_error_NoSuchTemplate,
                SD_VARLINK_SYMBOL_COMMENT("The specified volume type is not supported by this backend or system."),
                &vl_error_TypeNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("The specified request as volume type is inappropriate for the specified volume."),
                &vl_error_InvalidRequestAs,
                SD_VARLINK_SYMBOL_COMMENT("This backend does not support volume creation."),
                &vl_error_CreateNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("This backend or selected volume type requires a volume size to be specified if the volume does not exist yet and needs to be created."),
                &vl_error_CreateSizeRequired,
                SD_VARLINK_SYMBOL_COMMENT("A volume was to be acquired in writable mode, but only read-only access is permitted."),
                &vl_error_ReadOnlyVolume,
                SD_VARLINK_SYMBOL_COMMENT("Template not suitable for this volume type."),
                &vl_error_BadTemplate);
