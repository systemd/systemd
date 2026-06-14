/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.StorageProvider.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                VolumeType,
                SD_VARLINK_FIELD_COMMENT("Block device storage volumes, block-addressable"),
                SD_VARLINK_DEFINE_ENUM_VALUE(blk),
                SD_VARLINK_FIELD_COMMENT("Regular file storage volumes, byte-addressable"),
                SD_VARLINK_DEFINE_ENUM_VALUE(reg),
                SD_VARLINK_FIELD_COMMENT("POSIX file system storage volumes, path/offset-addressable"),
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
                SD_VARLINK_FIELD_COMMENT("The name of the storage volume to acquire"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Determines whether to open or create a storage volume"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(createMode, CreateMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The template to use when creating a new storage volume"),
                SD_VARLINK_DEFINE_INPUT(template, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Controls read/write access to the storage volume. If false and the storage volume cannot be opened in writable mode the call will fail. If null, storage volume will be acquired in writable mode if possible, read-only otherwise. If true, storage volume will be opened in read-only mode (and fail if that's not possible)."),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Dictates what kind of storage volume to request. Some storage volumes can be acquired either as regular file or as block device. In all other cases if this value doesn't match the volume type, the request will fail."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(requestAs, VolumeType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The size of the storage volume, if one is created. Has no effect if no storage volume is created."),
                SD_VARLINK_DEFINE_INPUT(createSizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Returns an index into the array of file descriptors associated with this reply. This may be used to get the file descriptor of the volume. The file descriptor must be properly opened, i.e. not an O_PATH file descriptor."),
                SD_VARLINK_DEFINE_OUTPUT(fileDescriptorIndex, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The storage volume type, i.e. ultimately the inode type of the returned file descriptor"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, VolumeType, 0),
                SD_VARLINK_FIELD_COMMENT("Whether storage volume has been opened in read-only mode"),
                SD_VARLINK_DEFINE_OUTPUT(readOnly, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Base UID for the returned file descriptor (if directory). If not specified shall default to 0."),
                SD_VARLINK_DEFINE_OUTPUT(baseUID, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Base GID for the returned file descriptor (if directory). If not specified shall default to 0."),
                SD_VARLINK_DEFINE_OUTPUT(baseGID, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListVolumes,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Specifies a shell glob to filter enumeration by"),
                SD_VARLINK_DEFINE_INPUT(matchName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The storage volume's primary name"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Additional names"),
                SD_VARLINK_DEFINE_OUTPUT(aliases, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The type of the storage volume"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, VolumeType, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the storage volume is read-only."),
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
                SD_VARLINK_FIELD_COMMENT("The type of the storage volumes defined by this template"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, VolumeType, 0));

static SD_VARLINK_DEFINE_ERROR(NoSuchVolume);
static SD_VARLINK_DEFINE_ERROR(VolumeExists);
static SD_VARLINK_DEFINE_ERROR(NoSuchTemplate);
static SD_VARLINK_DEFINE_ERROR(TypeNotSupported);
static SD_VARLINK_DEFINE_ERROR(WrongType);
static SD_VARLINK_DEFINE_ERROR(CreateNotSupported);
static SD_VARLINK_DEFINE_ERROR(CreateSizeRequired);
static SD_VARLINK_DEFINE_ERROR(ReadOnlyVolume);
static SD_VARLINK_DEFINE_ERROR(BadTemplate);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_StorageProvider,
                "io.systemd.StorageProvider",
                SD_VARLINK_INTERFACE_COMMENT("Storage Provider API, a generic interface for acquiring access to storage volumes"),
                SD_VARLINK_SYMBOL_COMMENT("Encodes three classes of storage volumes. This follows the kernel's nomenclature for inode types, i.e. reg, dir, blk."),
                &vl_type_VolumeType,
                SD_VARLINK_SYMBOL_COMMENT("Determines whether to open existing or create a new storage volume."),
                &vl_type_CreateMode,
                SD_VARLINK_SYMBOL_COMMENT("Acquires a file descriptor for a storage volume."),
                &vl_method_Acquire,
                SD_VARLINK_SYMBOL_COMMENT("Lists available storage volumes."),
                &vl_method_ListVolumes,
                SD_VARLINK_SYMBOL_COMMENT("Lists available templates."),
                &vl_method_ListTemplates,
                SD_VARLINK_SYMBOL_COMMENT("No storage volume under the specified name exists."),
                &vl_error_NoSuchVolume,
                SD_VARLINK_SYMBOL_COMMENT("A storage volume under the specified name already exists."),
                &vl_error_VolumeExists,
                SD_VARLINK_SYMBOL_COMMENT("No template under the specified name exists."),
                &vl_error_NoSuchTemplate,
                SD_VARLINK_SYMBOL_COMMENT("The specified volume type is not supported by this backend or system."),
                &vl_error_TypeNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("The volume's type does not match the requested volume type."),
                &vl_error_WrongType,
                SD_VARLINK_SYMBOL_COMMENT("This backend does not support storage volume creation of the requested type."),
                &vl_error_CreateNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("This backend or selected volume type requires a storage volume size to be specified if the storage volume does not exist yet and needs to be created."),
                &vl_error_CreateSizeRequired,
                SD_VARLINK_SYMBOL_COMMENT("A storage volume was to be acquired in writable mode, but only read-only access is permitted."),
                &vl_error_ReadOnlyVolume,
                SD_VARLINK_SYMBOL_COMMENT("Template not suitable for this storage volume type."),
                &vl_error_BadTemplate);
