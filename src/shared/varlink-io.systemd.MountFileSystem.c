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
                SD_VARLINK_FIELD_COMMENT("The designator of this partition."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(designator, PartitionDesignator, 0),
                SD_VARLINK_FIELD_COMMENT("Indicates whether this partition is marked for writable (non-read-only) operations."),
                SD_VARLINK_DEFINE_FIELD(writable, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Indicates whether this partition is marked for automatic growing."),
                SD_VARLINK_DEFINE_FIELD(growFileSystem, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Indicates the numeric partition number of this partition, or null if the image does not carry a partition table, and this object covers the whole block device."),
                SD_VARLINK_DEFINE_FIELD(partitionNumber, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates the intended CPU architecture of the partition, in case the partition type encodes such information."),
                SD_VARLINK_DEFINE_FIELD(architecture, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The partition UUID identifying the partition."),
                SD_VARLINK_DEFINE_FIELD(partitionUuid, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The file system type for the mount"),
                SD_VARLINK_DEFINE_FIELD(fileSystemType, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The partition label string of this partition."),
                SD_VARLINK_DEFINE_FIELD(partitionLabel, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The size of the partition in bytes."),
                SD_VARLINK_DEFINE_FIELD(size, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The start offset of the partition in bytes."),
                SD_VARLINK_DEFINE_FIELD(offset, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("A mount file descriptor to assign to a location."),
                SD_VARLINK_DEFINE_FIELD(mountFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("A relative path indicating the intended mount point for this file system, if applicable. May contain multiple paths, for certain partitions that can be mounted to multiple distinct places."),
                SD_VARLINK_DEFINE_FIELD(mountPoint, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                MountImage,
                SD_VARLINK_FIELD_COMMENT("File descriptor of the image file to mount and to assign to the user namespace. Must be a regular, i.e. non-O_PATH file descriptor."),
                SD_VARLINK_DEFINE_INPUT(imageFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("File descriptor to the user namespace to assign this image to. If not specified uses the host user namespace."),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Mounts the image read-only."),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Grows the contained file systems if necessary and indicated, before mounting them."),
                SD_VARLINK_DEFINE_INPUT(growFileSystems, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Takes a literal password in case of an encrypted image"),
                SD_VARLINK_DEFINE_INPUT(password, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Takes an image policy string (see systemd.image-policy(7) for details) to apply while mounting the image"),
                SD_VARLINK_DEFINE_INPUT(imagePolicy, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("An array with information about contained partitions that have been prepared for mounting, as well as their mount file descriptors."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(partitions, PartitionInfo, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The used image policy."),
                SD_VARLINK_DEFINE_OUTPUT(imagePolicy, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The size of the image in bytes."),
                SD_VARLINK_DEFINE_OUTPUT(imageSize, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The sector size of the image in bytes"),
                SD_VARLINK_DEFINE_OUTPUT(sectorSize, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The name of the image"),
                SD_VARLINK_DEFINE_OUTPUT(imageName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UUID of the image"),
                SD_VARLINK_DEFINE_OUTPUT(imageUuid, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                MountMapMode,
                SD_VARLINK_FIELD_COMMENT("Map the caller's UID to root in the user namespace, do not map anything else."),
                SD_VARLINK_DEFINE_ENUM_VALUE(root),
                SD_VARLINK_FIELD_COMMENT("Map the foreign UID range to the base UID range in the user namespace (i.e. UID zero and above), covering 64K users."),
                SD_VARLINK_DEFINE_ENUM_VALUE(foreign),
                SD_VARLINK_FIELD_COMMENT("Apply an identity (1:1) mapping, but limit it to 64K users."),
                SD_VARLINK_DEFINE_ENUM_VALUE(identity),
                SD_VARLINK_FIELD_COMMENT("Determine automatically based on provided directory and caller."),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto));

static SD_VARLINK_DEFINE_METHOD(
                MountDirectory,
                SD_VARLINK_FIELD_COMMENT("Directory file descriptor of the directory to assign to the user namespace. Must be a regular, i.e. non-O_PATH file descriptor."),
                SD_VARLINK_DEFINE_INPUT(directoryFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("File descriptor to the user namespace to assign this directory to. If not specified uses the host user namespace."),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to mark the resulting mount file descriptor as read-only. If not specified defaults to false."),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Which kind of UID/GID mapping to apply to the resulting mount file descriptor."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mode, MountMapMode, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The freshly allocated mount file descriptor for the mount."),
                SD_VARLINK_DEFINE_OUTPUT(mountFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                MakeDirectory,
                SD_VARLINK_FIELD_COMMENT("File descriptor of the directory to create the new directory in. Must be a regular, i.e. non-O_PATH file descriptor."),
                SD_VARLINK_DEFINE_INPUT(parentFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Name of the directory to create."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("File descriptor referencing the newly created directory."),
                SD_VARLINK_DEFINE_OUTPUT(directoryFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ERROR(IncompatibleImage);
static SD_VARLINK_DEFINE_ERROR(MultipleRootPartitionsFound);
static SD_VARLINK_DEFINE_ERROR(RootPartitionNotFound);
static SD_VARLINK_DEFINE_ERROR(DeniedByImagePolicy);
static SD_VARLINK_DEFINE_ERROR(KeyNotFound);
static SD_VARLINK_DEFINE_ERROR(VerityFailure);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_MountFileSystem,
                "io.systemd.MountFileSystem",
                SD_VARLINK_INTERFACE_COMMENT("APIs for unprivileged mounting."),
                SD_VARLINK_SYMBOL_COMMENT("Encodes the designated purpose of a partition."),
                &vl_type_PartitionDesignator,
                SD_VARLINK_SYMBOL_COMMENT("Information about a specific partition."),
                &vl_type_PartitionInfo,
                SD_VARLINK_SYMBOL_COMMENT("Selects the type of UID/GID mapping to apply."),
                &vl_type_MountMapMode,
                SD_VARLINK_SYMBOL_COMMENT("Takes a disk image file descriptor as input, returns a set of mount file descriptors for it, plus meta information about the image and the partitions selected for mounting."),
                &vl_method_MountImage,
                SD_VARLINK_SYMBOL_COMMENT("Takes a directory file descriptor as input, returns a mount file descriptor."),
                &vl_method_MountDirectory,
                SD_VARLINK_SYMBOL_COMMENT("Creates an empty directory, owned by the foreign UID/GID range's root user, returns an open file descriptor to the directory. Access mode will be set to 0700."),
                &vl_method_MakeDirectory,
                SD_VARLINK_SYMBOL_COMMENT("Disk image is not compatible with this service."),
                &vl_error_IncompatibleImage,
                SD_VARLINK_SYMBOL_COMMENT("Multiple suitable root partitions found."),
                &vl_error_MultipleRootPartitionsFound,
                SD_VARLINK_SYMBOL_COMMENT("No suitable root partition found."),
                &vl_error_RootPartitionNotFound,
                SD_VARLINK_SYMBOL_COMMENT("The specified image policy disallows mounting this disk image"),
                &vl_error_DeniedByImagePolicy,
                SD_VARLINK_SYMBOL_COMMENT("The authentication key for this image is not available."),
                &vl_error_KeyNotFound,
                SD_VARLINK_SYMBOL_COMMENT("Verity could not be set up."),
                &vl_error_VerityFailure);
