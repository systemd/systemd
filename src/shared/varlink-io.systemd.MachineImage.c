/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "bus-polkit.h"
#include "varlink-io.systemd.MachineImage.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                AcquireMetadata,
                SD_VARLINK_FIELD_COMMENT("Do not include metadata in the output"),
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_FIELD_COMMENT("Include metadata in the output"),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_FIELD_COMMENT("Include metadata in the output, but gracefully eat up errors"),
                SD_VARLINK_DEFINE_ENUM_VALUE(graceful));

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("If non-null the name of a image to report details on."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true the output will include image metadata fields such as 'machineInfo' and 'OSRelease'."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(acquireMetadata, AcquireMetadata, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Name of the image"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The file system path where image is stored"),
                SD_VARLINK_DEFINE_OUTPUT(path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The type of this image"),
                SD_VARLINK_DEFINE_OUTPUT(type, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The class of this image"),
                SD_VARLINK_DEFINE_OUTPUT(class, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the image is read-only"),
                SD_VARLINK_DEFINE_OUTPUT(readOnly, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The image creation timestamp"),
                SD_VARLINK_DEFINE_OUTPUT(creationTimestamp, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The image creation timestamp"),
                SD_VARLINK_DEFINE_OUTPUT(modificationTimestamp, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The image creation timestamp"),
                SD_VARLINK_DEFINE_OUTPUT(usage, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The image disk usage (exclusive)"),
                SD_VARLINK_DEFINE_OUTPUT(usageExclusive, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The image disk usage (exclusive)"),
                SD_VARLINK_DEFINE_OUTPUT(limit, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The image disk usage limit (exclusive)"),
                SD_VARLINK_DEFINE_OUTPUT(limitExclusive, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The hostname of the image"),
                SD_VARLINK_DEFINE_OUTPUT(hostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The machine ID of the image"),
                SD_VARLINK_DEFINE_OUTPUT(machineId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Machine info information of an image. It contains an array of key value pairs read from the machine-info(5) file in the image."),
                SD_VARLINK_DEFINE_OUTPUT(machineInfo, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("OS release information of an image. It contains an array of key value pairs read from the os-release(5) file in the image."),
                SD_VARLINK_DEFINE_OUTPUT(OSRelease, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

#define VARLINK_DEFINE_IMAGE_LOOKUP_AND_POLKIT_FIELDS           \
        SD_VARLINK_FIELD_COMMENT("The name of an image"),       \
        SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),    \
        VARLINK_DEFINE_POLKIT_INPUT

static SD_VARLINK_DEFINE_METHOD(
                Update,
                VARLINK_DEFINE_IMAGE_LOOKUP_AND_POLKIT_FIELDS,
                SD_VARLINK_FIELD_COMMENT("If non-null the new name of the image"),
                SD_VARLINK_DEFINE_INPUT(newName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If non-null value of the read-only flag of the image"),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If non-null value of image quota limit"),
                SD_VARLINK_DEFINE_INPUT(limit, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Clone,
                VARLINK_DEFINE_IMAGE_LOOKUP_AND_POLKIT_FIELDS,
                SD_VARLINK_FIELD_COMMENT("The new name of the image"),
                SD_VARLINK_DEFINE_INPUT(newName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("If non-null value of the read-only flag of the image"),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Remove,
                VARLINK_DEFINE_IMAGE_LOOKUP_AND_POLKIT_FIELDS);

static SD_VARLINK_DEFINE_METHOD(
                SetPoolLimit,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("New image quota limit"),
                SD_VARLINK_DEFINE_INPUT(limit, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                CleanPoolMode,
                SD_VARLINK_FIELD_COMMENT("Remove all unused images"),
                SD_VARLINK_DEFINE_ENUM_VALUE(all),
                SD_VARLINK_FIELD_COMMENT("Remove only hidden images"),
                SD_VARLINK_DEFINE_ENUM_VALUE(hidden));

static SD_VARLINK_DEFINE_METHOD_FULL(
                CleanPool,
                SD_VARLINK_REQUIRES_MORE,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Allows removing all or only hidden images"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mode, CleanPoolMode, 0),
                SD_VARLINK_FIELD_COMMENT("Image name"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The image disk usage (exclusive)"),
                SD_VARLINK_DEFINE_OUTPUT(usageExclusive, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoSuchImage);
static SD_VARLINK_DEFINE_ERROR(TooManyOperations);
static SD_VARLINK_DEFINE_ERROR(NotSupported);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_MachineImage,
                "io.systemd.MachineImage",
                SD_VARLINK_SYMBOL_COMMENT("A enum field allowing to gracefully get metadata"),
                &vl_type_AcquireMetadata,
                SD_VARLINK_SYMBOL_COMMENT("List images"),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("Update image allowing to rename, toggle read-only flag, or set a limit"),
                &vl_method_Update,
                SD_VARLINK_SYMBOL_COMMENT("Clone image"),
                &vl_method_Clone,
                SD_VARLINK_SYMBOL_COMMENT("Remove image"),
                &vl_method_Remove,
                SD_VARLINK_SYMBOL_COMMENT("Sets an overall quota limit on the pool of images"),
                &vl_method_SetPoolLimit,
                SD_VARLINK_SYMBOL_COMMENT("A enum field allowing to control what type of images are cleaned up"),
                &vl_type_CleanPoolMode,
                SD_VARLINK_SYMBOL_COMMENT("Clean unused images depending on the specified mode. Note that it does not process vendon and host images."),
                &vl_method_CleanPool,
                SD_VARLINK_SYMBOL_COMMENT("No matching image exists"),
                &vl_error_NoSuchImage,
                SD_VARLINK_SYMBOL_COMMENT("Too many ongoing background operations"),
                &vl_error_TooManyOperations,
                SD_VARLINK_SYMBOL_COMMENT("Requested operation is not supported"),
                &vl_error_NotSupported);
