/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.VirtualMachineInstance.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BlockFormat,
                SD_VARLINK_DEFINE_ENUM_VALUE(raw),
                SD_VARLINK_DEFINE_ENUM_VALUE(qcow2));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BlockDriver,
                SD_VARLINK_DEFINE_ENUM_VALUE(virtio_blk),
                SD_VARLINK_DEFINE_ENUM_VALUE(nvme),
                SD_VARLINK_DEFINE_ENUM_VALUE(scsi_hd),
                SD_VARLINK_DEFINE_ENUM_VALUE(scsi_cd));

static SD_VARLINK_DEFINE_METHOD(
                AddBlockDevice,
                SD_VARLINK_FIELD_COMMENT("File descriptor index of the opened block device or image file"),
                SD_VARLINK_DEFINE_INPUT(fileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Image format"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(format, BlockFormat, 0),
                SD_VARLINK_FIELD_COMMENT("Guest-visible device driver"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(driver, BlockDriver, 0),
                SD_VARLINK_FIELD_COMMENT("If true, attach the device read-only"),
                SD_VARLINK_DEFINE_INPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, enable discard/trim"),
                SD_VARLINK_DEFINE_INPUT(discard, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Drive serial string"),
                SD_VARLINK_DEFINE_INPUT(serial, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Caller-chosen device id; auto-generated if omitted"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Assigned device id"),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                RemoveBlockDevice,
                SD_VARLINK_FIELD_COMMENT("Id of the block device to remove"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListBlockDevices,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Device id"),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Image format"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(format, BlockFormat, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the device is read-only"),
                SD_VARLINK_DEFINE_OUTPUT(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoSuchBlockDevice);
static SD_VARLINK_DEFINE_ERROR(BlockDeviceIdInUse);
static SD_VARLINK_DEFINE_ERROR(InvalidBlockDeviceId);
static SD_VARLINK_DEFINE_ERROR(BlockBackendBusy);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_VirtualMachineInstance,
                "io.systemd.VirtualMachineInstance",
                &vl_type_BlockFormat,
                &vl_type_BlockDriver,
                SD_VARLINK_SYMBOL_COMMENT("Hotplug a block device into the VM"),
                &vl_method_AddBlockDevice,
                SD_VARLINK_SYMBOL_COMMENT("Hot-remove a block device from the VM"),
                &vl_method_RemoveBlockDevice,
                SD_VARLINK_SYMBOL_COMMENT("List all registered block devices"),
                &vl_method_ListBlockDevices,
                &vl_error_NoSuchBlockDevice,
                &vl_error_BlockDeviceIdInUse,
                &vl_error_InvalidBlockDeviceId,
                &vl_error_BlockBackendBusy);
