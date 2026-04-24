/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum ImageFormat {
        IMAGE_FORMAT_RAW,
        IMAGE_FORMAT_QCOW2,
        _IMAGE_FORMAT_MAX,
        _IMAGE_FORMAT_INVALID = -EINVAL,
} ImageFormat;

typedef enum DiskType {
        DISK_TYPE_VIRTIO_BLK,
        DISK_TYPE_VIRTIO_SCSI,
        DISK_TYPE_NVME,
        DISK_TYPE_VIRTIO_SCSI_CDROM,
        _DISK_TYPE_MAX,
        _DISK_TYPE_INVALID = -EINVAL,
} DiskType;

DECLARE_STRING_TABLE_LOOKUP(image_format, ImageFormat);
DECLARE_STRING_TABLE_LOOKUP(disk_type, DiskType);
DECLARE_STRING_TABLE_LOOKUP(block_driver, DiskType);
DECLARE_STRING_TABLE_LOOKUP(qemu_device_driver, DiskType);

/* Parse "[FORMAT:][DISKTYPE:]PATH"; *format and *disk_type are in-out. */
int parse_disk_spec(
                const char *arg,
                ImageFormat *format,
                DiskType *disk_type,
                char **ret_path);
