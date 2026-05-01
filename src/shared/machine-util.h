/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "storage-util.h"

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

/* Parsed "PROVIDER:VOLUME[:CONFIG][:K=V,K=V,...]" used by --bind-volume,
 * machinectl bind-volume, and (future) the BindVolume= unit setting. The 'config'
 * field is opaque here and interpreted per-backend (vmspawn: a DiskType name;
 * nspawn: a mount path). */
typedef struct BindVolume {
        char *provider;
        char *volume;
        char *config;

        /* Acquire() parameters parsed from the trailing key=value list. */
        char *template;
        CreateMode create_mode;
        int read_only;             /* -1 unset, -ENODATA auto, 0/1 no/yes */
        uint64_t create_size_bytes;
        VolumeType request_as;
} BindVolume;

#define BIND_VOLUME_INIT                                                        \
        (BindVolume) {                                                          \
                .read_only         = -1,                                        \
                .create_size_bytes = UINT64_MAX,                                \
                .create_mode       = _CREATE_MODE_INVALID,                      \
                .request_as        = _VOLUME_TYPE_INVALID,                      \
        }

BindVolume* bind_volume_free(BindVolume *v);
DEFINE_TRIVIAL_CLEANUP_FUNC(BindVolume*, bind_volume_free);

int bind_volume_parse(const char *arg, BindVolume **ret);

/* Validate a "<provider>:<volume>" binding name as used by AddStorage/RemoveStorage.
 * ret_provider/ret_volume may each be NULL when the caller only wants validation. */
int machine_storage_name_split(const char *s, char **ret_provider, char **ret_volume);
