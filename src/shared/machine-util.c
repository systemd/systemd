/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "machine-util.h"
#include "parse-argument.h"
#include "string-table.h"
#include "string-util.h"

static const char *const image_format_table[_IMAGE_FORMAT_MAX] = {
        [IMAGE_FORMAT_RAW]   = "raw",
        [IMAGE_FORMAT_QCOW2] = "qcow2",
};

DEFINE_STRING_TABLE_LOOKUP(image_format, ImageFormat);

static const char *const disk_type_table[_DISK_TYPE_MAX] = {
        [DISK_TYPE_VIRTIO_BLK]          = "virtio-blk",
        [DISK_TYPE_VIRTIO_SCSI]         = "virtio-scsi",
        [DISK_TYPE_NVME]                = "nvme",
        [DISK_TYPE_VIRTIO_SCSI_CDROM]   = "scsi-cd",
};

DEFINE_STRING_TABLE_LOOKUP(disk_type, DiskType);

const char* disk_type_to_block_driver(DiskType t) {
        switch (t) {
        case DISK_TYPE_VIRTIO_BLK:        return "virtio_blk";
        case DISK_TYPE_VIRTIO_SCSI:       return "scsi_hd";
        case DISK_TYPE_NVME:              return "nvme";
        case DISK_TYPE_VIRTIO_SCSI_CDROM: return "scsi_cd";
        default:                          return NULL;
        }
}

DiskType disk_type_from_block_driver(const char *s) {
        if (streq_ptr(s, "virtio_blk"))
                return DISK_TYPE_VIRTIO_BLK;
        if (streq_ptr(s, "scsi_hd"))
                return DISK_TYPE_VIRTIO_SCSI;
        if (streq_ptr(s, "nvme"))
                return DISK_TYPE_NVME;
        if (streq_ptr(s, "scsi_cd"))
                return DISK_TYPE_VIRTIO_SCSI_CDROM;
        return _DISK_TYPE_INVALID;
}

const char* disk_type_to_qemu_device_driver(DiskType t) {
        switch (t) {
        case DISK_TYPE_VIRTIO_BLK:        return "virtio-blk-pci";
        case DISK_TYPE_VIRTIO_SCSI:       return "scsi-hd";
        case DISK_TYPE_NVME:              return "nvme";
        case DISK_TYPE_VIRTIO_SCSI_CDROM: return "scsi-cd";
        default:                          return NULL;
        }
}

int parse_disk_spec(
                const char *arg,
                ImageFormat *format,
                DiskType *disk_type,
                char **ret_path) {

        int r;

        assert(arg);
        assert(format);
        assert(disk_type);
        assert(ret_path);

        ImageFormat parsed_format = *format;
        DiskType parsed_disk_type = *disk_type;
        const char *dp = arg;

        /* Format and disk-type vocabularies don't overlap, so prefixes may appear in any order. */
        for (;;) {
                const char *colon = strchr(dp, ':');
                if (!colon)
                        break;

                _cleanup_free_ char *prefix = strndup(dp, colon - dp);
                if (!prefix)
                        return -ENOMEM;

                ImageFormat f = image_format_from_string(prefix);
                if (f >= 0) {
                        parsed_format = f;
                        dp = colon + 1;
                        continue;
                }

                DiskType dt = disk_type_from_string(prefix);
                if (dt >= 0) {
                        parsed_disk_type = dt;
                        dp = colon + 1;
                        continue;
                }

                break;
        }

        _cleanup_free_ char *path = NULL;
        r = parse_path_argument(dp, /* suppress_root= */ false, &path);
        if (r < 0)
                return r;

        *format = parsed_format;
        *disk_type = parsed_disk_type;
        *ret_path = TAKE_PTR(path);
        return 0;
}
