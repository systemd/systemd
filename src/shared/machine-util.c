/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "machine-util.h"
#include "parse-argument.h"
#include "string-table.h"

static const char *const image_format_table[_IMAGE_FORMAT_MAX] = {
        [IMAGE_FORMAT_RAW]   = "raw",
        [IMAGE_FORMAT_QCOW2] = "qcow2",
};

DEFINE_STRING_TABLE_LOOKUP(image_format, ImageFormat);

static const char *const disk_type_table[_DISK_TYPE_MAX] = {
        [DISK_TYPE_VIRTIO_BLK]        = "virtio-blk",
        [DISK_TYPE_VIRTIO_SCSI]       = "virtio-scsi",
        [DISK_TYPE_NVME]              = "nvme",
        [DISK_TYPE_VIRTIO_SCSI_CDROM] = "scsi-cd",
};

DEFINE_STRING_TABLE_LOOKUP(disk_type, DiskType);

/* Wire value for the io.systemd.VirtualMachineInstance.BlockDriver IDL enum. */
static const char *const block_driver_table[_DISK_TYPE_MAX] = {
        [DISK_TYPE_VIRTIO_BLK]        = "virtio_blk",
        [DISK_TYPE_VIRTIO_SCSI]       = "scsi_hd",
        [DISK_TYPE_NVME]              = "nvme",
        [DISK_TYPE_VIRTIO_SCSI_CDROM] = "scsi_cd",
};

DEFINE_STRING_TABLE_LOOKUP(block_driver, DiskType);

/* QEMU -device driver name (e.g. "virtio-blk-pci"). */
static const char *const qemu_device_driver_table[_DISK_TYPE_MAX] = {
        [DISK_TYPE_VIRTIO_BLK]        = "virtio-blk-pci",
        [DISK_TYPE_VIRTIO_SCSI]       = "scsi-hd",
        [DISK_TYPE_NVME]              = "nvme",
        [DISK_TYPE_VIRTIO_SCSI_CDROM] = "scsi-cd",
};

DEFINE_STRING_TABLE_LOOKUP(qemu_device_driver, DiskType);

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
                _cleanup_free_ char *word = NULL;
                const char *save = dp;

                r = extract_first_word(&dp, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0 || !dp) {
                        /* No ':' remained after this word — rest is the path. */
                        dp = save;
                        break;
                }

                ImageFormat f = image_format_from_string(word);
                if (f >= 0) {
                        parsed_format = f;
                        continue;
                }

                DiskType dt = disk_type_from_string(word);
                if (dt >= 0) {
                        parsed_disk_type = dt;
                        continue;
                }

                /* Unknown prefix — rewind, remainder is the path. */
                dp = save;
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
