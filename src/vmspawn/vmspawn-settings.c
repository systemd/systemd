/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-table.h"
#include "vmspawn-settings.h"

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

void extra_drive_context_done(ExtraDriveContext *ctx) {
        assert(ctx);

        FOREACH_ARRAY(drive, ctx->drives, ctx->n_drives)
                free(drive->path);

        free(ctx->drives);
}

static const char *const console_mode_table[_CONSOLE_MODE_MAX] = {
        [CONSOLE_INTERACTIVE] = "interactive",
        [CONSOLE_READ_ONLY]   = "read-only",
        [CONSOLE_NATIVE]      = "native",
        [CONSOLE_GUI]         = "gui",
        [CONSOLE_HEADLESS]    = "headless",
};

DEFINE_STRING_TABLE_LOOKUP(console_mode, ConsoleMode);

static const char *const console_transport_table[_CONSOLE_TRANSPORT_MAX] = {
        [CONSOLE_TRANSPORT_VIRTIO] = "virtio",
        [CONSOLE_TRANSPORT_SERIAL] = "serial",
};

DEFINE_STRING_TABLE_LOOKUP(console_transport, ConsoleTransport);

static const char *const firmware_table[_FIRMWARE_MAX] = {
        [FIRMWARE_UEFI] = "uefi",
        [FIRMWARE_BIOS] = "bios",
        [FIRMWARE_NONE] = "none",
};

DEFINE_STRING_TABLE_LOOKUP(firmware, Firmware);
