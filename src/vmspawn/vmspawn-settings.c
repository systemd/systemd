/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-table.h"
#include "vmspawn-settings.h"

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
