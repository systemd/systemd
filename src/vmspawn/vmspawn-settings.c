/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "assert-fundamental.h"
#include "macro.h"
#include "string-table.h"
#include "vmspawn-settings.h"

static const char *const image_format_table[_IMAGE_FORMAT_MAX] = {
        [IMAGE_FORMAT_RAW]   = "raw",
        [IMAGE_FORMAT_QCOW2] = "qcow2",
};

DEFINE_STRING_TABLE_LOOKUP(image_format, ImageFormat);

void extra_drive_free(ExtraDrive *drive) {
        assert(drive);

        drive->path = mfree(drive->path);
}

void extra_drive_context_free(ExtraDriveContext *ctx) {
        assert(ctx);

        FOREACH_ARRAY(drive, ctx->drives, ctx->n_drives)
                extra_drive_free(drive);

        ctx->drives = mfree(ctx->drives);
        ctx->n_drives = 0;
}

static const char *const console_mode_table[_CONSOLE_MODE_MAX] = {
        [CONSOLE_INTERACTIVE] = "interactive",
        [CONSOLE_READ_ONLY]   = "read-only",
        [CONSOLE_NATIVE]      = "native",
        [CONSOLE_GUI]         = "gui",
};

DEFINE_STRING_TABLE_LOOKUP(console_mode, ConsoleMode);
