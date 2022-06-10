/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "log.h"

void efi_assert(const char *expr, const char *file, unsigned line, const char *function) {
        log_error("systemd-boot assertion '%s' failed at %s:%u@%s. Halting.", expr, file, line, function);
        for (;;)
                BS->Stall(60 * 1000 * 1000);
}

EFI_STATUS log_internal(EFI_STATUS status, const char *format, ...) {
        assert(format);

        int32_t attr = ST->ConOut->Mode->Attribute;

        if (ST->ConOut->Mode->CursorColumn > 0)
                ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, EFI_LIGHTRED | EFI_BACKGROUND_BLACK);

        va_list ap;
        va_start(ap, format);
        vprintf_status(status, format, ap);
        va_end(ap);

        ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, attr);

        /* Give the user a chance to see the message. */
        BS->Stall(3 * 1000 * 1000);
        return status;
}
