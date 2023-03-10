/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "proto/simple-text-io.h"

static unsigned log_count = 0;

_noreturn_ static void freeze(void) {
        for (;;)
                BS->Stall(60 * 1000 * 1000);
}

_noreturn_ static void panic(const char16_t *message) {
        if (ST->ConOut->Mode->CursorColumn > 0)
                ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, EFI_TEXT_ATTR(EFI_LIGHTRED, EFI_BLACK));
        ST->ConOut->OutputString(ST->ConOut, (char16_t *) message);
        freeze();
}

void efi_assert(const char *expr, const char *file, unsigned line, const char *function) {
        static bool asserting = false;

        /* Let's be paranoid. */
        if (asserting)
                panic(u"systemd-boot: Nested assertion failure, halting.");

        asserting = true;
        log_error("systemd-boot: Assertion '%s' failed at %s:%u@%s, halting.", expr, file, line, function);
        freeze();
}

EFI_STATUS log_internal(EFI_STATUS status, const char *format, ...) {
        assert(format);

        int32_t attr = ST->ConOut->Mode->Attribute;

        if (ST->ConOut->Mode->CursorColumn > 0)
                ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, EFI_TEXT_ATTR(EFI_LIGHTRED, EFI_BLACK));

        va_list ap;
        va_start(ap, format);
        vprintf_status(status, format, ap);
        va_end(ap);

        ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, attr);

        log_count++;
        return status;
}

void log_wait(void) {
        if (log_count == 0)
                return;

        BS->Stall(MIN(4u, log_count) * 2500 * 1000);
        log_count = 0;
}

#if defined(__ARM_EABI__)
/* These override the (weak) div0 handlers from libgcc as they would otherwise call raise() instead. */

_used_ _noreturn_ int __aeabi_idiv0(int return_value) {
        panic(u"systemd-boot: Division by zero, halting.");
}

_used_ _noreturn_ long long __aeabi_ldiv0(long long return_value) {
        panic(u"systemd-boot: Division by zero, halting.");
}
#endif
