/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "proto/rng.h"
#include "proto/simple-text-io.h"
#include "util.h"

static unsigned log_count = 0;

void freeze(void) {
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

#ifdef EFI_DEBUG
void log_hexdump(const char16_t *prefix, const void *data, size_t size) {
        /* Debugging helper — please keep this around, even if not used */

        _cleanup_free_ char16_t *hex = hexdump(data, size);
        log_internal(EFI_SUCCESS, "%ls[%zu]: %ls", prefix, size, hex);
}
#endif

void log_wait(void) {
        if (log_count == 0)
                return;

        BS->Stall(MIN(4u, log_count) * 2500 * 1000);
        log_count = 0;
}

_used_ uintptr_t __stack_chk_guard = (uintptr_t) 0x70f6967de78acae3;

/* We can only set a random stack canary if this function attribute is available,
 * otherwise this may create a stack check fail. */
#if STACK_PROTECTOR_RANDOM
void __stack_chk_guard_init(void) {
        EFI_RNG_PROTOCOL *rng;
        void *rng_raw;
        if (BS->LocateProtocol(MAKE_GUID_PTR(EFI_RNG_PROTOCOL), NULL, &rng_raw) == EFI_SUCCESS) {
                rng = rng_raw;
                (void) rng->GetRNG(rng, NULL, sizeof(__stack_chk_guard), (void *) &__stack_chk_guard);
        }
        else
                /* Better than no extra entropy. */
                __stack_chk_guard ^= (uintptr_t) __executable_start;
}
#endif

_used_ _noreturn_ void __stack_chk_fail(void);
_used_ _noreturn_ void __stack_chk_fail_local(void);
void __stack_chk_fail(void) {
        panic(u"systemd-boot: Stack check failed, halting.");
}
void __stack_chk_fail_local(void) {
        __stack_chk_fail();
}

/* Called by libgcc for some fatal errors like integer overflow with -ftrapv. */
_used_ _noreturn_ void abort(void);
void abort(void) {
        panic(u"systemd-boot: Unknown error, halting.");
}

#if defined(__ARM_EABI__)
/* These override the (weak) div0 handlers from libgcc as they would otherwise call raise() instead. */
_used_ _noreturn_ int __aeabi_idiv0(int return_value);
_used_ _noreturn_ long long __aeabi_ldiv0(long long return_value);

int __aeabi_idiv0(int return_value) {
        panic(u"systemd-boot: Division by zero, halting.");
}

long long __aeabi_ldiv0(long long return_value) {
        panic(u"systemd-boot: Division by zero, halting.");
}
#endif
