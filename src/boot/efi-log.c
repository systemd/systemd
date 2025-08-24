/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-log.h"
#include "efi-string-table.h"
#include "proto/rng.h"
#include "smbios.h"
#include "util.h"
#include "vmm.h"

static unsigned log_count = 0;
static LogLevel log_max_level = LOG_INFO;

static const uint8_t log_level_color[_LOG_MAX] = {
        [LOG_EMERG]   = EFI_LIGHTRED,
        [LOG_ALERT]   = EFI_LIGHTRED,
        [LOG_CRIT]    = EFI_LIGHTRED,
        [LOG_ERR]     = EFI_LIGHTRED,
        [LOG_WARNING] = EFI_YELLOW,
        [LOG_NOTICE]  = EFI_WHITE,
        [LOG_INFO]    = EFI_WHITE,
        [LOG_DEBUG]   = EFI_LIGHTGRAY,
};

static const char *const log_level_table[_LOG_MAX] = {
        [LOG_EMERG]   = "emerg",
        [LOG_ALERT]   = "alert",
        [LOG_CRIT]    = "crit",
        [LOG_ERR]     = "err",
        [LOG_WARNING] = "warning",
        [LOG_NOTICE]  = "notice",
        [LOG_INFO]    = "info",
        [LOG_DEBUG]   = "debug",
};

DEFINE_STRING_TABLE_LOOKUP(log_level, LogLevel);

LogLevel log_get_max_level(void) {
        return log_max_level;
}

int log_set_max_level(LogLevel level) {
        assert(level >= 0 && level < _LOG_MAX);

        int old = log_max_level;
        log_max_level = level;
        return old;
}

int log_set_max_level_from_string(const char *e) {
        int r;

        assert(e);

        r = log_level_from_string(e);
        if (r < 0)
                return r;

        log_set_max_level(r);
        return 0;
}

void log_set_max_level_from_smbios(void) {
        int r;

        if (is_confidential_vm())
                return; /* Don't consume SMBIOS in Confidential Computing contexts */

        const char *level_str = smbios_find_oem_string("io.systemd.boot.loglevel=", /* after= */ NULL);
        if (!level_str)
                return;

        r = log_set_max_level_from_string(level_str);
        if (r < 0)
                log_warning("Failed to parse log level '%s', ignoring.", level_str);
}

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

EFI_STATUS log_internal(EFI_STATUS status, LogLevel log_level, const char *format, ...) {
        assert(format);
        assert(log_level >= 0 && log_level < _LOG_MAX);

        if (log_level > log_max_level)
                return status;

        int32_t attr = ST->ConOut->Mode->Attribute;

        if (ST->ConOut->Mode->CursorColumn > 0)
                ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, EFI_TEXT_ATTR(log_level_color[log_level], EFI_BLACK));

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

_used_ intptr_t __stack_chk_guard = (intptr_t) 0x70f6967de78acae3;

/* We can only set a random stack canary if this function attribute is available,
 * otherwise this may create a stack check fail. */
#if STACK_PROTECTOR_RANDOM
void __stack_chk_guard_init(void) {
        EFI_RNG_PROTOCOL *rng;
        if (BS->LocateProtocol(MAKE_GUID_PTR(EFI_RNG_PROTOCOL), NULL, (void **) &rng) == EFI_SUCCESS)
                (void) rng->GetRNG(rng, NULL, sizeof(__stack_chk_guard), (void *) &__stack_chk_guard);
        else
                /* Better than no extra entropy. */
                __stack_chk_guard ^= (intptr_t) __executable_start;
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
