/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "device-path-util.h"
#include "log.h"
#include "proto/rng.h"
#include "proto/simple-text-io.h"
#include "util.h"
#include "vmm.h"

LogLevel max_log_level = LOG_WARNING;
static unsigned log_count = 0;

static const int32_t log_colors[] = {
        [LOG_FATAL] = EFI_TEXT_ATTR(EFI_LIGHTRED, EFI_BLACK),
        [LOG_ERROR] = EFI_TEXT_ATTR(EFI_LIGHTRED, EFI_BLACK),
        [LOG_WARNING] = EFI_TEXT_ATTR(EFI_YELLOW, EFI_BLACK),
        [LOG_INFO] = EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BLACK),
        [LOG_DEBUG] = EFI_TEXT_ATTR(EFI_BROWN, EFI_BLACK),
        [LOG_TRACE] = EFI_TEXT_ATTR(EFI_BROWN, EFI_BLACK),
};

static const char16_t * const log_level_table[] = {
        [LOG_FATAL] = u"fatal",
        [LOG_ERROR] = u"error",
        [LOG_WARNING] = u"warning",
        [LOG_INFO] = u"info",
        [LOG_DEBUG] = u"debug",
        [LOG_TRACE] = u"trace",
};

void freeze(void) {
        for (;;)
                BS->Stall(60 * 1000 * 1000);
}

_noreturn_ static void panic(const char16_t *message) {
        if (ST->ConOut->Mode->CursorColumn > 0)
                ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, log_colors[LOG_FATAL]);
        ST->ConOut->OutputString(ST->ConOut, (char16_t *) message);
        freeze();
}

void efi_assert(const char *expr, const char *file, unsigned line, const char *function) {
        static bool asserting = false;

        /* Let's be paranoid. */
        if (asserting)
                panic(u"systemd-boot: Nested assertion failure, halting.");

        asserting = true;
        log_internal(LOG_FATAL,
                     EFI_INVALID_PARAMETER,
                     file,
                     line,
                     function,
                     "Assertion '%s' failed, halting.",
                     expr);
        freeze();
}

EFI_STATUS log_internal(
                LogLevel level,
                EFI_STATUS status,
                const char *file_name,
                unsigned line,
                const char *function,
                const char *format,
                ...) {

        assert(format);

        int32_t attr = ST->ConOut->Mode->Attribute;

        if (ST->ConOut->Mode->CursorColumn > 0)
                ST->ConOut->OutputString(ST->ConOut, (char16_t *) u"\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, log_colors[level]);

        EFI_TIME time = {};
        (void) RT->GetTime(&time, NULL);
        printf_status(status,
                      "[sd-boot %4u-%02u-%02u %02u:%02u:%02u %s:%u] ",
                      time.Year,
                      time.Month,
                      time.Day,
                      time.Hour,
                      time.Minute,
                      time.Second,
                      file_name,
                      line);

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
        log_debug("%ls[%zu]: %ls", prefix, size, hex);
}

void log_device_path(const char16_t *prefix, const EFI_DEVICE_PATH *dp) {
        _cleanup_free_ char16_t *str = NULL;
        (void) device_path_to_str(dp, &str);
        log_debug("%ls: %ls", prefix, str);
}
#endif

static void set_log_level(const char16_t *level) {
        for (unsigned i = 0; i < ELEMENTSOF(log_level_table); i++) {
                if (strcaseeq16(level, log_level_table[i])) {
                        max_log_level = i;
                        return;
                }
        }
}

void log_init(void) {
        /* By using the UEFI shell environment variable namespace one can easily set the logging
         * level from the EFI shell with "set SYSTEMD_BOOT_LOG_LEVEL debug", which is much nicer
         * than having to write out a GUID with "setvar". */

        _cleanup_free_ char16_t *level = NULL;
        if (efivar_get(MAKE_GUID_PTR(EFI_SHELL_VARIABLE), u"SYSTEMD_BOOT_LOG_LEVEL", &level) != EFI_SUCCESS)
                return;
        set_log_level(level);
}

void log_wait(void) {
        EFI_STATUS err;

        /* Give the user a chance to catch up on log messages on the console. */

        if (log_count == 0)
                return;

        /* We skip this for VMs as these really should have a serial console with a scrollback
         * buffer for easy consumption. It also ensures we don't slow down any CI. */
        if (in_hypervisor())
                return;

        unsigned timeout_sec = CLAMP(log_count, 3u, 9u);
        log_count = 0;

        for (;;) {
                printf("\rContinuing in %u s, press any key to skip log timeout.", timeout_sec);

                err = console_key_read(&(uint64_t){ 0 }, 1000 * 1000);
                if (err == EFI_NOT_READY)
                        continue;
                if (err == EFI_TIMEOUT && timeout_sec > 0) {
                        timeout_sec--;
                        continue;
                }
                break;
        }
}

_used_ intptr_t __stack_chk_guard = (intptr_t) 0x70f6967de78acae3;

/* We can only set a random stack canary if this function attribute is available,
 * otherwise this may create a stack check fail. */
#if STACK_PROTECTOR_RANDOM
void __stack_chk_guard_init(void) {
        EFI_RNG_PROTOCOL *rng;
        if (BS->LocateProtocol(MAKE_GUID_PTR(EFI_RNG_PROTOCOL), NULL, (void **) &rng) == EFI_SUCCESS)
                (void) rng->GetRNG(rng, NULL, sizeof(__stack_chk_guard), (void *) &__stack_chk_guard);
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
