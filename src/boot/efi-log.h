/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi-string.h"
#include "proto/simple-text-io.h"

#if defined __has_attribute
#  if __has_attribute(no_stack_protector)
#    define HAVE_NO_STACK_PROTECTOR_ATTRIBUTE
#  endif
#endif

#if defined(HAVE_NO_STACK_PROTECTOR_ATTRIBUTE) && \
    (defined(__SSP__) || defined(__SSP_ALL__) || \
    defined(__SSP_STRONG__) || defined(__SSP_EXPLICIT__))
#  define STACK_PROTECTOR_RANDOM 1
__attribute__((no_stack_protector, noinline)) void __stack_chk_guard_init(void);
#else
#  define STACK_PROTECTOR_RANDOM 0
#  define __stack_chk_guard_init()
#endif

_noreturn_ void freeze(void);
void log_wait(void);
_gnu_printf_(3, 4) EFI_STATUS log_internal(EFI_STATUS status, uint8_t text_color, const char *format, ...);
#define log_full(status, text_color, format, ...)                       \
        log_internal(status, text_color, "%s:%i@%s: " format, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define log_debug(...) log_full(EFI_SUCCESS, EFI_LIGHTGRAY, __VA_ARGS__)
#define log_info(...) log_full(EFI_SUCCESS, EFI_WHITE, __VA_ARGS__)
#define log_warning_status(status, ...) log_full(status, EFI_YELLOW, __VA_ARGS__)
#define log_error_status(status, ...) log_full(status, EFI_LIGHTRED, __VA_ARGS__)
#define log_error(...) log_full(EFI_INVALID_PARAMETER, EFI_LIGHTRED, __VA_ARGS__)
#define log_oom() log_full(EFI_OUT_OF_RESOURCES, EFI_LIGHTRED, "Out of memory.")

/* Debugging helper — please keep this around, even if not used */
#define log_hexdump(prefix, data, size)                                 \
        ({                                                              \
                _cleanup_free_ char16_t *hex = hexdump(data, size);     \
                log_debug("%ls[%zu]: %ls", prefix, size, hex);          \
        })
