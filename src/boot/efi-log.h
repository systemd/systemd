/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "efi-string.h"
#include "proto/simple-text-io.h"       /* IWYU pragma: keep */

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

typedef enum LogLevel {
        LOG_EMERG,
        LOG_ALERT,
        LOG_CRIT,
        LOG_ERR,
        LOG_WARNING,
        LOG_NOTICE,
        LOG_INFO,
        LOG_DEBUG,
        _LOG_MAX,
        _LOG_INVALID = -1,
} LogLevel;

LogLevel log_level_from_string(const char *s) _pure_;
const char* log_level_to_string(LogLevel l) _const_;

LogLevel log_get_max_level(void) _pure_;
int log_set_max_level(LogLevel level);
int log_set_max_level_from_string(const char *e);
void log_set_max_level_from_smbios(void);

_noreturn_ void freeze(void);
void log_wait(void);
_gnu_printf_(3, 4) EFI_STATUS log_internal(EFI_STATUS status, LogLevel log_level, const char *format, ...);

#define log_full(status, log_level, format, ...)                        \
        log_internal(status, log_level, "%s:%i@%s: " format, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define log_debug(...)     log_full(EFI_SUCCESS, LOG_DEBUG, __VA_ARGS__)
#define log_info(...)      log_full(EFI_SUCCESS, LOG_INFO, __VA_ARGS__)
#define log_notice(...)    log_full(EFI_SUCCESS, LOG_NOTICE, __VA_ARGS__)
#define log_warning(...)   log_full(EFI_SUCCESS, LOG_WARNING, __VA_ARGS__)
#define log_error(...)     log_full(EFI_SUCCESS, LOG_ERR, __VA_ARGS__)
#define log_emergency(...) log_full(EFI_SUCCESS, LOG_EMERG, __VA_ARGS__)

#define log_debug_status(status, ...)     log_full(status, LOG_DEBUG, __VA_ARGS__)
#define log_info_status(status, ...)      log_full(status, LOG_INFO, __VA_ARGS__)
#define log_notice_status(status, ...)    log_full(status, LOG_NOTICE, __VA_ARGS__)
#define log_warning_status(status, ...)   log_full(status, LOG_WARNING, __VA_ARGS__)
#define log_error_status(status, ...)     log_full(status, LOG_ERR, __VA_ARGS__)
#define log_emergency_status(status, ...) log_full(status, LOG_EMERG, __VA_ARGS__)

#define log_oom() log_full(EFI_OUT_OF_RESOURCES, LOG_ERR, "Out of memory.")

/* Debugging helper — please keep this around, even if not used */
#define log_hexdump(prefix, data, size)                                 \
        ({                                                              \
                _cleanup_free_ char16_t *hex = hexdump(data, size);     \
                log_debug("%ls[%zu]: %ls", prefix, size, hex);          \
        })
