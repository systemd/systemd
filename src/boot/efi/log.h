/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi-string.h"

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

typedef enum {
        LOG_FATAL,
        LOG_ERROR,
        LOG_WARNING,
        LOG_INFO,
        LOG_DEBUG,
        LOG_TRACE,
} LogLevel;

extern LogLevel max_log_level;

_noreturn_ void freeze(void);
void log_init(void);
_gnu_printf_(6, 7) EFI_STATUS log_internal(
                LogLevel level,
                EFI_STATUS status,
                const char *file,
                unsigned line,
                const char *function,
                const char *format,
                ...);

#define log_full_status(level, status, ...)                                                                \
        ({                                                                                                 \
                LogLevel _level = (level);                                                                 \
                EFI_STATUS _status = (status);                                                             \
                if (_unlikely_(_level <= max_log_level))                                                   \
                        log_internal((_level), (_status), __FILE_NAME__, __LINE__, __func__, __VA_ARGS__); \
                (_status);                                                                                 \
        })

#define log_fatal_status(status, ...) log_full_status(LOG_FATAL, status, __VA_ARGS__)
#define log_error_status(status, ...) log_full_status(LOG_ERROR, status, __VA_ARGS__)
#define log_warning_status(status, ...) log_full_status(LOG_WARNING, status, __VA_ARGS__)
#define log_info_status(status, ...) log_full_status(LOG_INFO, status, __VA_ARGS__)
#define log_debug_status(status, ...) log_full_status(LOG_DEBUG, status, __VA_ARGS__)
#define log_trace_status(status, ...) log_full_status(LOG_TRACE, status, __VA_ARGS__)

#define log_fatal(...) log_full_status(LOG_FATAL, EFI_INVALID_PARAMETER, __VA_ARGS__)
#define log_error(...) log_full_status(LOG_ERROR, EFI_INVALID_PARAMETER, __VA_ARGS__)
#define log_warning(...) log_full_status(LOG_WARNING, EFI_INVALID_PARAMETER, __VA_ARGS__)
#define log_info(...) log_full_status(LOG_INFO, EFI_SUCCESS, __VA_ARGS__)
#define log_debug(...) log_full_status(LOG_DEBUG, EFI_SUCCESS, __VA_ARGS__)
#define log_trace(...) log_full_status(LOG_TRACE, EFI_SUCCESS, __VA_ARGS__)

#define log_oom() log_error_status(EFI_OUT_OF_RESOURCES, "Out of memory.")
#define log_trace_line() log_trace("%s:%i@%s", __FILE__, __LINE__, __func__)

#ifdef EFI_DEBUG
void log_hexdump(const char16_t *prefix, const void *data, size_t size);
void log_device_path(const char16_t *prefix, const EFI_DEVICE_PATH *dp);
#endif
