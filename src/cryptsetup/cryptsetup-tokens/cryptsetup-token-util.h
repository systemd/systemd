/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <libcryptsetup.h>

/* crypt_dump() internal indentation magic */
#define CRYPT_DUMP_LINE_SEP "\n\t            "

#define crypt_log_debug(cd, ...)   crypt_logf(cd, CRYPT_LOG_DEBUG,   __VA_ARGS__)
#define crypt_log_error(cd, ...)   crypt_logf(cd, CRYPT_LOG_ERROR,   __VA_ARGS__)
#define crypt_log_verbose(cd, ...) crypt_logf(cd, CRYPT_LOG_VERBOSE, __VA_ARGS__)
#define crypt_log(cd, ...)         crypt_logf(cd, CRYPT_LOG_NORMAL,  __VA_ARGS__)

#define crypt_log_full_errno(cd, e, lvl, ...) ({ \
        int _e = abs(e), _s = errno; \
        errno = _e; \
        crypt_logf(cd, lvl, __VA_ARGS__); \
        errno = _s; \
        -_e; \
})

#define crypt_log_debug_errno(cd, e, ...) \
        crypt_log_full_errno(cd, e, CRYPT_LOG_DEBUG, __VA_ARGS__)

#define crypt_log_error_errno(cd, e, ...) \
        crypt_log_full_errno(cd, e, CRYPT_LOG_ERROR, __VA_ARGS__)

#define crypt_log_oom(cd) crypt_log_error_errno(cd, ENOMEM, "Not enough memory.")

int crypt_dump_buffer_to_hex_string(
                const char *buf,
                size_t buf_size,
                char **ret_dump_str);

int crypt_dump_hex_string(const char *hex_str, char **ret_dump_str);

int crypt_normalize_pin(const void *pin, size_t pin_size, char **ret_pin_string);
