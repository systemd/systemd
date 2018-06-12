/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>

#include "macro.h"

/* Some structures we reference but don't want to pull in headers for */
struct iovec;
struct signalfd_siginfo;

typedef enum LogRealm {
        LOG_REALM_SYSTEMD,
        LOG_REALM_UDEV,
        _LOG_REALM_MAX,
} LogRealm;

#ifndef LOG_REALM
#  define LOG_REALM LOG_REALM_SYSTEMD
#endif

typedef enum LogTarget{
        LOG_TARGET_CONSOLE,
        LOG_TARGET_CONSOLE_PREFIXED,
        LOG_TARGET_KMSG,
        LOG_TARGET_JOURNAL,
        LOG_TARGET_JOURNAL_OR_KMSG,
        LOG_TARGET_SYSLOG,
        LOG_TARGET_SYSLOG_OR_KMSG,
        LOG_TARGET_AUTO, /* console if stderr is tty, JOURNAL_OR_KMSG otherwise */
        LOG_TARGET_NULL,
        _LOG_TARGET_MAX,
        _LOG_TARGET_INVALID = -1
} LogTarget;

#define LOG_REALM_PLUS_LEVEL(realm, level)      \
        ((realm) << 10 | (level))
#define LOG_REALM_REMOVE_LEVEL(realm_level)     \
        ((realm_level >> 10))

void log_set_target(LogTarget target);
void log_set_max_level_realm(LogRealm realm, int level);
#define log_set_max_level(level)                \
        log_set_max_level_realm(LOG_REALM, (level))

void log_set_facility(int facility);

int log_set_target_from_string(const char *e);
int log_set_max_level_from_string_realm(LogRealm realm, const char *e);
#define log_set_max_level_from_string(e)        \
        log_set_max_level_from_string_realm(LOG_REALM, (e))

void log_show_color(bool b);
bool log_get_show_color(void) _pure_;
void log_show_location(bool b);
bool log_get_show_location(void) _pure_;

int log_show_color_from_string(const char *e);
int log_show_location_from_string(const char *e);

LogTarget log_get_target(void) _pure_;
int log_get_max_level_realm(LogRealm realm) _pure_;
#define log_get_max_level()                     \
        log_get_max_level_realm(LOG_REALM)

/* Functions below that open and close logs or configure logging based on the
 * environment should not be called from library code — this is always a job
 * for the application itself.
 */

int log_open(void);
void log_close(void);
void log_forget_fds(void);

void log_parse_environment_realm(LogRealm realm);
#define log_parse_environment() \
        log_parse_environment_realm(LOG_REALM)

int log_dispatch_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *extra,
                const char *extra_field,
                char *buffer);

int log_internal_realm(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(6,7);
#define log_internal(level, ...) \
        log_internal_realm(LOG_REALM_PLUS_LEVEL(LOG_REALM, (level)), __VA_ARGS__)

int log_internalv_realm(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format,
                va_list ap) _printf_(6,0);
#define log_internalv(level, ...) \
        log_internalv_realm(LOG_REALM_PLUS_LEVEL(LOG_REALM, (level)), __VA_ARGS__)

/* Realm is fixed to LOG_REALM_SYSTEMD for those */
int log_object_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *extra_field,
                const char *extra,
                const char *format, ...) _printf_(10,11);

int log_struct_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(6,0) _sentinel_;

int log_oom_internal(
                LogRealm realm,
                const char *file,
                int line,
                const char *func);

int log_format_iovec(
                struct iovec *iovec,
                size_t iovec_len,
                size_t *n,
                bool newline_separator,
                int error,
                const char *format,
                va_list ap) _printf_(6, 0);

int log_struct_iovec_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const struct iovec *input_iovec,
                size_t n_input_iovec);

/* This modifies the buffer passed! */
int log_dump_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                char *buffer);

/* Logging for various assertions */
_noreturn_ void log_assert_failed_realm(
                LogRealm realm,
                const char *text,
                const char *file,
                int line,
                const char *func);
#define log_assert_failed(text, ...) \
        log_assert_failed_realm(LOG_REALM, (text), __VA_ARGS__)

_noreturn_ void log_assert_failed_unreachable_realm(
                LogRealm realm,
                const char *text,
                const char *file,
                int line,
                const char *func);
#define log_assert_failed_unreachable(text, ...) \
        log_assert_failed_unreachable_realm(LOG_REALM, (text), __VA_ARGS__)

void log_assert_failed_return_realm(
                LogRealm realm,
                const char *text,
                const char *file,
                int line,
                const char *func);
#define log_assert_failed_return(text, ...) \
        log_assert_failed_return_realm(LOG_REALM, (text), __VA_ARGS__)

#define log_dispatch(level, error, buffer)                              \
        log_dispatch_internal(level, error, __FILE__, __LINE__, __func__, NULL, NULL, NULL, NULL, buffer)

/* Logging with level */
#define log_full_errno_realm(realm, level, error, ...)                  \
        ({                                                              \
                int _level = (level), _e = (error), _realm = (realm);   \
                (log_get_max_level_realm(_realm) >= LOG_PRI(_level))   \
                        ? log_internal_realm(LOG_REALM_PLUS_LEVEL(_realm, _level), _e, \
                                             __FILE__, __LINE__, __func__, __VA_ARGS__) \
                        : -abs(_e);                                     \
        })

#define log_full_errno(level, error, ...)                               \
        log_full_errno_realm(LOG_REALM, (level), (error), __VA_ARGS__)

#define log_full(level, ...) log_full_errno((level), 0, __VA_ARGS__)

int log_emergency_level(void);

/* Normal logging */
#define log_debug(...)     log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_info(...)      log_full(LOG_INFO,    __VA_ARGS__)
#define log_notice(...)    log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_warning(...)   log_full(LOG_WARNING, __VA_ARGS__)
#define log_error(...)     log_full(LOG_ERR,     __VA_ARGS__)
#define log_emergency(...) log_full(log_emergency_level(), __VA_ARGS__)

/* Logging triggered by an errno-like error */
#define log_debug_errno(error, ...)     log_full_errno(LOG_DEBUG,   error, __VA_ARGS__)
#define log_info_errno(error, ...)      log_full_errno(LOG_INFO,    error, __VA_ARGS__)
#define log_notice_errno(error, ...)    log_full_errno(LOG_NOTICE,  error, __VA_ARGS__)
#define log_warning_errno(error, ...)   log_full_errno(LOG_WARNING, error, __VA_ARGS__)
#define log_error_errno(error, ...)     log_full_errno(LOG_ERR,     error, __VA_ARGS__)
#define log_emergency_errno(error, ...) log_full_errno(log_emergency_level(), error, __VA_ARGS__)

#ifdef LOG_TRACE
#  define log_trace(...) log_debug(__VA_ARGS__)
#else
#  define log_trace(...) do {} while (0)
#endif

/* Structured logging */
#define log_struct_errno(level, error, ...) \
        log_struct_internal(LOG_REALM_PLUS_LEVEL(LOG_REALM, level), \
                            error, __FILE__, __LINE__, __func__, __VA_ARGS__, NULL)
#define log_struct(level, ...) log_struct_errno(level, 0, __VA_ARGS__)

#define log_struct_iovec_errno(level, error, iovec, n_iovec)            \
        log_struct_iovec_internal(LOG_REALM_PLUS_LEVEL(LOG_REALM, level), \
                                  error, __FILE__, __LINE__, __func__, iovec, n_iovec)
#define log_struct_iovec(level, iovec, n_iovec) log_struct_iovec_errno(level, 0, iovec, n_iovec)

/* This modifies the buffer passed! */
#define log_dump(level, buffer) \
        log_dump_internal(LOG_REALM_PLUS_LEVEL(LOG_REALM, level), \
                          0, __FILE__, __LINE__, __func__, buffer)

#define log_oom() log_oom_internal(LOG_REALM, __FILE__, __LINE__, __func__)

bool log_on_console(void) _pure_;

const char *log_target_to_string(LogTarget target) _const_;
LogTarget log_target_from_string(const char *s) _pure_;

/* Helper to prepare various field for structured logging */
#define LOG_MESSAGE(fmt, ...) "MESSAGE=" fmt, ##__VA_ARGS__

void log_received_signal(int level, const struct signalfd_siginfo *si);

/* If turned on, any requests for a log target involving "syslog" will be implicitly upgraded to the equivalent journal target */
void log_set_upgrade_syslog_to_journal(bool b);

/* If turned on, and log_open() is called, we'll not use STDERR_FILENO for logging ever, but rather open /dev/console */
void log_set_always_reopen_console(bool b);

/* If turned on, we'll open the log stream implicitly if needed on each individual log call. This is normally not
 * desired as we want to reuse our logging streams. It is useful however  */
void log_set_open_when_needed(bool b);

/* If turned on, then we'll never use IPC-based logging, i.e. never log to syslog or the journal. We'll only log to
 * stderr, the console or kmsg */
void log_set_prohibit_ipc(bool b);

int log_dup_console(void);

int log_syntax_internal(
                const char *unit,
                int level,
                const char *config_file,
                unsigned config_line,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(9, 10);

int log_syntax_invalid_utf8_internal(
                const char *unit,
                int level,
                const char *config_file,
                unsigned config_line,
                const char *file,
                int line,
                const char *func,
                const char *rvalue);

#define log_syntax(unit, level, config_file, config_line, error, ...)   \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_internal(unit, _level, config_file, config_line, _e, __FILE__, __LINE__, __func__, __VA_ARGS__) \
                        : -abs(_e);                                     \
        })

#define log_syntax_invalid_utf8(unit, level, config_file, config_line, rvalue) \
        ({                                                              \
                int _level = (level);                                   \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_invalid_utf8_internal(unit, _level, config_file, config_line, __FILE__, __LINE__, __func__, rvalue) \
                        : -EINVAL;                                      \
        })

#define DEBUG_LOGGING _unlikely_(log_get_max_level() >= LOG_DEBUG)
