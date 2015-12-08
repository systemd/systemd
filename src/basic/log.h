/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <syslog.h>

#include "sd-id128.h"

#include "macro.h"

typedef enum LogTarget{
        LOG_TARGET_CONSOLE,
        LOG_TARGET_CONSOLE_PREFIXED,
        LOG_TARGET_KMSG,
        LOG_TARGET_JOURNAL,
        LOG_TARGET_JOURNAL_OR_KMSG,
        LOG_TARGET_SYSLOG,
        LOG_TARGET_SYSLOG_OR_KMSG,
        LOG_TARGET_AUTO, /* console if stderr is tty, JOURNAL_OR_KMSG otherwise */
        LOG_TARGET_SAFE, /* console if stderr is tty, KMSG otherwise */
        LOG_TARGET_NULL,
        _LOG_TARGET_MAX,
        _LOG_TARGET_INVALID = -1
}  LogTarget;

void log_set_target(LogTarget target);
void log_set_max_level(int level);
void log_set_facility(int facility);

int log_set_target_from_string(const char *e);
int log_set_max_level_from_string(const char *e);

void log_show_color(bool b);
bool log_get_show_color(void) _pure_;
void log_show_location(bool b);
bool log_get_show_location(void) _pure_;

int log_show_color_from_string(const char *e);
int log_show_location_from_string(const char *e);

LogTarget log_get_target(void) _pure_;
int log_get_max_level(void) _pure_;

int log_open(void);
void log_close(void);
void log_forget_fds(void);

void log_close_syslog(void);
void log_close_journal(void);
void log_close_kmsg(void);
void log_close_console(void);

void log_parse_environment(void);

int log_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(6,7);

int log_internalv(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format,
                va_list ap) _printf_(6,0);

int log_object_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *format, ...) _printf_(8,9);

int log_object_internalv(
                int level,
                int error,
                const char*file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *format,
                va_list ap) _printf_(8,0);

int log_struct_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(6,0) _sentinel_;

int log_oom_internal(
                const char *file,
                int line,
                const char *func);

/* This modifies the buffer passed! */
int log_dump_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                char *buffer);

/* Logging for various assertions */
noreturn void log_assert_failed(
                const char *text,
                const char *file,
                int line,
                const char *func);

noreturn void log_assert_failed_unreachable(
                const char *text,
                const char *file,
                int line,
                const char *func);

void log_assert_failed_return(
                const char *text,
                const char *file,
                int line,
                const char *func);

/* Logging with level */
#define log_full_errno(level, error, ...)                               \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_internal(_level, _e, __FILE__, __LINE__, __func__, __VA_ARGS__) \
                        : -abs(_e);                                     \
        })

#define log_full(level, ...) log_full_errno(level, 0, __VA_ARGS__)

/* Normal logging */
#define log_debug(...)     log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_info(...)      log_full(LOG_INFO,    __VA_ARGS__)
#define log_notice(...)    log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_warning(...)   log_full(LOG_WARNING, __VA_ARGS__)
#define log_error(...)     log_full(LOG_ERR,     __VA_ARGS__)
#define log_emergency(...) log_full(getpid() == 1 ? LOG_EMERG : LOG_ERR, __VA_ARGS__)

/* Logging triggered by an errno-like error */
#define log_debug_errno(error, ...)     log_full_errno(LOG_DEBUG,   error, __VA_ARGS__)
#define log_info_errno(error, ...)      log_full_errno(LOG_INFO,    error, __VA_ARGS__)
#define log_notice_errno(error, ...)    log_full_errno(LOG_NOTICE,  error, __VA_ARGS__)
#define log_warning_errno(error, ...)   log_full_errno(LOG_WARNING, error, __VA_ARGS__)
#define log_error_errno(error, ...)     log_full_errno(LOG_ERR,     error, __VA_ARGS__)
#define log_emergency_errno(error, ...) log_full_errno(getpid() == 1 ? LOG_EMERG : LOG_ERR, error, __VA_ARGS__)

#ifdef LOG_TRACE
#  define log_trace(...) log_debug(__VA_ARGS__)
#else
#  define log_trace(...) do {} while(0)
#endif

/* Structured logging */
#define log_struct(level, ...) log_struct_internal(level, 0, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_struct_errno(level, error, ...) log_struct_internal(level, error, __FILE__, __LINE__, __func__, __VA_ARGS__)

/* This modifies the buffer passed! */
#define log_dump(level, buffer) log_dump_internal(level, 0, __FILE__, __LINE__, __func__, buffer)

#define log_oom() log_oom_internal(__FILE__, __LINE__, __func__)

bool log_on_console(void) _pure_;

const char *log_target_to_string(LogTarget target) _const_;
LogTarget log_target_from_string(const char *s) _pure_;

/* Helpers to prepare various fields for structured logging */
#define LOG_MESSAGE(fmt, ...) "MESSAGE=" fmt, ##__VA_ARGS__
#define LOG_MESSAGE_ID(x) "MESSAGE_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(x)

void log_received_signal(int level, const struct signalfd_siginfo *si);

void log_set_upgrade_syslog_to_journal(bool b);

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
                if (log_get_max_level() >= LOG_PRI(_level)) {           \
                        _cleanup_free_ char *_p = NULL;                 \
                        _p = utf8_escape_invalid(rvalue);               \
                        log_syntax_internal(unit, _level, config_file, config_line, 0, __FILE__, __LINE__, __func__, \
                                            "String is not UTF-8 clean, ignoring assignment: %s", strna(_p)); \
                }                                                       \
                -EINVAL;                                                \
        })
