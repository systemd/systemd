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

#include <stdbool.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/signalfd.h>
#include <errno.h>

#include "macro.h"
#include "sd-id128.h"

typedef enum LogTarget{
        LOG_TARGET_CONSOLE,
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

int log_meta(
                int level,
                const char*file,
                int line,
                const char *func,
                const char *format, ...) _printf_(5,6);

int log_metav(
                int level,
                const char*file,
                int line,
                const char *func,
                const char *format,
                va_list ap) _printf_(5,0);

int log_meta_object(
                int level,
                const char*file,
                int line,
                const char *func,
                const char *object_name,
                const char *object,
                const char *format, ...) _printf_(7,8);

int log_metav_object(
                int level,
                const char*file,
                int line,
                const char *func,
                const char *object_name,
                const char *object,
                const char *format,
                va_list ap) _printf_(7,0);

int log_struct_internal(
                int level,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(5,0) _sentinel_;

int log_oom_internal(
                const char *file,
                int line,
                const char *func);

/* This modifies the buffer passed! */
int log_dump_internal(
                int level,
                const char*file,
                int line,
                const char *func,
                char *buffer);

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

#define log_full(level, ...) \
do { \
        if (log_get_max_level() >= (level)) \
                log_meta((level), __FILE__, __LINE__, __func__, __VA_ARGS__); \
} while (0)

#define log_debug(...)   log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_info(...)    log_full(LOG_INFO,    __VA_ARGS__)
#define log_notice(...)  log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_warning(...) log_full(LOG_WARNING, __VA_ARGS__)
#define log_error(...)   log_full(LOG_ERR,     __VA_ARGS__)

#define log_struct(level, ...) log_struct_internal(level, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define log_oom() log_oom_internal(__FILE__, __LINE__, __func__)

/* This modifies the buffer passed! */
#define log_dump(level, buffer) log_dump_internal(level, __FILE__, __LINE__, __func__, buffer)

bool log_on_console(void) _pure_;

const char *log_target_to_string(LogTarget target) _const_;
LogTarget log_target_from_string(const char *s) _pure_;

#define MESSAGE_ID(x) "MESSAGE_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(x)

void log_received_signal(int level, const struct signalfd_siginfo *si);
