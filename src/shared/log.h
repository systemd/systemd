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

#include <syslog.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>

#include "macro.h"

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
void log_show_location(bool b);

int log_show_color_from_string(const char *e);
int log_show_location_from_string(const char *e);

LogTarget log_get_target(void);
int log_get_max_level(void);

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
        const char *format, ...) _printf_attr_(5,6);

int log_metav(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format,
        va_list ap);

_noreturn_ void log_assert_failed(const char *text, const char *file, int line, const char *func);
_noreturn_ void log_assert_failed_unreachable(const char *text, const char *file, int line, const char *func);

/* This modifies the buffer passed! */
int log_dump_internal(
        int level,
        const char*file,
        int line,
        const char *func,
        char *buffer);

#define log_full(level, ...) log_meta(level,   __FILE__, __LINE__, __func__, __VA_ARGS__)

#define log_debug(...)   log_meta(LOG_DEBUG,   __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_info(...)    log_meta(LOG_INFO,    __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_notice(...)  log_meta(LOG_NOTICE,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_warning(...) log_meta(LOG_WARNING, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_error(...)   log_meta(LOG_ERR,     __FILE__, __LINE__, __func__, __VA_ARGS__)

/* This must be a macro for __LINE__ etc. to work */
#define log_oom() ({ \
       log_error("Out of memory."); \
       -ENOMEM; \
})

/* This modifies the buffer passed! */
#define log_dump(level, buffer) log_dump_internal(level, __FILE__, __LINE__, __func__, buffer)

const char *log_target_to_string(LogTarget target);
LogTarget log_target_from_string(const char *s);
