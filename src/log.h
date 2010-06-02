/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foologhfoo
#define foologhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <syslog.h>

#include "macro.h"

/* If set to SYSLOG and /dev/log can not be opened we fall back to
 * KSMG. If KMSG fails, we fall back to CONSOLE */
typedef enum LogTarget{
        LOG_TARGET_CONSOLE,
        LOG_TARGET_KMSG,
        LOG_TARGET_SYSLOG,
        LOG_TARGET_SYSLOG_OR_KMSG,
        _LOG_TARGET_MAX,
        _LOG_TARGET_INVALID = -1
}  LogTarget;

void log_set_target(LogTarget target);
void log_set_max_level(int level);

int log_set_target_from_string(const char *e);
int log_set_max_level_from_string(const char *e);

LogTarget log_get_target(void);
int log_get_max_level(void);

int log_open(void);

void log_close_syslog(void);
void log_close_kmsg(void);
void log_close_console(void);

void log_parse_environment(void);

int log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) _printf_attr_(5,6);

_noreturn_ void log_assert(
        const char*file,
        int line,
        const char *func,
        const char *format, ...) _printf_attr_(4,5);

#define log_debug(...)   log_meta(LOG_DEBUG,   __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_info(...)    log_meta(LOG_INFO,    __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_notice(...)  log_meta(LOG_NOTICE,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_warning(...) log_meta(LOG_WARNING, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define log_error(...)   log_meta(LOG_ERR,     __FILE__, __LINE__, __func__, __VA_ARGS__)

const char *log_target_to_string(LogTarget target);
LogTarget log_target_from_string(const char *s);

#endif
