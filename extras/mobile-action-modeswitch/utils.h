/*
 * Modem mode switcher
 *
 * Copyright (C) 2009  Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details:
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#define LOG_ERR  0
#define LOG_MSG  1
#define LOG_DBG  2

#define message(fmt, args...)   do_log (LOG_MSG, fmt, ##args);
#define error(fmt, args...)     do_log (LOG_ERR, fmt, ##args);
#define debug(fmt, args...)     do_log (LOG_DBG, fmt, ##args);

void do_log (int level, const char *fmt, ...);
int log_startup (const char *path, int do_debug, int be_quiet);
void log_shutdown (void);

#endif  /* __UTILS_H__ */
