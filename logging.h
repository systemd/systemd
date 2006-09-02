/*
 * simple logging functions that can be expanded into nothing
 *
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef LOGGING_H
#define LOGGING_H

#define err(format, arg...)		do { } while (0)
#define info(format, arg...)		do { } while (0)
#define dbg(format, arg...)		do { } while (0)
#define logging_init(foo)		do { } while (0)
#define logging_close(foo)		do { } while (0)

#ifdef USE_LOG
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>

#undef err
#define err(format, arg...)							\
	do {									\
		log_message(LOG_ERR ,"%s: " format ,__FUNCTION__ ,## arg);	\
	} while (0)

#undef info
#define info(format, arg...)							\
	do {									\
		log_message(LOG_INFO ,"%s: " format ,__FUNCTION__ ,## arg);	\
	} while (0)

#ifdef DEBUG
#undef dbg
#define dbg(format, arg...)							\
	do {									\
		log_message(LOG_DEBUG ,"%s: " format ,__FUNCTION__ ,## arg);	\
	} while (0)
#endif

extern void log_message(int priority, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

#undef logging_init
static inline void logging_init(const char *program_name)
{
	openlog(program_name, LOG_PID | LOG_CONS, LOG_DAEMON);
}

#undef logging_close
static inline void logging_close(void)
{
	closelog();
}

#endif	/* USE_LOG */

#endif
