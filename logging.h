/*
 * udev.h
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef LOGGING_H
#define LOGGING_H

#ifdef LOG
#include <syslog.h>
#define info(format, arg...)								\
	do {										\
		log_message (LOG_INFO , format , ## arg);	\
	} while (0)
#else
	#define info(format, arg...) do { } while (0)
#endif

#ifdef DEBUG
#define dbg(format, arg...)								\
	do {										\
		log_message (LOG_DEBUG , "%s: " format , __FUNCTION__ , ## arg);	\
	} while (0)
#else
	#define dbg(format, arg...) do { } while (0)
#endif

/* Parser needs it's own debugging statement, we usually don't care about this at all */
#ifdef DEBUG_PARSER
#define dbg_parse(format, arg...)							\
	do {										\
		log_message (LOG_DEBUG , "%s: " format , __FUNCTION__ , ## arg);	\
	} while (0)
#else
	#define dbg_parse(format, arg...) do { } while (0)
#endif


extern int log_message (int level, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

#endif
