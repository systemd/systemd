/*
 * logging.c
 *
 * Simple logging functions that can be compiled away into nothing.
 *
 * Copyright (C) 2001-2003 Greg Kroah-Hartman <greg@kroah.com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation, version 2 of the License.
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

#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include "udev.h"

#ifdef DEBUG

static int logging_init = 0;
static unsigned char udev_logname[42];

static void init_logging (void)
{
	snprintf(udev_logname,42,"udev[%d]", getpid());

	openlog (udev_logname, 0, LOG_DAEMON);
	logging_init = 1;
}

/**
 * log_message - sends a message to the logging facility
 */
int log_message (int level, const char *format, ...)
{
	va_list	args;

	if (!logging_init)
		init_logging();
	va_start (args, format);
	vsyslog (level, format, args);
	va_end (args);
	return 1;
}

#endif
