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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "utils.h"

static int debug_on = 0;
static int quiet = 0;
FILE *logfile = NULL;

void
do_log (int level, const char *fmt, ...)
{
	va_list args;
	char buffer[1024];
	char tag = 'L';

	if (level >= LOG_DBG && !debug_on)
		return;

	va_start (args, fmt);
	vsnprintf (buffer, sizeof (buffer), fmt, args);
	va_end (args);

	if (level == LOG_ERR)
		tag = 'E';
	else if (level == LOG_MSG)
		tag = 'L';
	else if (level == LOG_DBG)
		tag = 'D';

	if (logfile)
		fprintf (logfile, "%c: %s\n", tag, buffer);
	if (!quiet)
		fprintf ((level == LOG_ERR) ? stderr : stdout, "%c: %s\n", tag, buffer);
}

int
log_startup (const char *path, int do_debug, int be_quiet)
{
	time_t t;

	quiet = be_quiet;
	debug_on = do_debug;

	if (!path)
		return 0;

	logfile = fopen (path, "a+");
	if (!logfile)
		return 1;

	t = time (NULL);
	message ("\n**** Started: %s\n", ctime (&t));
	return 0;
}

void
log_shutdown (void)
{
	if (logfile)
		fclose (logfile);
}

