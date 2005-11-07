/*
 * udeveventrecorder.c
 *
 * Copyright (C) 2004-2005 SuSE Linux Products GmbH
 * Author:
 *	Olaf Hering <olh@suse.de>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "udev.h"
#include "udev_version.h"
#include "udev_utils.h"
#include "logging.h"

#define BUFSIZE 12345
#define FNSIZE  123

static int udev_log = 0;

#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list	args;

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

int main(int argc, char **argv, char **envp)
{
	int fd, i;
	unsigned long seq;
	char **ep = envp;
	char *buf, *p, *a;
	struct stat sb;
	const char *env;

	if (stat("/events", &sb) || !(S_ISDIR(sb.st_mode)))
		return 0;

	env = getenv("UDEV_LOG");
	if (env)
		udev_log = log_priority(env);

	logging_init("udeveventrecorder");
	dbg("version %s", UDEV_VERSION);

	p = getenv("SEQNUM");
	a = getenv("ACTION");
	buf = malloc(FNSIZE);
	if (!(buf && a && argv[1]))
		goto error;
	if (p)
		seq = strtoul(p, NULL, 0);
	else
		seq = 0;

	snprintf(buf, FNSIZE, "/events/debug.%05lu.%s.%s.%u", seq, argv[1], a ? a : "", getpid());
	if ((fd = open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0644)) < 0) {
		err("error creating '%s': %s", buf, strerror(errno));
		goto error;
	}
	free(buf);
	p = malloc(BUFSIZE);
	buf = p;
	buf += snprintf(buf, p + BUFSIZE - buf, "set --");
	for (i = 1; i < argc; ++i) {
		buf += snprintf(buf, p + BUFSIZE - buf, " %s", argv[i]);
		if (buf > p + BUFSIZE)
			goto full;
	}
	buf += snprintf(buf, p + BUFSIZE - buf, "\n");
	if (buf > p + BUFSIZE)
		goto full;
	while (*ep) {
		unsigned char *t;
		t = memchr(*ep, '=', strlen(*ep));
		if (t) {
			*t = '\0';
			t++;
			buf += snprintf(buf, p + BUFSIZE - buf, "%s='%s'\n", *ep, t);
			--t;
			*t = '=';
		}
		ep++;
		if (buf > p + BUFSIZE)
			break;
	}

full:
	buf = p;
	write(fd, buf, strlen(buf));
	close(fd);
	free(buf);
	return 0;

error:
	fprintf(stderr, "record enviroment to /events, to be called from udev context\n");
	return 1;
}
