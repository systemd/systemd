/*
 * udev_selinux.c
 *
 * Copyright (C) 2004 Daniel J Walsh <dwalsh@redhat.com>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <selinux/selinux.h>

#include "../../udev_lib.h"
#include "../../logging.h"

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

static void selinux_add_node(char *filename)
{
	int retval;

	if (is_selinux_enabled() > 0) {
		security_context_t scontext;
		retval = matchpathcon(filename, 0, &scontext);
		if (retval < 0) {
			dbg("matchpathcon(%s) failed\n", filename);
		} else {
			retval = setfilecon(filename,scontext);
			if (retval < 0)
				dbg("setfiles %s failed with error '%s'",
				    filename, strerror(errno));
			free(scontext);
		}
	}
}

int main(int argc, char *argv[], char *envp[])
{
	char *action;
	char *devname;
	int retval = 0;

	init_logging("udev_selinux");

	action = get_action();
	if (!action) {
		dbg("no action?");
		goto exit;
	}
	devname = get_devname();
	if (!devname) {
		dbg("no devname?");
		goto exit;
	}

	if (strcmp(action, "add") == 0)
		selinux_add_node(devname);

exit:
	return retval;
}
