/*
 * udev.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 *
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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "udev.h"
#include "udev_version.h"
#include "udev_dbus.h"
#include "namedev.h"
#include "udevdb.h"
#include "libsysfs/libsysfs.h"

/* global variables */
char **main_argv;
char **main_envp;

static inline char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}

static inline char *get_devpath(void)
{
	char *devpath;

	devpath = getenv("DEVPATH");
	return devpath;
}

static inline char *get_seqnum(void)
{
	char *seqnum;

	seqnum = getenv("SEQNUM");
	return seqnum;
}

int main(int argc, char **argv, char **envp)
{
	char *action;
	char *devpath;
	char *subsystem;
	int retval = -EINVAL;
	
	main_argv = argv;
	main_envp = envp;

	dbg("version %s", UDEV_VERSION);

	if (argc != 2) {
		dbg ("unknown number of arguments");
		goto exit;
	}

	subsystem = argv[1];

	devpath = get_devpath();
	if (!devpath) {
		dbg ("no devpath?");
		goto exit;
	}
	dbg("looking at '%s'", devpath);

	/* we only care about class devices and block stuff */
	if (!strstr(devpath, "class") &&
	    !strstr(devpath, "block")) {
		dbg("not a block or class device");
		goto exit;
	}

	/* but we don't care about net class devices */
	if (strcmp(subsystem, "net") == 0) {
		dbg("don't care about net devices");
		goto exit;
	}

	action = get_action();
	if (!action) {
		dbg ("no action?");
		goto exit;
	}

	/* initialize our configuration */
	udev_init_config();

	/* connect to the system message bus */
	sysbus_connect();

	/* initialize udev database */
	retval = udevdb_init(UDEVDB_DEFAULT);
	if (retval != 0) {
		dbg("unable to initialize database");
		goto exit;
	}

	/* initialize the naming deamon */
	namedev_init();

	if (strcmp(action, "add") == 0)
		retval = udev_add_device(devpath, subsystem);

	else if (strcmp(action, "remove") == 0)
		retval = udev_remove_device(devpath, subsystem);

	else {
		dbg("unknown action '%s'", action);
		retval = -EINVAL;
	}
	udevdb_exit();

	/* disconnect from the system message bus */
	sysbus_disconnect();

exit:
	return retval;
}
