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

#include "udev.h"
#include "udev_version.h"
#include "namedev.h"
#include "udevdb.h"
#include "libsysfs/libsysfs.h"


static char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}


static char *get_device(void)
{
	char *device;

	device = getenv("DEVPATH");
	return device;
}

int main(int argc, char *argv[])
{
	char *action;
	char *device;
	char *subsystem;
	int retval = -EINVAL;
	
	if (argc != 2) {
		dbg ("unknown number of arguments");
		goto exit;
	}

	subsystem = argv[1];

	device = get_device();
	if (!device) {
		dbg ("no device?");
		goto exit;
	}
	dbg("looking at %s", device);

	/* we only care about class devices and block stuff */
	if (!strstr(device, "class") &&
	    !strstr(device, "block")) {
		dbg("not block or class");
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

	/* initialize udev database */
	retval = udevdb_init(UDEVDB_DEFAULT);
	if (retval != 0) {
		dbg("Unable to initialize database.");
		goto exit;
	}

	/* initialize the naming deamon */
	namedev_init();

	if (strcmp(action, "add") == 0)
		retval = udev_add_device(device, argv[1]);

	else if (strcmp(action, "remove") == 0)
		retval = udev_remove_device(device, argv[1]);

	else {
		dbg("Unknown action: %s", action);
		retval = -EINVAL;
	}
	udevdb_exit();

exit:	
	return retval;
}

