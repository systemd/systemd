/*
 * udev-remove.c
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


/*
 * Look up the sysfs path in the database to see if we have named this device
 * something different from the kernel name.  If we have, us it.  If not, use
 * the default kernel name for lack of anything else to know to do.
 */
static char *get_name(char *path, int major, int minor)
{
	static char name[100];
	struct udevice *dev;
	char *temp;

	dev = udevdb_get_dev(path);
	if (dev != NULL) {
		strcpy(name, dev->name);
		goto exit;
	}

	dbg("%s not found in database, falling back on default name", path);
	temp = strrchr(path, '/');
	if (temp == NULL)
		return NULL;
	strncpy(name, &temp[1], sizeof(name));

exit:
	dbg("name is %s", name);
	return &name[0];
}

/*
 * We also want to clean up any symlinks that were created in create_node()
 */
static int delete_node(char *name)
{
	char filename[255];

	strncpy(filename, udev_root, sizeof(filename));
	strncat(filename, name, sizeof(filename));

	dbg("unlinking %s", filename);
	return unlink(filename);
}

int udev_remove_device(char *device, char *subsystem)
{
	char *name;
	int retval = 0;

	name = get_name(device, 0, 0);
	if (name == NULL) {
		dbg ("get_name failed");
		retval = -ENODEV;
		goto exit;
	}

	udevdb_delete_dev(device);

	return delete_node(name);

exit:
	return retval;
}
