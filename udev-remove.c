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
 * Here would go a call to the naming deamon, to get the name we want to have
 * for this device.  But for now, let's just default to whatever the kernel is
 * calling the device as that will keep the "old-style" naming policy
 */
static char *get_name(char *dev, int major, int minor)
{
	static char name[100];
	char *temp;

	temp = strrchr(dev, '/');
	if (temp == NULL)
		return NULL;
	strncpy(name, &temp[1], sizeof(name));

	dbg("name is %s", name);

	return &name[0];
}

/*
 * We also want to clean up any symlinks that were created in create_node()
 */
static int delete_node(char *name)
{
	char filename[255];

	strncpy(filename, UDEV_ROOT, sizeof(filename));
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

	udevdb_delete_udevice(name);

	return delete_node(name);

exit:
	return retval;
}
