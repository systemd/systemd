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
#include "udev_dbus.h"
#include "namedev.h"
#include "udevdb.h"
#include "libsysfs/libsysfs.h"

static int delete_path(char *path)
{
	char *pos;
	int retval;

	pos = strrchr(path, '/');
	while (1) {
		*pos = '\0';
		pos = strrchr(path, '/');

		/* don't remove the last one */
		if ((pos == path) || (pos == NULL))
			break;

		/* remove if empty */
		retval = rmdir(path);
		if (retval) {
			if (errno == ENOTEMPTY)
				return 0;
			dbg("rmdir(%s) failed with error '%s'",
			    path, strerror(errno));
			break;
		}
		dbg("removed '%s'", path);
	}
	return 0;
}

static int delete_node(struct udevice *dev)
{
	char filename[255];
	char *symlinks;
	char *linkname;
	int retval;

	strncpy(filename, udev_root, sizeof(filename));
	strncat(filename, dev->name, sizeof(filename));

	dbg("unlinking node '%s'", filename);
	retval = unlink(filename);
	if (retval) {
		dbg("unlink(%s) failed with error '%s'",
			filename, strerror(errno));
		return retval;
	}

	/* remove subdirectories */
	if (strchr(dev->name, '/'))
		delete_path(filename);

	if (*dev->symlink) {
		symlinks = dev->symlink;
		while (1) {
			linkname = strsep(&symlinks, " ");
			if (linkname == NULL)
				break;

			strncpy(filename, udev_root, sizeof(filename));
			strncat(filename, linkname, sizeof(filename));

			dbg("unlinking symlink '%s'", filename);
			retval = unlink(filename);
			if (retval) {
				dbg("unlink(%s) failed with error '%s'",
					filename, strerror(errno));
				return retval;
			}
			if (strchr(dev->symlink, '/')) {
				delete_path(filename);
			}
		}
	}

	return retval;
}

/*
 * Look up the sysfs path in the database to see if we have named this device
 * something different from the kernel name.  If we have, us it.  If not, use
 * the default kernel name for lack of anything else to know to do.
 */
int udev_remove_device(char *path, char *subsystem)
{
	char name[100];
	struct udevice *dev;
	char *temp;

	dev = udevdb_get_dev(path);
	if (dev == NULL) {
		dbg("'%s' not found in database, falling back on default name", path);
		temp = strrchr(path, '/');
		if (temp == NULL)
			return -ENODEV;
		strncpy(name, &temp[1], sizeof(name));
	}

	dbg("name is '%s'", dev->name);
	udevdb_delete_dev(path);

	sysbus_send_remove(name, path);

	return delete_node(dev);
}
