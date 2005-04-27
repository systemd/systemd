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
#include "udev.h"
#include "udev_version.h"


static char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}


/* yeah this should be dynamically allocated... */
static char device[255];

static char *get_device(void)
{
	char *temp;

	temp = getenv("DEVPATH");
	if (temp == NULL)
		return NULL;
	strcpy(device, SYSFS_ROOT);
	strcat(device, temp);

	return device;
}


int main(int argc, char *argv[])
{
	char *subsystem;
	char *action;
	char *dev;
	
	if (argc != 2) {
		dbg ("unknown number of arguments");
		return 1;
	}

	subsystem = argv[1];

	action = get_action();
	if (!action) {
		dbg ("no action?");
		return 1;
	}

	dev = get_device();
	if (!dev) {
		dbg ("no device?");
		return 1;
	}

	return 0;
}

