/*
 * udevdb.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003 IBM Corp.
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

/*
 * udev database library
 */
#define _KLIBC_HAS_ARCH_SIG_ATOMIC_T
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#include "udev_version.h"
#include "udev.h"
#include "namedev.h"
#include "udevdb.h"
#include "tdb/tdb.h"
#include "libsysfs/libsysfs.h"

static TDB_CONTEXT *udevdb;


int udevdb_add_dev(const char *path, const struct udevice *dev)
{
	TDB_DATA key, data;
	char keystr[SYSFS_PATH_MAX];

	if ((path == NULL) || (dev == NULL))
		return -ENODEV;

	memset(keystr, 0, NAME_SIZE);
	strcpy(keystr, path);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data.dptr = (void *)dev;
	data.dsize = sizeof(*dev);
	
	return tdb_store(udevdb, key, data, TDB_REPLACE); 
}

struct udevice *udevdb_get_dev(const char *path)
{
	TDB_DATA key, data;
	struct udevice *dev;

	if (path == NULL)
		return NULL;

	key.dptr = (void *)path;
	key.dsize = strlen(path) + 1;

	data = tdb_fetch(udevdb, key);
	if (data.dptr == NULL || data.dsize == 0)
		return NULL;

	dev = malloc(sizeof(*dev));
	if (dev == NULL)
		goto exit;

	memcpy(dev, data.dptr, sizeof(*dev));
exit:
	free(data.dptr);
	return dev;
}

int udevdb_delete_dev(const char *path)
{
	TDB_DATA key;
	char keystr[SYSFS_PATH_MAX];

	if (path == NULL)
		return -EINVAL;

	memset(keystr, 0, sizeof(keystr));
	strcpy(keystr, path);

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	return tdb_delete(udevdb, key);
}

/**
 * udevdb_exit: closes database
 */
void udevdb_exit(void)
{
	if (udevdb != NULL) {
		tdb_close(udevdb);
		udevdb = NULL;
	}
}

/**
 * udevdb_init: initializes database
 * @init_flag: UDEVDB_INTERNAL - database stays in memory
 *	       UDEVDB_DEFAULT - database is written to a file
 */
int udevdb_init(int init_flag)
{
	if (init_flag != UDEVDB_DEFAULT && init_flag != UDEVDB_INTERNAL)
		return -EINVAL;

	udevdb = tdb_open(udev_db_filename, 0, init_flag, O_RDWR | O_CREAT, 0644);
	if (udevdb == NULL) {
		if (init_flag == UDEVDB_INTERNAL)
			dbg("unable to initialize in-memory database");
		else
			dbg("unable to initialize database at '%s'", udev_db_filename);
		return -EINVAL;
	}
	return 0;
}
