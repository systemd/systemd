/*
 * udevdb.c - udev database library
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

#define _KLIBC_HAS_ARCH_SIG_ATOMIC_T
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_lib.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"
#include "udevdb.h"
#include "tdb/tdb.h"

static TDB_CONTEXT *udevdb;
sig_atomic_t gotalarm;

int udevdb_add_dev(struct udevice *udev)
{
	TDB_DATA key, data;
	char keystr[SYSFS_PATH_MAX];

	if (udev->test_run)
		return 0;

	if (udevdb == NULL)
		return -1;

	memset(keystr, 0x00, SYSFS_PATH_MAX);
	strfieldcpy(keystr, udev->devpath);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	data.dptr = (void *) udev;
	data.dsize = UDEVICE_DB_LEN;
	dbg("store key '%s' for device '%s'", keystr, udev->name);

	return tdb_store(udevdb, key, data, TDB_REPLACE); 
}

int udevdb_get_dev(const char *path, struct udevice *udev)
{
	TDB_DATA key, data;

	if (udevdb == NULL)
		return -1;

	if (path == NULL)
		return -ENODEV;

	key.dptr = (void *)path;
	key.dsize = strlen(path) + 1;

	data = tdb_fetch(udevdb, key);
	if (data.dptr == NULL || data.dsize == 0)
		return -ENODEV;

	memset(udev, 0x00, sizeof(struct udevice));
	memcpy(udev, data.dptr, UDEVICE_DB_LEN);

	return 0;
}

int udevdb_delete_dev(const char *path)
{
	TDB_DATA key;
	char keystr[SYSFS_PATH_MAX];

	if (udevdb == NULL)
		return -1;

	if (path == NULL)
		return -EINVAL;

	memset(keystr, 0, sizeof(keystr));
	strfieldcpy(keystr, path);

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

	tdb_set_lock_alarm(&gotalarm);

	udevdb = tdb_open(udev_db_filename, 0, init_flag, O_RDWR | O_CREAT, 0644);
	if (udevdb == NULL) {
		if (init_flag == UDEVDB_INTERNAL)
			dbg("unable to initialize in-memory database");
		else
			dbg("unable to initialize database at '%s'", udev_db_filename);
		return -EACCES;
	}
	return 0;
}

/**
 * udevdb_open_ro: open database for reading
 */
int udevdb_open_ro(void)
{
	udevdb = tdb_open(udev_db_filename, 0, 0, O_RDONLY, 0);
	if (udevdb == NULL) {
		dbg("unable to open database at '%s'", udev_db_filename);
		return -EACCES;
	}
	return 0;
}

static int (*user_record_callback) (const char *path, struct udevice *dev);

static int traverse_callback(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	return user_record_callback((char*) key.dptr, (struct udevice*) dbuf.dptr);
}

/**
 * udevdb_call_foreach: dumps whole database by passing record data to user function
 * @user_record_handler: user function called for every record in the database
 */
int udevdb_call_foreach(int (*user_record_handler) (const char *path, struct udevice *dev))
{
	int retval = 0;

	if (udevdb == NULL)
		return -1;

	if (user_record_handler == NULL) {
		dbg("invalid user record handling function");
		return -EINVAL;
	}
	user_record_callback = user_record_handler;
	retval = tdb_traverse(udevdb, traverse_callback, NULL);
	if (retval < 0)
		return -ENODEV;
	else
		return 0;
}

static struct udevice *find_dev;
static char *find_path;
static const char *find_name;
static int find_found;

static int find_device_by_name(const char *path, struct udevice *udev)
{
	char *pos;
	int len;

	if (strncmp(udev->name, find_name, sizeof(udev->name)) == 0) {
		memcpy(find_dev, udev, sizeof(struct udevice));
		strfieldcpymax(find_path, path, NAME_SIZE);
		find_found = 1;
		/* stop search */
		return 1;
	}
	/* look for matching symlink*/
	foreach_strpart(udev->symlink, " ", pos, len) {
		if (strncmp(pos, find_name, len) != 0)
			continue;

		if (len != strlen(find_name))
			continue;

		memcpy(find_dev, udev, sizeof(struct udevice));
		strfieldcpymax(find_path, path, NAME_SIZE);
		find_found = 1;
		return 1;
	}
	return 0;
}

/**
 * udevdb_get_dev_byname: search device with given name by traversing the whole database
 */
int udevdb_get_dev_byname(const char *name, char *path, struct udevice *dev)
{
	find_found = 0;
	find_path = path;
	find_dev = dev;
	find_name = name;
	udevdb_call_foreach(find_device_by_name);
	if (find_found == 1)
		return 0;
	else
		return -1;
}
