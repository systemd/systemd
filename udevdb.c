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

struct sysfsdb_record {
	char name[PATH_SIZE];
};

/**
 * namedb_record - device name is key, remaining udevice info stored here.
 */
struct namedb_record {
	char sysfs_dev_path[PATH_SIZE];
	char class_dev_name[NAME_SIZE];
	char class_name[NAME_SIZE];
	char id[ID_SIZE];
	char type;
	int major;
	int minor;
	mode_t mode;
};

/**
 * udevdb_close: close udev database
 */
static void udevdb_close(void)
{
	if (udevdb != NULL) {
		tdb_close(udevdb);
		udevdb = NULL;
	}
}

/**
 * udevdb_open: opens udev's database
 * @method: database can either be in memory - UDEVDB_INTERNAL - or
 * 	written to a file with UDEVDB_DEFAULT.
 */
static int udevdb_open(int method)
{
	udevdb = tdb_open(UDEV_CONFIG_DIR UDEV_DB, 0, method, O_RDWR | O_CREAT, 0644);
	if (udevdb == NULL) {
		if (method == UDEVDB_INTERNAL)
			dbg("Unable to initialize in-memory database");
		else
			dbg("Unable to initialize database at %s", UDEV_CONFIG_DIR UDEV_DB);
		return -EINVAL;
	}
	return 0;
}

static struct sysfsdb_record *sysfsdb_fetch(const char *path)
{
	TDB_DATA key, data;
	char keystr[PATH_SIZE+2]; 
	struct sysfsdb_record *rec = NULL;

	if (strlen(path) >= PATH_SIZE)
		return NULL;

	memset(keystr, 0, sizeof(keystr));
	strcpy(keystr, path);

	dbg("keystr = %s", keystr);

	key.dptr = (void *)keystr;
	key.dsize = strlen(keystr) + 1;

	data = tdb_fetch(udevdb, key);
	if (data.dptr == NULL || data.dsize == 0) {
		dbg("tdb_fetch did not work :(");
		return NULL;
	}
	
	rec = (struct sysfsdb_record *)malloc(sizeof(struct sysfsdb_record));
	if (rec == NULL) {
		free(data.dptr);
		return NULL;
	}
	
	memcpy(rec, data.dptr, sizeof(struct sysfsdb_record));
	free(data.dptr);

	return rec;
}

/**
 * namedb_fetch
 */
static struct namedb_record *namedb_fetch(const char *name)
{
	TDB_DATA key, data;
	char nm_keystr[NAME_SIZE]; 
	struct namedb_record *nrec = NULL;

	if (name == NULL)
		return NULL; 
	if (strlen(name) >= NAME_SIZE)
		return NULL;

	memset(nm_keystr, 0, NAME_SIZE);
	strcpy(nm_keystr, name);

	key.dptr = (void *)nm_keystr;
	key.dsize = strlen(nm_keystr) + 1;

	data = tdb_fetch(udevdb, key);
	if (data.dptr == NULL || data.dsize == 0)
		return NULL;

	nrec = (struct namedb_record *)malloc(sizeof(struct namedb_record));
	if (nrec == NULL) {
		free(data.dptr);
		return NULL;
	}
	
	memcpy(nrec, data.dptr, sizeof(struct namedb_record));
	free(data.dptr);

	return nrec;
}

static int sysfs_store(const char *path, const struct udevice *dev)
{
	TDB_DATA key, data;
	char keystr[PATH_SIZE+2];
	struct sysfsdb_record rec;
	int retval = 0;

	if (dev == NULL)
		return -ENODEV;

	memset(keystr, 0, sizeof(keystr));
	strcpy(keystr, path);

	key.dptr = (void *)keystr;
	key.dsize = strlen(keystr) + 1;
	
	strcpy(rec.name, dev->name);

	data.dptr = (void *) &rec;
	data.dsize = sizeof(rec);
	
	retval = tdb_store(udevdb, key, data, TDB_REPLACE); 
	return retval;
}

/**
 * namedb_store
 */
static int namedb_store(const struct udevice *dev)
{
	TDB_DATA key, data;
	char keystr[NAME_SIZE];
	struct namedb_record rec;
	int retval = 0;

	if (dev == NULL)
		return -1;

	memset(keystr, 0, NAME_SIZE);
	strcpy(keystr, dev->name);

	key.dptr = (void *)keystr;
	key.dsize = strlen(keystr) + 1;
	
	strcpy(rec.sysfs_dev_path, dev->sysfs_dev_path);
	strcpy(rec.id, dev->bus_id);
	strcpy(rec.class_dev_name, dev->class_dev_name);
	strcpy(rec.class_name, dev->class_name);
	rec.type = dev->type;
	rec.major = dev->major;
	rec.minor = dev->minor;
	rec.mode = dev->mode;

	data.dptr = (void *) &rec;
	data.dsize = sizeof(rec);
	
	retval = tdb_store(udevdb, key, data, TDB_REPLACE); 
	return retval;
}

/**
 * namedb_delete
 */
static int namedb_delete(const char *name)
{
	TDB_DATA key;
	char keystr[NAME_SIZE]; 
	int retval = 0;

	if (name == NULL)
		return -1; 
	if (strlen(name) >= NAME_SIZE)
		return -1;

	memset(keystr, 0, NAME_SIZE);
	strcpy(keystr, name);

	key.dptr = (void *)keystr;
	key.dsize = strlen(keystr) + 1;

	retval = tdb_delete(udevdb, key);
	return retval;
}

static int sysfs_delete(const char *path)
{
	TDB_DATA key;
	char keystr[PATH_SIZE];

	memset(keystr, 0, sizeof(keystr));
	strcpy(keystr, path);

	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;
	
	return tdb_delete(udevdb, key);
}

/**
 * udevdb_delete_udevice
 */
int udevdb_delete_udevice(const char *name)
{
	struct namedb_record *nrec = NULL;

	if (name == NULL)
		return -1; 

	nrec = namedb_fetch(name);
	if (nrec == NULL)
		return -1;

	namedb_delete(name);
	free(nrec);

	return 0;
}

/**
 * udevdb_add_device: adds class device to database
 */
int udevdb_add_device(const char *device, const struct sysfs_class_device *class_dev, const char *name, char type, int major, int minor, int mode)
{
	struct udevice dbdev;

	if (class_dev == NULL)
		return -ENODEV;

	memset(&dbdev, 0, sizeof(dbdev));
	strncpy(dbdev.name, name, NAME_SIZE);
	if (class_dev->sysdevice) {
		strncpy(dbdev.sysfs_dev_path, class_dev->sysdevice->directory->path, PATH_SIZE);
		strncpy(dbdev.bus_id, class_dev->sysdevice->bus_id, ID_SIZE);
	}
	strncpy(dbdev.class_dev_name, class_dev->name, NAME_SIZE);
//	if ((sysfs_get_name_from_path(subsystem, dbdev.class_name, NAME_SIZE)) != 0)
//		strcpy(dbdev.class_name, "unknown");
	dbdev.type = type;
	dbdev.major = major;
	dbdev.minor = minor;
	dbdev.mode = mode;
	
	if ((sysfs_store(device, &dbdev)) != 0)
		return -1;
//	if ((namedb_store(&dbdev)) != 0)
//		return -1;

	return 0;
}

/**
 * udevdb_get_device: grab's device by name
 */
struct udevice *udevdb_get_udevice(const char *name)
{
	struct namedb_record *nrec = NULL;
	struct udevice *dev = NULL;

	if (name == NULL)
		return NULL; 

	nrec = namedb_fetch(name);
	if (nrec == NULL)
		return NULL;

	dev = (struct udevice *)malloc(sizeof(struct udevice));
	if (dev == NULL) {
		free(nrec);
		return NULL;
	}

	strcpy(dev->name, name);
	strcpy(dev->sysfs_dev_path, nrec->sysfs_dev_path);
	strcpy(dev->class_dev_name, nrec->class_dev_name);
	strcpy(dev->class_name, nrec->class_name);
	strcpy(dev->bus_id, nrec->id);
	dev->type = nrec->type;
	dev->major = nrec->major;
	dev->minor = nrec->minor;
	dev->mode = nrec->mode;

	free(nrec);

	return dev;
}

int udevdb_get_dev(const char *path, char *name, size_t name_size)
{
	struct sysfsdb_record *rec = NULL;

	if ((path == NULL) || (name == NULL) || (name_size < 1))
		return -EINVAL;

	rec = sysfsdb_fetch(path);
	if (rec == NULL)
		return -ENODEV;

	if (strlen(rec->name) >= name_size)
		return -EINVAL;

	strncpy(name, rec->name, name_size);
	return 0;
}

int udevdb_delete_dev(const char *path)
{
	if (path == NULL)
		return -EINVAL;

	return sysfs_delete(path);
}

/**
 * udevdb_exit: closes database
 */
void udevdb_exit(void)
{
	udevdb_close();
}

/**
 * udevdb_init: initializes database
 */
int udevdb_init(int init_flag)
{
	if (init_flag != UDEVDB_DEFAULT && init_flag != UDEVDB_INTERNAL)
		return -1;

	return udevdb_open(init_flag);
}
