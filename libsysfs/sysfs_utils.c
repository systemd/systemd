/*
 * syfs_utils.c
 *
 * System utility functions for libsysfs
 *
 * Copyright (C) IBM Corp. 2003
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */
#include "libsysfs.h"
#include "sysfs.h"

/**
 * sysfs_get_mnt_path: Gets the mount point for specified filesystem.
 * @fs_type: filesystem type to retrieve mount point
 * @mnt_path: place to put the retrieved mount path
 * @len: size of mnt_path
 * returns 0 with success and -1 with error.
 */
static int sysfs_get_fs_mnt_path(const unsigned char *fs_type, 
				unsigned char *mnt_path, size_t len)
{
	FILE *mnt;
	struct mntent *mntent;
	int ret = 0;
	size_t dirlen = 0;

	/* check arg */
	if (fs_type == NULL || mnt_path == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((mnt = setmntent(SYSFS_PROC_MNTS, "r")) == NULL) {
		dprintf("Error getting mount information\n");
		return -1;
	}
	while (ret == 0 && dirlen == 0 && (mntent = getmntent(mnt)) != NULL) {
		if (strcmp(mntent->mnt_type, fs_type) == 0) {
			dirlen = strlen(mntent->mnt_dir);
			if (dirlen <= (len - 1)) {
				strcpy(mnt_path, mntent->mnt_dir);
			} else {
				dprintf("Error - mount path too long\n");
				ret = -1;
			}
		}
	}
	endmntent(mnt);
	if (dirlen == 0 && ret == 0) {
		dprintf("Filesystem %s not found!\n", fs_type);
		errno = EINVAL;
		ret = -1;
	}
	return ret;
}

/*
 * sysfs_get_mnt_path: Gets the sysfs mount point.
 * @mnt_path: place to put "sysfs" mount point
 * @len: size of mnt_path
 * returns 0 with success and -1 with error.
 */
int sysfs_get_mnt_path(unsigned char *mnt_path, size_t len)
{
	int ret = -1;

	if (mnt_path != NULL)
		ret = sysfs_get_fs_mnt_path(SYSFS_FSTYPE_NAME, mnt_path, len);
	else
		errno = EINVAL;

	return ret;
}

/**
 * sysfs_get_name_from_path: returns last name from a "/" delimited path
 * @path: path to get name from
 * @name: where to put name
 * @len: size of name
 */
int sysfs_get_name_from_path(const unsigned char *path, unsigned char *name, 
								size_t len)
{
	unsigned char *n = NULL;
                                                                                
	if (path == NULL || name == NULL) {
		errno = EINVAL;
		return -1;
	}
	n = strrchr(path, '/');
	if (n == NULL) {
		errno = EINVAL;
		return -1;
	}
	n++;
	strncpy(name, n, len);

	return 0;
}

/**
 * sysfs_get_link: returns link source
 * @path: symbolic link's path
 * @target: where to put name
 * @len: size of name
 */
int sysfs_get_link(const unsigned char *path, unsigned char *target, size_t len)
{
	unsigned char devdir[SYSFS_PATH_MAX];
	unsigned char linkpath[SYSFS_PATH_MAX];
	unsigned char *d = NULL;

	if (path == NULL || target == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(devdir, 0, SYSFS_PATH_MAX);
	memset(linkpath, 0, SYSFS_PATH_MAX);

	if ((sysfs_get_mnt_path(devdir, SYSFS_PATH_MAX)) != 0) {
		dprintf("Sysfs not supported on this system\n");
		return -1;
	}
								        
	if ((readlink(path, linkpath, SYSFS_PATH_MAX)) < 0) {
		return -1;
	}
									        
	d = linkpath;

	/* getting rid of leading "../.." */	
	while (*d == '/' || *d == '.')
		d++;

	d--;
	
	strcat(devdir, d);
	strncpy(target, devdir, len);

	return 0;
}


/**
 * sysfs_del_name: free function for sysfs_open_subsystem_list
 * @name: memory area to be freed
 */ 
void sysfs_del_name(void *name)
{
	free(name);
}


/**
 * sysfs_close_list: generic list free routine
 * @list: dlist to free
 * Returns nothing
 */
void sysfs_close_list(struct dlist *list)
{
	if (list != NULL)
		dlist_destroy(list);
}

/**
 * sysfs_open_subsystem_list: gets a list of all supported "name" subsystem
 * 	details from the system
 * @name: name of the subsystem, eg., "bus", "class", "devices"
 * Returns a dlist of supported names or NULL if subsystem not supported
 */ 
struct dlist *sysfs_open_subsystem_list(unsigned char *name)
{
	unsigned char sysfs_path[SYSFS_PATH_MAX], *subsys_name = NULL;
	struct sysfs_directory *dir = NULL, *cur = NULL;
	struct dlist *list = NULL;
	
	if (name == NULL)
		return NULL;

	if (sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX) != 0) {
		dprintf("Error getting sysfs mount point\n");
		return NULL;
	}

	strcat(sysfs_path, name);
	dir = sysfs_open_directory(sysfs_path);
	if (dir == NULL) {
		dprintf("Error opening sysfs_directory at %s\n", sysfs_path);
		return NULL;
	}

	if (sysfs_read_directory(dir) != 0) {
		dprintf("Error reading sysfs_directory at %s\n", sysfs_path);
		sysfs_close_directory(dir);
		return NULL;
	}

	if (dir->subdirs != NULL) {
		list = dlist_new_with_delete(SYSFS_NAME_LEN,
				sysfs_del_name);
		if (list == NULL) {
			dprintf("Error creating list\n");
			sysfs_close_directory(dir);
			return NULL;
		}

		dlist_for_each_data(dir->subdirs, cur,
				struct sysfs_directory) {
			subsys_name = (char *)calloc(1, SYSFS_NAME_LEN);
			strcpy(subsys_name, cur->name);
			dlist_unshift(list, subsys_name);
		}
	}
	sysfs_close_directory(dir);
	return list;
}


/**
 * sysfs_open_bus_devices_list: gets a list of all devices on "name" bus
 * @name: name of the subsystem, eg., "pci", "scsi", "usb"
 * Returns a dlist of supported names or NULL if subsystem not supported
 */ 
struct dlist *sysfs_open_bus_devices_list(unsigned char *name)
{
	unsigned char sysfs_path[SYSFS_PATH_MAX], *device_name = NULL;
	struct sysfs_directory *dir = NULL;
	struct sysfs_link *cur = NULL;
	struct dlist *list = NULL;
	
	if (name == NULL)
		return NULL;

	if (sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX) != 0) {
		dprintf("Error getting sysfs mount point\n");
		return NULL;
	}

	strcat(sysfs_path, SYSFS_BUS_DIR);
	strcat(sysfs_path, "/");
	strcat(sysfs_path, name);
	strcat(sysfs_path, SYSFS_DEVICES_DIR);
	dir = sysfs_open_directory(sysfs_path);
	if (dir == NULL) {
		dprintf("Error opening sysfs_directory at %s\n", sysfs_path);
		return NULL;
	}

	if (sysfs_read_directory(dir) != 0) {
		dprintf("Error reading sysfs_directory at %s\n", sysfs_path);
		sysfs_close_directory(dir);
		return NULL;
	}

	if (dir->links != NULL) {
		list = dlist_new_with_delete(SYSFS_NAME_LEN,
				sysfs_del_name);
		if (list == NULL) {
			dprintf("Error creating list\n");
			sysfs_close_directory(dir);
			return NULL;
		}

		dlist_for_each_data(dir->links, cur,
				struct sysfs_link) {
			device_name = (char *)calloc(1, SYSFS_NAME_LEN);
			strcpy(device_name, cur->name);
			dlist_unshift(list, device_name);
		}
	}
	sysfs_close_directory(dir);
	return list;
}

