/*
 * syfs_utils.c
 *
 * System utility functions for libsysfs
 *
 * Copyright (C) 2003 International Business Machines, Inc.
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
static int sysfs_get_fs_mnt_path(const char *fs_type, char *mnt_path, 
				 size_t len)
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
		dprintf(stderr, "Error getting mount information\n");
		return -1;
	}
	while (ret == 0 && dirlen == 0 && (mntent = getmntent(mnt)) != NULL) {
		if (strcmp(mntent->mnt_type, fs_type) == 0) {
			dirlen = strlen(mntent->mnt_dir);
			if (dirlen <= (len - 1)) {
				strcpy(mnt_path, mntent->mnt_dir);
			} else {
				dprintf(stderr, 
					"Error - mount path too long\n");
				ret = -1;
			}
		}
	}
	endmntent(mnt);
	if (dirlen == 0 && ret == 0) {
		dprintf(stderr, "Filesystem %s not found!\n", fs_type);
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
int sysfs_get_mnt_path(char *mnt_path, size_t len)
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
int sysfs_get_name_from_path(const char *path, char *name, size_t len)
{
	char *n = NULL;
                                                                                
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
int sysfs_get_link(const char *path, char *target, size_t len)
{
	char devdir[SYSFS_PATH_MAX];
	char linkpath[SYSFS_PATH_MAX];
	char *d = NULL;

	if (path == NULL || target == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(devdir, 0, SYSFS_PATH_MAX);
	memset(linkpath, 0, SYSFS_PATH_MAX);

	if ((sysfs_get_mnt_path(devdir, SYSFS_PATH_MAX)) != 0) {
		dprintf(stderr, "Sysfs not supported on this system\n");
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
