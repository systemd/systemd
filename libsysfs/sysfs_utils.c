/*
 * sysfs_utils.c
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
#include "sysfs/libsysfs.h"
#include "sysfs.h"
#ifndef __KLIBC__
#include <mntent.h>
#endif

static int sort_char(void *new_elem, void *old_elem)
{
	return ((strncmp((char *)new_elem, (char *)old_elem, 
			strlen((char *)new_elem))) < 0 ? 1 : 0);
}

/**
 * sysfs_remove_trailing_slash: Removes any trailing '/' in the given path
 * @path: Path to look for the trailing '/'
 * Returns 0 on success 1 on error
 */ 
int sysfs_remove_trailing_slash(char *path)
{
	char *c = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return 1;
	}
	c = strrchr(path, '/');
	if (c == NULL) {
		dprintf("Invalid path %s\n", path);
		errno = EINVAL;
		return 1;
	}
	if (*(c+1) == '\0') 
		*c = '\0';
	return 0;
}

/**
 * sysfs_get_fs_mnt_path: Gets the mount point for specified filesystem.
 * @fs_type: filesystem type to retrieve mount point
 * @mnt_path: place to put the retrieved mount path
 * @len: size of mnt_path
 * returns 0 with success and -1 with error.
 */
static int sysfs_get_fs_mnt_path(const char *fs_type, 
				char *mnt_path, size_t len)
{
#ifdef __KLIBC__
	safestrncpy(mnt_path, "/sys", len);
	return 0;
#else
	FILE *mnt;
	struct mntent *mntent;
	int ret = 0;
	size_t dirlen = 0;

	/* check arg */
	if (fs_type == NULL || mnt_path == NULL || len == 0) {
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
				safestrncpy(mnt_path, mntent->mnt_dir, len);
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
	if ((sysfs_remove_trailing_slash(mnt_path)) != 0)
		ret = -1;
	
	return ret;
#endif
}

/*
 * sysfs_get_mnt_path: Gets the sysfs mount point.
 * @mnt_path: place to put "sysfs" mount point
 * @len: size of mnt_path
 * returns 0 with success and -1 with error.
 */
int sysfs_get_mnt_path(char *mnt_path, size_t len)
{
	char *sysfs_path = NULL;
	int ret = 0;

	if (mnt_path == NULL || len == 0) {
		errno = EINVAL;
		return -1;
	}
	sysfs_path = getenv(SYSFS_PATH_ENV);
	if (sysfs_path != NULL) {
		safestrncpy(mnt_path, sysfs_path, len);
		if ((sysfs_remove_trailing_slash(mnt_path)) != 0)
			return 1;
	} else
		ret = sysfs_get_fs_mnt_path(SYSFS_FSTYPE_NAME, mnt_path, len);

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
	char tmp[SYSFS_PATH_MAX];
	char *n = NULL;
                                                                                
	if (path == NULL || name == NULL || len == 0) {
		errno = EINVAL;
		return -1;
	}
	memset(tmp, 0, SYSFS_PATH_MAX);
	safestrcpy(tmp, path);
	n = strrchr(tmp, '/');
	if (n == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (*(n+1) == '\0') {
		*n = '\0';
		n = strrchr(tmp, '/');
		if (n == NULL) {
			errno = EINVAL;
			return -1;
		}
	}
	n++;
	safestrncpy(name, n, len);
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
	char temp_path[SYSFS_PATH_MAX];
	char *d = NULL, *s = NULL;
	int slashes = 0, count = 0;

	if (path == NULL || target == NULL || len == 0) {
		errno = EINVAL;
		return -1;
	}

	memset(devdir, 0, SYSFS_PATH_MAX);
	memset(linkpath, 0, SYSFS_PATH_MAX);
	memset(temp_path, 0, SYSFS_PATH_MAX);
	safestrcpy(devdir, path);

	if ((readlink(path, linkpath, SYSFS_PATH_MAX)) < 0) {
		return -1;
	}
	d = linkpath;
	/* 
	 * Three cases here:
	 * 1. relative path => format ../..
	 * 2. absolute path => format /abcd/efgh
	 * 3. relative path _from_ this dir => format abcd/efgh
	 */ 
	switch (*d) {
		case '.': 
			/* 
			 * handle the case where link is of type ./abcd/xxx
			 */
			safestrcpy(temp_path, devdir);
			if (*(d+1) == '/')
				d += 2;
			else if (*(d+1) == '.')
				goto parse_path;
			s = strrchr(temp_path, '/');
			if (s != NULL) {
				*(s+1) = '\0';
				safestrcat(temp_path, d);
			} else {
				safestrcpy(temp_path, d);
			}
			safestrncpy(target, temp_path, len);
			break;
			/* 
			 * relative path  
			 * getting rid of leading "../.." 
			 */
parse_path:
			while (*d == '/' || *d == '.') {
				if (*d == '/')
					slashes++;
				d++;
			}
			d--;
			s = &devdir[strlen(devdir)-1];
			while (s != NULL && count != (slashes+1)) {
				s--;
				if (*s == '/')
					count++;
			}
			safestrncpy(s, d, (SYSFS_PATH_MAX-strlen(devdir)));
			safestrncpy(target, devdir, len);
			break;
		case '/':
			/* absolute path - copy as is */
			safestrncpy(target, linkpath, len);
			break;
		default:
			/* relative path from this directory */
			safestrcpy(temp_path, devdir);
			s = strrchr(temp_path, '/');
			if (s != NULL) {
				*(s+1) = '\0';
				safestrcat(temp_path, linkpath);
			} else {
				safestrcpy(temp_path, linkpath);
			}
			safestrncpy(target, temp_path, len);
	}
	return 0;
}

/**
 * sysfs_del_name: free function for sysfs_open_subsystem_list
 * @name: memory area to be freed
 */ 
static void sysfs_del_name(void *name)
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
struct dlist *sysfs_open_subsystem_list(char *name)
{
	char sysfs_path[SYSFS_PATH_MAX], *subsys_name = NULL;
	char *c = NULL;
	struct sysfs_directory *dir = NULL, *cur = NULL;
	struct dlist *list = NULL;
	
	if (name == NULL)
		return NULL;

	if (sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX) != 0) {
		dprintf("Error getting sysfs mount point\n");
		return NULL;
	}

	safestrcat(sysfs_path, "/");
	safestrcat(sysfs_path, name);
	dir = sysfs_open_directory(sysfs_path);
	if (dir == NULL) {
		dprintf("Error opening sysfs_directory at %s\n", sysfs_path);
		return NULL;
	}

	if ((sysfs_read_dir_subdirs(dir)) != 0) {
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
			safestrncpy(subsys_name, cur->name, SYSFS_NAME_LEN);
			dlist_unshift_sorted(list, subsys_name, sort_char);
		}
	}
	sysfs_close_directory(dir);
	/*
	 * We are now considering "block" as a "class". Hence, if the subsys
	 * name requested here is "class", verify if "block" is supported on
	 * this system and return the same.
	 */ 
	if (strcmp(name, SYSFS_CLASS_NAME) == 0) {
		c = strstr(sysfs_path, SYSFS_CLASS_NAME);
		if (c == NULL)
			goto out;
		*c = '\0';
		safestrncpy(c, SYSFS_BLOCK_NAME, 
				sizeof(sysfs_path) - strlen(sysfs_path));
		if ((sysfs_path_is_dir(sysfs_path)) == 0) {
			subsys_name = (char *)calloc(1, SYSFS_NAME_LEN);
			safestrncpy(subsys_name, SYSFS_BLOCK_NAME, 
					SYSFS_NAME_LEN);
			dlist_unshift_sorted(list, subsys_name, sort_char);
		}
	}
out:
	return list;
}


/**
 * sysfs_open_bus_devices_list: gets a list of all devices on "name" bus
 * @name: name of the subsystem, eg., "pci", "scsi", "usb"
 * Returns a dlist of supported names or NULL if subsystem not supported
 */ 
struct dlist *sysfs_open_bus_devices_list(char *name)
{
	char sysfs_path[SYSFS_PATH_MAX], *device_name = NULL;
	struct sysfs_directory *dir = NULL;
	struct sysfs_link *cur = NULL;
	struct dlist *list = NULL;
	
	if (name == NULL)
		return NULL;

	if (sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX) != 0) {
		dprintf("Error getting sysfs mount point\n");
		return NULL;
	}

	safestrcat(sysfs_path, "/");
	safestrcat(sysfs_path, SYSFS_BUS_NAME);
	safestrcat(sysfs_path, "/");
	safestrcat(sysfs_path, name);
	safestrcat(sysfs_path, "/");
	safestrcat(sysfs_path, SYSFS_DEVICES_NAME);
	dir = sysfs_open_directory(sysfs_path);
	if (dir == NULL) {
		dprintf("Error opening sysfs_directory at %s\n", sysfs_path);
		return NULL;
	}

	if ((sysfs_read_dir_links(dir)) != 0) {
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
			safestrncpy(device_name, cur->name, SYSFS_NAME_LEN);
			dlist_unshift_sorted(list, device_name, sort_char);
		}
	}
	sysfs_close_directory(dir);
	return list;
}

/**
 * sysfs_path_is_dir: Check if the path supplied points to a directory
 * @path: path to validate
 * Returns 0 if path points to dir, 1 otherwise
 */
int sysfs_path_is_dir(const char *path)
{
	struct stat astats;

	if (path == NULL) {
		errno = EINVAL;
		return 1;
	}
	if ((lstat(path, &astats)) != 0) {
		dprintf("stat() failed\n");
		return 1;
	}
	if (S_ISDIR(astats.st_mode))
		return 0;
		
	return 1;
}

/**
 * sysfs_path_is_link: Check if the path supplied points to a link
 * @path: path to validate
 * Returns 0 if path points to link, 1 otherwise
 */
int sysfs_path_is_link(const char *path)
{
	struct stat astats;

	if (path == NULL) {
		errno = EINVAL;
		return 1;
	}
	if ((lstat(path, &astats)) != 0) {
		dprintf("stat() failed\n");
		return 1;
	}
	if (S_ISLNK(astats.st_mode))
		return 0;
		
	return 1;
}

/**
 * sysfs_path_is_file: Check if the path supplied points to a file
 * @path: path to validate
 * Returns 0 if path points to file, 1 otherwise
 */
int sysfs_path_is_file(const char *path)
{
	struct stat astats;

	if (path == NULL) {
		errno = EINVAL;
		return 1;
	}
	if ((lstat(path, &astats)) != 0) {
		dprintf("stat() failed\n");
		return 1;
	}
	if (S_ISREG(astats.st_mode))
		return 0;
		
	return 1;
}
