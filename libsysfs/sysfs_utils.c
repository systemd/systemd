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
#include "libsysfs.h"
#include "sysfs.h"

/**
 * sysfs_remove_trailing_slash: Removes any trailing '/' in the given path
 * @path: Path to look for the trailing '/'
 * Returns 0 on success 1 on error
 */ 
int sysfs_remove_trailing_slash(char *path)
{
	size_t len;

	if (!path) {
		errno = EINVAL;
		return 1;
	}

	len = strlen(path);
	while (len > 0 && path[len-1] == '/')
		path[--len] = '\0';
	return 0;
}

/*
 * sysfs_get_mnt_path: Gets the sysfs mount point.
 * @mnt_path: place to put "sysfs" mount point
 * @len: size of mnt_path
 * returns 0 with success and -1 with error.
 */
int sysfs_get_mnt_path(char *mnt_path, size_t len)
{
	static char sysfs_path[SYSFS_PATH_MAX] = "";
	const char *sysfs_path_env;

	/* evaluate only at the first call */
	if (sysfs_path[0] == '\0') {
		/* possible overrride of real mount path */
		sysfs_path_env = getenv(SYSFS_PATH_ENV);
		if (sysfs_path_env != NULL) {
			safestrcpymax(mnt_path, sysfs_path_env, len);
			sysfs_remove_trailing_slash(mnt_path);
			return 0;
		}
		safestrcpymax(mnt_path, SYSFS_MNT_PATH, len);
	}

	return 0;
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

	if (!path || !name || len == 0) {
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
	safestrcpymax(name, n, len);
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

	if (!path || !target || len == 0) {
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
			safestrcpymax(target, temp_path, len);
			break;
			/*
			 * relative path, getting rid of leading "../.."
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
			safestrcpymax(s, d, (SYSFS_PATH_MAX-strlen(devdir)));
			safestrcpymax(target, devdir, len);
			break;
		case '/':
			/* absolute path - copy as is */
			safestrcpymax(target, linkpath, len);
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
			safestrcpymax(target, temp_path, len);
	}
	return 0;
}

/**
 * sysfs_close_list: generic list free routine
 * @list: dlist to free
 * Returns nothing
 */
void sysfs_close_list(struct dlist *list)
{
	if (list)
		dlist_destroy(list);
}

/**
 * sysfs_open_directory_list: gets a list of all directories under "path"
 * @path: path to read
 * Returns a dlist of supported names or NULL no directories (errno is set
 * 	in case of error
 */
struct dlist *sysfs_open_directory_list(const char *path)
{
	if (!path)
		return NULL;

	return (read_dir_subdirs(path));
}

/**
 * sysfs_path_is_dir: Check if the path supplied points to a directory
 * @path: path to validate
 * Returns 0 if path points to dir, 1 otherwise
 */
int sysfs_path_is_dir(const char *path)
{
	struct stat astats;

	if (!path) {
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

	if (!path) {
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

	if (!path) {
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
