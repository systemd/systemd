/*
 * sysfs_dir.c
 *
 * Directory utility functions for libsysfs
 *
 * Copyright (C) IBM Corp. 2003-2005
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

static int sort_char(void *new, void *old)
{
	return ((strncmp((char *)new, (char *)old, 
			strlen((char *)new))) < 0 ? 1 : 0);
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
 * sysfs_del_attribute: routine for dlist integration
 */
static void sysfs_del_attribute(void *attr)
{
	sysfs_close_attribute((struct sysfs_attribute *)attr);
}

/**
 * attr_name_equal: compares attributes by name
 * @a: attribute name for comparison
 * @b: sysfs_attribute to be compared.
 * returns 1 if a==b->name or 0 if not equal
 */
static int attr_name_equal(void *a, void *b)
{
	if (!a || !b)
		return 0;

	if (strcmp(((char *)a), ((struct sysfs_attribute *)b)->name) == 0)
		return 1;

	return 0;
}

/**
 * sysfs_close_attribute: closes and cleans up attribute
 * @sysattr: attribute to close.
 */
void sysfs_close_attribute(struct sysfs_attribute *sysattr)
{
	if (sysattr) {
		if (sysattr->value)
			free(sysattr->value);
		free(sysattr);
	}
}

/**
 * alloc_attribute: allocates and initializes attribute structure
 * returns struct sysfs_attribute with success and NULL with error.
 */
static struct sysfs_attribute *alloc_attribute(void)
{
	return (struct sysfs_attribute *)
			calloc(1, sizeof(struct sysfs_attribute));
}

/**
 * sysfs_open_attribute: creates sysfs_attribute structure
 * @path: path to attribute.
 * returns sysfs_attribute struct with success and NULL with error.
 */
struct sysfs_attribute *sysfs_open_attribute(const char *path)
{
	struct sysfs_attribute *sysattr = NULL;
	struct stat fileinfo;

	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	sysattr = alloc_attribute();
	if (!sysattr) {
		dprintf("Error allocating attribute at %s\n", path);
		return NULL;
	}
	if (sysfs_get_name_from_path(path, sysattr->name, 
				SYSFS_NAME_LEN) != 0) {
		dprintf("Error retrieving attrib name from path: %s\n", path);
		sysfs_close_attribute(sysattr);
		return NULL;
	}
	safestrcpy(sysattr->path, path);
	if ((stat(sysattr->path, &fileinfo)) != 0) {
		dprintf("Stat failed: No such attribute?\n");
		sysattr->method = 0;
		free(sysattr);
		sysattr = NULL;
	} else {
		if (fileinfo.st_mode & S_IRUSR)
			sysattr->method |= SYSFS_METHOD_SHOW;
		if (fileinfo.st_mode & S_IWUSR)
			sysattr->method |= SYSFS_METHOD_STORE;
	}

	return sysattr;
}

/**
 * sysfs_read_attribute: reads value from attribute
 * @sysattr: attribute to read
 * returns 0 with success and -1 with error.
 */
int sysfs_read_attribute(struct sysfs_attribute *sysattr)
{
	char *fbuf = NULL;
	char *vbuf = NULL;
	ssize_t length = 0;
	long pgsize = 0;
	int fd;

	if (!sysattr) {
		errno = EINVAL;
		return -1;
	}
	if (!(sysattr->method & SYSFS_METHOD_SHOW)) {
		dprintf("Show method not supported for attribute %s\n",
			sysattr->path);
		errno = EACCES;
		return -1;
	}
	pgsize = getpagesize();
	fbuf = (char *)calloc(1, pgsize+1);
	if (!fbuf) {
		dprintf("calloc failed\n");
		return -1;
	}
	if ((fd = open(sysattr->path, O_RDONLY)) < 0) {
		dprintf("Error reading attribute %s\n", sysattr->path);
		free(fbuf);
		return -1;
	}
	length = read(fd, fbuf, pgsize);
	if (length < 0) {
		dprintf("Error reading from attribute %s\n", sysattr->path);
		close(fd);
		free(fbuf);
		return -1;
	}
	if (sysattr->len > 0) {
		if ((sysattr->len == length) && 
				(!(strncmp(sysattr->value, fbuf, length)))) {
			close(fd);
			free(fbuf);
			return 0;
		}
		free(sysattr->value);
	}
	sysattr->len = length;
	close(fd);
	vbuf = (char *)realloc(fbuf, length+1);
	if (!vbuf) {
		dprintf("realloc failed\n");
		free(fbuf);
		return -1;
	}
	sysattr->value = vbuf;

	return 0;
}

/**
 * sysfs_write_attribute: write value to the attribute
 * @sysattr: attribute to write
 * @new_value: value to write
 * @len: length of "new_value"
 * returns 0 with success and -1 with error.
 */
int sysfs_write_attribute(struct sysfs_attribute *sysattr,
		const char *new_value, size_t len)
{
	int fd;
	int length;

	if (!sysattr || !new_value || len == 0) {
		errno = EINVAL;
		return -1;
	}

	if (!(sysattr->method & SYSFS_METHOD_STORE)) {
		dprintf ("Store method not supported for attribute %s\n",
			sysattr->path);
		errno = EACCES;
		return -1;
	}
	if (sysattr->method & SYSFS_METHOD_SHOW) {
		/*
		 * read attribute again to see if we can get an updated value 
		 */
		if ((sysfs_read_attribute(sysattr))) {
			dprintf("Error reading attribute\n");
			return -1;
		}
		if ((strncmp(sysattr->value, new_value, sysattr->len)) == 0) {
			dprintf("Attr %s already has the requested value %s\n",
					sysattr->name, new_value);
			return 0;	
		}
	}
	/*
	 * open O_WRONLY since some attributes have no "read" but only
	 * "write" permission 
	 */
	if ((fd = open(sysattr->path, O_WRONLY)) < 0) {
		dprintf("Error reading attribute %s\n", sysattr->path);
		return -1;
	}

	length = write(fd, new_value, len);
	if (length < 0) {
		dprintf("Error writing to the attribute %s - invalid value?\n",
			sysattr->name);
		close(fd);
		return -1;
	} else if ((unsigned int)length != len) {
		dprintf("Could not write %zd bytes to attribute %s\n", 
					len, sysattr->name);
		/* 
		 * since we could not write user supplied number of bytes,
		 * restore the old value if one available
		 */
		if (sysattr->method & SYSFS_METHOD_SHOW) {
			length = write(fd, sysattr->value, sysattr->len);
			close(fd);
			return -1;
		}
	}

	/*
	 * Validate length that has been copied. Alloc appropriate area
	 * in sysfs_attribute. Verify first if the attribute supports reading
	 * (show method). If it does not, do not bother
	 */ 
	if (sysattr->method & SYSFS_METHOD_SHOW) {
		if (length != sysattr->len) {
			sysattr->value = (char *)realloc
				(sysattr->value, length);
			sysattr->len = length;
			safestrcpymax(sysattr->value, new_value, length);
		} else {
			/*"length" of the new value is same as old one */ 
			safestrcpymax(sysattr->value, new_value, length);
		}
	}
			
	close(fd);	
	return 0;
}

/**
 * add_attribute: open and add attribute at path to given directory
 * @dev: device whose attribute is to be added
 * @path: path to attribute
 * returns pointer to attr added with success and NULL with error.
 */
static struct sysfs_attribute *add_attribute(void *dev, const char *path)
{
	struct sysfs_attribute *attr;

	attr = sysfs_open_attribute(path);
	if (!attr) {
		dprintf("Error opening attribute %s\n",	path);
		return NULL;
	}
	if (attr->method & SYSFS_METHOD_SHOW) {
		if (sysfs_read_attribute(attr)) {
			dprintf("Error reading attribute %s\n",	path);
			sysfs_close_attribute(attr);
			return NULL;
		}
	}

	if (!((struct sysfs_device *)dev)->attrlist) {
		((struct sysfs_device *)dev)->attrlist = dlist_new_with_delete
			(sizeof(struct sysfs_attribute), sysfs_del_attribute);
	}
	dlist_unshift_sorted(((struct sysfs_device *)dev)->attrlist, 
			attr, sort_list);

	return attr;
}

/*
 * get_attribute - given a sysfs_* struct and a name, return the 
 * sysfs_attribute corresponding to "name"
 * returns sysfs_attribute on success and NULL on error
 */
struct sysfs_attribute *get_attribute(void *dev, const char *name)
{
	struct sysfs_attribute *cur = NULL;
	char path[SYSFS_PATH_MAX];

	if (!dev || !name) {
		errno = EINVAL;
		return NULL;
	}

	if (((struct sysfs_device *)dev)->attrlist) {
		/* check if attr is already in the list */
		cur = (struct sysfs_attribute *)dlist_find_custom
			((((struct sysfs_device *)dev)->attrlist), 
			 	(void *)name, attr_name_equal);
		if (cur)
			return cur;
	}
	safestrcpymax(path, ((struct sysfs_device *)dev)->path, 
			SYSFS_PATH_MAX);
	safestrcatmax(path, "/", SYSFS_PATH_MAX);
	safestrcatmax(path, name, SYSFS_PATH_MAX);
	if (!(sysfs_path_is_file(path)))
		cur = add_attribute((void *)dev, path);
	return cur;
}

/**
 * read_dir_links: grabs links in a specific directory
 * @sysdir: sysfs directory to read
 * returns list of link names with success and NULL with error.
 */
struct dlist *read_dir_links(const char *path)
{
	DIR *dir = NULL;
	struct dirent *dirent = NULL;
	char file_path[SYSFS_PATH_MAX], *linkname;
	struct dlist *linklist = NULL;

	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	dir = opendir(path);
	if (!dir) {
		dprintf("Error opening directory %s\n", path);
		return NULL;
	}
	while ((dirent = readdir(dir)) != NULL) {
		if (0 == strcmp(dirent->d_name, "."))
			 continue;
		if (0 == strcmp(dirent->d_name, ".."))
			continue;
		memset(file_path, 0, SYSFS_PATH_MAX);
		safestrcpy(file_path, path);
		safestrcat(file_path, "/");
		safestrcat(file_path, dirent->d_name);
		if ((sysfs_path_is_link(file_path)) == 0) {
			if (!linklist) {
				linklist = dlist_new_with_delete
					(SYSFS_NAME_LEN, sysfs_del_name);
				if (!linklist) {
					dprintf("Error creating list\n");
					return NULL;
				}
			}
			linkname = (char *)calloc(1, SYSFS_NAME_LEN);
			safestrcpymax(linkname, dirent->d_name, SYSFS_NAME_LEN);
			dlist_unshift_sorted(linklist, linkname, sort_char);
		}
	}
	closedir(dir);
	return linklist;
}

/**
 * read_dir_subdirs: grabs subdirs in a specific directory
 * @sysdir: sysfs directory to read
 * returns list of directory names with success and NULL with error.
 */
struct dlist *read_dir_subdirs(const char *path)
{
	DIR *dir = NULL;
	struct dirent *dirent = NULL;
	char file_path[SYSFS_PATH_MAX], *dir_name;
	struct dlist *dirlist = NULL;

	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	dir = opendir(path);
	if (!dir) {
		dprintf("Error opening directory %s\n", path);
		return NULL;
	}
	while ((dirent = readdir(dir)) != NULL) {
		if (0 == strcmp(dirent->d_name, "."))
			 continue;
		if (0 == strcmp(dirent->d_name, ".."))
			continue;
		memset(file_path, 0, SYSFS_PATH_MAX);
		safestrcpy(file_path, path);
		safestrcat(file_path, "/");
		safestrcat(file_path, dirent->d_name);
		if ((sysfs_path_is_dir(file_path)) == 0) {
			if (!dirlist) {
				dirlist = dlist_new_with_delete
					(SYSFS_NAME_LEN, sysfs_del_name);
				if (!dirlist) {
					dprintf("Error creating list\n");
					return NULL;
				}
			}
			dir_name = (char *)calloc(1, SYSFS_NAME_LEN);
			safestrcpymax(dir_name, dirent->d_name, SYSFS_NAME_LEN);
			dlist_unshift_sorted(dirlist, dir_name, sort_char);
		}
	}
	closedir(dir);
	return dirlist;
}

/**
 * get_attributes_list: build a list of attributes for the given device
 * @dev: devices whose attributes list is required
 * returns dlist of attributes on success and NULL on failure
 */
struct dlist *get_attributes_list(void *dev)
{
	DIR *dir = NULL;
	struct dirent *dirent = NULL;
	struct sysfs_attribute *attr = NULL;
	char file_path[SYSFS_PATH_MAX], path[SYSFS_PATH_MAX];

	if (!dev) {
		errno = EINVAL;
		return NULL;
	}
	memset(path, 0, SYSFS_PATH_MAX);
	safestrcpy(path, ((struct sysfs_device *)dev)->path);
	dir = opendir(path);
	if (!dir) {
		dprintf("Error opening directory %s\n", path);
		return NULL;
	}
	while ((dirent = readdir(dir)) != NULL) {
		if (0 == strcmp(dirent->d_name, "."))
			 continue;
		if (0 == strcmp(dirent->d_name, ".."))
			continue;
		memset(file_path, 0, SYSFS_PATH_MAX);
		safestrcpy(file_path, path);
		safestrcat(file_path, "/");
		safestrcat(file_path, dirent->d_name);
		if ((sysfs_path_is_file(file_path)) == 0) {
			if (((struct sysfs_device *)dev)->attrlist) {
				/* check if attr is already in the list */
				attr = (struct sysfs_attribute *)
				dlist_find_custom
				((((struct sysfs_device *)dev)->attrlist), 
			 	(void *)dirent->d_name, attr_name_equal);
				if (attr) 
					continue;
				else 
					add_attribute(dev, file_path);
			} else 
				attr = add_attribute(dev, file_path);
		}
	}
	closedir(dir);
	return ((struct sysfs_device *)dev)->attrlist;
}
