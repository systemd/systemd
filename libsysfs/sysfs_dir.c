/*
 * syfs_dir.c
 *
 * Directory utility functions for libsysfs
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
 * sysfs_close_attribute: closes and cleans up attribute
 * @sysattr: attribute to close.
 */
void sysfs_close_attribute(struct sysfs_attribute *sysattr)
{
	if (sysattr != NULL) {
		if (sysattr->value != NULL)
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
	
	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	sysattr = alloc_attribute();
	if (sysattr == NULL) {
		dprintf(stderr, "Error allocating attribute at %s\n", path);
		return NULL;
	}
	strncpy(sysattr->path, path, sizeof(sysattr->path));
	if ((stat(sysattr->path, &fileinfo)) != 0) {
		perror("stat");
		sysattr->method = 0;
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
	size_t length = 0;
	int pgsize = 0;
	int fd;

	if (sysattr == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (!(sysattr->method & SYSFS_METHOD_SHOW)) {
		dprintf (stderr, "Show method not supported for attribute %s\n",
			sysattr->path);
		return -1;
	}
	pgsize = getpagesize();
	fbuf = (char *)calloc(1, pgsize+1);
	if (fbuf == NULL) {
		perror("calloc");
		return -1;
	}
	if ((fd = open(sysattr->path, O_RDONLY)) < 0) {
		dprintf (stderr, "Error reading attribute %s\n", sysattr->path);
		free(fbuf);
		return -1;
	}
	length = read(fd, fbuf, pgsize);
	if (length < 0) {
		dprintf (stderr, "Error reading from attribute %s\n",
			sysattr->path);
		close(fd);
		free(fbuf);
		return -1;
	}
	sysattr->len = length;
	close(fd);
	vbuf = (char *)realloc(fbuf, length+1);
	if (vbuf == NULL) {
		perror("realloc");
		free(fbuf);
		return -1;
	}
	sysattr->value = vbuf;

	return 0;
}

/**
 * sysfs_read_attribute_value: given path to attribute, return its value.
 *	values can be up to a pagesize, if buffer is smaller the value will 
 *	be truncated. 
 * @attrpath: sysfs path to attribute
 * @value: buffer to put value
 * @vsize: size of value buffer
 * returns 0 with success and -1 with error.
 */
int sysfs_read_attribute_value(const char *attrpath, char *value, size_t vsize)
{
	struct sysfs_attribute *attr = NULL;
	size_t length = 0;

	if (attrpath == NULL || value == NULL) {
		errno = EINVAL;
		return -1;
	}

	attr = sysfs_open_attribute(attrpath);
	if (attr == NULL) {
		dprintf(stderr, "Invalid attribute path %s\n", attrpath);
		errno = EINVAL;
		return -1;
	}
	if((sysfs_read_attribute(attr)) != 0 || attr->value == NULL) {
		dprintf(stderr, "Error reading from attribute %s\n", attrpath);
		sysfs_close_attribute(attr);
		return -1;
	}
	length = strlen(attr->value);
	if (length > vsize) 
		dprintf(stderr, 
			"Value length %d is larger than supplied buffer %d\n",
			length, vsize);
	strncpy(value, attr->value, vsize);
	sysfs_close_attribute(attr);

	return 0;
}

/**
 * sysfs_get_value_from_attrbutes: given a linked list of attributes and an 
 * 	attribute name, return its value
 * @attr: attribute to search
 * @name: name to look for
 * returns char * value - could be NULL
 */
char *sysfs_get_value_from_attributes(struct sysfs_attribute *attr, 
					const char *name)
{	
	struct sysfs_attribute *cur = NULL;
	char tmpname[SYSFS_NAME_LEN];
	
	if (attr == NULL || name == NULL) {
		errno = EINVAL;
		return NULL;
	}	
	cur = attr;
	while (cur != NULL) {
		memset(tmpname, 0, SYSFS_NAME_LEN);	
		if ((sysfs_get_name_from_path(cur->path, tmpname,
		    SYSFS_NAME_LEN)) != 0) {
			cur = cur->next;
			continue;
		}
		if (strcmp(tmpname, name) == 0)
			return cur->value;
		cur = cur->next;
	}
	return NULL;
}

/**
 * add_subdir_to_dir: adds subdirectory to directory's subdirs
 * @sysdir: directory to add subdir to
 * @subdir: subdirectory to add.
 */
static void add_subdir_to_dir(struct sysfs_directory *sysdir, 
		     struct sysfs_directory *subdir)
{
	if (sysdir != NULL && subdir != NULL) {
		subdir->next = sysdir->subdirs;
		sysdir->subdirs = subdir;
	}
}

/**
 * add_attr_to_dir: adds attribute to directory's attributes
 * @sysdir: directory to add attribute to
 * @sysattr: attribute to add.
 */
static void add_attr_to_dir(struct sysfs_directory *sysdir, 
		     			struct sysfs_attribute *sysattr)
{
	if (sysdir != NULL && sysattr != NULL) {
		sysattr->next = sysdir->attributes;
		sysdir->attributes = sysattr;
	}
}

/**
 * sysfs_close_dlink: closes and cleans up directory link.
 * @dlink: directory link to close.
 */
void sysfs_close_dlink(struct sysfs_dlink *dlink)
{
	if (dlink != NULL) {
		dlink->next = NULL;
		if (dlink->target != NULL)
			sysfs_close_directory(dlink->target);
		free(dlink);
	}
}

/**
 * add_dlink_to_dir: adds directory link to directory's links list.
 * @sysdir: directory to add it to.
 * @dlink: link to add.
 */
static void add_dlink_to_dir(struct sysfs_directory *sysdir, 
					struct sysfs_dlink *dlink)
{
	if (sysdir != NULL && dlink != NULL) {
		dlink->next = sysdir->links;
		sysdir->links = dlink;
	}
}

/**
 * sysfs_close_directory: closes directory, cleans up attributes and links
 * @sysdir: sysfs_directory to close
 */
void sysfs_close_directory(struct sysfs_directory *sysdir)
{
	struct sysfs_directory *sdir = NULL, *dnext = NULL;
	struct sysfs_dlink *dlink = NULL, *nextl = NULL;
	struct sysfs_attribute *attr = NULL, *anext = NULL;

	if (sysdir != NULL) {
		if (sysdir->subdirs != NULL) {
			for (sdir = sysdir->subdirs; sdir != NULL;
			     sdir = dnext) {
				dnext = sdir->next;
				sysfs_close_directory(sdir);
			}
		}
		if (sysdir->links != NULL) {
			for (dlink = sysdir->links; dlink != NULL;
			    dlink = nextl) {
				nextl = dlink->next;
				sysfs_close_dlink(dlink);
			}
		}
		if (sysdir->attributes != NULL) {
			for (attr = sysdir->attributes; attr != NULL;
			     attr = anext) {
				anext = attr->next;
				/* sysfs_close_attribute(attr); */
				if (attr->value != NULL)
					free(attr->value);
				free(attr);
			}
		}
		free(sysdir);
	}
}

/**
 * alloc_directory: allocates and initializes directory structure
 * returns struct sysfs_directory with success or NULL with error.
 */
static struct sysfs_directory *alloc_directory(void)
{
	return (struct sysfs_directory *)
			calloc(1, sizeof(struct sysfs_directory));
}

/**
 * alloc_dlink: allocates and initializes directory link structure
 * returns struct sysfs_dlink with success or NULL with error.
 */
static struct sysfs_dlink *alloc_dlink(void)
{
	return (struct sysfs_dlink *)calloc(1, sizeof(struct sysfs_dlink));
}

/**
 * sysfs_open_directory: opens a sysfs directory, creates dir struct, and
 *		returns.
 * @path: path of directory to open.
 * returns: struct sysfs_directory * with success and NULL on error.
 */
struct sysfs_directory *sysfs_open_directory(const char *path)
{
	struct sysfs_directory *sdir = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	sdir = alloc_directory();
	if (sdir == NULL) {
		dprintf(stderr, "Error allocating directory %s\n", path);
		return NULL;
	}
	strncpy(sdir->path, path, sizeof(sdir->path));

	return sdir;
}

/**
 * sysfs_open_dlink: opens a sysfs directory link, creates struct, and returns
 * @path: path of link to open.
 * returns: struct sysfs_dlink * with success and NULL on error.
 */
struct sysfs_dlink *sysfs_open_dlink(const char *linkpath)
{
	struct sysfs_dlink *dlink = NULL;
	struct sysfs_directory *tdir = NULL;
	char name[SYSFS_NAME_LEN];
	char target[SYSFS_PATH_MAX];

	if (linkpath == NULL) {
		errno = EINVAL;
		return NULL;
	}

	memset(name, 0, SYSFS_NAME_LEN);
	memset(target, 0, SYSFS_PATH_MAX);
	if ((sysfs_get_name_from_path(linkpath, name, SYSFS_NAME_LEN)) != 0
	    || (sysfs_get_link(linkpath, target, SYSFS_PATH_MAX)) != 0) {
		errno = EINVAL;
		dprintf(stderr, "Invalid link path %s\n", linkpath);
		return NULL;
	}
	dlink = alloc_dlink();
	if (dlink == NULL) {
		dprintf(stderr, 
			"Error allocating directory link %s\n", linkpath);
		return NULL;
	}
	strcpy(dlink->name, name);
	tdir = sysfs_open_directory(target);
	if (tdir == NULL) {
		dprintf(stderr, "Invalid directory link target %s\n", target);
		sysfs_close_dlink(dlink);
		return NULL;
	}	
	dlink->target = tdir;

	return dlink;
}

/**
 * sysfs_read_directory: grabs attributes, links, and subdirectories
 * @sysdir: sysfs directory to open
 * returns 0 with success and -1 with error.
 */
int sysfs_read_directory(struct sysfs_directory *sysdir)
{
	DIR *dir = NULL;
	struct dirent *dirent = NULL;
	struct stat astats;
	struct sysfs_attribute *attr = NULL;
	struct sysfs_directory *subdir = NULL;
	struct sysfs_dlink *dlink = NULL;
	char file_path[SYSFS_PATH_MAX];
	int retval = 0;

	if (sysdir == NULL) {
		errno = EINVAL;
		return -1;
	}
	dir = opendir(sysdir->path);
	if (dir == NULL) {
		perror("opendir");
		return -1;
	}
	while(((dirent = readdir(dir)) != NULL) && retval == 0) {
		if (0 == strcmp(dirent->d_name, "."))
			 continue;
		if (0 == strcmp(dirent->d_name, ".."))
			continue;
		memset(file_path, 0, SYSFS_PATH_MAX);
		strncpy(file_path, sysdir->path, sizeof(file_path));
		strncat(file_path, "/", sizeof(file_path));
		strncat(file_path, dirent->d_name, sizeof(file_path));
		if ((lstat(file_path, &astats)) != 0) {
			perror("stat");
			continue;
		}
		if (S_ISREG(astats.st_mode)) {	
			attr = sysfs_open_attribute(file_path);
			if (attr == NULL) {
				dprintf (stderr, "Error opening attribute %s\n",
					file_path);
				retval = -1;
				break;
			}
			if (attr->method & SYSFS_METHOD_SHOW) {
				if ((sysfs_read_attribute(attr)) != 0) {
					dprintf (stderr, 
						"Error reading attribute %s\n",
						file_path);
					sysfs_close_attribute(attr);
					continue;
				}
			}
			add_attr_to_dir(sysdir, attr);
		} else if (S_ISDIR(astats.st_mode)) {
			subdir = sysfs_open_directory(file_path);
			if (subdir == NULL) {
				dprintf (stderr, "Error opening directory %s\n",
					file_path);
				retval = -1;
				break;
			}
			add_subdir_to_dir(sysdir, subdir);
		} else if (S_ISLNK(astats.st_mode)) {
			dlink = sysfs_open_dlink(file_path);
			if (dlink == NULL) {
				dprintf(stderr, "Error opening link %s\n",
					file_path);
				retval = -1;
				break;
			}
			add_dlink_to_dir(sysdir, dlink);
		}
	}
	closedir(dir);
	return(retval);
}

/**
 * sysfs_read_dlinks: reads a directory link's target directory. Can
 * 	supply a linked list of links.
 * @dlink: directory link to read.
 * returns 0 with success or -1 with error.
 */
int sysfs_read_dlinks(struct sysfs_dlink *dlink)
{
	struct sysfs_dlink *cur = NULL;

	if (dlink == NULL || dlink->target == NULL) {
		errno = EINVAL;
		return -1;
	}
	cur = dlink;
	while (cur != NULL) {
		if ((sysfs_read_directory(cur->target)) != 0) {
			dprintf(stderr, 
				"Error reading directory link target %s\n",
				dlink->name);
			return -1;
		}
		cur = cur->next;
	}
	
	return 0;
}
