/*
 * libsysfs.h
 *
 * Header Definitions for libsysfs
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
#ifndef _LIBSYSFS_H_
#define _LIBSYSFS_H_

#include <sys/types.h>
#include <string.h>

/* 
 * Defines to prevent buffer overruns
 */
#define safestrcpy(to, from)	strncpy(to, from, sizeof(to)-1)
#define safestrcat(to, from)	strncat(to, from, sizeof(to) - strlen(to)-1)

#define safestrcpymax(to, from, max) \
do { \
	to[max-1] = '\0'; \
	strncpy(to, from, max-1); \
} while (0)

#define safestrcatmax(to, from, max) \
do { \
	to[max-1] = '\0'; \
	strncat(to, from, max - strlen(to)-1); \
} while (0)

/*
 * Generic #defines go here..
 */ 
#define SYSFS_FSTYPE_NAME	"sysfs"
#define SYSFS_PROC_MNTS		"/proc/mounts"
#define SYSFS_BUS_NAME		"bus"
#define SYSFS_CLASS_NAME	"class"
#define SYSFS_BLOCK_NAME	"block"
#define SYSFS_DEVICES_NAME	"devices"
#define SYSFS_DRIVERS_NAME	"drivers"
#define SYSFS_NAME_ATTRIBUTE	"name"
#define SYSFS_UNKNOWN		"unknown"
#define SYSFS_PATH_ENV		"SYSFS_PATH"

#define SYSFS_PATH_MAX		255
#define	SYSFS_NAME_LEN		50
#define SYSFS_BUS_ID_SIZE	20

#define SYSFS_METHOD_SHOW	0x01	/* attr can be read by user */
#define SYSFS_METHOD_STORE	0x02	/* attr can be changed by user */

/*
 * NOTE: We have the statically allocated "name" as the first element of all 
 * the structures. This feature is used in the "sorter" function for dlists
 */

struct sysfs_attribute {
	char name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];
	char *value;
	unsigned short len;		/* value length */
	unsigned short method;		/* show and store */
};

struct sysfs_link {
	char name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];
	char target[SYSFS_PATH_MAX];
};

struct sysfs_directory {
	char name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];

	/* Private: for internal use only */
	struct dlist *subdirs;	
	struct dlist *links;		
	struct dlist *attributes;
};

struct sysfs_driver {
	char name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];

	/* Private: for internal use only */
	struct dlist *devices;
	struct sysfs_directory *directory;	
};

struct sysfs_device {
	char name[SYSFS_NAME_LEN];
	char bus_id[SYSFS_NAME_LEN];
	char bus[SYSFS_NAME_LEN];
	char driver_name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];

	/* Private: for internal use only */
	struct sysfs_device *parent;		
	struct dlist *children;	
	struct sysfs_directory *directory;	
};

struct sysfs_root_device {
	char name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];

	/* Private: for internal use only */
	struct dlist *devices;
	struct sysfs_directory *directory;
};

struct sysfs_bus {
	char name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];

	/* Private: for internal use only */
	struct dlist *drivers;
	struct dlist *devices;
	struct sysfs_directory *directory;	
};

struct sysfs_class_device {
	char name[SYSFS_NAME_LEN];
	char classname[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];

	/* Private: for internal use only */
	struct sysfs_class_device *parent;	
	struct sysfs_device *sysdevice;		/* NULL if virtual */
	struct sysfs_driver *driver;		/* NULL if not implemented */
	struct sysfs_directory *directory;	
};

struct sysfs_class {
	char name[SYSFS_NAME_LEN];
	char path[SYSFS_PATH_MAX];

	/* Private: for internal use only */
	struct dlist *devices;
	struct sysfs_directory *directory;	
};

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function Prototypes
 */
extern int sysfs_get_mnt_path(char *mnt_path, size_t len);
extern int sysfs_remove_trailing_slash(char *path);
extern int sysfs_get_name_from_path(const char *path, char *name, size_t len);
extern int sysfs_path_is_dir(const char *path);
extern int sysfs_path_is_link(const char *path);
extern int sysfs_path_is_file(const char *path);
extern int sysfs_get_link(const char *path, char *target, size_t len);
extern struct dlist *sysfs_open_subsystem_list(char *name);
extern struct dlist *sysfs_open_bus_devices_list(char *name);
extern void sysfs_close_list(struct dlist *list);

/* sysfs directory and file access */
extern void sysfs_close_attribute(struct sysfs_attribute *sysattr);
extern struct sysfs_attribute *sysfs_open_attribute(const char *path);
extern int sysfs_read_attribute(struct sysfs_attribute *sysattr);
extern int sysfs_read_attribute_value(const char *attrpath, 
		char *value, size_t vsize);
extern int sysfs_write_attribute(struct sysfs_attribute *sysattr,
		const char *new_value, size_t len);
extern char *sysfs_get_value_from_attributes(struct dlist *attr, 
		const char *name);
extern int sysfs_refresh_dir_attributes(struct sysfs_directory *sysdir);
extern int sysfs_refresh_dir_links(struct sysfs_directory *sysdir);
extern int sysfs_refresh_dir_subdirs(struct sysfs_directory *sysdir);
extern void sysfs_close_directory(struct sysfs_directory *sysdir);
extern struct sysfs_directory *sysfs_open_directory(const char *path);
extern int sysfs_read_dir_attributes(struct sysfs_directory *sysdir);
extern int sysfs_read_dir_links(struct sysfs_directory *sysdir);
extern int sysfs_read_dir_subdirs(struct sysfs_directory *sysdir);
extern int sysfs_read_directory(struct sysfs_directory *sysdir);
extern int sysfs_read_all_subdirs(struct sysfs_directory *sysdir);
extern struct sysfs_directory *sysfs_get_subdirectory
	(struct sysfs_directory *dir, char *subname);
extern void sysfs_close_link(struct sysfs_link *ln);
extern struct sysfs_link *sysfs_open_link(const char *lnpath);
extern struct sysfs_link *sysfs_get_directory_link
	(struct sysfs_directory *dir, char *linkname);
extern struct sysfs_link *sysfs_get_subdirectory_link
	(struct sysfs_directory *dir, char *linkname);
extern struct sysfs_attribute *sysfs_get_directory_attribute
	(struct sysfs_directory *dir, char *attrname);
extern struct dlist *sysfs_get_dir_attributes(struct sysfs_directory *dir);
extern struct dlist *sysfs_get_dir_links(struct sysfs_directory *dir);
extern struct dlist *sysfs_get_dir_subdirs(struct sysfs_directory *dir);

/* sysfs driver access */
extern void sysfs_close_driver(struct sysfs_driver *driver);
extern struct sysfs_driver *sysfs_open_driver
	(const char *bus_name, const char *drv_name);
extern struct sysfs_driver *sysfs_open_driver_path(const char *path);
extern struct sysfs_attribute *sysfs_get_driver_attr
	(struct sysfs_driver *drv, const char *name);
extern struct dlist *sysfs_get_driver_attributes(struct sysfs_driver *driver);
extern struct dlist *sysfs_get_driver_devices(struct sysfs_driver *driver);
extern struct dlist *sysfs_refresh_driver_devices(struct sysfs_driver *driver);
extern struct dlist *sysfs_get_driver_links(struct sysfs_driver *driver);
extern struct sysfs_device *sysfs_get_driver_device
	(struct sysfs_driver *driver, const char *name);
extern struct dlist *sysfs_refresh_driver_attributes
	(struct sysfs_driver *driver);
extern struct sysfs_attribute *sysfs_open_driver_attr
	(const char *bus, const char *drv, const char *attrib);

/* generic sysfs device access */
extern void sysfs_close_root_device(struct sysfs_root_device *root);
extern struct sysfs_root_device *sysfs_open_root_device(const char *name);
extern struct dlist *sysfs_get_root_devices(struct sysfs_root_device *root);
extern void sysfs_close_device_tree(struct sysfs_device *device);
extern struct sysfs_device *sysfs_open_device_tree(const char *path);
extern void sysfs_close_device(struct sysfs_device *dev);
extern struct sysfs_device *sysfs_open_device
	(const char *bus, const char *bus_id);
extern struct sysfs_device *sysfs_get_device_parent(struct sysfs_device *dev);
extern struct sysfs_device *sysfs_open_device_path(const char *path);
extern int sysfs_get_device_bus(struct sysfs_device *dev);
extern struct sysfs_attribute *sysfs_get_device_attr
	(struct sysfs_device *dev, const char *name);
extern struct dlist *sysfs_get_device_attributes(struct sysfs_device *device);
extern struct dlist *sysfs_refresh_device_attributes
	(struct sysfs_device *device);
extern struct sysfs_attribute *sysfs_open_device_attr(const char *bus, 
		const char *bus_id, const char *attrib);

/* generic sysfs bus access */
extern void sysfs_close_bus(struct sysfs_bus *bus);
extern struct sysfs_bus *sysfs_open_bus(const char *name);
extern struct sysfs_device *sysfs_get_bus_device(struct sysfs_bus *bus, 
		char *id);
extern struct sysfs_driver *sysfs_get_bus_driver(struct sysfs_bus *bus,
		char *drvname);
extern struct dlist *sysfs_get_bus_drivers(struct sysfs_bus *bus);
extern struct dlist *sysfs_get_bus_devices(struct sysfs_bus *bus);
extern struct dlist *sysfs_get_bus_attributes(struct sysfs_bus *bus);
extern struct dlist *sysfs_refresh_bus_attributes(struct sysfs_bus *bus);
extern struct sysfs_attribute *sysfs_get_bus_attribute
	(struct sysfs_bus *bus,	char *attrname);
extern int sysfs_find_driver_bus(const char *driver, char *busname, 
		size_t bsize);

/* generic sysfs class access */
extern void sysfs_close_class_device(struct sysfs_class_device *dev);
extern struct sysfs_class_device *sysfs_open_class_device_path
	(const char *path);
extern struct sysfs_class_device *sysfs_open_class_device
	(const char *classname, const char *name);
extern struct sysfs_device *sysfs_get_classdev_device
	(struct sysfs_class_device *clsdev);
extern struct sysfs_driver *sysfs_get_classdev_driver
	(struct sysfs_class_device *clsdev);
extern struct sysfs_class_device *sysfs_get_classdev_parent
	(struct sysfs_class_device *clsdev);
extern void sysfs_close_class(struct sysfs_class *cls);
extern struct sysfs_class *sysfs_open_class(const char *name);
extern struct dlist *sysfs_get_class_devices(struct sysfs_class *cls);
extern struct sysfs_class_device *sysfs_get_class_device
	(struct sysfs_class *cls, char *name);
extern struct dlist *sysfs_get_classdev_attributes
	(struct sysfs_class_device *cdev);
extern struct dlist *sysfs_refresh_classdev_attributes
	(struct sysfs_class_device *cdev);
extern struct sysfs_attribute *sysfs_get_classdev_attr
	(struct sysfs_class_device *clsdev, const char *name);
extern struct sysfs_attribute *sysfs_open_classdev_attr
	(const char *classname, const char *dev, 
	 					const char *attrib); 

/**
 * sort_list: sorter function to keep list elements sorted in alphabetical 
 * 	order. Just does a strncmp as you can see :)
 * 	
 * Returns 1 if less than 0 otherwise
 *
 * NOTE: We take care to have a statically allocated "name" as the first 
 * 	lement of all libsysfs structures. Hence, this function will work 
 * 	AS IS for _ALL_ the lists that have to be sorted.
 */
static inline int sort_list(void *new_elem, void *old_elem)
{
        return ((strncmp(((struct sysfs_attribute *)new_elem)->name,
		((struct sysfs_attribute *)old_elem)->name,
		strlen(((struct sysfs_attribute *)new_elem)->name))) < 0 ? 1 : 0);
}


#ifdef __cplusplus
}
#endif

#endif /* _LIBSYSFS_H_ */
