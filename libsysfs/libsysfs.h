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
#include "dlist.h"

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

struct sysfs_attribute {
	unsigned char *value;
	unsigned short len;		/* value length */
	unsigned short method;		/* show and store */
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];
};

struct sysfs_link {
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];
	unsigned char target[SYSFS_PATH_MAX];
};

struct sysfs_directory {
	struct dlist *subdirs;	
	struct dlist *links;		
	struct dlist *attributes;
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];
};

struct sysfs_driver {
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];

	/* for internal use only */
	struct dlist *devices;
	struct sysfs_directory *directory;	
};

struct sysfs_device {
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char bus_id[SYSFS_NAME_LEN];
	unsigned char bus[SYSFS_NAME_LEN];
	unsigned char driver_name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];

	/* for internal use only */
	struct sysfs_device *parent;		
	struct dlist *children;	
	struct sysfs_directory *directory;	
};

struct sysfs_root_device {
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];

	/* for internal use only */
	struct dlist *devices;
	struct sysfs_directory *directory;
};

struct sysfs_bus {
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];

	/* internal use only */
	struct dlist *drivers;
	struct dlist *devices;
	struct sysfs_directory *directory;	
};

struct sysfs_class_device {
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char classname[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];

	/* for internal use only */
	struct sysfs_class_device *parent;	
	struct sysfs_device *sysdevice;		/* NULL if virtual */
	struct sysfs_driver *driver;		/* NULL if not implemented */
	struct sysfs_directory *directory;	
};

struct sysfs_class {
	unsigned char name[SYSFS_NAME_LEN];
	unsigned char path[SYSFS_PATH_MAX];

	/* for internal use only */
	struct dlist *devices;
	struct sysfs_directory *directory;	
};

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function Prototypes
 */
extern int sysfs_trailing_slash(unsigned char *path);
extern int sysfs_get_mnt_path(unsigned char *mnt_path, size_t len);
extern int sysfs_get_name_from_path(const unsigned char *path, 
					unsigned char *name, size_t len);
extern int sysfs_path_is_dir(const unsigned char *path);
extern int sysfs_path_is_link(const unsigned char *path);
extern int sysfs_path_is_file(const unsigned char *path);
extern int sysfs_get_link(const unsigned char *path, unsigned char *target, 
								size_t len);
extern struct dlist *sysfs_open_subsystem_list(unsigned char *name);
extern struct dlist *sysfs_open_bus_devices_list(unsigned char *name);
extern void sysfs_close_list(struct dlist *list);

/* sysfs directory and file access */
extern void sysfs_close_attribute(struct sysfs_attribute *sysattr);
extern struct sysfs_attribute *sysfs_open_attribute(const unsigned char *path);
extern int sysfs_read_attribute(struct sysfs_attribute *sysattr);
extern int sysfs_read_attribute_value(const unsigned char *attrpath, 
				unsigned char *value, size_t vsize);
extern int sysfs_write_attribute(struct sysfs_attribute *sysattr,
		const unsigned char *new_value, size_t len);
extern unsigned char *sysfs_get_value_from_attributes(struct dlist *attr, 
						const unsigned char * name);
extern int sysfs_refresh_attributes(struct dlist *attrlist);
extern void sysfs_close_directory(struct sysfs_directory *sysdir);
extern struct sysfs_directory *sysfs_open_directory(const unsigned char *path);
extern int sysfs_read_dir_attributes(struct sysfs_directory *sysdir);
extern int sysfs_read_dir_links(struct sysfs_directory *sysdir);
extern int sysfs_read_dir_subdirs(struct sysfs_directory *sysdir);
extern int sysfs_read_directory(struct sysfs_directory *sysdir);
extern int sysfs_read_all_subdirs(struct sysfs_directory *sysdir);
extern struct sysfs_directory *sysfs_get_subdirectory
			(struct sysfs_directory *dir, unsigned char *subname);
extern void sysfs_close_link(struct sysfs_link *ln);
extern struct sysfs_link *sysfs_open_link(const unsigned char *lnpath);
extern struct sysfs_link *sysfs_get_directory_link(struct sysfs_directory *dir,
						unsigned char *linkname);
extern struct sysfs_link *sysfs_get_subdirectory_link
			(struct sysfs_directory *dir, unsigned char *linkname);
extern struct sysfs_attribute *sysfs_get_directory_attribute
			(struct sysfs_directory *dir, unsigned char *attrname);

/* sysfs driver access */
extern void sysfs_close_driver(struct sysfs_driver *driver);
extern struct sysfs_driver *sysfs_open_driver
	(const unsigned char *drv_name, const unsigned char *bus_name);
extern struct sysfs_driver *sysfs_open_driver_path(const unsigned char *path);
extern struct sysfs_attribute *sysfs_get_driver_attr
		(struct sysfs_driver *drv, const unsigned char *name);
extern struct dlist *sysfs_get_driver_attributes(struct sysfs_driver *driver);
extern struct dlist *sysfs_get_driver_devices(struct sysfs_driver *driver);
extern struct dlist *sysfs_get_driver_links(struct sysfs_driver *driver);
extern struct sysfs_device *sysfs_get_driver_device
	(struct sysfs_driver *driver, const unsigned char *name);
extern struct sysfs_attribute *sysfs_open_driver_attr(const unsigned char *bus, 
		const unsigned char *drv, const unsigned char *attrib);

/* generic sysfs device access */
extern void sysfs_close_root_device(struct sysfs_root_device *root);
extern struct sysfs_root_device *sysfs_open_root_device
						(const unsigned char *name);
extern struct dlist *sysfs_get_root_devices(struct sysfs_root_device *root);
extern void sysfs_close_device(struct sysfs_device *dev);
extern struct sysfs_device *sysfs_open_device
		(const unsigned char *bus_id, const unsigned char *bus);
extern struct sysfs_device *sysfs_get_device_parent(struct sysfs_device *dev);
extern struct sysfs_device *sysfs_open_device_path(const unsigned char *path);
extern struct sysfs_attribute *sysfs_get_device_attr
			(struct sysfs_device *dev, const unsigned char *name);
extern struct dlist *sysfs_get_device_attributes(struct sysfs_device *device);
extern struct sysfs_attribute *sysfs_open_device_attr(const unsigned char *bus, 
		const unsigned char *bus_id, const unsigned char *attrib);

/* generic sysfs bus access */
extern void sysfs_close_bus(struct sysfs_bus *bus);
extern struct sysfs_bus *sysfs_open_bus(const unsigned char *name);
extern struct sysfs_device *sysfs_get_bus_device(struct sysfs_bus *bus,
						unsigned char *id);
extern struct sysfs_driver *sysfs_get_bus_driver(struct sysfs_bus *bus,
						unsigned char *drvname);
extern struct dlist *sysfs_get_bus_drivers(struct sysfs_bus *bus);
extern struct dlist *sysfs_get_bus_devices(struct sysfs_bus *bus);
extern struct dlist *sysfs_get_bus_attributes(struct sysfs_bus *bus);
extern struct sysfs_attribute *sysfs_get_bus_attribute(struct sysfs_bus *bus,
						unsigned char *attrname);
extern struct sysfs_device *sysfs_open_bus_device(unsigned char *busname, 
							unsigned char *dev_id);
extern int sysfs_find_driver_bus(const unsigned char *driver, 
					unsigned char *busname,	size_t bsize);

/* generic sysfs class access */
extern void sysfs_close_class_device(struct sysfs_class_device *dev);
extern struct sysfs_class_device *sysfs_open_class_device_path
					(const unsigned char *path);
extern struct sysfs_class_device *sysfs_open_class_device
	(const unsigned char *class, const unsigned char *name);
extern struct sysfs_device *sysfs_get_classdev_device
				(struct sysfs_class_device *clsdev);
extern struct sysfs_driver *sysfs_get_classdev_driver
				(struct sysfs_class_device *clsdev);
extern struct sysfs_class_device *sysfs_get_classdev_parent
				(struct sysfs_class_device *clsdev);
extern void sysfs_close_class(struct sysfs_class *cls);
extern struct sysfs_class *sysfs_open_class(const unsigned char *name);
extern struct dlist *sysfs_get_class_devices(struct sysfs_class *cls);
extern struct sysfs_class_device *sysfs_get_class_device
	(struct sysfs_class *class, unsigned char *name);
extern struct dlist *sysfs_get_classdev_attributes
	(struct sysfs_class_device *cdev);
extern struct sysfs_attribute *sysfs_get_classdev_attr
	(struct sysfs_class_device *clsdev, const unsigned char *name);
extern struct sysfs_attribute *sysfs_open_classdev_attr
	(const unsigned char *classname, const unsigned char *dev, 
	 					const unsigned char *attrib); 

#ifdef __cplusplus
}
#endif

#endif /* _LIBSYSFS_H_ */
