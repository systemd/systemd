/*
 * libsysfs.h
 *
 * Header Definitions for libsysfs
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
#ifndef _LIBSYSFS_H_
#define _LIBSYSFS_H_

#include <sys/types.h>

/*
 * Generic #defines go here..
 */ 
#define SYSFS_FSTYPE_NAME	"sysfs"
#define SYSFS_PROC_MNTS		"/proc/mounts"
#define SYSFS_BUS_DIR		"/bus"
#define SYSFS_CLASS_DIR		"/class"
#define SYSFS_DEVICES_DIR	"/devices"
#define SYSFS_DEVICES_NAME	"devices"
#define SYSFS_DRIVERS_DIR	"/drivers"
#define SYSFS_DRIVERS_NAME	"drivers"
#define SYSFS_NAME_ATTRIBUTE	"name"

#define SYSFS_PATH_MAX		255
#define	SYSFS_NAME_LEN		50
#define SYSFS_BUS_ID_SIZE	20

#define SYSFS_METHOD_SHOW	0x01	/* attr can be read by user */
#define SYSFS_METHOD_STORE	0x02	/* attr can be changed by user */

struct sysfs_attribute {
	struct sysfs_attribute *next;
	char path[SYSFS_PATH_MAX];
	char *value;
	unsigned short len;		/* value length */
	unsigned short method;		/* show and store */
};

struct sysfs_dlink {
	struct sysfs_dlink *next;
	char name[SYSFS_NAME_LEN];
	struct sysfs_directory *target;
};

struct sysfs_directory {
	struct sysfs_directory *next;
	char path[SYSFS_PATH_MAX];
	struct sysfs_directory *subdirs;
	struct sysfs_dlink *links;
	struct sysfs_attribute *attributes;
};

struct sysfs_driver {
	struct sysfs_driver *next;
	char name[SYSFS_NAME_LEN];
	struct sysfs_directory *directory;
	struct sysfs_device *device;
};

struct sysfs_device {
	struct sysfs_device *next;
	char name[SYSFS_NAME_LEN];
	char bus_id[SYSFS_NAME_LEN];
	struct sysfs_driver *driver;
	struct sysfs_directory *directory;
	struct sysfs_device *parent;
	struct sysfs_device *children;
};

struct sysfs_bus {
	struct sysfs_bus *next;
	char name[SYSFS_NAME_LEN];
	struct sysfs_directory *directory;
	struct sysfs_driver *drivers;
	struct sysfs_device *devices;
};

struct sysfs_class_device {
	struct sysfs_class_device *next;
	char name[SYSFS_NAME_LEN];
	struct sysfs_directory *directory;
	struct sysfs_device *sysdevice;		/* NULL if virtual */
	struct sysfs_driver *driver;		/* NULL if not implemented */
};

struct sysfs_class {
	struct sysfs_class *next;
	char name[SYSFS_NAME_LEN];
	struct sysfs_directory *directory;
	struct sysfs_class_device *devices;
};

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function Prototypes
 */
extern int sysfs_get_mnt_path(char *mnt_path, size_t len);
extern int sysfs_get_name_from_path(const char *path, char *name, size_t len);
extern int sysfs_get_link(const char *path, char *target, size_t len);

/* sysfs directory and file access */
extern void sysfs_close_attribute(struct sysfs_attribute *sysattr);
extern struct sysfs_attribute *sysfs_open_attribute(const char *path);
extern int sysfs_read_attribute(struct sysfs_attribute *sysattr);
extern int sysfs_read_attribute_value(const char *attrpath, char *value, 
								size_t vsize);
extern char *sysfs_get_value_from_attributes(struct sysfs_attribute *attr, 
							const char * name);
extern void sysfs_close_directory(struct sysfs_directory *sysdir);
extern struct sysfs_directory *sysfs_open_directory(const char *path);
extern int sysfs_read_directory(struct sysfs_directory *sysdir);
extern void sysfs_close_dlink(struct sysfs_dlink *dlink);
extern struct sysfs_dlink *sysfs_open_dlink(const char *linkpath);
extern int sysfs_read_dlinks(struct sysfs_dlink *dlink);

/* sysfs driver access */
extern void sysfs_close_driver(struct sysfs_driver *driver);
extern struct sysfs_driver *sysfs_open_driver(const char *path);

/* generic sysfs device access */
extern void sysfs_close_device(struct sysfs_device *dev);
extern void sysfs_close_device_tree(struct sysfs_device *dev);
extern struct sysfs_device *sysfs_open_device(const char *path);
extern struct sysfs_device *sysfs_open_device_tree(const char *path);
extern struct sysfs_attribute *sysfs_get_device_attr
				(struct sysfs_device *dev, const char *name);

/* generic sysfs bus access */
extern void sysfs_close_bus(struct sysfs_bus *bus);
extern struct sysfs_bus *sysfs_open_bus(const char *name);

/* generic sysfs class access */
extern void sysfs_close_class_device(struct sysfs_class_device *dev);
extern struct sysfs_class_device *sysfs_open_class_device(const char *path);
extern void sysfs_close_class(struct sysfs_class *cls);
extern struct sysfs_class *sysfs_open_class(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _LIBSYSFS_H_ */
