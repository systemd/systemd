/*
 * namedev.h
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
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

#ifndef NAMEDEV_H
#define NAMEDEV_H

#include "udev.h"
#include "list.h"

struct sysfs_class_device;

#define COMMENT_CHARACTER		'#'

enum config_type {
	KERNEL_NAME	= 0,	/* must be 0 to let memset() default to this value */
	LABEL		= 1,
	NUMBER		= 2,
	TOPOLOGY	= 3,
	REPLACE		= 4,
	CALLOUT		= 5,
};

#define BUS_SIZE	30
#define FILE_SIZE	50
#define VALUE_SIZE	100
#define ID_SIZE		50
#define PLACE_SIZE	50

#define TYPE_LABEL	"LABEL"
#define TYPE_NUMBER	"NUMBER"
#define TYPE_TOPOLOGY	"TOPOLOGY"
#define TYPE_REPLACE	"REPLACE"
#define TYPE_CALLOUT	"CALLOUT"
#define CALLOUT_MAXARG	8

struct config_device {
	struct list_head node;

	enum config_type type;
	char bus[BUS_SIZE];
	char sysfs_file[FILE_SIZE];
	char sysfs_value[VALUE_SIZE];
	char id[ID_SIZE];
	char place[PLACE_SIZE];
	char kernel_name[NAME_SIZE];
	char exec_program[FILE_SIZE];

	/* what to set the device to */
	char name[NAME_SIZE];
	char owner[OWNER_SIZE];
	char group[GROUP_SIZE];
	mode_t mode;
};

extern struct list_head config_device_list;

extern int namedev_init(void);
extern int namedev_name_device(struct sysfs_class_device *class_dev, struct udevice *dev);
extern int namedev_init_permissions(void);
extern int namedev_init_config(void);

extern int add_config_dev(struct config_device *new_dev);
extern void dump_config_dev(struct config_device *dev);
extern void dump_config_dev_list(void);

#endif
