/*
 * namedev.h
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
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

#define BUS_SIZE		32
#define FILE_SIZE		64
#define VALUE_SIZE		128
#define ID_SIZE			64
#define PLACE_SIZE		64
#define DRIVER_SIZE		64
#define PROGRAM_SIZE		128

#define FIELD_BUS		"BUS"
#define FIELD_SYSFS		"SYSFS"
#define FIELD_ID		"ID"
#define FIELD_PLACE		"PLACE"
#define FIELD_PROGRAM		"PROGRAM"
#define FIELD_RESULT		"RESULT"
#define FIELD_KERNEL		"KERNEL"
#define FIELD_SUBSYSTEM		"SUBSYSTEM"
#define FIELD_DRIVER		"DRIVER"
#define FIELD_NAME		"NAME"
#define FIELD_SYMLINK		"SYMLINK"
#define FIELD_OWNER		"OWNER"
#define FIELD_GROUP		"GROUP"
#define FIELD_MODE		"MODE"

#define ATTR_PARTITIONS		"all_partitions"
#define ATTR_IGNORE_REMOVE	"ignore_remove"
#define PARTITIONS_COUNT	15

#define MAX_SYSFS_PAIRS		5

#define RULEFILE_SUFFIX		".rules"

struct sysfs_pair {
	char file[FILE_SIZE];
	char value[VALUE_SIZE];
};

struct config_device {
	struct list_head node;

	char bus[BUS_SIZE];
	char id[ID_SIZE];
	char place[PLACE_SIZE];
	char kernel[NAME_SIZE];
	char program[PROGRAM_SIZE];
	char result[PROGRAM_SIZE];
	char subsystem[SUBSYSTEM_SIZE];
	char driver[DRIVER_SIZE];
	char name[NAME_SIZE];
	char symlink[NAME_SIZE];
	struct sysfs_pair sysfs_pair[MAX_SYSFS_PAIRS];
	char owner[USER_SIZE];
	char group[USER_SIZE];
	mode_t mode;
	int partitions;
	int ignore_remove;
	char config_file[NAME_SIZE];
	int config_line;
};

extern struct list_head config_device_list;

extern int namedev_init(void);
extern int namedev_name_device(struct udevice *udev, struct sysfs_class_device *class_dev);

extern void dump_config_dev(struct config_device *dev);
extern void dump_config_dev_list(void);

#endif
