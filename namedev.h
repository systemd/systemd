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

#define BUS_SIZE		30
#define FILE_SIZE		50
#define VALUE_SIZE		100
#define ID_SIZE			50
#define PLACE_SIZE		50
#define PROGRAM_SIZE		100

#define FIELD_BUS		"BUS"
#define FIELD_SYSFS		"SYSFS"
#define FIELD_ID		"ID"
#define FIELD_PLACE		"PLACE"
#define FIELD_PROGRAM		"PROGRAM"
#define FIELD_RESULT		"RESULT"
#define FIELD_KERNEL		"KERNEL"
#define FIELD_SUBSYSTEM		"SUBSYSTEM"
#define FIELD_NAME		"NAME"
#define FIELD_SYMLINK		"SYMLINK"
#define FIELD_OWNER		"OWNER"
#define FIELD_GROUP		"GROUP"
#define FIELD_MODE		"MODE"

#define ATTR_PARTITIONS		"all_partitions"
#define PARTITIONS_COUNT	15

#define MAX_SYSFS_PAIRS		5

#define RULEFILE_SUFFIX		".rules"
#define PERMFILE_SUFFIX		".permissions"

#define set_empty_perms(dev, m, o, g)		\
	if (dev->mode == 0)			\
		dev->mode = m;			\
	if (dev->owner[0] == '\0')		\
		strfieldcpy(dev->owner, o);	\
	if (dev->group[0] == '\0')		\
		strfieldcpy(dev->group, g);

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
	char name[NAME_SIZE];
	char symlink[NAME_SIZE];
	struct sysfs_pair sysfs_pair[MAX_SYSFS_PAIRS];
	char owner[OWNER_SIZE];
	char group[GROUP_SIZE];
	unsigned int mode;
	int partitions;
	char config_file[NAME_SIZE];
	int config_line;
};

struct perm_device {
	struct list_head node;

	char name[NAME_SIZE];
	char owner[OWNER_SIZE];
	char group[GROUP_SIZE];
	unsigned int mode;
};

extern struct list_head config_device_list;
extern struct list_head perm_device_list;

extern int namedev_init(void);
extern int namedev_name_device(struct udevice *udev, struct sysfs_class_device *class_dev);
extern int namedev_init_permissions(void);
extern int namedev_init_rules(void);

extern void dump_config_dev(struct config_device *dev);
extern void dump_config_dev_list(void);
extern void dump_perm_dev(struct perm_device *dev);
extern void dump_perm_dev_list(void);

#endif
