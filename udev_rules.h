/*
 * udev_rules.h
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

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "list.h"


#define FIELD_KERNEL		"KERNEL"
#define FIELD_SUBSYSTEM		"SUBSYSTEM"
#define FIELD_BUS		"BUS"
#define FIELD_SYSFS		"SYSFS"
#define FIELD_ID		"ID"
#define FIELD_PROGRAM		"PROGRAM"
#define FIELD_RESULT		"RESULT"
#define FIELD_DRIVER		"DRIVER"
#define FIELD_NAME		"NAME"
#define FIELD_SYMLINK		"SYMLINK"
#define FIELD_OWNER		"OWNER"
#define FIELD_GROUP		"GROUP"
#define FIELD_MODE		"MODE"
#define FIELD_OPTIONS		"OPTIONS"

#define OPTION_LAST_RULE	"last_rule"
#define OPTION_IGNORE_DEVICE	"ignore_device"
#define OPTION_IGNORE_REMOVE	"ignore_remove"
#define OPTION_PARTITIONS	"all_partitions"

#define MAX_SYSFS_PAIRS		5

#define RULEFILE_SUFFIX		".rules"

struct sysfs_pair {
	char file[PATH_SIZE];
	char value[VALUE_SIZE];
};

struct udev_rule {
	struct list_head node;

	char kernel[NAME_SIZE];
	char subsystem[NAME_SIZE];
	char bus[NAME_SIZE];
	char id[NAME_SIZE];
	struct sysfs_pair sysfs_pair[MAX_SYSFS_PAIRS];
	char program[PATH_SIZE];
	char result[PATH_SIZE];
	char driver[NAME_SIZE];
	char name[PATH_SIZE];
	char symlink[PATH_SIZE];

	char owner[USER_SIZE];
	char group[USER_SIZE];
	mode_t mode;

	int last_rule;
	int ignore_device;
	int ignore_remove;
	int partitions;

	char config_file[PATH_SIZE];
	int config_line;
};

extern struct list_head udev_rule_list;

extern int udev_rules_init(void);
extern int udev_rules_get_name(struct udevice *udev, struct sysfs_class_device *class_dev);
extern void udev_rules_close(void);

extern void udev_rule_dump(struct udev_rule *rule);
extern void udev_rule_list_dump(void);

#endif
