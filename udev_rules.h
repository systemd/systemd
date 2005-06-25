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

#ifndef UDEV_RULES_H
#define UDEV_RULES_H

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "list.h"


#define KEY_KERNEL		"KERNEL"
#define KEY_SUBSYSTEM		"SUBSYSTEM"
#define KEY_ACTION		"ACTION"
#define KEY_DEVPATH		"DEVPATH"
#define KEY_BUS			"BUS"
#define KEY_ID			"ID"
#define KEY_PROGRAM		"PROGRAM"
#define KEY_RESULT		"RESULT"
#define KEY_DRIVER		"DRIVER"
#define KEY_SYSFS		"SYSFS"
#define KEY_ENV			"ENV"
#define KEY_MODALIAS		"MODALIAS"
#define KEY_IMPORT		"IMPORT"
#define KEY_NAME		"NAME"
#define KEY_SYMLINK		"SYMLINK"
#define KEY_OWNER		"OWNER"
#define KEY_GROUP		"GROUP"
#define KEY_MODE		"MODE"
#define KEY_RUN			"RUN"
#define KEY_OPTIONS		"OPTIONS"

#define OPTION_LAST_RULE	"last_rule"
#define OPTION_IGNORE_DEVICE	"ignore_device"
#define OPTION_IGNORE_REMOVE	"ignore_remove"
#define OPTION_PARTITIONS	"all_partitions"

#define KEY_SYSFS_PAIRS_MAX	5
#define KEY_ENV_PAIRS_MAX	5

#define RULEFILE_SUFFIX		".rules"

enum key_operation {
	KEY_OP_UNSET,
	KEY_OP_MATCH,
	KEY_OP_NOMATCH,
	KEY_OP_ADD,
	KEY_OP_ASSIGN,
	KEY_OP_ASSIGN_FINAL,
};

struct key_pair {
	char name[NAME_SIZE];
	char value[VALUE_SIZE];
	enum key_operation operation;
};

struct udev_rule {
	struct list_head node;

	char kernel[NAME_SIZE];
	enum key_operation kernel_operation;
	char subsystem[NAME_SIZE];
	enum key_operation subsystem_operation;
	char action[NAME_SIZE];
	enum key_operation action_operation;
	char devpath[PATH_SIZE];
	enum key_operation devpath_operation;
	char bus[NAME_SIZE];
	enum key_operation bus_operation;
	char id[NAME_SIZE];
	enum key_operation id_operation;
	char driver[NAME_SIZE];
	enum key_operation driver_operation;
	char program[PATH_SIZE];
	enum key_operation program_operation;
	char result[PATH_SIZE];
	enum key_operation result_operation;
	struct key_pair sysfs_pair[KEY_SYSFS_PAIRS_MAX];
	int sysfs_pair_count;
	struct key_pair env_pair[KEY_ENV_PAIRS_MAX];
	int env_pair_count;
	char modalias[NAME_SIZE];
	enum key_operation modalias_operation;
	char import[PATH_SIZE];
	enum key_operation import_operation;
	int import_exec;

	char name[PATH_SIZE];
	enum key_operation name_operation;
	char symlink[PATH_SIZE];
	enum key_operation symlink_operation;
	char owner[USER_SIZE];
	enum key_operation owner_operation;
	char group[USER_SIZE];
	enum key_operation group_operation;
	mode_t mode;
	enum key_operation mode_operation;
	char run[PATH_SIZE];
	enum key_operation run_operation;

	int last_rule;
	int ignore_device;
	int ignore_remove;
	int partitions;

	char config_file[PATH_SIZE];
	int config_line;
};

extern int udev_rules_init(void);
extern void udev_rules_close(void);

extern int udev_rules_iter_init(void);
extern struct udev_rule *udev_rules_iter_next(void);

extern int udev_rules_get_name(struct udevice *udev, struct sysfs_class_device *class_dev);
extern int udev_rules_get_run(struct udevice *udev, struct sysfs_device *sysfs_device);

#endif
