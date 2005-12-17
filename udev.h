/*
 * udev.h
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2005 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _UDEV_H_
#define _UDEV_H_

#include <sys/types.h>
#include <sys/param.h>
#include "libsysfs/sysfs/libsysfs.h"
#include "list.h"

#define COMMENT_CHARACTER		'#'
#define PATH_TO_NAME_CHAR		'@'
#define LINE_SIZE			512
#define NAME_SIZE			128
#define PATH_SIZE			256
#define USER_SIZE			32
#define SEQNUM_SIZE			32
#define VALUE_SIZE			128

#define DEFAULT_PARTITIONS_COUNT	15
#define UDEV_ALARM_TIMEOUT		180

#define DB_DIR				".udev/db"

struct udev_rules;

enum device_type {
	DEV_UNKNOWN,
	DEV_CLASS,
	DEV_BLOCK,
	DEV_NET,
	DEV_DEVICE,
};

struct udevice {
	char devpath[PATH_SIZE];
	char subsystem[NAME_SIZE];
	char action[NAME_SIZE];

	enum device_type type;
	char name[PATH_SIZE];
	struct list_head symlink_list;
	int symlink_final;
	char owner[USER_SIZE];
	int owner_final;
	char group[USER_SIZE];
	int group_final;
	mode_t mode;
	int mode_final;
	dev_t devt;
	struct list_head run_list;
	int run_final;
	struct list_head env_list;

	char tmp_node[PATH_SIZE];
	int partitions;
	int ignore_device;
	int ignore_remove;
	char bus_id[NAME_SIZE];
	char program_result[PATH_SIZE];
	char kernel_number[NAME_SIZE];
	char kernel_name[NAME_SIZE];
	int test_run;
};

extern int udev_init_device(struct udevice *udev, const char* devpath, const char *subsystem, const char *action);
extern void udev_cleanup_device(struct udevice *udev);
extern dev_t get_devt(struct sysfs_class_device *class_dev);
extern int udev_process_event(struct udev_rules *rules, struct udevice *udev);
extern int udev_add_device(struct udevice *udev, struct sysfs_class_device *class_dev);
extern int udev_remove_device(struct udevice *udev);
extern void udev_init_config(void);
extern int udev_start(void);
extern int udev_make_node(struct udevice *udev, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid);

extern int udev_db_add_device(struct udevice *dev);
extern int udev_db_delete_device(struct udevice *dev);
extern int udev_db_get_device(struct udevice *udev, const char *devpath);
extern int udev_db_lookup_name(const char *name, char *devpath, size_t len);
extern int udev_db_get_all_entries(struct list_head *name_list);

extern char sysfs_path[PATH_SIZE];
extern char udev_root[PATH_SIZE];
extern char udev_config_filename[PATH_SIZE];
extern char udev_rules_filename[PATH_SIZE];
extern int udev_log_priority;
extern int udev_run;

#endif
