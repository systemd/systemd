/*
 * udev.h
 *
 * Userspace devfs
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

#define ALARM_TIMEOUT			120
#define COMMENT_CHARACTER		'#'

#define LINE_SIZE			512
#define NAME_SIZE			128
#define PATH_SIZE			256
#define USER_SIZE			32
#define SEQNUM_SIZE			32
#define VALUE_SIZE			128

#define DEVD_DIR			"/etc/dev.d"
#define DEVD_SUFFIX			".dev"

#define HOTPLUGD_DIR			"/etc/hotplug.d"
#define HOTPLUG_SUFFIX			".hotplug"

#define DEFAULT_PARTITIONS_COUNT	15

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
	char devname[PATH_SIZE];
	struct list_head symlink_list;
	char owner[USER_SIZE];
	char group[USER_SIZE];
	mode_t mode;
	dev_t devt;
	struct list_head run_list;

	char tmp_node[PATH_SIZE];
	int partitions;
	int ignore_device;
	int ignore_remove;
	int config_line;
	char config_file[PATH_SIZE];
	char bus_id[NAME_SIZE];
	char program_result[PATH_SIZE];
	char kernel_number[NAME_SIZE];
	char kernel_name[NAME_SIZE];
	int test_run;
};

extern int udev_add_device(struct udevice *udev, struct sysfs_class_device *class_dev);
extern int udev_remove_device(struct udevice *udev);
extern void udev_init_config(void);
extern int udev_start(void);
extern void udev_multiplex_directory(struct udevice *udev, const char *basedir, const char *suffix);
extern int udev_make_node(struct udevice *udev, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid);

extern char sysfs_path[PATH_SIZE];
extern char udev_root[PATH_SIZE];
extern char udev_db_path[PATH_SIZE];
extern char udev_config_filename[PATH_SIZE];
extern char udev_rules_filename[PATH_SIZE];
extern int udev_log_priority;
extern int udev_run;
extern int udev_dev_d;
extern int udev_hotplug_d;

#endif
