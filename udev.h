/*
 * udev.h
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

#ifndef _UDEV_H_
#define _UDEV_H_

#include <sys/param.h>
#include "libsysfs/sysfs/libsysfs.h"

#define ALARM_TIMEOUT			120
#define COMMENT_CHARACTER		'#'

#define NAME_SIZE			256
#define OWNER_SIZE			32
#define GROUP_SIZE			32
#define MODE_SIZE			8

#define ACTION_SIZE			32
#define DEVPATH_SIZE			256
#define SUBSYSTEM_SIZE			32
#define SEQNUM_SIZE			32

#define LINE_SIZE			256

#define DEVD_DIR			"/etc/dev.d"
#define DEVD_SUFFIX			".dev"

#define HOTPLUGD_DIR			"/etc/hotplug.d"
#define HOTPLUG_SUFFIX			".hotplug"

struct udevice {
	char devpath[DEVPATH_SIZE];
	char subsystem[SUBSYSTEM_SIZE];

	char name[NAME_SIZE];
	char symlink[NAME_SIZE];
	char owner[OWNER_SIZE];
	char group[GROUP_SIZE];
	mode_t mode;
	char type;
	int major;
	int minor;

	char devname[NAME_SIZE];
	int partitions;
	int ignore_remove;
	int config_line;
	char config_file[NAME_SIZE];
	long config_uptime;
	char bus_id[SYSFS_NAME_LEN];
	char program_result[NAME_SIZE];
	char kernel_number[NAME_SIZE];
	char kernel_name[NAME_SIZE];
	int test_run;
};

extern int udev_add_device(struct udevice *udev, struct sysfs_class_device *class_dev);
extern int udev_remove_device(struct udevice *udev);
extern void udev_init_config(void);
extern int udev_start(void);
extern int parse_get_pair(char **orig_string, char **left, char **right);
extern void udev_multiplex_directory(struct udevice *udev, const char *basedir, const char *suffix);

extern char sysfs_path[SYSFS_PATH_MAX];
extern char udev_root[PATH_MAX];
extern char udev_db_path[PATH_MAX+NAME_MAX];
extern char udev_permissions_filename[PATH_MAX+NAME_MAX];
extern char udev_config_filename[PATH_MAX+NAME_MAX];
extern char udev_rules_filename[PATH_MAX+NAME_MAX];
extern char default_mode_str[MODE_SIZE];
extern char default_owner_str[OWNER_SIZE];
extern char default_group_str[GROUP_SIZE];
extern int udev_log;
extern int udev_dev_d;
extern int udev_hotplug_d;

#endif
