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
#define NAME_SIZE			256
#define USER_SIZE			32

#define ACTION_SIZE			32
#define DEVPATH_SIZE			256
#define SUBSYSTEM_SIZE			32
#define SEQNUM_SIZE			32

#define DEVD_DIR			"/etc/dev.d"
#define DEVD_SUFFIX			".dev"

#define HOTPLUGD_DIR			"/etc/hotplug.d"
#define HOTPLUG_SUFFIX			".hotplug"

#define DEFAULT_PARTITIONS_COUNT	15

enum device_type {
	UNKNOWN,
	CLASS,
	BLOCK,
	NET,
	PHYSDEV,
};

struct udevice {
	char devpath[DEVPATH_SIZE];
	char subsystem[SUBSYSTEM_SIZE];

	char name[NAME_SIZE];
	char devname[NAME_SIZE];
	char symlink[NAME_SIZE];
	char owner[USER_SIZE];
	char group[USER_SIZE];
	mode_t mode;
	char type;
	dev_t devt;

	char tmp_node[NAME_SIZE];
	int partitions;
	int ignore_remove;
	int config_line;
	char config_file[NAME_SIZE];
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
extern void udev_multiplex_directory(struct udevice *udev, const char *basedir, const char *suffix);
extern int udev_make_node(struct udevice *udev, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid);

extern char sysfs_path[SYSFS_PATH_MAX];
extern char udev_root[PATH_MAX];
extern char udev_db_path[PATH_MAX+NAME_MAX];
extern char udev_config_filename[PATH_MAX+NAME_MAX];
extern char udev_rules_filename[PATH_MAX+NAME_MAX];
extern int udev_log;
extern int udev_dev_d;
extern int udev_hotplug_d;

#endif
