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

#ifndef UDEV_H
#define UDEV_H

#include "libsysfs/libsysfs.h"
#include <sys/param.h>

#define COMMENT_CHARACTER		'#'

#define NAME_SIZE	100
#define OWNER_SIZE	30
#define GROUP_SIZE	30
#define MODE_SIZE	8

struct udevice {
	char name[NAME_SIZE];
	char owner[OWNER_SIZE];
	char group[GROUP_SIZE];
	char type;
	int major;
	int minor;
	mode_t mode;
	char symlink[NAME_SIZE];

	/* fields that help us in building strings */
	unsigned char bus_id[SYSFS_NAME_LEN];
	unsigned char program_result[NAME_SIZE];
	unsigned char kernel_number[NAME_SIZE];
	unsigned char kernel_name[NAME_SIZE];
};

#define strfieldcpy(to, from) \
do { \
	to[sizeof(to)-1] = '\0'; \
	strncpy(to, from, sizeof(to)-1); \
} while (0)

extern int udev_add_device(char *path, char *subsystem);
extern int udev_remove_device(char *path, char *subsystem);
extern void udev_init_config(void);
extern int parse_get_pair(char **orig_string, char **left, char **right);

extern char **main_argv;
extern char **main_envp;
extern char sysfs_path[SYSFS_PATH_MAX];
extern char udev_root[PATH_MAX];
extern char udev_db_filename[PATH_MAX+NAME_MAX];
extern char udev_permissions_filename[PATH_MAX+NAME_MAX];
extern char udev_config_filename[PATH_MAX+NAME_MAX];
extern char udev_rules_filename[PATH_MAX+NAME_MAX];
extern char default_mode_str[MODE_SIZE];
extern char default_owner_str[OWNER_SIZE];
extern char default_group_str[GROUP_SIZE];

#endif
