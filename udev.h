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
#include <limits.h>

#ifdef DEBUG
#include <syslog.h>
#define dbg(format, arg...)								\
	do {										\
		log_message (LOG_DEBUG , "%s: " format , __FUNCTION__ , ## arg);	\
	} while (0)
#else
	#define dbg(format, arg...) do { } while (0)
#endif

/* Parser needs it's own debugging statement, we usually don't care about this at all */
#ifdef DEBUG_PARSER
#define dbg_parse(format, arg...)							\
	do {										\
		log_message (LOG_DEBUG , "%s: " format , __FUNCTION__ , ## arg);	\
	} while (0)
#else
	#define dbg_parse(format, arg...) do { } while (0)
#endif


extern int log_message (int level, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));


/* filenames for the config and database files */
#define UDEV_DB				"udev.tdb"
#define UDEV_CONFIG_PERMISSION_FILE	"udev.permissions"
#define UDEV_CONFIG_FILE		"udev.config"

#define NAME_SIZE	100
#define OWNER_SIZE	30
#define GROUP_SIZE	30

struct udevice {
	char name[NAME_SIZE];
	char owner[OWNER_SIZE];
	char group[GROUP_SIZE];
	char type;
	int major;
	int minor;
	mode_t mode;

	/* fields that help us in building strings */
	unsigned char bus_id[SYSFS_NAME_LEN];
	unsigned char callout_value[NAME_SIZE];
	unsigned char kernel_number[NAME_SIZE];

};

#define strfieldcpy(to, from) \
do { \
	to[sizeof(to)-1] = '\0'; \
	strncpy(to, from, sizeof(to)-1); \
} while (0)

extern int udev_add_device(char *path, char *subsystem);
extern int udev_remove_device(char *path, char *subsystem);

extern char **main_argv;
extern char **main_envp;
extern char sysfs_path[SYSFS_PATH_MAX];
extern char *udev_config_dir;
extern char *udev_root;
extern char udev_db_filename[PATH_MAX+NAME_MAX];
extern char udev_config_permission_filename[PATH_MAX+NAME_MAX];
extern char udev_config_filename[PATH_MAX+NAME_MAX];

#endif
