/*
 * udev.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 *
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "udev.h"
#include "udev_version.h"
#include "namedev.h"
#include "udevdb.h"
#include "libsysfs/libsysfs.h"

/* global variables */
char **main_argv;
char **main_envp;

char sysfs_path[SYSFS_PATH_MAX];
char *udev_config_dir;
char *udev_root;
char udev_db_filename[PATH_MAX+NAME_MAX];
char udev_config_permission_filename[PATH_MAX+NAME_MAX];
char udev_config_filename[PATH_MAX+NAME_MAX];


static inline char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}

static inline char *get_devpath(void)
{
	char *devpath;

	devpath = getenv("DEVPATH");
	return devpath;
}

static inline char *get_seqnum(void)
{
	char *seqnum;

	seqnum = getenv("SEQNUM");
	return seqnum;
}

static void get_dirs(void)
{
	char *udev_test;
	char *temp;
	int retval;

	udev_test = getenv("UDEV_TEST");
	if (udev_test == NULL) {
		/* normal operation, use the compiled in defaults */
		udev_config_dir = UDEV_CONFIG_DIR;
		udev_root = UDEV_ROOT;
		retval = sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX);
		dbg("sysfs_path = %s", sysfs_path);
		if (retval)
			dbg("sysfs_get_mnt_path failed");

	} else {
		/* hm testing is happening, use the specified values */
		temp = getenv("UDEV_SYSFS_PATH");
		strncpy(sysfs_path, temp, sizeof(sysfs_path));
		udev_config_dir = getenv("UDEV_CONFIG_DIR");
		udev_root = getenv("UDEV_ROOT");
	}

	strncpy(udev_db_filename, udev_config_dir, sizeof(udev_db_filename));
	strncat(udev_db_filename, UDEV_DB, sizeof(udev_db_filename));

	strncpy(udev_config_filename, udev_config_dir, sizeof(udev_config_filename));
	strncat(udev_config_filename, NAMEDEV_CONFIG_FILE, sizeof(udev_config_filename));
	
	strncpy(udev_config_permission_filename, udev_config_dir, sizeof(udev_config_permission_filename));
	strncat(udev_config_permission_filename, NAMEDEV_CONFIG_PERMISSION_FILE, sizeof(udev_config_permission_filename));
}

int main(int argc, char **argv, char **envp)
{
	char *action;
	char *devpath;
	char *subsystem;
	int retval = -EINVAL;
	
	main_argv = argv;
	main_envp = envp;

	dbg("version %s", UDEV_VERSION);

	if (argc != 2) {
		dbg ("unknown number of arguments");
		goto exit;
	}

	subsystem = argv[1];

	devpath = get_devpath();
	if (!devpath) {
		dbg ("no devpath?");
		goto exit;
	}
	dbg("looking at %s", devpath);

	/* we only care about class devices and block stuff */
	if (!strstr(devpath, "class") &&
	    !strstr(devpath, "block")) {
		dbg("not block or class");
		goto exit;
	}

	/* but we don't care about net class devices */
	if (strcmp(subsystem, "net") == 0) {
		dbg("don't care about net devices");
		goto exit;
	}

	action = get_action();
	if (!action) {
		dbg ("no action?");
		goto exit;
	}

	/* initialize udev database */
	get_dirs();
	retval = udevdb_init(UDEVDB_DEFAULT);
	if (retval != 0) {
		dbg("Unable to initialize database.");
		goto exit;
	}

	/* initialize the naming deamon */
	namedev_init();

	if (strcmp(action, "add") == 0)
		retval = udev_add_device(devpath, subsystem);

	else if (strcmp(action, "remove") == 0)
		retval = udev_remove_device(devpath, subsystem);

	else {
		dbg("Unknown action: %s", action);
		retval = -EINVAL;
	}
	udevdb_exit();

exit:	
	return retval;
}

