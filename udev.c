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
char *udev_config_dir = UDEV_CONFIG_DIR;
char *udev_root = UDEV_ROOT;
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
	char *temp;
	char *udev_db = UDEV_DB;
	char *udev_config = UDEV_CONFIG_FILE;
	char *udev_permission = UDEV_CONFIG_PERMISSION_FILE;
	int retval;

	retval = sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX);
	if (retval)
		dbg("sysfs_get_mnt_path failed");

	/* see if we should try to override any of the default values */
	temp = getenv("UDEV_TEST");
	if (temp != NULL) {
		/* hm testing is happening, use the specified values, if they are present */
		temp = getenv("SYSFS_PATH");
		if (temp)
			strncpy(sysfs_path, temp, sizeof(sysfs_path));
		temp = getenv("UDEV_CONFIG_DIR");
		if (temp)
			udev_config_dir = temp;
		temp = getenv("UDEV_ROOT");
		if (temp)
			udev_root = temp;
		temp = getenv("UDEV_DB");
		if (temp)
			udev_db = temp;
		temp = getenv("UDEV_CONFIG_FILE");
		if (temp)
			udev_config = temp;
		temp = getenv("UDEV_PERMISSION_FILE");
		if (temp)
			udev_permission = temp;
	}
	dbg("sysfs_path='%s'", sysfs_path);

	strncpy(udev_db_filename, udev_config_dir, sizeof(udev_db_filename));
	strncat(udev_db_filename, udev_db, sizeof(udev_db_filename));

	strncpy(udev_config_filename, udev_config_dir, sizeof(udev_config_filename));
	strncat(udev_config_filename, udev_config, sizeof(udev_config_filename));
	
	strncpy(udev_config_permission_filename, udev_config_dir, sizeof(udev_config_permission_filename));
	strncat(udev_config_permission_filename, udev_permission, sizeof(udev_config_permission_filename));
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
	dbg("looking at '%s'", devpath);

	/* we only care about class devices and block stuff */
	if (!strstr(devpath, "class") &&
	    !strstr(devpath, "block")) {
		dbg("not a block or class device");
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
		dbg("unable to initialize database");
		goto exit;
	}

	/* initialize the naming deamon */
	namedev_init();

	if (strcmp(action, "add") == 0)
		retval = udev_add_device(devpath, subsystem);

	else if (strcmp(action, "remove") == 0)
		retval = udev_remove_device(devpath, subsystem);

	else {
		dbg("unknown action '%s'", action);
		retval = -EINVAL;
	}
	udevdb_exit();

exit:	
	return retval;
}
