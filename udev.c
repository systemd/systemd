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
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>

#include "udev.h"
#include "udev_version.h"
#include "udev_dbus.h"
#include "namedev.h"
#include "udevdb.h"
#include "libsysfs/libsysfs.h"

/* global variables */
char **main_argv;
char **main_envp;

static void sig_handler(int signum)
{
	dbg("caught signal %d", signum);
	switch (signum) {
		case SIGINT:
		case SIGTERM:
		case SIGKILL:
			sysbus_disconnect();
			udevdb_exit();
			exit(20 + signum);
			break;
		default:
			dbg("unhandled signal");
	}
}

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

static inline int udev_user(int argc, char **argv)
{
	static const char short_options[] = "q:rVh";
	int option;
	int retval = -EINVAL;
	struct udevice dev;

	while (1) {
		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		dbg("option '%c'", option);
		switch (option) {
		case 'q':
			dbg("udev query: %s\n", optarg);
			retval = udevdb_open_ro();
			if (retval != 0) {
				printf("unable to open udev database\n");
				return -1;
			}
			retval = udevdb_get_dev(optarg, &dev);
			if (retval == 0) {
				printf("%s\n", dev.name);
			} else {
				printf("device not found in udev database\n");
			}
			udevdb_exit();
			return retval;

		case 'r':
			printf("%s\n", udev_root);
			return 0;

		case 'V':
			printf("udev, version %s\n", UDEV_VERSION);
			return 0;

		case 'h':
			retval = 0;
		case '?':
		default:
			goto help;
		}
	}

help:
	printf("Usage: [-qrVh]\n"
	       "  -q <path>  query database for the name of the created node\n"
	       "  -r         print udev root\n"
	       "  -V         print udev version\n"
	       "  -h         print this help text\n"
	       "\n");

	return retval;
}

static char *subsystem_blacklist[] = {
	"net",
	"scsi_host",
	"scsi_device",
	"",
};

static inline int udev_hotplug(int argc, char **argv)
{
	char *action;
	char *devpath;
	char *subsystem;
	int retval = -EINVAL;
	int i;

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

	/* skip blacklisted subsystems */
	i = 0;
	while (subsystem_blacklist[i][0] != '\0') {
		if (strcmp(subsystem, subsystem_blacklist[i]) == 0) {
			dbg("don't care about '%s' devices", subsystem);
			goto exit;
		}
		i++;
	}

	action = get_action();
	if (!action) {
		dbg ("no action?");
		goto exit;
	}

	/* connect to the system message bus */
	sysbus_connect();

	/* initialize udev database */
	retval = udevdb_init(UDEVDB_DEFAULT);
	if (retval != 0) {
		dbg("unable to initialize database");
		goto exit_sysbus;
	}

	/* set up a default signal handler for now */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGKILL, sig_handler);

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

exit_sysbus:
	/* disconnect from the system message bus */
	sysbus_disconnect();

exit:
	if (retval > 0)
		retval = 0;

	return -retval;
}

int main(int argc, char **argv, char **envp)
{
	int retval;
	main_argv = argv;
	main_envp = envp;

	dbg("version %s", UDEV_VERSION);

	/* initialize our configuration */
	udev_init_config();

	if (argc == 2 && argv[1][0] != '-') {
		dbg("called by hotplug");
		retval = udev_hotplug(argc, argv);
	} else {
		dbg("called by user");
		retval = udev_user(argc, argv);
	}

	return retval;
}


