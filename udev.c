/*
 * udev.c
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_lib.h"
#include "udev_sysfs.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"
#include "udevdb.h"

/* timeout flag for udevdb */
extern sig_atomic_t gotalarm;

/* global variables */
char **main_argv;
char **main_envp;

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	if (!udev_log)
		return;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

static void asmlinkage sig_handler(int signum)
{
	switch (signum) {
		case SIGALRM:
			gotalarm = 1;
			info("error: timeout reached, event probably not handled correctly");
			break;
		case SIGINT:
		case SIGTERM:
			udevdb_exit();
			exit(20 + signum);
		default:
			dbg("unhandled signal %d", signum);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	struct sigaction act;
	struct sysfs_class_device *class_dev;
	struct udevice udev;
	char path[SYSFS_PATH_MAX];
	int retval = -EINVAL;
	enum {
		ADD,
		REMOVE,
		UDEVSTART,
	} act_type;

	dbg("version %s", UDEV_VERSION);

	main_argv = argv;
	main_envp = envp;

	logging_init("udev");

	udev_init_config();

	if (strstr(argv[0], "udevstart")) {
		act_type = UDEVSTART;
	} else {
		const char *action = get_action();
		const char *devpath = get_devpath();
		const char *subsystem = get_subsystem(main_argv[1]);

		if (!action) {
			dbg("no action?");
			goto exit;
		}
		if (strcmp(action, "add") == 0) {
			act_type = ADD;
		} else if (strcmp(action, "remove") == 0) {
			act_type = REMOVE;
		} else {
			dbg("no action '%s' for us", action);
			goto exit;
		}

		if (!devpath) {
			dbg("no devpath?");
			goto exit;
		}
		dbg("looking at '%s'", devpath);

		/* we only care about class devices and block stuff */
		if (!strstr(devpath, "class") && !strstr(devpath, "block")) {
			dbg("not a block or class device");
			goto exit;
		}

		if (!subsystem) {
			dbg("no subsystem");
			goto exit;
		}

		udev_set_values(&udev, devpath, subsystem);

		/* skip blacklisted subsystems */
		if (udev.type != 'n' && subsystem_expect_no_dev(subsystem)) {
			dbg("don't care about '%s' devices", subsystem);
			goto exit;
		};

	}

	/* set signal handlers */
	act.sa_handler = (void (*) (int))sig_handler;
	sigemptyset (&act.sa_mask);
	/* alarm must not restart syscalls*/
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* trigger timout to interrupt blocking syscalls */
	alarm(ALARM_TIMEOUT);

	/* initialize udev database */
	if (udevdb_init(UDEVDB_DEFAULT) != 0)
		info("error: unable to initialize database, continuing without database");

	switch(act_type) {
	case UDEVSTART:
		dbg("udevstart");
		namedev_init();
		retval = udev_start();
		break;
	case ADD:
		dbg("udev add");

		/* open the device */
		snprintf(path, SYSFS_PATH_MAX, "%s%s", sysfs_path, udev.devpath);
		class_dev = sysfs_open_class_device_path(path);
		if (class_dev == NULL) {
			dbg ("sysfs_open_class_device_path failed");
			break;
		}
		dbg("opened class_dev->name='%s'", class_dev->name);

		/* init rules */
		namedev_init();

		/* name, create node, store in db */
		retval = udev_add_device(&udev, class_dev);

		/* run scripts */
		dev_d_execute(&udev);

		sysfs_close_class_device(class_dev);
		break;
	case REMOVE:
		dbg("udev remove");

		/* get node from db, delete it*/
		retval = udev_remove_device(&udev);

		/* run scripts */
		dev_d_execute(&udev);
	}

	udevdb_exit();

exit:
	logging_close();
	return retval;
}
