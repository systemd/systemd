/*
 * udev.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_sysfs.h"
#include "udev_version.h"
#include "udev_rules.h"
#include "logging.h"

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

static void asmlinkage sig_handler(int signum)
{
	switch (signum) {
		case SIGALRM:
			exit(1);
		case SIGINT:
		case SIGTERM:
			exit(20 + signum);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	struct udevice udev;
	char path[PATH_SIZE];
	const char *error;
	const char *action;
	const char *devpath;
	const char *subsystem;
	struct sigaction act;
	int retval = -EINVAL;

	if (argc == 2 && strcmp(argv[1], "-V") == 0) {
		printf("%s\n", UDEV_VERSION);
		exit(0);
	}

	logging_init("udev");
	udev_init_config();
	dbg("version %s", UDEV_VERSION);

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*)(int)) sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(ALARM_TIMEOUT);

	action = getenv("ACTION");
	devpath = getenv("DEVPATH");
	subsystem = getenv("SUBSYSTEM");
	/* older kernels passed the SUBSYSTEM only as argument */
	if (!subsystem && argc == 2)
		subsystem = argv[1];

	if (!action || !subsystem || !devpath) {
		err("action, subsystem or devpath missing");
		goto exit;
	}

	/* export log_priority , as called programs may want to do the same as udev */
	if (udev_log_priority) {
		char priority[32];

		sprintf(priority, "%i", udev_log_priority);
		setenv("UDEV_LOG", priority, 1);
	}

	udev_init_device(&udev, devpath, subsystem, action);
	udev_rules_init();

	if (udev.type == DEV_BLOCK || udev.type == DEV_CLASS || udev.type == DEV_NET) {
		/* handle device node */
		if (strcmp(action, "add") == 0) {
			struct sysfs_class_device *class_dev;

			/* wait for sysfs of /sys/class /sys/block */
			dbg("node add");
			snprintf(path, sizeof(path), "%s%s", sysfs_path, udev.devpath);
			path[sizeof(path)-1] = '\0';
			class_dev = wait_class_device_open(path);
			if (class_dev == NULL) {
				dbg("open class device failed");
				goto run;
			}
			dbg("opened class_dev->name='%s'", class_dev->name);
			wait_for_class_device(class_dev, &error);

			/* get major/minor */
			if (udev.type == DEV_BLOCK || udev.type == DEV_CLASS)
				udev.devt = get_devt(class_dev);

			if (udev.type == DEV_NET || udev.devt) {
				/* name device */
				udev_rules_get_name(&udev, class_dev);
				if (udev.ignore_device) {
					info("device event will be ignored");
					goto cleanup;
				}
				if (udev.name[0] == '\0') {
					info("device node creation supressed");
					goto cleanup;
				}
				
				/* create node, store in db */
				retval = udev_add_device(&udev, class_dev);
			} else {
				dbg("no dev-file found");
				udev_rules_get_run(&udev, NULL);
				if (udev.ignore_device) {
					info("device event will be ignored");
					goto cleanup;
				}
			}
			sysfs_close_class_device(class_dev);
		} else if (strcmp(action, "remove") == 0) {
			dbg("node remove");
			udev_rules_get_run(&udev, NULL);
			if (udev.ignore_device) {
				dbg("device event will be ignored");
				goto cleanup;
			}

			/* get name from db, remove db-entry, delete node */
			retval = udev_remove_device(&udev);
		}

		/* export name of device node or netif */
		if (udev.devname[0] != '\0')
			setenv("DEVNAME", udev.devname, 1);
	} else if (udev.type == DEV_DEVICE) {
		if (strcmp(action, "add") == 0) {
			struct sysfs_device *devices_dev;

			/* wait for sysfs of /sys/devices/ */
			dbg("devices add");
			snprintf(path, sizeof(path), "%s%s", sysfs_path, devpath);
			path[sizeof(path)-1] = '\0';
			devices_dev = wait_devices_device_open(path);
			if (!devices_dev) {
				dbg("devices device unavailable (probably remove has beaten us)");
				goto run;
			}
			dbg("devices device opened '%s'", path);
			wait_for_devices_device(devices_dev, &error);
			udev_rules_get_run(&udev, devices_dev);
			sysfs_close_device(devices_dev);
			if (udev.ignore_device) {
				info("device event will be ignored");
				goto cleanup;
			}
		}
	} else {
		dbg("default handling");
		udev_rules_get_run(&udev, NULL);
		if (udev.ignore_device) {
			info("device event will be ignored");
			goto cleanup;
		}
	}

run:
	if (udev_run && !list_empty(&udev.run_list)) {
		struct name_entry *name_loop;

		dbg("executing run list");
		list_for_each_entry(name_loop, &udev.run_list, node)
			execute_command(name_loop->name, udev.subsystem);
	}

cleanup:
	udev_cleanup_device(&udev);

exit:
	logging_close();
	return retval;
}
