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
#include "udev.h"
#include "udev_lib.h"
#include "udev_sysfs.h"
#include "udev_version.h"
#include "namedev.h"
#include "logging.h"


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

/* (for now) true if udevsend is the helper */
static int manage_hotplug_event(void) {
	char helper[256];
	int fd;
	int len;

	fd = open("/proc/sys/kernel/hotplug", O_RDONLY);
	if (fd < 0)
		goto exit;

	len = read(fd, helper, 256);
	close(fd);

	if (len < 0)
		goto exit;
	helper[len] = '\0';

	if (strstr(helper, "udevsend"))
		return 1;

exit:
	return 0;
}

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
	struct sigaction act;
	struct sysfs_class_device *class_dev;
	struct sysfs_device *devices_dev;
	struct udevice udev;
	char path[SYSFS_PATH_MAX];
	int retval = -EINVAL;
	const char *error;
	const char *action = getenv("ACTION");
	const char *devpath = getenv("DEVPATH");
	const char *subsystem = argv[1];

	dbg("version %s", UDEV_VERSION);
	logging_init("udev");
	udev_init_config();

	/* set signal handlers */
	act.sa_handler = (void (*) (int))sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	/* alarm must not restart syscalls*/
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* trigger timeout to interrupt blocking syscalls */
	alarm(ALARM_TIMEOUT);

	udev_set_values(&udev, devpath, subsystem, action);

	if (strstr(argv[0], "udevstart") || (argv[1] != NULL && strstr(argv[1], "udevstart"))) {
		dbg("udevstart");

		/* disable all logging, as it's much too slow on some facilities */
		udev_log = 0;

		namedev_init();
		retval = udev_start();
		goto exit;
	}

	if (!action) {
		dbg("no action");
		goto hotplug;
	}

	if (!subsystem) {
		dbg("no subsystem");
		goto hotplug;
	}

	if (!devpath) {
		dbg("no devpath");
		goto hotplug;
	}

	/* export logging flag, as called scripts may want to do the same as udev */
	if (udev_log)
		setenv("UDEV_LOG", "1", 1);

	if ((strncmp(devpath, "/block/", 7) == 0) || (strncmp(devpath, "/class/", 7) == 0)) {
		if (strcmp(action, "add") == 0) {
			/* wait for sysfs and possibly add node */
			dbg("udev add");

			/* skip blacklisted subsystems */
			if (udev.type != 'n' && subsystem_expect_no_dev(udev.subsystem)) {
				dbg("don't care about '%s' devices", udev.subsystem);
				goto hotplug;
			};

			snprintf(path, SYSFS_PATH_MAX, "%s%s", sysfs_path, udev.devpath);
			class_dev = wait_class_device_open(path);
			if (class_dev == NULL) {
				dbg ("open class device failed");
				goto hotplug;
			}
			dbg("opened class_dev->name='%s'", class_dev->name);

			wait_for_class_device(class_dev, &error);

			/* init rules, permissions */
			namedev_init();

			/* name, create node, store in db */
			retval = udev_add_device(&udev, class_dev);

			/* run dev.d/ scripts if we created a node or changed a netif name */
			if (udev.devname[0] != '\0') {
				setenv("DEVNAME", udev.devname, 1);
				dev_d_execute(&udev, DEVD_DIR, DEVD_SUFFIX);
			}

			sysfs_close_class_device(class_dev);
		} else if (strcmp(action, "remove") == 0) {
			/* possibly remove a node */
			dbg("udev remove");

			/* get node from db, remove db-entry, delete created node */
			retval = udev_remove_device(&udev);

			/* run dev.d/ scripts if we're not instructed to ignore the event */
			if (udev.devname[0] != '\0') {
				setenv("DEVNAME", udev.devname, 1);
				dev_d_execute(&udev, DEVD_DIR, DEVD_SUFFIX);
			}

		}
	} else if ((strncmp(devpath, "/devices/", 9) == 0)) {
		if (strcmp(action, "add") == 0) {
			/* wait for sysfs */
			dbg("devices add");

			snprintf(path, SYSFS_PATH_MAX, "%s%s", sysfs_path, devpath);
			devices_dev = wait_devices_device_open(path);
			if (!devices_dev) {
				dbg("devices device unavailable (probably remove has beaten us)");
				goto hotplug;
			}
			dbg("devices device opened '%s'", path);

			wait_for_devices_device(devices_dev, &error);

			sysfs_close_device(devices_dev);
		} else if (strcmp(action, "remove") == 0) {
			dbg("devices remove");
		}
	} else {
		dbg("unhandled");
	}

hotplug:
	if (manage_hotplug_event())
		dev_d_execute(&udev, HOTPLUGD_DIR, HOTPLUG_SUFFIX);

exit:
	logging_close();
	return retval;
}
