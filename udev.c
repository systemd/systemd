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
#include "namedev.h"
#include "logging.h"


#ifdef USE_LOG
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

/* decide if we should manage the whole hotplug event
 * for now look if the kernel calls udevsend instead of /sbin/hotplug
 */
static int manage_hotplug_event(void) {
	char helper[256];
	int fd;
	int len;

	/* don't handle hotplug.d if we are called directly */
	if (!getenv("UDEVD_EVENT"))
		return 0;

	fd = open("/proc/sys/kernel/hotplug", O_RDONLY);
	if (fd < 0)
		return 0;

	len = read(fd, helper, 256);
	close(fd);

	if (len < 0)
		return 0;
	helper[len] = '\0';

	if (strstr(helper, "udevsend"))
		return 1;

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
	struct sysfs_class_device *class_dev;
	struct sysfs_device *devices_dev;
	struct udevice udev;
	char path[PATH_SIZE];
	const char *error;
	const char *action;
	const char *devpath;
	const char *subsystem;
	int managed_event;
	struct sigaction act;
	int retval = -EINVAL;

	if (argc == 2 && strcmp(argv[1], "-V") == 0) {
		printf("%s\n", UDEV_VERSION);
		exit(0);
	}

	logging_init("udev");
	dbg("version %s", UDEV_VERSION);

	udev_init_config();

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*) (int))sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(ALARM_TIMEOUT);

	/* let the executed programs know if we handle the whole hotplug event */
	managed_event = manage_hotplug_event();
	if (managed_event)
		setenv("MANAGED_EVENT", "1", 1);

	action = getenv("ACTION");
	devpath = getenv("DEVPATH");
	subsystem = getenv("SUBSYSTEM");
	/* older kernels passed the SUBSYSTEM only as argument */
	if (!subsystem && argc == 2)
		subsystem = argv[1];

	udev_init_device(&udev, devpath, subsystem);

	if (!action || !subsystem || !devpath) {
		dbg("action, subsystem or devpath missing");
		goto hotplug;
	}

	/* export logging flag, as called scripts may want to do the same as udev */
	if (udev_log)
		setenv("UDEV_LOG", "1", 1);

	if (udev.type == BLOCK || udev.type == CLASS || udev.type == NET) {
		if (strcmp(action, "add") == 0) {
			/* wait for sysfs and possibly add node */
			dbg("udev add");

			/* skip subsystems without "dev", but handle net devices */
			if (udev.type != NET && subsystem_expect_no_dev(udev.subsystem)) {
				dbg("don't care about '%s' devices", udev.subsystem);
				goto hotplug;
			}

			snprintf(path, sizeof(path), "%s%s", sysfs_path, udev.devpath);
			path[sizeof(path)-1] = '\0';
			class_dev = wait_class_device_open(path);
			if (class_dev == NULL) {
				dbg ("open class device failed");
				goto hotplug;
			}
			dbg("opened class_dev->name='%s'", class_dev->name);

			wait_for_class_device(class_dev, &error);

			/* init rules */
			namedev_init();

			/* name, create node, store in db */
			retval = udev_add_device(&udev, class_dev);

			sysfs_close_class_device(class_dev);
		} else if (strcmp(action, "remove") == 0) {
			/* possibly remove a node */
			dbg("udev remove");

			/* skip subsystems without "dev" */
			if (subsystem_expect_no_dev(udev.subsystem)) {
				dbg("don't care about '%s' devices", udev.subsystem);
				goto hotplug;
			}

			/* get node from db, remove db-entry, delete created node */
			retval = udev_remove_device(&udev);
		}

		/* run dev.d/ scripts if we created/deleted a node or changed a netif name */
		if (udev.devname[0] != '\0') {
			setenv("DEVNAME", udev.devname, 1);
			if (udev_dev_d)
				udev_multiplex_directory(&udev, DEVD_DIR, DEVD_SUFFIX);
		}
	} else if (udev.type == PHYSDEV) {
		if (strcmp(action, "add") == 0) {
			/* wait for sysfs */
			dbg("devices add");

			snprintf(path, sizeof(path), "%s%s", sysfs_path, devpath);
			path[sizeof(path)-1] = '\0';
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
	udev_cleanup_device(&udev);
	if (udev_hotplug_d && managed_event)
		udev_multiplex_directory(&udev, HOTPLUGD_DIR, HOTPLUG_SUFFIX);

	logging_close();
	return retval;
}
