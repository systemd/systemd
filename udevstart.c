/*
 * udevstart.c
 *
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 * 
 * Quick and dirty way to populate a /dev with udev if your system
 * does not have access to a shell.  Based originally on a patch to udev 
 * from Harald Hoyer <harald@redhat.com>
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
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "namedev.h"
#include "udev_utils.h"
#include "list.h"

#ifdef USE_LOG
void log_message(int level, const char *format, ...)
{
}
#endif

struct device {
	struct list_head list;
	char path[PATH_SIZE];
	char subsys[NAME_SIZE];
};

/* sort files in lexical order */
static int device_list_insert(const char *path, char *subsystem, struct list_head *device_list)
{
	struct device *loop_device;
	struct device *new_device;

	dbg("insert: '%s'\n", path);

	list_for_each_entry(loop_device, device_list, list) {
		if (strcmp(loop_device->path, path) > 0) {
			break;
		}
	}

	new_device = malloc(sizeof(struct device));
	if (new_device == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}

	strlcpy(new_device->path, path, sizeof(new_device->path));
	strlcpy(new_device->subsys, subsystem, sizeof(new_device->subsys));
	list_add_tail(&new_device->list, &loop_device->list);
	dbg("add '%s' from subsys '%s'", new_device->path, new_device->subsys);
	return 0;
}

/* list of devices that we should run last due to any one of a number of reasons */
static char *last_list[] = {
	"/block/dm",	/* on here because dm wants to have the block devices around before it */
	NULL,
};

/* list of devices that we should run first due to any one of a number of reasons */
static char *first_list[] = {
	"/class/mem",	/* people tend to like their memory devices around first... */
	NULL,
};

static int add_device(const char *path, const char *subsystem)
{
	struct udevice udev;
	struct sysfs_class_device *class_dev;
	const char *devpath;

	devpath = &path[strlen(sysfs_path)];

	/* set environment for callouts and dev.d/ */
	setenv("DEVPATH", devpath, 1);
	setenv("SUBSYSTEM", subsystem, 1);

	dbg("exec: '%s' (%s)\n", devpath, path);

	class_dev = sysfs_open_class_device_path(path);
	if (class_dev == NULL) {
		dbg ("sysfs_open_class_device_path failed");
		return -ENODEV;
	}

	udev_init_device(&udev, devpath, subsystem);
	udev_add_device(&udev, class_dev);

	/* run dev.d/ scripts if we created a node or changed a netif name */
	if (udev_dev_d && udev.devname[0] != '\0') {
		setenv("DEVNAME", udev.devname, 1);
		udev_multiplex_directory(&udev, DEVD_DIR, DEVD_SUFFIX);
	}

	sysfs_close_class_device(class_dev);
	udev_cleanup_device(&udev);

	return 0;
}

static void exec_list(struct list_head *device_list)
{
	struct device *loop_device;
	struct device *tmp_device;
	int i;

	/* handle the "first" type devices first */
	list_for_each_entry_safe(loop_device, tmp_device, device_list, list) {
		for (i = 0; first_list[i] != NULL; i++) {
			if (strncmp(loop_device->path, first_list[i], strlen(first_list[i])) == 0) {
				add_device(loop_device->path, loop_device->subsys);
				list_del(&loop_device->list);
				free(loop_device);
				break;
			}
		}
	}

	/* handle the devices we are allowed to, excluding the "last" type devices */
	list_for_each_entry_safe(loop_device, tmp_device, device_list, list) {
		int found = 0;
		for (i = 0; last_list[i] != NULL; i++) {
			if (strncmp(loop_device->path, last_list[i], strlen(last_list[i])) == 0) {
				found = 1;
				break;
			}
		}
		if (found)
			continue;

		add_device(loop_device->path, loop_device->subsys);
		list_del(&loop_device->list);
		free(loop_device);
	}

	/* handle the rest of the devices left over, if any */
	list_for_each_entry_safe(loop_device, tmp_device, device_list, list) {
		add_device(loop_device->path, loop_device->subsys);
		list_del(&loop_device->list);
		free(loop_device);
	}
}

static int has_devt(const char *directory)
{
	char filename[PATH_SIZE];
	struct stat statbuf;

	snprintf(filename, sizeof(filename), "%s/dev", directory);
	filename[sizeof(filename)-1] = '\0';

	if (stat(filename, &statbuf) == 0)
		return 1;

	return 0;
}

static void udev_scan_block(void)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;
	LIST_HEAD(device_list);

	snprintf(base, sizeof(base), "%s/block", sysfs_path);
	base[sizeof(base)-1] = '\0';

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char dirname[PATH_SIZE];
			DIR *dir2;
			struct dirent *dent2;

			if (dent->d_name[0] == '.')
				continue;

			snprintf(dirname, sizeof(dirname), "%s/%s", base, dent->d_name);
			dirname[sizeof(dirname)-1] = '\0';
			if (has_devt(dirname))
				device_list_insert(dirname, "block", &device_list);
			else
				continue;

			/* look for partitions */
			dir2 = opendir(dirname);
			if (dir2 != NULL) {
				for (dent2 = readdir(dir2); dent2 != NULL; dent2 = readdir(dir2)) {
					char dirname2[PATH_SIZE];

					if (dent2->d_name[0] == '.')
						continue;

					snprintf(dirname2, sizeof(dirname2), "%s/%s", dirname, dent2->d_name);
					dirname2[sizeof(dirname2)-1] = '\0';

					if (has_devt(dirname2))
						device_list_insert(dirname2, "block", &device_list);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
	exec_list(&device_list);
}

static void udev_scan_class(void)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;
	LIST_HEAD(device_list);

	snprintf(base, sizeof(base), "%s/class", sysfs_path);
	base[sizeof(base)-1] = '\0';

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char dirname[PATH_SIZE];
			DIR *dir2;
			struct dirent *dent2;

			if (dent->d_name[0] == '.')
				continue;

			snprintf(dirname, sizeof(dirname), "%s/%s", base, dent->d_name);
			dirname[sizeof(dirname)-1] = '\0';

			dir2 = opendir(dirname);
			if (dir2 != NULL) {
				for (dent2 = readdir(dir2); dent2 != NULL; dent2 = readdir(dir2)) {
					char dirname2[PATH_SIZE];

					if (dent2->d_name[0] == '.')
						continue;

					snprintf(dirname2, sizeof(dirname2), "%s/%s", dirname, dent2->d_name);
					dirname2[sizeof(dirname2)-1] = '\0';

					/* pass the net class as it is */
					if (strcmp(dent->d_name, "net") == 0)
						device_list_insert(dirname2, "net", &device_list);
					else if (has_devt(dirname2))
						device_list_insert(dirname2, dent->d_name, &device_list);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
	exec_list(&device_list);
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

	/* set environment for executed programs */
	setenv("ACTION", "add", 1);
	setenv("UDEV_START", "1", 1);

	namedev_init();

	udev_scan_block();
	udev_scan_class();

	return 0;
}
