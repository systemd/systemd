/*
 * quick and dirty way to populate a /dev directory
 *
 * Copyright (C) 2004 Harald Hoyer <harald@redhat.com>
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2006 Kay Sievers <kay@vrfy.org>
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include <syslog.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"
#include "udev_rules.h"
#include "udev_selinux.h"

static const char *udev_run_str;
static const char *udev_log_str;
static struct udev_rules rules;

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

struct device {
	struct list_head node;
	char path[PATH_SIZE];
};

/* sort files in lexical order */
static int device_list_insert(const char *path, struct list_head *device_list)
{
	struct device *loop_device;
	struct device *new_device;
	const char *devpath = &path[strlen(sysfs_path)];

	dbg("insert: '%s'\n", devpath);

	list_for_each_entry(loop_device, device_list, node) {
		if (strcmp(loop_device->path, devpath) > 0) {
			break;
		}
	}

	new_device = malloc(sizeof(struct device));
	if (new_device == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}

	strlcpy(new_device->path, devpath, sizeof(new_device->path));
	list_add_tail(&new_device->node, &loop_device->node);
	dbg("add '%s'" , new_device->path);
	return 0;
}

/* list of devices that we should run last due to any one of a number of reasons */
static char *last_list[] = {
	"/block/dm",	/* on here because dm wants to have the block devices around before it */
	NULL,
};

/* list of devices that we should run first due to any one of a number of reasons */
static char *first_list[] = {
	"/class/mem",
	"/class/tty",
	NULL,
};

static int add_device(const char *devpath)
{
	struct sysfs_device *dev;
	struct udevice *udev;
	int retval = 0;

	/* clear and set environment for next event */
	clearenv();
	setenv("ACTION", "add", 1);
	setenv("UDEV_START", "1", 1);
	if (udev_log_str)
		setenv("UDEV_LOG", udev_log_str, 1);
	if (udev_run_str)
		setenv("UDEV_RUN", udev_run_str, 1);

	dev = sysfs_device_get(devpath);
	if (dev == NULL)
		return -1;

	udev = udev_device_init();
	if (udev == NULL)
		return -1;

	/* override built-in sysfs device */
	udev->dev = dev;
	strcpy(udev->action, "add");

	if (strcmp(udev->dev->subsystem, "net") != 0) {
		udev->devt = udev_device_get_devt(udev);
		if (major(udev->devt) == 0)
			return -1;
	}

	dbg("add '%s'", udev->dev->devpath);
	setenv("DEVPATH", udev->dev->devpath, 1);
	setenv("SUBSYSTEM", udev->dev->subsystem, 1);

	udev_rules_get_name(&rules, udev);
	if (udev->ignore_device) {
		dbg("device event will be ignored");
		goto exit;
	}
	if (udev->name[0] != '\0')
		retval = udev_device_event(&rules, udev);
	else
		info("device node creation supressed");

	if (retval == 0 && udev_run) {
		struct name_entry *name_loop;

		dbg("executing run list");
		list_for_each_entry(name_loop, &udev->run_list, node) {
			if (strncmp(name_loop->name, "socket:", strlen("socket:")) == 0)
				pass_env_to_socket(&name_loop->name[strlen("socket:")], udev->dev->devpath, "add");
			else {
				char program[PATH_SIZE];

				strlcpy(program, name_loop->name, sizeof(program));
				udev_rules_apply_format(udev, program, sizeof(program));
				run_program(program, udev->dev->subsystem, NULL, 0, NULL, (udev_log_priority >= LOG_INFO));
			}
		}
	}

exit:
	udev_device_cleanup(udev);
	return 0;
}

static void exec_list(struct list_head *device_list)
{
	struct device *loop_device;
	struct device *tmp_device;
	int i;

	/* handle the "first" type devices first */
	list_for_each_entry_safe(loop_device, tmp_device, device_list, node) {
		for (i = 0; first_list[i] != NULL; i++) {
			if (strncmp(loop_device->path, first_list[i], strlen(first_list[i])) == 0) {
				add_device(loop_device->path);
				list_del(&loop_device->node);
				free(loop_device);
				break;
			}
		}
	}

	/* handle the devices we are allowed to, excluding the "last" type devices */
	list_for_each_entry_safe(loop_device, tmp_device, device_list, node) {
		int found = 0;
		for (i = 0; last_list[i] != NULL; i++) {
			if (strncmp(loop_device->path, last_list[i], strlen(last_list[i])) == 0) {
				found = 1;
				break;
			}
		}
		if (found)
			continue;

		add_device(loop_device->path);
		list_del(&loop_device->node);
		free(loop_device);
	}

	/* handle the rest of the devices left over, if any */
	list_for_each_entry_safe(loop_device, tmp_device, device_list, node) {
		add_device(loop_device->path);
		list_del(&loop_device->node);
		free(loop_device);
	}
}

static int has_devt(const char *path)
{
	char filename[PATH_SIZE];
	struct stat statbuf;

	snprintf(filename, sizeof(filename), "%s/dev", path);
	filename[sizeof(filename)-1] = '\0';

	if (stat(filename, &statbuf) == 0)
		return 1;

	return 0;
}

static void udev_scan_block(struct list_head *device_list)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

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
				device_list_insert(dirname, device_list);
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
						device_list_insert(dirname2, device_list);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
}

static void udev_scan_class(struct list_head *device_list)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

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

					if (has_devt(dirname2) || strcmp(dent->d_name, "net") == 0)
						device_list_insert(dirname2, device_list);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
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
	LIST_HEAD(device_list);
	struct sigaction act;

	logging_init("udevstart");
	udev_config_init();
	selinux_init();
	dbg("version %s", UDEV_VERSION);

	udev_run_str = getenv("UDEV_RUN");
	udev_log_str = getenv("UDEV_LOG");

	/* disable all logging if not explicitely requested */
	if (udev_log_str == NULL)
		udev_log_priority = 0;

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*) (int))sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(UDEV_ALARM_TIMEOUT);

	sysfs_init();
	udev_rules_init(&rules, 1);

	udev_scan_class(&device_list);
	udev_scan_block(&device_list);
	exec_list(&device_list);

	udev_rules_cleanup(&rules);
	sysfs_cleanup();
	logging_close();
	return 0;
}
