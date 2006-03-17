/*
 * udevtrigger.c
 *
 * Copyright (C) 2004-2006 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2006 Hannes Reinecke <hare@suse.de>
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
#include <dirent.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"

static const char *udev_log_str;
static int verbose;
static int dry_run;

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

/* list of devices that we should run last due to any one of a number of reasons */
static char *last_list[] = {
	"/class/block/md",
	"/class/block/dm-",
	"/block/md",
	"/block/dm-",
	NULL
};

/* list of devices that we should run first due to any one of a number of reasons */
static char *first_list[] = {
	"/class/mem",
	"/class/tty",
	NULL
};

LIST_HEAD(device_first_list);
LIST_HEAD(device_default_list);
LIST_HEAD(device_last_list);

static int device_list_insert(const char *path)
{
	struct list_head *device_list = &device_default_list;
	int i;

	for (i = 0; first_list[i] != NULL; i++) {
		if (strncmp(path, first_list[i], strlen(first_list[i])) == 0) {
			device_list = &device_first_list;
			break;
		}
	}
	for (i = 0; last_list[i] != NULL; i++) {
		if (strncmp(path, last_list[i], strlen(last_list[i])) == 0) {
			device_list = &device_last_list;
			break;
		}
	}

	dbg("add '%s'" , path);
	/* double entries will be ignored */
	name_list_add(device_list, path, 0);
	return 0;
}

static void trigger_uevent(const char *path)
{
	char filename[PATH_SIZE];
	int fd;

	strlcpy(filename, path, sizeof(filename));
	strlcat(filename, "/uevent", sizeof(filename));

	if (verbose)
		printf("%s\n", path);

	if (dry_run)
		return;

	fd = open(filename, O_WRONLY);
	if (fd < 0) {
		dbg("error on opening %s: %s\n", filename, strerror(errno));
		return;
	}

	if (write(fd, "add", 3) < 0)
		info("error on triggering %s: %s\n", filename, strerror(errno));

	close(fd);
}

static void exec_lists(void)
{
	struct name_entry *loop_device;
	struct name_entry *tmp_device;

	/* handle the devices on the "first" list first */
	list_for_each_entry_safe(loop_device, tmp_device, &device_first_list, node) {
		trigger_uevent(loop_device->name);
		list_del(&loop_device->node);
		free(loop_device);
	}

	/* handle the devices on the "default" list next */
	list_for_each_entry_safe(loop_device, tmp_device, &device_default_list, node) {
		trigger_uevent(loop_device->name);
		list_del(&loop_device->node);
		free(loop_device);
	}

	/* handle devices on the "last" list, if any */
	list_for_each_entry_safe(loop_device, tmp_device, &device_last_list, node) {
		trigger_uevent(loop_device->name);
		list_del(&loop_device->node);
		free(loop_device);
	}
}

static int is_device(const char *path)
{
	char filename[PATH_SIZE];
	struct stat statbuf;

	/* look for the uevent file of the kobject */
	strlcpy(filename, path, sizeof(filename));
	strlcat(filename, "/uevent", sizeof(filename));
	if (stat(filename, &statbuf) < 0)
		return 0;

	if (!(statbuf.st_mode & S_IWUSR))
		return 0;

	return 1;
}

static void udev_scan_bus(void)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	strlcpy(base, sysfs_path, sizeof(base));
	strlcat(base, "/bus", sizeof(base));

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char dirname[PATH_SIZE];
			DIR *dir2;
			struct dirent *dent2;

			if (dent->d_name[0] == '.')
				continue;

			strlcpy(dirname, base, sizeof(dirname));
			strlcat(dirname, "/", sizeof(dirname));
			strlcat(dirname, dent->d_name, sizeof(dirname));
			strlcat(dirname, "/devices", sizeof(dirname));

			/* look for devices */
			dir2 = opendir(dirname);
			if (dir2 != NULL) {
				for (dent2 = readdir(dir2); dent2 != NULL; dent2 = readdir(dir2)) {
					char dirname2[PATH_SIZE];

					if (dent2->d_name[0] == '.')
						continue;

					strlcpy(dirname2, dirname, sizeof(dirname2));
					strlcat(dirname2, "/", sizeof(dirname2));
					strlcat(dirname2, dent2->d_name, sizeof(dirname2));

					if (is_device(dirname2))
						device_list_insert(dirname2);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
}

static void udev_scan_block(void)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;
	struct stat statbuf;

	/* skip if "block" is already a "class" */
	strlcpy(base, sysfs_path, sizeof(base));
	strlcat(base, "/class/block", sizeof(base));
	if (stat(base, &statbuf) == 0)
		return;

	strlcpy(base, sysfs_path, sizeof(base));
	strlcat(base, "/block", sizeof(base));

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char dirname[PATH_SIZE];
			DIR *dir2;
			struct dirent *dent2;

			if (dent->d_name[0] == '.')
				continue;

			strlcpy(dirname, base, sizeof(dirname));
			strlcat(dirname, "/", sizeof(dirname));
			strlcat(dirname, dent->d_name, sizeof(dirname));
			if (is_device(dirname))
				device_list_insert(dirname);
			else
				continue;

			/* look for partitions */
			dir2 = opendir(dirname);
			if (dir2 != NULL) {
				for (dent2 = readdir(dir2); dent2 != NULL; dent2 = readdir(dir2)) {
					char dirname2[PATH_SIZE];

					if (dent2->d_name[0] == '.')
						continue;

					if (!strcmp(dent2->d_name,"device"))
						continue;

					strlcpy(dirname2, dirname, sizeof(dirname2));
					strlcat(dirname2, "/", sizeof(dirname2));
					strlcat(dirname2, dent2->d_name, sizeof(dirname2));
					if (is_device(dirname2))
						device_list_insert(dirname2);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
}

static void udev_scan_class(void)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	strlcpy(base, sysfs_path, sizeof(base));
	strlcat(base, "/class", sizeof(base));

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char dirname[PATH_SIZE];
			DIR *dir2;
			struct dirent *dent2;

			if (dent->d_name[0] == '.')
				continue;

			strlcpy(dirname, base, sizeof(dirname));
			strlcat(dirname, "/", sizeof(dirname));
			strlcat(dirname, dent->d_name, sizeof(dirname));
			dir2 = opendir(dirname);
			if (dir2 != NULL) {
				for (dent2 = readdir(dir2); dent2 != NULL; dent2 = readdir(dir2)) {
					char dirname2[PATH_SIZE];

					if (dent2->d_name[0] == '.')
						continue;

					if (!strcmp(dent2->d_name, "device"))
						continue;

					strlcpy(dirname2, dirname, sizeof(dirname2));
					strlcat(dirname2, "/", sizeof(dirname2));
					strlcat(dirname2, dent2->d_name, sizeof(dirname2));
					if (is_device(dirname2))
						device_list_insert(dirname2);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	int i;

	logging_init("udevtrigger");
	udev_config_init();
	dbg("version %s", UDEV_VERSION);

	udev_log_str = getenv("UDEV_LOG");

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];

		if (strcmp(arg, "--verbose") == 0 || strcmp(arg, "-v") == 0)
			verbose = 1;
		else if (strcmp(arg, "--dry-run") == 0 || strcmp(arg, "-n") == 0)
			dry_run = 1;
		else {
			fprintf(stderr, "Usage: udevtrigger [--verbose] [--dry-run]\n");
			goto exit;
		}
	}

	sysfs_init();

	udev_scan_bus();
	udev_scan_class();
	udev_scan_block();
	exec_lists();

	sysfs_cleanup();
exit:
	logging_close();
	return 0;
}
