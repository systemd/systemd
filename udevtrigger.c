/*
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <syslog.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"
#include "udevd.h"

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

static int verbose;
static int dry_run;

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

LIST_HEAD(filter_subsytem_match_list);
LIST_HEAD(filter_subsytem_nomatch_list);
LIST_HEAD(filter_attr_match_list);
LIST_HEAD(filter_attr_nomatch_list);

static int device_list_insert(const char *path)
{
	struct list_head *device_list = &device_default_list;
	const char *devpath = &path[strlen(sysfs_path)];
	int i;

	for (i = 0; first_list[i] != NULL; i++) {
		if (strncmp(devpath, first_list[i], strlen(first_list[i])) == 0) {
			device_list = &device_first_list;
			break;
		}
	}
	for (i = 0; last_list[i] != NULL; i++) {
		if (strncmp(devpath, last_list[i], strlen(last_list[i])) == 0) {
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

static int subsystem_filtered(const char *subsystem)
{
	struct name_entry *loop_name;

	/* skip devices matching the listed subsystems */
	list_for_each_entry(loop_name, &filter_subsytem_nomatch_list, node)
		if (fnmatch(subsystem, loop_name->name, 0) == 0)
			return 1;

	/* skip devices not matching the listed subsystems */
	if (!list_empty(&filter_subsytem_match_list)) {
		list_for_each_entry(loop_name, &filter_subsytem_match_list, node)
			if (fnmatch(subsystem, loop_name->name, 0) == 0)
				return 0;
		return 1;
	}

	return 0;
}

static int attr_match(const char *path, const char *attr_value)
{
	char attr[NAME_SIZE];
	char file[PATH_SIZE];
	char *match_value;

	strlcpy(attr, attr_value, sizeof(attr));

	/* separate attr and match value */
	match_value = strchr(attr, '=');
	if (match_value != NULL) {
		match_value[0] = '\0';
		match_value = &match_value[1];
	}

	strlcpy(file, path, sizeof(file));
	strlcat(file, "/", sizeof(file));
	strlcat(file, attr, sizeof(file));

	if (match_value != NULL) {
		/* match file content */
		char value[NAME_SIZE];
		int fd;
		ssize_t size;

		fd = open(file, O_RDONLY);
		if (fd < 0)
			return 0;
		size = read(fd, value, sizeof(value));
		close(fd);
		if (size < 0)
			return 0;
		value[size] = '\0';
		remove_trailing_chars(value, '\n');

		/* match if attribute value matches */
		if (fnmatch(match_value, value, 0) == 0)
			return 1;
	} else {
		/* match if attribute exists */
		struct stat statbuf;

		if (stat(file, &statbuf) == 0)
			return 1;
	}
	return 0;
}

static int attr_filtered(const char *path)
{
	struct name_entry *loop_name;

	/* skip devices matching the listed sysfs attributes */
	list_for_each_entry(loop_name, &filter_attr_nomatch_list, node)
		if (attr_match(path, loop_name->name))
			return 1;

	/* skip devices not matching the listed sysfs attributes */
	if (!list_empty(&filter_attr_match_list)) {
		list_for_each_entry(loop_name, &filter_attr_match_list, node)
			if (attr_match(path, loop_name->name))
				return 0;
		return 1;
	}
	return 0;
}

static void scan_bus(void)
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

			if (subsystem_filtered(dent->d_name))
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
					if (attr_filtered(dirname2))
						continue;
					if (is_device(dirname2))
						device_list_insert(dirname2);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
}

static void scan_block(void)
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

	if (subsystem_filtered("block"))
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
			if (attr_filtered(dirname))
				continue;
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
					if (attr_filtered(dirname2))
						continue;
					if (is_device(dirname2))
						device_list_insert(dirname2);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
}

static void scan_class(void)
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

			if (subsystem_filtered(dent->d_name))
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
					if (attr_filtered(dirname2))
						continue;
					if (is_device(dirname2))
						device_list_insert(dirname2);
				}
				closedir(dir2);
			}
		}
		closedir(dir);
	}
}

static void scan_failed(void)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	strlcpy(base, udev_root, sizeof(base));
	strlcat(base, "/", sizeof(base));
	strlcat(base, EVENT_FAILED_DIR, sizeof(base));

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char linkname[PATH_SIZE];
			char target[PATH_SIZE];
			int len;

			if (dent->d_name[0] == '.')
				continue;

			strlcpy(linkname, base, sizeof(linkname));
			strlcat(linkname, "/", sizeof(linkname));
			strlcat(linkname, dent->d_name, sizeof(linkname));

			len = readlink(linkname, target, sizeof(target));
			if (len <= 0)
				continue;
			target[len] = '\0';

			if (is_device(target))
				device_list_insert(target);
			else
				continue;
		}
		closedir(dir);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	int failed = 0;
	int option;
	struct option options[] = {
		{ "verbose", 0, NULL, 'v' },
		{ "dry-run", 0, NULL, 'n' },
		{ "retry-failed", 0, NULL, 'F' },
		{ "help", 0, NULL, 'h' },
		{ "subsystem-match", 1, NULL, 's' },
		{ "subsystem-nomatch", 1, NULL, 'S' },
		{ "attr-match", 1, NULL, 'a' },
		{ "attr-nomatch", 1, NULL, 'A' },
		{}
	};

	logging_init("udevtrigger");
	udev_config_init();
	dbg("version %s", UDEV_VERSION);
	sysfs_init();

	while (1) {
		option = getopt_long(argc, argv, "vnFhs:S:a:A:", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'v':
			verbose = 1;
			break;
		case 'n':
			dry_run = 1;
			break;
		case 'F':
			failed = 1;
			break;
		case 's':
			name_list_add(&filter_subsytem_match_list, optarg, 0);
			break;
		case 'S':
			name_list_add(&filter_subsytem_nomatch_list, optarg, 0);
			break;
		case 'a':
			name_list_add(&filter_attr_match_list, optarg, 0);
			break;
		case 'A':
			name_list_add(&filter_attr_nomatch_list, optarg, 0);
			break;
		case 'h':
			printf("Usage: udevtrigger OPTIONS\n"
			       "  --verbose                        print the list of devices which will be triggered\n"
			       "  --dry-run                        do not actually trigger the event\n"
			       "  --retry-failed                   trigger only the events which are failed during a previous run\n"
			       "  --subsystem-match=<subsystem>    select only devices from the specified subystem\n"
			       "  --subsystem-nomatch=<subsystem>  exclude devices from the specified subystem\n"
			       "  --attr-match=<file[=<value>]>    select only devices with a matching sysfs attribute\n"
			       "  --attr-nomatch=<file[=<value>]>  exclude devices with a matching sysfs attribute\n"
			       "  --help                           print this text\n"
			       "\n");
			goto exit;
		default:
			goto exit;
		}
	}

	if (failed)
		scan_failed();
	else {
		scan_bus();
		scan_class();
		scan_block();
	}
	exec_lists();

exit:
	name_list_cleanup(&filter_subsytem_match_list);
	name_list_cleanup(&filter_subsytem_nomatch_list);
	name_list_cleanup(&filter_attr_match_list);
	name_list_cleanup(&filter_attr_nomatch_list);

	sysfs_cleanup();
	logging_close();
	return 0;
}
