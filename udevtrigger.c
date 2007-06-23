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

static int verbose;
static int dry_run;
LIST_HEAD(device_list);
LIST_HEAD(filter_subsystem_match_list);
LIST_HEAD(filter_subsystem_nomatch_list);
LIST_HEAD(filter_attr_match_list);
LIST_HEAD(filter_attr_nomatch_list);

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

/* devices that should run last cause of their dependencies */
static int delay_device(const char *devpath)
{
	static const char *delay_device_list[] = {
		"*/md*",
		"*/dm-*",
		NULL
	};
	int i;

	for (i = 0; delay_device_list[i] != NULL; i++)
		if (fnmatch(delay_device_list[i], devpath, 0) == 0)
			return 1;
	return 0;
}

static int device_list_insert(const char *path)
{
	char filename[PATH_SIZE];
	char devpath[PATH_SIZE];
	struct stat statbuf;

	dbg("add '%s'" , path);

	/* we only have a device, if we have an uevent file */
	strlcpy(filename, path, sizeof(filename));
	strlcat(filename, "/uevent", sizeof(filename));
	if (stat(filename, &statbuf) < 0)
		return -1;
	if (!(statbuf.st_mode & S_IWUSR))
		return -1;

	strlcpy(devpath, &path[strlen(sysfs_path)], sizeof(devpath));

	/* resolve possible link to real target */
	if (lstat(path, &statbuf) < 0)
		return -1;
	if (S_ISLNK(statbuf.st_mode))
		if (sysfs_resolve_link(devpath, sizeof(devpath)) != 0)
			return -1;

	name_list_add(&device_list, devpath, 1);
	return 0;
}

static void trigger_uevent(const char *devpath)
{
	char filename[PATH_SIZE];
	int fd;

	strlcpy(filename, sysfs_path, sizeof(filename));
	strlcat(filename, devpath, sizeof(filename));
	strlcat(filename, "/uevent", sizeof(filename));

	if (verbose)
		printf("%s\n", devpath);

	if (dry_run)
		return;

	fd = open(filename, O_WRONLY);
	if (fd < 0) {
		dbg("error on opening %s: %s", filename, strerror(errno));
		return;
	}

	if (write(fd, "add", 3) < 0)
		info("error on triggering %s: %s", filename, strerror(errno));

	close(fd);
}

static void exec_list(void)
{
	struct name_entry *loop_device;
	struct name_entry *tmp_device;

	list_for_each_entry_safe(loop_device, tmp_device, &device_list, node) {
		if (delay_device(loop_device->name))
			continue;

		trigger_uevent(loop_device->name);
		list_del(&loop_device->node);
		free(loop_device);
	}

	/* trigger remaining delayed devices */
	list_for_each_entry_safe(loop_device, tmp_device, &device_list, node) {
		trigger_uevent(loop_device->name);
		list_del(&loop_device->node);
		free(loop_device);
	}
}

static int subsystem_filtered(const char *subsystem)
{
	struct name_entry *loop_name;

	/* skip devices matching the listed subsystems */
	list_for_each_entry(loop_name, &filter_subsystem_nomatch_list, node)
		if (fnmatch(loop_name->name, subsystem, 0) == 0)
			return 1;

	/* skip devices not matching the listed subsystems */
	if (!list_empty(&filter_subsystem_match_list)) {
		list_for_each_entry(loop_name, &filter_subsystem_match_list, node)
			if (fnmatch(loop_name->name, subsystem, 0) == 0)
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

static void scan_subsystem(const char *subsys)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	strlcpy(base, sysfs_path, sizeof(base));
	strlcat(base, "/", sizeof(base));
	strlcat(base, subsys, sizeof(base));

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
			if (device_list_insert(dirname) != 0)
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
	strlcat(base, "/" EVENT_FAILED_DIR, sizeof(base));

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char device[PATH_SIZE];
			size_t start;

			if (dent->d_name[0] == '.')
				continue;

			start = strlcpy(device, sysfs_path, sizeof(device));
			strlcat(device, dent->d_name, sizeof(device));
			path_decode(&device[start]);
			device_list_insert(device);
		}
		closedir(dir);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	int failed = 0;
	int option;
	static const struct option options[] = {
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
			name_list_add(&filter_subsystem_match_list, optarg, 0);
			break;
		case 'S':
			name_list_add(&filter_subsystem_nomatch_list, optarg, 0);
			break;
		case 'a':
			name_list_add(&filter_attr_match_list, optarg, 0);
			break;
		case 'A':
			name_list_add(&filter_attr_nomatch_list, optarg, 0);
			break;
		case 'h':
			printf("Usage: udevtrigger OPTIONS\n"
			       "  --verbose                       print the list of devices while running\n"
			       "  --dry-run                       do not actually trigger the events\n"
			       "  --retry-failed                  trigger only the events which have been\n"
			       "                                  marked as failed during a previous run\n"
			       "  --subsystem-match=<subsystem>   trigger devices from a matching subystem\n"
			       "  --subsystem-nomatch=<subsystem> exclude devices from a matching subystem\n"
			       "  --attr-match=<file[=<value>]>   trigger devices with a matching sysfs\n"
			       "                                  attribute\n"
			       "  --attr-nomatch=<file[=<value>]> exclude devices with a matching sysfs\n"
			       "                                  attribute\n"
			       "  --help                          print this text\n"
			       "\n");
			goto exit;
		default:
			goto exit;
		}
	}

	if (failed)
		scan_failed();
	else {
		char base[PATH_SIZE];
		struct stat statbuf;

		/* if we have /sys/subsystem, forget all the old stuff */
		strlcpy(base, sysfs_path, sizeof(base));
		strlcat(base, "/subsystem", sizeof(base));
		if (stat(base, &statbuf) == 0)
			scan_subsystem("subsystem");
		else {
			scan_subsystem("bus");
			scan_class();

			/* scan "block" if it isn't a "class" */
			strlcpy(base, sysfs_path, sizeof(base));
			strlcat(base, "/class/block", sizeof(base));
			if (stat(base, &statbuf) != 0)
				scan_block();
		}
	}
	exec_list();

exit:
	name_list_cleanup(&filter_subsystem_match_list);
	name_list_cleanup(&filter_subsystem_nomatch_list);
	name_list_cleanup(&filter_attr_match_list);
	name_list_cleanup(&filter_attr_nomatch_list);

	sysfs_cleanup();
	logging_close();
	return 0;
}
