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
#include <sys/socket.h>
#include <sys/un.h>

#include "udev.h"
#include "udevd.h"
#include "udev_rules.h"

static int verbose;
static int dry_run;
LIST_HEAD(device_list);
LIST_HEAD(filter_subsystem_match_list);
LIST_HEAD(filter_subsystem_nomatch_list);
LIST_HEAD(filter_attr_match_list);
LIST_HEAD(filter_attr_nomatch_list);
static int sock = -1;
static struct sockaddr_un saddr;
static socklen_t saddrlen;

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

	dbg("add '%s'\n" , path);

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

static void trigger_uevent(const char *devpath, const char *action)
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
		dbg("error on opening %s: %s\n", filename, strerror(errno));
		return;
	}

	if (write(fd, action, strlen(action)) < 0)
		info("error writing '%s' to '%s': %s\n", action, filename, strerror(errno));

	close(fd);
}

static int pass_to_socket(const char *devpath, const char *action, const char *env)
{
	struct udevice *udev;
	struct name_entry *name_loop;
	char buf[4096];
	size_t bufpos = 0;
	ssize_t count;
	char path[PATH_SIZE];
	int fd;
	char link_target[PATH_SIZE];
	int len;
	int err = 0;

	if (verbose)
		printf("%s\n", devpath);

	udev = udev_device_init();
	if (udev == NULL)
		return -1;
	udev_db_get_device(udev, devpath);

	/* add header */
	bufpos = snprintf(buf, sizeof(buf)-1, "%s@%s", action, devpath);
	bufpos++;

	/* add cookie */
	if (env != NULL) {
		bufpos += snprintf(&buf[bufpos], sizeof(buf)-1, "%s", env);
		bufpos++;
	}

	/* add standard keys */
	bufpos += snprintf(&buf[bufpos], sizeof(buf)-1, "DEVPATH=%s", devpath);
	bufpos++;
	bufpos += snprintf(&buf[bufpos], sizeof(buf)-1, "ACTION=%s", action);
	bufpos++;

	/* add subsystem */
	strlcpy(path, sysfs_path, sizeof(path));
	strlcat(path, devpath, sizeof(path));
	strlcat(path, "/subsystem", sizeof(path));
	len = readlink(path, link_target, sizeof(link_target));
	if (len > 0) {
		char *pos;

		link_target[len] = '\0';
		pos = strrchr(link_target, '/');
		if (pos != NULL) {
			bufpos += snprintf(&buf[bufpos], sizeof(buf)-1, "SUBSYSTEM=%s", &pos[1]);
			bufpos++;
		}
	}

	/* add symlinks and node name */
	path[0] = '\0';
	list_for_each_entry(name_loop, &udev->symlink_list, node) {
		strlcat(path, udev_root, sizeof(path));
		strlcat(path, "/", sizeof(path));
		strlcat(path, name_loop->name, sizeof(path));
		strlcat(path, " ", sizeof(path));
	}
	remove_trailing_chars(path, ' ');
	if (path[0] != '\0') {
		bufpos += snprintf(&buf[bufpos], sizeof(buf)-1, "DEVLINKS=%s", path);
		bufpos++;
	}
	if (udev->name[0] != '\0') {
		strlcpy(path, udev_root, sizeof(path));
		strlcat(path, "/", sizeof(path));
		strlcat(path, udev->name, sizeof(path));
		bufpos += snprintf(&buf[bufpos], sizeof(buf)-1, "DEVNAME=%s", path);
		bufpos++;
	}

	/* add keys from device "uevent" file */
	strlcpy(path, sysfs_path, sizeof(path));
	strlcat(path, devpath, sizeof(path));
	strlcat(path, "/uevent", sizeof(path));
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		char value[4096];

		count = read(fd, value, sizeof(value));
		close(fd);
		if (count > 0) {
			char *key;

			value[count] = '\0';
			key = value;
			while (key[0] != '\0') {
				char *next;

				next = strchr(key, '\n');
				if (next == NULL)
					break;
				next[0] = '\0';
				bufpos += strlcpy(&buf[bufpos], key, sizeof(buf) - bufpos-1);
				bufpos++;
				key = &next[1];
			}
		}
	}

	/* add keys from database */
	list_for_each_entry(name_loop, &udev->env_list, node) {
		bufpos += strlcpy(&buf[bufpos], name_loop->name, sizeof(buf) - bufpos-1);
		bufpos++;
	}
	if (bufpos > sizeof(buf))
		bufpos = sizeof(buf);

	count = sendto(sock, &buf, bufpos, 0, (struct sockaddr *)&saddr, saddrlen);
	if (count < 0)
		err = -1;

	return err;
}

static void exec_list(const char *action, const char *env)
{
	struct name_entry *loop_device;
	struct name_entry *tmp_device;

	list_for_each_entry_safe(loop_device, tmp_device, &device_list, node) {
		if (delay_device(loop_device->name))
			continue;
		if (sock >= 0)
			pass_to_socket(loop_device->name, action, env);
		else
			trigger_uevent(loop_device->name, action);
		list_del(&loop_device->node);
		free(loop_device);
	}

	/* trigger remaining delayed devices */
	list_for_each_entry_safe(loop_device, tmp_device, &device_list, node) {
		if (sock >= 0)
			pass_to_socket(loop_device->name, action, env);
		else
			trigger_uevent(loop_device->name, action);
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

enum scan_type {
	SCAN_DEVICES,
	SCAN_SUBSYSTEM,
};

static void scan_subsystem(const char *subsys, enum scan_type scan)
{
	char base[PATH_SIZE];
	DIR *dir;
	struct dirent *dent;
	const char *subdir;

	if (scan == SCAN_DEVICES)
		subdir = "/devices";
	else if (scan == SCAN_SUBSYSTEM)
		subdir = "/drivers";
	else
		return;

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

			if (scan == SCAN_DEVICES)
				if (subsystem_filtered(dent->d_name))
					continue;

			strlcpy(dirname, base, sizeof(dirname));
			strlcat(dirname, "/", sizeof(dirname));
			strlcat(dirname, dent->d_name, sizeof(dirname));

			if (scan == SCAN_SUBSYSTEM) {
				if (attr_filtered(dirname))
					continue;
				if (!subsystem_filtered("subsystem"))
					device_list_insert(dirname);
				if (subsystem_filtered("drivers"))
					continue;
			}

			strlcat(dirname, subdir, sizeof(dirname));

			/* look for devices/drivers */
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
	strlcat(base, "/.udev/failed", sizeof(base));

	dir = opendir(base);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char device[PATH_SIZE];
			size_t start;

			if (dent->d_name[0] == '.')
				continue;

			start = strlcpy(device, sysfs_path, sizeof(device));
			if(start >= sizeof(device))
				start = sizeof(device) - 1;
			strlcat(device, dent->d_name, sizeof(device));
			path_decode(&device[start]);
			device_list_insert(device);
		}
		closedir(dir);
	}
}

int udevtrigger(int argc, char *argv[])
{
	int failed = 0;
	const char *sockpath = NULL;
	int option;
	const char *action = "add";
	const char *env = NULL;
	static const struct option options[] = {
		{ "verbose", 0, NULL, 'v' },
		{ "dry-run", 0, NULL, 'n' },
		{ "retry-failed", 0, NULL, 'F' },
		{ "socket", 1, NULL, 'o' },
		{ "help", 0, NULL, 'h' },
		{ "action", 1, NULL, 'c' },
		{ "subsystem-match", 1, NULL, 's' },
		{ "subsystem-nomatch", 1, NULL, 'S' },
		{ "attr-match", 1, NULL, 'a' },
		{ "attr-nomatch", 1, NULL, 'A' },
		{ "env", 1, NULL, 'e' },
		{}
	};

	logging_init("udevtrigger");
	udev_config_init();
	dbg("version %s\n", VERSION);
	sysfs_init();

	while (1) {
		option = getopt_long(argc, argv, "vnFo:hce::s:S:a:A:", options, NULL);
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
		case 'o':
			sockpath = optarg;
			break;
		case 'c':
			action = optarg;
			break;
		case 'e':
			if (strchr(optarg, '=') != NULL)
				env = optarg;
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
			printf("Usage: udevadm trigger OPTIONS\n"
			       "  --verbose                       print the list of devices while running\n"
			       "  --dry-run                       do not actually trigger the events\n"
			       "  --retry-failed                  trigger only the events which have been\n"
			       "                                  marked as failed during a previous run\n"
			       "  --socket=<socket path>          pass events to socket instead of triggering kernel events\n"
			       "  --env=<KEY>=<value>             pass an additional key (works only with --socket=)\n"
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

	if (sockpath != NULL) {
		struct stat stats;

		sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
		memset(&saddr, 0x00, sizeof(struct sockaddr_un));
		saddr.sun_family = AF_LOCAL;
		if (sockpath[0] == '@') {
			/* abstract namespace socket requested */
			strlcpy(&saddr.sun_path[1], &sockpath[1], sizeof(saddr.sun_path)-1);
			saddrlen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(&saddr.sun_path[1]);
		} else if (stat(sockpath, &stats) == 0 && S_ISSOCK(stats.st_mode)) {
			/* existing socket file */
			strlcpy(saddr.sun_path, sockpath, sizeof(saddr.sun_path));
			saddrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path);
		} else {
			/* no socket file, assume abstract namespace socket */
			strlcpy(&saddr.sun_path[1], sockpath, sizeof(saddr.sun_path)-1);
			saddrlen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(&saddr.sun_path[1]);
		}
	} else if (env != NULL) {
		fprintf(stderr, "error: --env= only valid with --socket= option\n");
		goto exit;
	}

	if (failed) {
		scan_failed();
		exec_list(action, env);
	} else {
		char base[PATH_SIZE];
		struct stat statbuf;

		/* if we have /sys/subsystem, forget all the old stuff */
		strlcpy(base, sysfs_path, sizeof(base));
		strlcat(base, "/subsystem", sizeof(base));
		if (stat(base, &statbuf) == 0) {
			scan_subsystem("subsystem", SCAN_SUBSYSTEM);
			exec_list(action, env);
			scan_subsystem("subsystem", SCAN_DEVICES);
			exec_list(action, env);
		} else {
			scan_subsystem("bus", SCAN_SUBSYSTEM);
			exec_list(action, env);
			scan_subsystem("bus", SCAN_DEVICES);
			scan_class();

			/* scan "block" if it isn't a "class" */
			strlcpy(base, sysfs_path, sizeof(base));
			strlcat(base, "/class/block", sizeof(base));
			if (stat(base, &statbuf) != 0)
				scan_block();
			exec_list(action, env);
		}
	}

exit:
	name_list_cleanup(&filter_subsystem_match_list);
	name_list_cleanup(&filter_subsystem_nomatch_list);
	name_list_cleanup(&filter_attr_match_list);
	name_list_cleanup(&filter_attr_nomatch_list);

	if (sock >= 0)
		close(sock);
	sysfs_cleanup();
	logging_close();
	return 0;
}
