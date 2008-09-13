/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"

static size_t devpath_to_db_path(struct udev *udev, const char *devpath, char *filename, size_t len)
{
	size_t start;

	/* translate to location of db file */
	util_strlcpy(filename, udev_get_dev_path(udev), len);
	start = util_strlcat(filename, "/.udev/db/", len);
	util_strlcat(filename, devpath, len);
	return util_path_encode(&filename[start], len - start);
}

/* reverse mapping from the device file name to the devpath */
static int name_index(struct udev *udev, const char *devpath, const char *name, int add)
{
	char device[UTIL_PATH_SIZE];
	char filename[UTIL_PATH_SIZE * 2];
	size_t start;
	int fd;

	/* directory with device name */
	util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
	start = util_strlcat(filename, "/.udev/names/", sizeof(filename));
	util_strlcat(filename, name, sizeof(filename));
	util_path_encode(&filename[start], sizeof(filename) - start);
	/* entry with the devpath */
	util_strlcpy(device, devpath, sizeof(device));
	util_path_encode(device, sizeof(device));
	util_strlcat(filename, "/", sizeof(filename));
	util_strlcat(filename, device, sizeof(filename));

	if (add) {
		info(udev, "creating index: '%s'\n", filename);
		create_path(udev, filename);
		fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (fd > 0)
			close(fd);
	} else {
		info(udev, "removing index: '%s'\n", filename);
		unlink(filename);
		delete_path(udev, filename);
	}
	return 0;
}

int udev_db_get_devices_by_name(struct udev *udev, const char *name, struct list_head *name_list)
{
	char dirname[PATH_MAX];
	size_t start;
	DIR *dir;
	int rc = 0;

	util_strlcpy(dirname, udev_get_dev_path(udev), sizeof(dirname));
	start = util_strlcat(dirname, "/.udev/names/", sizeof(dirname));
	util_strlcat(dirname, name, sizeof(dirname));
	util_path_encode(&dirname[start], sizeof(dirname) - start);

	dir = opendir(dirname);
	if (dir == NULL) {
		info(udev, "no index directory '%s': %s\n", dirname, strerror(errno));
		rc = -1;
		goto out;
	}

	info(udev, "found index directory '%s'\n", dirname);
	while (1) {
		struct dirent *ent;
		char device[UTIL_PATH_SIZE];

		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;
		if (ent->d_name[0] == '.')
			continue;

		util_strlcpy(device, ent->d_name, sizeof(device));
		util_path_decode(device);
		name_list_add(udev, name_list, device, 0);
		rc++;
	}
	closedir(dir);
out:
	return rc;
}

int udev_db_rename(struct udev *udev, const char *devpath_old, const char *devpath)
{
	char filename[UTIL_PATH_SIZE];
	char filename_old[UTIL_PATH_SIZE];

	devpath_to_db_path(udev, devpath_old, filename_old, sizeof(filename_old));
	devpath_to_db_path(udev, devpath, filename, sizeof(filename));
	return rename(filename_old, filename);
}

int udev_db_add_device(struct udevice *udevice)
{
	char filename[UTIL_PATH_SIZE];

	if (udevice->test_run)
		return 0;

	devpath_to_db_path(udevice->udev, udevice->dev->devpath, filename, sizeof(filename));
	create_path(udevice->udev, filename);
	unlink(filename);

	/*
	 * don't waste tmpfs memory pages, if we don't have any data to store
	 * create fake db-file; store the node-name in a symlink target
	 */
	if (list_empty(&udevice->symlink_list) && list_empty(&udevice->env_list) &&
	    !udevice->partitions && !udevice->ignore_remove) {
		int ret;
		dbg(udevice->udev, "nothing interesting to store, create symlink\n");
		udev_selinux_setfscreatecon(udevice->udev, filename, S_IFLNK);
		ret = symlink(udevice->name, filename);
		udev_selinux_resetfscreatecon(udevice->udev);
		if (ret != 0) {
			err(udevice->udev, "unable to create db link '%s': %s\n", filename, strerror(errno));
			return -1;
		}
	} else {
		FILE *f;
		struct name_entry *name_loop;

		f = fopen(filename, "w");
		if (f == NULL) {
			err(udevice->udev, "unable to create db file '%s': %s\n", filename, strerror(errno));
			return -1;
		}
		dbg(udevice->udev, "storing data for device '%s' in '%s'\n", udevice->dev->devpath, filename);

		fprintf(f, "N:%s\n", udevice->name);
		list_for_each_entry(name_loop, &udevice->symlink_list, node) {
			fprintf(f, "S:%s\n", name_loop->name);
			/* add symlink-name to index */
			name_index(udevice->udev, udevice->dev->devpath, name_loop->name, 1);
		}
		fprintf(f, "M:%u:%u\n", major(udevice->devt), minor(udevice->devt));
		if (udevice->link_priority != 0)
			fprintf(f, "L:%u\n", udevice->link_priority);
		if (udevice->event_timeout >= 0)
			fprintf(f, "T:%u\n", udevice->event_timeout);
		if (udevice->partitions != 0)
			fprintf(f, "A:%u\n", udevice->partitions);
		if (udevice->ignore_remove)
			fprintf(f, "R:%u\n", udevice->ignore_remove);
		list_for_each_entry(name_loop, &udevice->env_list, node)
			fprintf(f, "E:%s\n", name_loop->name);
		fclose(f);
	}

	/* add name to index */
	name_index(udevice->udev, udevice->dev->devpath, udevice->name, 1);

	return 0;
}

int udev_db_get_device(struct udevice *udevice, const char *devpath)
{
	struct stat stats;
	char filename[UTIL_PATH_SIZE];
	char line[UTIL_PATH_SIZE];
	unsigned int maj, min;
	char *bufline;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;

	sysfs_device_set_values(udevice->udev, udevice->dev, devpath, NULL, NULL);
	devpath_to_db_path(udevice->udev, devpath, filename, sizeof(filename));

	if (lstat(filename, &stats) != 0) {
		info(udevice->udev, "no db file to read %s: %s\n", filename, strerror(errno));
		return -1;
	}
	if ((stats.st_mode & S_IFMT) == S_IFLNK) {
		char target[UTIL_NAME_SIZE];
		int target_len;

		info(udevice->udev, "found a symlink as db file\n");
		target_len = readlink(filename, target, sizeof(target));
		if (target_len > 0)
			target[target_len] = '\0';
		else {
			info(udevice->udev, "error reading db link %s: %s\n", filename, strerror(errno));
			return -1;
		}
		dbg(udevice->udev, "db link points to '%s'\n", target);
		util_strlcpy(udevice->name, target, sizeof(udevice->name));
		return 0;
	}

	if (file_map(filename, &buf, &bufsize) != 0) {
		info(udevice->udev, "error reading db file %s: %s\n", filename, strerror(errno));
		return -1;
	}

	cur = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;

		if (count > sizeof(line))
			count = sizeof(line);
		memcpy(line, &bufline[2], count-2);
		line[count-2] = '\0';

		switch(bufline[0]) {
		case 'N':
			util_strlcpy(udevice->name, line, sizeof(udevice->name));
			break;
		case 'M':
			sscanf(line, "%u:%u", &maj, &min);
			udevice->devt = makedev(maj, min);
			break;
		case 'S':
			name_list_add(udevice->udev, &udevice->symlink_list, line, 0);
			break;
		case 'L':
			udevice->link_priority = atoi(line);
			break;
		case 'T':
			udevice->event_timeout = atoi(line);
			break;
		case 'A':
			udevice->partitions = atoi(line);
			break;
		case 'R':
			udevice->ignore_remove = atoi(line);
			break;
		case 'E':
			name_list_add(udevice->udev, &udevice->env_list, line, 0);
			break;
		}
	}
	file_unmap(buf, bufsize);

	if (udevice->name[0] == '\0')
		return -1;

	return 0;
}

int udev_db_delete_device(struct udevice *udevice)
{
	char filename[UTIL_PATH_SIZE];
	struct name_entry *name_loop;

	if (udevice->test_run)
		return 0;

	devpath_to_db_path(udevice->udev, udevice->dev->devpath, filename, sizeof(filename));
	unlink(filename);

	name_index(udevice->udev, udevice->dev->devpath, udevice->name, 0);
	list_for_each_entry(name_loop, &udevice->symlink_list, node)
		name_index(udevice->udev, udevice->dev->devpath, name_loop->name, 0);

	return 0;
}
