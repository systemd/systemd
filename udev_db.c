/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
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


static size_t devpath_to_db_path(const char *devpath, char *filename, size_t len)
{
	size_t start;

	/* add location of db files */
	strlcpy(filename, udev_root, len);
	start = strlcat(filename, "/"DB_DIR"/", len);
	strlcat(filename, devpath, len);
	return path_encode(&filename[start], len - start);
}

/* reverse mapping from the device file name to the devpath */
static int name_index(const char *devpath, const char *name, int add)
{
	char device[PATH_SIZE];
	char filename[PATH_SIZE * 2];
	size_t start;
	int fd;

	/* directory with device name */
	strlcpy(filename, udev_root, sizeof(filename));
	start = strlcat(filename, "/"DB_NAME_INDEX_DIR"/", sizeof(filename));
	strlcat(filename, name, sizeof(filename));
	path_encode(&filename[start], sizeof(filename) - start);
	/* entry with the devpath */
	strlcpy(device, devpath, sizeof(device));
	path_encode(device, sizeof(device));
	strlcat(filename, "/", sizeof(filename));
	strlcat(filename, device, sizeof(filename));

	if (add) {
		info("creating index: '%s'", filename);
		create_path(filename);
		fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (fd > 0)
			close(fd);
	} else {
		info("removing index: '%s'", filename);
		unlink(filename);
		delete_path(filename);
	}
	return 0;
}

int udev_db_get_devices_by_name(const char *name, struct list_head *name_list)
{
	char dirname[PATH_MAX];
	size_t start;
	DIR *dir;
	int rc = 0;

	strlcpy(dirname, udev_root, sizeof(dirname));
	start = strlcat(dirname, "/"DB_NAME_INDEX_DIR"/", sizeof(dirname));
	strlcat(dirname, name, sizeof(dirname));
	path_encode(&dirname[start], sizeof(dirname) - start);

	dir = opendir(dirname);
	if (dir == NULL) {
		info("no index directory '%s': %s", dirname, strerror(errno));
		rc = -1;
		goto out;
	}

	info("found index directory '%s'", dirname);
	while (1) {
		struct dirent *ent;
		char device[PATH_SIZE];

		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;
		if (ent->d_name[0] == '.')
			continue;

		strlcpy(device, ent->d_name, sizeof(device));
		path_decode(device);
		name_list_add(name_list, device, 0);
		rc++;
	}
	closedir(dir);
out:
	return rc;
}

int udev_db_add_device(struct udevice *udev)
{
	char filename[PATH_SIZE];

	if (udev->test_run)
		return 0;

	devpath_to_db_path(udev->dev->devpath, filename, sizeof(filename));
	create_path(filename);
	unlink(filename);

	/*
	 * don't waste tmpfs memory pages, if we don't have any data to store
	 * create fake db-file; store the node-name in a symlink target
	 */
	if (list_empty(&udev->symlink_list) && list_empty(&udev->env_list) &&
	    !udev->partitions && !udev->ignore_remove) {
		dbg("nothing interesting to store, create symlink");
		if (symlink(udev->name, filename) != 0) {
			err("unable to create db link '%s': %s", filename, strerror(errno));
			return -1;
		}
	} else {
		FILE *f;
		struct name_entry *name_loop;

		f = fopen(filename, "w");
		if (f == NULL) {
			err("unable to create db file '%s': %s", filename, strerror(errno));
			return -1;
		}
		dbg("storing data for device '%s' in '%s'", udev->dev->devpath, filename);

		fprintf(f, "N:%s\n", udev->name);
		list_for_each_entry(name_loop, &udev->symlink_list, node) {
			fprintf(f, "S:%s\n", name_loop->name);
			/* add symlink-name to index */
			name_index(udev->dev->devpath, name_loop->name, 1);
		}
		fprintf(f, "M:%u:%u\n", major(udev->devt), minor(udev->devt));
		if (udev->link_priority != 0)
			fprintf(f, "L:%u\n", udev->link_priority);
		if (udev->partitions != 0)
			fprintf(f, "A:%u\n", udev->partitions);
		if (udev->ignore_remove)
			fprintf(f, "R:%u\n", udev->ignore_remove);
		list_for_each_entry(name_loop, &udev->env_list, node)
			fprintf(f, "E:%s\n", name_loop->name);
		fclose(f);
	}

	/* add name to index */
	name_index(udev->dev->devpath, udev->name, 1);

	return 0;
}

int udev_db_get_device(struct udevice *udev, const char *devpath)
{
	struct stat stats;
	char filename[PATH_SIZE];
	char line[PATH_SIZE];
	unsigned int maj, min;
	char *bufline;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;

	sysfs_device_set_values(udev->dev, devpath, NULL, NULL);
	devpath_to_db_path(devpath, filename, sizeof(filename));

	if (lstat(filename, &stats) != 0) {
		info("no db file to read %s: %s", filename, strerror(errno));
		return -1;
	}
	if ((stats.st_mode & S_IFMT) == S_IFLNK) {
		char target[NAME_SIZE];
		int target_len;

		info("found a symlink as db file");
		target_len = readlink(filename, target, sizeof(target));
		if (target_len > 0)
			target[target_len] = '\0';
		else {
			info("error reading db link %s: %s", filename, strerror(errno));
			return -1;
		}
		dbg("db link points to '%s'", target);
		strlcpy(udev->name, target, sizeof(udev->name));
		return 0;
	}

	if (file_map(filename, &buf, &bufsize) != 0) {
		info("error reading db file %s: %s", filename, strerror(errno));
		return -1;
	}

	cur = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;

		switch(bufline[0]) {
		case 'N':
			if (count > sizeof(udev->name))
				count = sizeof(udev->name);
			memcpy(udev->name, &bufline[2], count-2);
			udev->name[count-2] = '\0';
			break;
		case 'M':
			if (count > sizeof(line))
				count = sizeof(line);
			memcpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			sscanf(line, "%u:%u", &maj, &min);
			udev->devt = makedev(maj, min);
			break;
		case 'S':
			if (count > sizeof(line))
				count =  sizeof(line);
			memcpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			name_list_add(&udev->symlink_list, line, 0);
			break;
		case 'L':
			if (count > sizeof(line))
				count =  sizeof(line);
			memcpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			udev->link_priority = atoi(line);
			break;
		case 'A':
			if (count > sizeof(line))
				count =  sizeof(line);
			memcpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			udev->partitions = atoi(line);
			break;
		case 'R':
			if (count > sizeof(line))
				count =  sizeof(line);
			memcpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			udev->ignore_remove = atoi(line);
			break;
		case 'E':
			if (count > sizeof(line))
				count =  sizeof(line);
			memcpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			name_list_add(&udev->env_list, line, 0);
			break;
		}
	}
	file_unmap(buf, bufsize);

	if (udev->name[0] == '\0')
		return -1;

	return 0;
}

int udev_db_delete_device(struct udevice *udev)
{
	char filename[PATH_SIZE];
	struct name_entry *name_loop;

	if (udev->test_run)
		return 0;

	devpath_to_db_path(udev->dev->devpath, filename, sizeof(filename));
	unlink(filename);

	name_index(udev->dev->devpath, udev->name, 0);
	list_for_each_entry(name_loop, &udev->symlink_list, node)
		name_index(udev->dev->devpath, name_loop->name, 0);

	return 0;
}

int udev_db_get_all_entries(struct list_head *name_list)
{
	char dbpath[PATH_MAX];
	DIR *dir;

	strlcpy(dbpath, udev_root, sizeof(dbpath));
	strlcat(dbpath, "/"DB_DIR, sizeof(dbpath));
	dir = opendir(dbpath);
	if (dir == NULL) {
		info("no udev_db available '%s': %s", dbpath, strerror(errno));
		return -1;
	}

	while (1) {
		struct dirent *ent;
		char device[PATH_SIZE];

		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;
		if (ent->d_name[0] == '.')
			continue;

		strlcpy(device, ent->d_name, sizeof(device));
		path_decode(device);
		name_list_add(name_list, device, 1);
		dbg("added '%s'", device);
	}

	closedir(dir);
	return 0;
}
