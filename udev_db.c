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


static int devpath_to_db_path(const char *devpath, char *filename, size_t len)
{
	size_t start, end, i;

	/* add location of db files */
	strlcpy(filename, udev_root, len);
	start = strlcat(filename, "/"DB_DIR, len);
	end = strlcat(filename, devpath, len);
	if (end > len)
		end = len;

	/* replace '/' to transform path into a filename */
	for (i = start+1; i < end; i++)
		if (filename[i] == '/')
			filename[i] = PATH_TO_NAME_CHAR;

	return 0;
}

static int db_file_to_devpath(const char *filename, char *devpath, size_t len)
{
	size_t end, i;

	strlcpy(devpath, "/", len);
	end = strlcat(devpath, filename, len);

	/* replace PATH_TO_NAME_CHAR to transform name into devpath */
	for (i = 1; i < end; i++)
		if (devpath[i] == PATH_TO_NAME_CHAR)
			devpath[i] = '/';

	return 0;
}

int udev_db_add_device(struct udevice *udev)
{
	char filename[PATH_SIZE];

	if (udev->test_run)
		return 0;

	devpath_to_db_path(udev->dev->devpath, filename, sizeof(filename));
	create_path(filename);

	/*
	 * create only a symlink with the name as the target
	 * if we don't have any interesting data to remember
	 */
	if (list_empty(&udev->symlink_list) && list_empty(&udev->env_list) &&
	    !udev->partitions && !udev->ignore_remove) {
		dbg("nothing interesting to store, create symlink");
		unlink(filename);
		if (symlink(udev->name, filename) != 0) {
			err("unable to create db link '%s': %s", filename, strerror(errno));
			return -1;
		}
	} else {
		struct name_entry *name_loop;
		FILE *f;

		unlink(filename);
		f = fopen(filename, "w");
		if (f == NULL) {
			err("unable to create db file '%s': %s", filename, strerror(errno));
			return -1;
		}
		dbg("storing data for device '%s' in '%s'", udev->dev->devpath, filename);

		fprintf(f, "N:%s\n", udev->name);
		list_for_each_entry(name_loop, &udev->symlink_list, node)
			fprintf(f, "S:%s\n", name_loop->name);
		fprintf(f, "M:%u:%u\n", major(udev->devt), minor(udev->devt));
		if (udev->partitions)
			fprintf(f, "A:%u\n", udev->partitions);
		if (udev->ignore_remove)
			fprintf(f, "R:%u\n", udev->ignore_remove);
		list_for_each_entry(name_loop, &udev->env_list, node)
			fprintf(f, "E:%s\n", name_loop->name);
		fclose(f);
	}
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

	strlcpy(udev->dev->devpath, devpath, sizeof(udev->dev->devpath));
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

	devpath_to_db_path(udev->dev->devpath, filename, sizeof(filename));
	unlink(filename);

	return 0;
}

int udev_db_lookup_name(const char *name, char *devpath, size_t len)
{
	char dbpath[PATH_MAX];
	DIR *dir;
	int found = 0;

	strlcpy(dbpath, udev_root, sizeof(dbpath));
	strlcat(dbpath, "/"DB_DIR, sizeof(dbpath));
	dir = opendir(dbpath);
	if (dir == NULL) {
		info("no udev_db available '%s': %s", dbpath, strerror(errno));
		return -1;
	}

	while (!found) {
		struct dirent *ent;
		char filename[PATH_SIZE];
		char nodename[PATH_SIZE];
		struct stat stats;
		char *bufline;
		char *buf;
		size_t bufsize;
		size_t cur;
		size_t count;

		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;
		if (ent->d_name[0] == '.')
			continue;

		snprintf(filename, sizeof(filename), "%s/%s", dbpath, ent->d_name);
		filename[sizeof(filename)-1] = '\0';
		dbg("looking at '%s'", filename);

		if (lstat(filename, &stats) != 0) {
			info("unable to read %s: %s", filename, strerror(errno));
			continue;
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
			if (strcmp(name, target) == 0) {
				db_file_to_devpath(ent->d_name, devpath, len);
				found =1;
			}
			continue;
		}

		if (file_map(filename, &buf, &bufsize) != 0) {
			info("unable to read db file '%s': %s", filename, strerror(errno));
			continue;
		}

		cur = 0;
		while (cur < bufsize && !found) {
			count = buf_get_line(buf, bufsize, cur);
			bufline = &buf[cur];
			cur += count+1;

			switch(bufline[0]) {
			case 'N':
			case 'S':
				if (count > sizeof(nodename))
					count = sizeof(nodename);
				memcpy(nodename, &bufline[2], count-2);
				nodename[count-2] = '\0';
				dbg("compare '%s' '%s'", nodename, name);
				if (strcmp(nodename, name) == 0) {
					db_file_to_devpath(ent->d_name, devpath, len);
					found = 1;
				}
				break;
			default:
				continue;
			}
		}
		file_unmap(buf, bufsize);
	}

	closedir(dir);
	if (found)
		return 0;
	else
		return -1;
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
		char filename[PATH_SIZE] = "/";
		size_t end, i;

		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;
		if (ent->d_name[0] == '.')
			continue;

		end = strlcat(filename, ent->d_name, sizeof(filename));
		for (i = 1; i < end; i++)
			if (filename[i] == PATH_TO_NAME_CHAR)
				filename[i] = '/';
		name_list_add(name_list, filename, 1);
		dbg("added '%s'", filename);
	}

	closedir(dir);
	return 0;
}
