/*
 * udev_db.c
 *
 * Userspace devfs
 *
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
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_utils.h"
#include "logging.h"
#include "udev_db.h"

#define PATH_TO_NAME_CHAR		'@'

static int get_db_filename(const char *devpath, char *filename, int len)
{
	char temp[SYSFS_PATH_MAX];
	char *pos;

	/* replace '/' to transform path into a filename */
	strfieldcpy(temp, devpath);
	pos = strchr(&temp[1], '/');
	while (pos) {
		pos[0] = PATH_TO_NAME_CHAR;
		pos = strchr(&pos[1], '/');
	}
	snprintf(filename, len, "%s%s", udev_db_path, temp);
	filename[len-1] = '\0';

	return 0;
}

int udev_db_add_device(struct udevice *udev)
{
	char filename[SYSFS_PATH_MAX];
	struct name_entry *name_loop;
	FILE *f;

	if (udev->test_run)
		return 0;

	get_db_filename(udev->devpath, filename, SYSFS_PATH_MAX);

	create_path(filename);

	f = fopen(filename, "w");
	if (f == NULL) {
		dbg("unable to create db file '%s'", filename);
		return -1;
	}
	dbg("storing data for device '%s' in '%s'", udev->devpath, filename);

	fprintf(f, "P:%s\n", udev->devpath);
	fprintf(f, "N:%s\n", udev->name);
	list_for_each_entry(name_loop, &udev->symlink_list, node)
		fprintf(f, "S:%s\n", name_loop->name);
	fprintf(f, "M:%u:%u\n", major(udev->devt), minor(udev->devt));
	fprintf(f, "A:%u\n", udev->partitions);
	fprintf(f, "R:%u\n", udev->ignore_remove);

	fclose(f);

	return 0;
}

static int parse_db_file(struct udevice *udev, const char *filename)
{
	char line[NAME_SIZE];
	char temp[NAME_SIZE];
	unsigned int major, minor;
	char *bufline;
	char *buf;
	size_t bufsize;
	size_t cur;
	size_t count;

	if (file_map(filename, &buf, &bufsize) != 0) {
		dbg("unable to read db file '%s'", filename);
		return -1;
	}

	cur = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;

		switch(bufline[0]) {
		case 'P':
			if (count > DEVPATH_SIZE)
				count = DEVPATH_SIZE-1;
			strncpy(udev->devpath, &bufline[2], count-2);
			udev->devpath[count-2] = '\0';
			break;
		case 'N':
			if (count > NAME_SIZE)
				count = NAME_SIZE-1;
			strncpy(udev->name, &bufline[2], count-2);
			udev->name[count-2] = '\0';
			break;
		case 'M':
			if (count > NAME_SIZE)
				count = NAME_SIZE-1;
			strncpy(temp, &bufline[2], count-2);
			temp[count-2] = '\0';
			sscanf(temp, "%u:%u", &major, &minor);
			udev->devt = makedev(major, minor);
			break;
		case 'S':
			if (count > NAME_SIZE)
				count = NAME_SIZE-1;
			strncpy(temp, &bufline[2], count-2);
			temp[count-2] = '\0';
			name_list_add(&udev->symlink_list, temp, 0);
			break;
		case 'A':
			if (count > NAME_SIZE)
				count = NAME_SIZE-1;
			strncpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			udev->partitions = atoi(line);
			break;
		case 'R':
			if (count > NAME_SIZE)
				count = NAME_SIZE-1;
			strncpy(line, &bufline[2], count-2);
			line[count-2] = '\0';
			udev->ignore_remove = atoi(line);
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
	char filename[SYSFS_PATH_MAX];

	get_db_filename(udev->devpath, filename, SYSFS_PATH_MAX);
	unlink(filename);

	return 0;
}

int udev_db_get_device(struct udevice *udev, const char *devpath)
{
	char filename[SYSFS_PATH_MAX];

	get_db_filename(devpath, filename, SYSFS_PATH_MAX);

	if (parse_db_file(udev, filename) != 0)
		return -1;

	return 0;
}

int udev_db_search_name(char *devpath, size_t len, const char *name)
{
	struct dirent *ent;
	DIR *dir;
	char filename[NAME_SIZE];

	dir = opendir(udev_db_path);
	if (dir == NULL) {
		dbg("unable to udev db '%s'", udev_db_path);
		return -1;
	}

	while (1) {
		char path[DEVPATH_SIZE];
		char nodename[NAME_SIZE];
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

		snprintf(filename, NAME_SIZE, "%s/%s", udev_db_path, ent->d_name);
		filename[NAME_SIZE-1] = '\0';
		dbg("looking at '%s'", filename);

		if (file_map(filename, &buf, &bufsize) != 0) {
			dbg("unable to read db file '%s'", filename);
			continue;
		}

		cur = 0;
		while (cur < bufsize) {
			count = buf_get_line(buf, bufsize, cur);
			bufline = &buf[cur];
			cur += count+1;

			switch(bufline[0]) {
			case 'P':
				if (count > DEVPATH_SIZE)
					count = DEVPATH_SIZE-1;
				strncpy(path, &bufline[2], count-2);
				path[count-2] = '\0';
				break;
			case 'N':
			case 'S':
				if (count > NAME_SIZE)
				count = NAME_SIZE-1;
				strncpy(nodename, &bufline[2], count-2);
				nodename[count-2] = '\0';
				dbg("compare '%s' '%s'", nodename, name);
				if (strcmp(nodename, name) == 0) {
					strncpy(devpath, path, len);
					devpath[len] = '\0';
					file_unmap(buf, bufsize);
					closedir(dir);
					return 0;
				}
				break;
			default:
				continue;
			}
		}
		file_unmap(buf, bufsize);
	}

	closedir(dir);
	return -1;
}

int udev_db_call_foreach(int (*handler_function)(struct udevice *udev))
{
	struct dirent *ent;
	DIR *dir;
	char filename[NAME_SIZE];
	struct udevice db_udev;

	dir = opendir(udev_db_path);
	if (dir == NULL) {
		dbg("unable to udev db '%s'", udev_db_path);
		return -1;
	}

	while (1) {
		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;

		if (ent->d_name[0] == '.')
			continue;

		snprintf(filename, NAME_SIZE, "%s/%s", udev_db_path, ent->d_name);
		filename[NAME_SIZE-1] = '\0';

		dbg("found '%s'", filename);

		udev_init_device(&db_udev, NULL, NULL);
		if (parse_db_file(&db_udev, filename) == 0) {
			if (handler_function(&db_udev) != 0)
				break;
		}
	}

	closedir(dir);
	return 0;
}
