/*
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
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
#include <sys/stat.h>

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

int udev_device_update_db(struct udev_device *udev_device)
{
	struct udev *udev = udev_device_get_udev(udev_device);
	char filename[UTIL_PATH_SIZE];
	FILE *f;
	char target[232]; /* on 64bit, tmpfs inlines up to 239 bytes */
	size_t devlen = strlen(udev_get_dev_path(udev))+1;
	struct udev_list_entry *list_entry;
	int ret;

	devpath_to_db_path(udev,
			   udev_device_get_devpath(udev_device),
			   filename, sizeof(filename));
	create_path(udev, filename);
	unlink(filename);

	udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device))
		if (udev_list_entry_get_flag(list_entry))
			goto file;
	if (udev_device_get_num_fake_partitions(udev_device))
		goto file;
	if (udev_device_get_ignore_remove(udev_device))
		goto file;
	/* try not to waste tmpfs memory; store values, if they fit, in a symlink target */
	util_strlcpy(target, &udev_device_get_devnode(udev_device)[devlen], sizeof(target));
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(udev_device)) {
		size_t len;

		util_strlcat(target, " ", sizeof(target));
		len = util_strlcat(target, &udev_list_entry_get_name(list_entry)[devlen], sizeof(target));
		if (len >= sizeof(target)) {
			info(udev, "size of links too large, create file\n");
			goto file;
		}
	}
	info(udev, "create db link (%s)\n", target);
	udev_selinux_setfscreatecon(udev, filename, S_IFLNK);
	ret = symlink(target, filename);
	udev_selinux_resetfscreatecon(udev);
	if (ret == 0)
		goto out;
file:
	f = fopen(filename, "w");
	if (f == NULL) {
		err(udev, "unable to create db file '%s': %m\n", filename);
		return -1;
		}
	info(udev, "created db file for '%s' in '%s'\n", udev_device_get_devpath(udev_device), filename);

	fprintf(f, "N:%s\n", &udev_device_get_devnode(udev_device)[devlen]);
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(udev_device))
		fprintf(f, "S:%s\n", &udev_list_entry_get_name(list_entry)[devlen]);
	if (udev_device_get_devlink_priority(udev_device) != 0)
		fprintf(f, "L:%u\n", udev_device_get_devlink_priority(udev_device));
	if (udev_device_get_event_timeout(udev_device) >= 0)
		fprintf(f, "T:%u\n", udev_device_get_event_timeout(udev_device));
	if (udev_device_get_num_fake_partitions(udev_device) != 0)
		fprintf(f, "A:%u\n", udev_device_get_num_fake_partitions(udev_device));
	if (udev_device_get_ignore_remove(udev_device))
		fprintf(f, "R:%u\n", udev_device_get_ignore_remove(udev_device));
	udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(udev_device)) {
		if (!udev_list_entry_get_flag(list_entry))
			continue;
		fprintf(f, "E:%s=%s\n",
			udev_list_entry_get_name(list_entry),
			udev_list_entry_get_value(list_entry));
	}
	fclose(f);
out:
	return 0;
}

int udev_device_delete_db(struct udev_device *udev_device)
{
	char filename[UTIL_PATH_SIZE];

	devpath_to_db_path(udev_device_get_udev(udev_device),
			   udev_device_get_devpath(udev_device),
			   filename, sizeof(filename));
	unlink(filename);
	return 0;
}

int udev_device_rename_db(struct udev_device *udev_device, const char *devpath_old)
{
	char filename_old[UTIL_PATH_SIZE];
	char filename[UTIL_PATH_SIZE];

	devpath_to_db_path(udev_device_get_udev(udev_device),
			   devpath_old,
			   filename_old, sizeof(filename_old));
	devpath_to_db_path(udev_device_get_udev(udev_device),
			   udev_device_get_devpath(udev_device),
			   filename, sizeof(filename));
	return rename(filename_old, filename);
}
