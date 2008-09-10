/*
 * libudev - interface to udev device information
 *
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"
#include "../udev.h"

static ssize_t get_sys_link(struct udev *udev, const char *slink, const char *devpath, char *subsystem, size_t size)
{
	char path[PATH_SIZE];
	ssize_t len;
	const char *pos;

	strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	strlcat(path, devpath, sizeof(path));
	strlcat(path, "/", sizeof(path));
	strlcat(path, slink, sizeof(path));
	len = readlink(path, path, sizeof(path));
	if (len < 0 || len >= (ssize_t) sizeof(path))
		return -1;
	path[len] = '\0';
	pos = strrchr(path, '/');
	if (pos == NULL)
		return -1;
	pos = &pos[1];
	return strlcpy(subsystem, pos, size);
}

ssize_t util_get_sys_subsystem(struct udev *udev, const char *devpath, char *subsystem, size_t size)
{
	return get_sys_link(udev, "subsystem", devpath, subsystem, size);
}

ssize_t util_get_sys_driver(struct udev *udev, const char *devpath, char *driver, size_t size)
{
	return get_sys_link(udev, "driver", devpath, driver, size);
}

int util_resolve_sys_link(struct udev *udev, char *devpath, size_t size)
{
	char link_path[PATH_SIZE];
	char link_target[PATH_SIZE];
	int len;
	int i;
	int back;

	strlcpy(link_path, udev_get_sys_path(udev), sizeof(link_path));
	strlcat(link_path, devpath, sizeof(link_path));
	len = readlink(link_path, link_target, sizeof(link_target));
	if (len <= 0)
		return -1;
	link_target[len] = '\0';
	dbg(udev, "path link '%s' points to '%s'\n", devpath, link_target);

	for (back = 0; strncmp(&link_target[back * 3], "../", 3) == 0; back++)
		;
	dbg(udev, "base '%s', tail '%s', back %i\n", devpath, &link_target[back * 3], back);
	for (i = 0; i <= back; i++) {
		char *pos = strrchr(devpath, '/');

		if (pos == NULL)
			return -1;
		pos[0] = '\0';
	}
	dbg(udev, "after moving back '%s'\n", devpath);
	strlcat(devpath, "/", size);
	strlcat(devpath, &link_target[back * 3], size);
	return 0;
}
