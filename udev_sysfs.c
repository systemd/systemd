/*
 * udev_sysfs.c - sysfs access
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include "udev.h"

char sysfs_path[PATH_SIZE];

/* device cache */
static LIST_HEAD(dev_list);

/* attribute value cache */
static LIST_HEAD(attr_list);
struct sysfs_attr {
	struct list_head node;
	char path[PATH_SIZE];
	char value[NAME_SIZE];
};

int sysfs_init(void)
{
	const char *env;

	env = getenv("SYSFS_PATH");
	if (env) {
		strlcpy(sysfs_path, env, sizeof(sysfs_path));
		remove_trailing_chars(sysfs_path, '/');
	} else
		strlcpy(sysfs_path, "/sys", sizeof(sysfs_path));
	dbg("sysfs_path='%s'", sysfs_path);

	INIT_LIST_HEAD(&dev_list);
	INIT_LIST_HEAD(&attr_list);
	return 0;
}

void sysfs_cleanup(void)
{
	struct sysfs_attr *attr_loop;
	struct sysfs_attr *attr_temp;
	struct sysfs_device *dev_loop;
	struct sysfs_device *dev_temp;

	list_for_each_entry_safe(attr_loop, attr_temp, &attr_list, node) {
		list_del(&attr_loop->node);
		free(attr_loop);
	}

	list_for_each_entry_safe(dev_loop, dev_temp, &dev_list, node) {
		list_del(&dev_loop->node);
		free(dev_loop);
	}
}

void sysfs_device_set_values(struct sysfs_device *dev, const char *devpath, const char *subsystem)
{
	char *pos;

	strlcpy(dev->devpath, devpath, sizeof(dev->devpath));
	if (subsystem != NULL)
		strlcpy(dev->subsystem, subsystem, sizeof(dev->subsystem));

	/* set kernel name */
	pos = strrchr(dev->devpath, '/');
	if (pos == NULL)
		return;

	strlcpy(dev->kernel_name, &pos[1], sizeof(dev->kernel_name));
	dbg("kernel_name='%s'", dev->kernel_name);

	/* some devices have '!' in their name, change that to '/' */
	pos = dev->kernel_name;
	while (pos[0] != '\0') {
		if (pos[0] == '!')
			pos[0] = '/';
		pos++;
	}

	/* get kernel number */
	pos = &dev->kernel_name[strlen(dev->kernel_name)];
	while (isdigit(pos[-1]))
		pos--;
	strlcpy(dev->kernel_number, pos, sizeof(dev->kernel_number));
	dbg("kernel_number='%s'", dev->kernel_number);
}

struct sysfs_device *sysfs_device_get(const char *devpath)
{
	char path[PATH_SIZE];
	char devpath_real[PATH_SIZE];
	struct sysfs_device *dev;
	struct sysfs_device *dev_loop;
	struct stat statbuf;
	char link_path[PATH_SIZE];
	char link_target[PATH_SIZE];
	int len;
	char *pos;

	dbg("open '%s'", devpath);
	strlcpy(devpath_real, devpath, sizeof(devpath_real));
	remove_trailing_chars(devpath_real, '/');

	strlcpy(path, sysfs_path, sizeof(path));
	strlcat(path, devpath_real, sizeof(path));
	if (lstat(path, &statbuf) != 0) {
		dbg("stat '%s' failed: %s", path, strerror(errno));
		return NULL;
	}

	/* if we got a link, resolve it to the real device */
	if (S_ISLNK(statbuf.st_mode)) {
		int i;
		int back;

		len = readlink(path, link_target, sizeof(link_target));
		if (len <= 0)
			return NULL;
		link_target[len] = '\0';
		dbg("devpath link '%s' points to '%s'", path, link_target);

		for (back = 0; strncmp(&link_target[back * 3], "../", 3) == 0; back++)
			;
		dbg("base '%s', tail '%s', back %i", devpath_real, &link_target[back * 3], back);
		for (i = 0; i <= back; i++) {
			pos = strrchr(devpath_real, '/');
			if (pos == NULL)
				return NULL;
			pos[0] = '\0';
		}
		dbg("after moving back '%s'", devpath_real);
		strlcat(devpath_real, "/", sizeof(devpath_real));
		strlcat(devpath_real, &link_target[back * 3], sizeof(devpath_real));
	}

	/* look for device in cache */
	list_for_each_entry(dev_loop, &dev_list, node) {
		if (strcmp(dev_loop->devpath, devpath_real) == 0) {
			dbg("found in cache '%s'", dev_loop->devpath);
			return dev_loop;
		}
	}

	/* new device */
	dbg("'%s'", devpath_real);
	dev = malloc(sizeof(struct sysfs_device));
	if (dev == NULL)
		return NULL;
	memset(dev, 0x00, sizeof(struct sysfs_device));

	sysfs_device_set_values(dev, devpath_real, NULL);

	/* get subsystem */
	if (strncmp(dev->devpath, "/class/", 7) == 0) {
		strlcpy(dev->subsystem, &dev->devpath[7], sizeof(dev->subsystem));
		pos = strchr(dev->subsystem, '/');
		if (pos != NULL)
			pos[0] = '\0';
		else
			dev->subsystem[0] = '\0';
	} else if (strncmp(dev->devpath, "/block/", 7) == 0) {
		strlcpy(dev->subsystem, "block", sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/devices/", 9) == 0) {
		/* get subsystem from "bus" link */
		strlcpy(link_path, sysfs_path, sizeof(link_path));
		strlcat(link_path, dev->devpath, sizeof(link_path));
		strlcat(link_path, "/bus", sizeof(link_path));
		len = readlink(link_path, link_target, sizeof(link_target));
		if (len > 0) {
			link_target[len] = '\0';
			dbg("bus link '%s' points to '%s'", link_path, link_target);
			pos = strrchr(link_target, '/');
			if (pos != NULL)
				strlcpy(dev->subsystem, &pos[1], sizeof(dev->subsystem));
		} else {
			/* get subsystem from "subsystem" link */
			strlcpy(link_path, sysfs_path, sizeof(link_path));
			strlcat(link_path, dev->devpath, sizeof(link_path));
			strlcat(link_path, "/subsystem", sizeof(link_path));
			len = readlink(link_path, link_target, sizeof(link_target));
			if (len > 0) {
				link_target[len] = '\0';
				dbg("subsystem link '%s' points to '%s'", link_path, link_target);
				pos = strrchr(link_target, '/');
				if (pos != NULL)
					strlcpy(dev->subsystem, &pos[1], sizeof(dev->subsystem));
			}
		}
		/* get driver name */
		strlcpy(link_path, sysfs_path, sizeof(link_path));
		strlcat(link_path, dev->devpath, sizeof(link_path));
		strlcat(link_path, "/driver", sizeof(link_path));
		len = readlink(link_path, link_target, sizeof(link_target));
		if (len > 0) {
			link_target[len] = '\0';
			dbg("driver link '%s' points to '%s'", link_path, link_target);
			pos = strrchr(link_target, '/');
			if (pos != NULL)
				strlcpy(dev->driver, &pos[1], sizeof(dev->driver));
		}
	} else if (strncmp(dev->devpath, "/bus/", 5) == 0 && strstr(dev->devpath, "/drivers/")) {
		strlcpy(dev->subsystem, "drivers", sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/module/", 8) == 0) {
		strlcpy(dev->subsystem, "module", sizeof(dev->subsystem));
	}

	dbg("add to cache 'devpath=%s', subsystem='%s', driver='%s'", dev->devpath, dev->subsystem, dev->driver);
	list_add(&dev->node, &dev_list);

	return dev;
}

struct sysfs_device *sysfs_device_get_parent(struct sysfs_device *dev)
{
	char parent_devpath[PATH_SIZE];
	char device_link[PATH_SIZE];
	char device_link_target[PATH_SIZE];
	char *pos;
	int i;
	int len;
	int back;

	/* requesting a parent is only valid for devices */
	if ((strncmp(dev->devpath, "/devices/", 9) != 0) &&
	    (strncmp(dev->devpath, "/class/", 7) != 0) &&
	    (strncmp(dev->devpath, "/block/", 7) != 0))
		return NULL;

	strlcpy(parent_devpath, dev->devpath, sizeof(parent_devpath));
	dbg("'%s'", parent_devpath);

	/* strip last element */
	pos = strrchr(parent_devpath, '/');
	if (pos == NULL || pos == parent_devpath)
		return NULL;
	pos[0] = '\0';

	/* are we at the top level */
	if (strcmp(parent_devpath, "/devices") == 0) {
		dbg("/devices top level");
		return NULL;
	}

	/* at the top level we may follow the "device" link */
	if (strcmp(parent_devpath, "/block") == 0) {
		dbg("/block top level, look for device link");
		goto device_link;
	}

	if (strncmp(parent_devpath, "/class", 6) == 0) {
		pos = strrchr(parent_devpath, '/');
		if (pos == &parent_devpath[6] || pos == parent_devpath) {
			dbg("class top level, look for device link");
			goto device_link;
		}
	}
	return sysfs_device_get(parent_devpath);

device_link:
	strlcpy(device_link, sysfs_path, sizeof(device_link));
	strlcat(device_link, dev->devpath, sizeof(device_link));
	strlcat(device_link, "/device", sizeof(device_link));
	len = readlink(device_link, device_link_target, sizeof(device_link_target));
	if (len < 0)
		return NULL;
	device_link_target[len] = '\0';
	dbg("device link '%s' points to '%s'", device_link, device_link_target);

	for (back = 0; strncmp(&device_link_target[back * 3], "../", 3) == 0; back++)
		;
	strlcpy(parent_devpath, dev->devpath, sizeof(parent_devpath));
	dbg("base='%s', tail='%s', back=%i", parent_devpath, &device_link_target[back * 3], back);
	for (i = 0; i < back; i++) {
		pos = strrchr(parent_devpath, '/');
		if (pos == NULL)
			return NULL;
		pos[0] = '\0';
	}
	dbg("after moving back '%s'", parent_devpath);
	strlcat(parent_devpath, "/", sizeof(parent_devpath));
	strlcat(parent_devpath, &device_link_target[back * 3], sizeof(parent_devpath));
	return sysfs_device_get(parent_devpath);
}

struct sysfs_device *sysfs_device_get_parent_with_subsystem(struct sysfs_device *dev, const char *subsystem)
{
	struct sysfs_device *dev_parent;

	dev_parent = sysfs_device_get_parent(dev);
	while (dev_parent != NULL) {
		if (strcmp(dev_parent->subsystem, subsystem) == 0)
			return dev_parent;
		dev_parent = sysfs_device_get_parent(dev_parent);
	}
	return NULL;
}

char *sysfs_attr_get_value(const char *devpath, const char *attr_name)
{
	char path_full[PATH_SIZE];
	const char *path;
	char value[NAME_SIZE];
	struct sysfs_attr *attr_loop;
	struct sysfs_attr *attr;
	int fd;
	ssize_t size;
	size_t sysfs_len;

	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	path = &path_full[sysfs_len];
	strlcat(path_full, devpath, sizeof(path_full));
	strlcat(path_full, "/", sizeof(path_full));
	strlcat(path_full, attr_name, sizeof(path_full));

	/* look for attribute in cache */
	list_for_each_entry(attr_loop, &attr_list, node) {
		if (strcmp(attr_loop->path, path) == 0) {
			dbg("found in cache '%s'", attr_loop->path);
			return attr_loop->value;
		}
	}

	/* read attribute value */
	fd = open(path_full, O_RDONLY);
	if (fd < 0)
		return NULL;
	size = read(fd, value, sizeof(value));
	close(fd);
	if (size < 0)
		return NULL;
	if (size == sizeof(value))
		return NULL;
	value[size] = '\0';
	remove_trailing_chars(value, '\n');

	/* store attribute in cache */
	attr = malloc(sizeof(struct sysfs_attr));
	if (attr == NULL)
		return NULL;
	strlcpy(attr->path, path, sizeof(attr->path));
	strlcpy(attr->value, value, sizeof(attr->value));
	dbg("add to cache '%s' '%s'", attr->path, attr->value);
	list_add(&attr->node, &attr_list);

	return attr->value;
}
