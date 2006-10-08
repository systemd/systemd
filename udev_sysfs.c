/*
 * Copyright (C) 2005-2006 Kay Sievers <kay.sievers@vrfy.org>
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
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#include "udev.h"

char sysfs_path[PATH_SIZE];

/* device cache */
static LIST_HEAD(dev_list);

/* attribute value cache */
static LIST_HEAD(attr_list);
struct sysfs_attr {
	struct list_head node;
	char path[PATH_SIZE];
	char *value;			/* points to value_local if value is cached */
	char value_local[NAME_SIZE];
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

void sysfs_device_set_values(struct sysfs_device *dev, const char *devpath,
			     const char *subsystem, const char *driver)
{
	char *pos;

	strlcpy(dev->devpath, devpath, sizeof(dev->devpath));
	if (subsystem != NULL)
		strlcpy(dev->subsystem, subsystem, sizeof(dev->subsystem));
	if (driver != NULL)
		strlcpy(dev->driver, driver, sizeof(dev->driver));

	/* set kernel name */
	pos = strrchr(dev->devpath, '/');
	if (pos == NULL)
		return;

	strlcpy(dev->kernel, &pos[1], sizeof(dev->kernel));
	dbg("kernel='%s'", dev->kernel);

	/* some devices have '!' in their name, change that to '/' */
	pos = dev->kernel;
	while (pos[0] != '\0') {
		if (pos[0] == '!')
			pos[0] = '/';
		pos++;
	}

	/* get kernel number */
	pos = &dev->kernel[strlen(dev->kernel)];
	while (isdigit(pos[-1]))
		pos--;
	strlcpy(dev->kernel_number, pos, sizeof(dev->kernel_number));
	dbg("kernel_number='%s'", dev->kernel_number);
}

int sysfs_resolve_link(char *devpath, size_t size)
{
	char link_path[PATH_SIZE];
	char link_target[PATH_SIZE];
	int len;
	int i;
	int back;

	strlcpy(link_path, sysfs_path, sizeof(link_path));
	strlcat(link_path, devpath, sizeof(link_path));
	len = readlink(link_path, link_target, sizeof(link_target));
	if (len <= 0)
		return -1;
	link_target[len] = '\0';
	dbg("path link '%s' points to '%s'", devpath, link_target);

	for (back = 0; strncmp(&link_target[back * 3], "../", 3) == 0; back++)
		;
	dbg("base '%s', tail '%s', back %i", devpath, &link_target[back * 3], back);
	for (i = 0; i <= back; i++) {
		char *pos = strrchr(devpath, '/');

		if (pos == NULL)
			return -1;
		pos[0] = '\0';
	}
	dbg("after moving back '%s'", devpath);
	strlcat(devpath, "/", size);
	strlcat(devpath, &link_target[back * 3], size);
	return 0;
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

	/* look for device already in cache (we never put an untranslated path in the cache) */
	list_for_each_entry(dev_loop, &dev_list, node) {
		if (strcmp(dev_loop->devpath, devpath_real) == 0) {
			dbg("found in cache '%s'", dev_loop->devpath);
			return dev_loop;
		}
	}

	/* if we got a link, resolve it to the real device */
	strlcpy(path, sysfs_path, sizeof(path));
	strlcat(path, devpath_real, sizeof(path));
	if (lstat(path, &statbuf) != 0) {
		dbg("stat '%s' failed: %s", path, strerror(errno));
		return NULL;
	}
	if (S_ISLNK(statbuf.st_mode)) {
		if (sysfs_resolve_link(devpath_real, sizeof(devpath_real)) != 0)
			return NULL;

		/* now look for device in cache after path translation */
		list_for_each_entry(dev_loop, &dev_list, node) {
			if (strcmp(dev_loop->devpath, devpath_real) == 0) {
				dbg("found in cache '%s'", dev_loop->devpath);
				return dev_loop;
			}
		}
	}

	/* it is a new device */
	dbg("new uncached device '%s'", devpath_real);
	dev = malloc(sizeof(struct sysfs_device));
	if (dev == NULL)
		return NULL;
	memset(dev, 0x00, sizeof(struct sysfs_device));

	sysfs_device_set_values(dev, devpath_real, NULL, NULL);

	/* get subsystem name */
	strlcpy(link_path, sysfs_path, sizeof(link_path));
	strlcat(link_path, dev->devpath, sizeof(link_path));
	strlcat(link_path, "/subsystem", sizeof(link_path));
	len = readlink(link_path, link_target, sizeof(link_target));
	if (len > 0) {
		/* get subsystem from "subsystem" link */
		link_target[len] = '\0';
		dbg("subsystem link '%s' points to '%s'", link_path, link_target);
		pos = strrchr(link_target, '/');
		if (pos != NULL)
			strlcpy(dev->subsystem, &pos[1], sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/class/", 7) == 0) {
		/* get subsystem from class dir */
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
		}
	} else if (strstr(dev->devpath, "/drivers/") != NULL) {
		strlcpy(dev->subsystem, "drivers", sizeof(dev->subsystem));
	} else if (strncmp(dev->devpath, "/module/", 8) == 0) {
		strlcpy(dev->subsystem, "module", sizeof(dev->subsystem));
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

	dbg("add to cache 'devpath=%s', subsystem='%s', driver='%s'", dev->devpath, dev->subsystem, dev->driver);
	list_add(&dev->node, &dev_list);

	return dev;
}

struct sysfs_device *sysfs_device_get_parent(struct sysfs_device *dev)
{
	char parent_devpath[PATH_SIZE];
	char *pos;

	dbg("open '%s'", dev->devpath);

	/* look if we already know the parent */
	if (dev->parent != NULL)
		return dev->parent;

	/* requesting a parent is only valid for devices */
	if ((strncmp(dev->devpath, "/devices/", 9) != 0) &&
	    (strncmp(dev->devpath, "/subsystem/", 11) != 0) &&
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

	/* are we at the top level of /devices */
	if (strcmp(parent_devpath, "/devices") == 0) {
		dbg("/devices top level");
		return NULL;
	}

	/* at the subsystems top level we want to follow the old-style "device" link */
	if (strncmp(parent_devpath, "/subsystem", 10) == 0) {
		pos = strrchr(parent_devpath, '/');
		if (pos == &parent_devpath[10] || pos == parent_devpath || strcmp(pos, "/devices") == 0) {
			dbg("/subsystem top level, look for device link");
			goto device_link;
		}
	}
	if (strncmp(parent_devpath, "/class", 6) == 0) {
		pos = strrchr(parent_devpath, '/');
		if (pos == &parent_devpath[6] || pos == parent_devpath) {
			dbg("/class top level, look for device link");
			goto device_link;
		}
	}
	if (strcmp(parent_devpath, "/block") == 0) {
		dbg("/block top level, look for device link");
		goto device_link;
	}

	/* get parent and remember it */
	dev->parent = sysfs_device_get(parent_devpath);
	return dev->parent;

device_link:
	strlcpy(parent_devpath, dev->devpath, sizeof(parent_devpath));
	strlcat(parent_devpath, "/device", sizeof(parent_devpath));
	if (sysfs_resolve_link(parent_devpath, sizeof(parent_devpath)) != 0)
		return NULL;

	/* get parent and remember it */
	dev->parent = sysfs_device_get(parent_devpath);
	return dev->parent;
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
	struct stat statbuf;
	int fd;
	ssize_t size;
	size_t sysfs_len;

	dbg("open '%s'/'%s'", devpath, attr_name);
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

	/* store attribute in cache (also negatives are kept in cache) */
	dbg("new uncached attribute '%s'", path_full);
	attr = malloc(sizeof(struct sysfs_attr));
	if (attr == NULL)
		return NULL;
	memset(attr, 0x00, sizeof(struct sysfs_attr));
	strlcpy(attr->path, path, sizeof(attr->path));
	dbg("add to cache '%s'", path_full);
	list_add(&attr->node, &attr_list);

	if (lstat(path_full, &statbuf) != 0) {
		dbg("stat '%s' failed: %s", path_full, strerror(errno));
		goto out;
	}

	if (S_ISLNK(statbuf.st_mode)) {
		/* links return the last element of the target path */
		char link_target[PATH_SIZE];
		int len;
		const char *pos;

		len = readlink(path_full, link_target, sizeof(link_target));
		if (len > 0) {
			link_target[len] = '\0';
			pos = strrchr(link_target, '/');
			if (pos != NULL) {
				dbg("cache '%s' with link value '%s'", path_full, value);
				strlcpy(attr->value_local, &pos[1], sizeof(attr->value_local));
				attr->value = attr->value_local;
			}
		}
		goto out;
	}

	/* skip directories */
	if (S_ISDIR(statbuf.st_mode))
		goto out;

	/* skip non-readable files */
	if ((statbuf.st_mode & S_IRUSR) == 0)
		goto out;

	/* read attribute value */
	fd = open(path_full, O_RDONLY);
	if (fd < 0) {
		dbg("attribute '%s' does not exist", path_full);
		goto out;
	}
	size = read(fd, value, sizeof(value));
	close(fd);
	if (size < 0)
		goto out;
	if (size == sizeof(value))
		goto out;

	/* got a valid value, store and return it */
	value[size] = '\0';
	remove_trailing_chars(value, '\n');
	dbg("cache '%s' with attribute value '%s'", path_full, value);
	strlcpy(attr->value_local, value, sizeof(attr->value_local));
	attr->value = attr->value_local;

out:
	return attr->value;
}
