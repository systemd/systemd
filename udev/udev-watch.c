/*
 * Copyright (C) 2004-2010 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2009 Canonical Ltd.
 * Copyright (C) 2009 Scott James Remnant <scott@netsplit.com>
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

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "udev.h"

static int inotify_fd = -1;

/* inotify descriptor, will be shared with rules directory;
 * set to cloexec since we need our children to be able to add
 * watches for us
 */
int udev_watch_init(struct udev *udev)
{
	inotify_fd = inotify_init1(IN_CLOEXEC);
	if (inotify_fd < 0)
		err(udev, "inotify_init failed: %m\n");
	return inotify_fd;
}

/* move any old watches directory out of the way, and then restore
 * the watches
 */
void udev_watch_restore(struct udev *udev)
{
	char filename[UTIL_PATH_SIZE], oldname[UTIL_PATH_SIZE];

	if (inotify_fd < 0)
		return;

	util_strscpyl(oldname, sizeof(oldname), udev_get_dev_path(udev), "/.udev/watch.old", NULL);
	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/watch", NULL);
	if (rename(filename, oldname) == 0) {
		DIR *dir;
		struct dirent *ent;

		dir = opendir(oldname);
		if (dir == NULL) {
			err(udev, "unable to open old watches dir '%s', old watches will not be restored: %m", oldname);
			return;
		}

		for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
			char device[UTIL_PATH_SIZE];
			char *s;
			size_t l;
			ssize_t len;
			struct udev_device *dev;
			int maj, min;
			char type;

			if (ent->d_name[0] == '.')
				continue;

			s = device;
			l = util_strpcpy(&s, sizeof(device), udev_get_sys_path(udev));
			len = readlinkat(dirfd(dir), ent->d_name, s, l);
			if (len <= 0 || len == (ssize_t)l)
				goto unlink;
			s[len] = '\0';

			if (sscanf(s, "%c%i:%i", &type, &maj, &min) != 3)
				goto unlink;
			dev = udev_device_new_from_devnum(udev, type, makedev(maj, min));
			if (dev == NULL)
				goto unlink;

			info(udev, "restoring old watch on '%s'\n", udev_device_get_devnode(dev));
			udev_watch_begin(udev, dev);
			udev_device_unref(dev);
unlink:
			unlinkat(dirfd(dir), ent->d_name, 0);
		}

		closedir(dir);
		rmdir(oldname);

	} else if (errno != ENOENT) {
		err(udev, "unable to move watches dir '%s', old watches will not be restored: %m", filename);
	}
}

void udev_watch_begin(struct udev *udev, struct udev_device *dev)
{
	char filename[UTIL_PATH_SIZE];
	char majmin[UTIL_PATH_SIZE];
	int wd;

	if (inotify_fd < 0)
		return;

	info(udev, "adding watch on '%s'\n", udev_device_get_devnode(dev));
	wd = inotify_add_watch(inotify_fd, udev_device_get_devnode(dev), IN_CLOSE_WRITE);
	if (wd < 0) {
		err(udev, "inotify_add_watch(%d, %s, %o) failed: %m\n",
		    inotify_fd, udev_device_get_devnode(dev), IN_CLOSE_WRITE);
		return;
	}

	snprintf(majmin, sizeof(majmin), "%c%i:%i",
		 strcmp(udev_device_get_subsystem(dev), "block") == 0 ? 'b' : 'c',
		 major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)));
	snprintf(filename, sizeof(filename), "%s/.udev/watch/%d", udev_get_dev_path(udev), wd);
	util_create_path(udev, filename);
	unlink(filename);
	symlink(majmin, filename);

	udev_device_set_watch_handle(dev, wd);
}

void udev_watch_end(struct udev *udev, struct udev_device *dev)
{
	int wd;
	char filename[UTIL_PATH_SIZE];

	if (inotify_fd < 0)
		return;

	wd = udev_device_get_watch_handle(dev);
	if (wd < 0)
		return;

	info(udev, "removing watch on '%s'\n", udev_device_get_devnode(dev));
	inotify_rm_watch(inotify_fd, wd);

	snprintf(filename, sizeof(filename), "%s/.udev/watch/%d", udev_get_dev_path(udev), wd);
	unlink(filename);

	udev_device_set_watch_handle(dev, -1);
}

struct udev_device *udev_watch_lookup(struct udev *udev, int wd)
{
	char filename[UTIL_PATH_SIZE];
	char majmin[UTIL_PATH_SIZE];
	char *s;
	size_t l;
	ssize_t len;
	int maj, min;
	char type;
	dev_t devnum;

	if (inotify_fd < 0 || wd < 0)
		return NULL;

	snprintf(filename, sizeof(filename), "%s/.udev/watch/%d", udev_get_dev_path(udev), wd);
	s = majmin;
	l = util_strpcpy(&s, sizeof(majmin), udev_get_sys_path(udev));
	len = readlink(filename, s, l);
	if (len <= 0 || (size_t)len == l)
		return NULL;
	s[len] = '\0';

	if (sscanf(s, "%c%i:%i", &type, &maj, &min) != 3)
		return NULL;
	devnum = makedev(maj, min);
	return udev_device_new_from_devnum(udev, type, devnum);
}
