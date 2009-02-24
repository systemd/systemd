/*
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
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
#ifdef HAVE_INOTIFY
#include <sys/inotify.h>
#endif

#include "udev.h"

int inotify_fd = -1;

/* inotify descriptor, will be shared with rules directory;
 * set to cloexec since we need our children to be able to add
 * watches for us
 */
void udev_watch_init(struct udev *udev)
{
	inotify_fd = inotify_init();
	if (inotify_fd >= 0) {
		int flags;

		flags = fcntl(inotify_fd, F_GETFD);
		if (flags < 0)
			flags = FD_CLOEXEC;
		else
			flags |= FD_CLOEXEC;
		fcntl(inotify_fd, F_SETFD, flags);
	} else if (errno == ENOSYS)
		info(udev, "unable to use inotify, udevd will not monitor rule files changes\n");
	else
		err(udev, "inotify_init failed: %m\n");
}

/* move any old watches directory out of the way, and then restore
 * the watches
 */
void udev_watch_restore(struct udev *udev)
{
	char filename[UTIL_PATH_SIZE], oldname[UTIL_PATH_SIZE];

	if (inotify_fd < 0)
		return;

	util_strlcpy(oldname, udev_get_dev_path(udev), sizeof(oldname));
	util_strlcat(oldname, "/.udev/watch.old", sizeof(oldname));

	util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
	util_strlcat(filename, "/.udev/watch", sizeof(filename));

	if (rename(filename, oldname) == 0) {
		DIR *dir;
		struct dirent *ent;

		dir = opendir(oldname);
		if (dir == NULL) {
			err(udev, "unable to open old watches dir '%s', old watches will not be restored: %m", oldname);
			return;
		}

		while ((ent = readdir(dir)) != NULL) {
			char path[UTIL_PATH_SIZE];
			char buf[UTIL_PATH_SIZE];
			ssize_t len;
			struct udev_device *dev;

			if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
				continue;

			util_strlcpy(path, oldname, sizeof(path));
			util_strlcat(path, "/", sizeof(path));
			util_strlcat(path, ent->d_name, sizeof(path));

			len = readlink(path, buf, sizeof(buf));
			if (len <= 0) {
				unlink(path);
				continue;
			}

			buf[len] = '\0';
			dbg(udev, "old watch to '%s' found\n", buf);
			dev = udev_device_new_from_syspath(udev, buf);
			if (dev == NULL) {
				unlink(path);
				continue;
			}

			info(udev, "restoring old watch on '%s'\n", udev_device_get_devnode(dev));
			udev_watch_begin(udev, dev);

			udev_device_unref(dev);
			unlink(path);
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
	int wd;

	if (inotify_fd < 0 || major(udev_device_get_devnum(dev)) == 0)
		return;

	info(udev, "adding watch on '%s'\n", udev_device_get_devnode(dev));
	wd = inotify_add_watch(inotify_fd, udev_device_get_devnode(dev), IN_CLOSE_WRITE);
	if (wd < 0) {
		err(udev, "inotify_add_watch(%d, %s, %o) failed: %m\n",
		    inotify_fd, udev_device_get_devnode(dev), IN_CLOSE_WRITE);
	}

	snprintf(filename, sizeof(filename), "%s/.udev/watch/%d", udev_get_dev_path(udev), wd);
	util_create_path(udev, filename);
	unlink(filename);
	symlink(udev_device_get_syspath(dev), filename);

	udev_device_set_watch_handle(dev, wd);
	udev_device_update_db(dev);
}

void udev_watch_end(struct udev *udev, struct udev_device *dev)
{
	int wd;
	char filename[UTIL_PATH_SIZE];

	if (inotify_fd < 0 || major(udev_device_get_devnum(dev)) == 0)
		return;

	wd = udev_device_get_watch_handle(dev);
	if (wd < 0)
		return;

	info(udev, "removing watch on '%s'\n", udev_device_get_devnode(dev));
	inotify_rm_watch(inotify_fd, wd);

	snprintf(filename, sizeof(filename), "%s/.udev/watch/%d", udev_get_dev_path(udev), wd);
	unlink(filename);

	udev_device_set_watch_handle(dev, -1);
	udev_device_update_db(dev);
}

struct udev_device *udev_watch_lookup(struct udev *udev, int wd)
{
	char filename[UTIL_PATH_SIZE];
	char buf[UTIL_PATH_SIZE];
	ssize_t len;

	if (inotify_fd < 0 || wd < 0)
		return NULL;

	snprintf(filename, sizeof(filename), "%s/.udev/watch/%d", udev_get_dev_path(udev), wd);
	len = readlink(filename, buf, sizeof(buf));
	if (len > 0) {
		buf[len] = '\0';

		return udev_device_new_from_syspath(udev, buf);
	}

	return NULL;
}
