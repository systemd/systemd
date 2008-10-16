/*
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
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include "udev.h"

int create_path(struct udev *udev, const char *path)
{
	char p[UTIL_PATH_SIZE];
	char *pos;
	struct stat stats;
	int ret;

	util_strlcpy(p, path, sizeof(p));
	pos = strrchr(p, '/');
	if (pos == p || pos == NULL)
		return 0;

	while (pos[-1] == '/')
		pos--;
	pos[0] = '\0';

	dbg(udev, "stat '%s'\n", p);
	if (stat(p, &stats) == 0 && (stats.st_mode & S_IFMT) == S_IFDIR)
		return 0;

	if (create_path(udev, p) != 0)
		return -1;

	dbg(udev, "mkdir '%s'\n", p);
	udev_selinux_setfscreatecon(udev, p, S_IFDIR|0755);
	ret = mkdir(p, 0755);
	udev_selinux_resetfscreatecon(udev);
	if (ret == 0)
		return 0;

	if (errno == EEXIST)
		if (stat(p, &stats) == 0 && (stats.st_mode & S_IFMT) == S_IFDIR)
			return 0;
	return -1;
}

int delete_path(struct udev *udev, const char *path)
{
	char p[UTIL_PATH_SIZE];
	char *pos;
	int retval;

	strcpy (p, path);
	pos = strrchr(p, '/');
	if (pos == p || pos == NULL)
		return 0;

	while (1) {
		*pos = '\0';
		pos = strrchr(p, '/');

		/* don't remove the last one */
		if ((pos == p) || (pos == NULL))
			break;

		/* remove if empty */
		retval = rmdir(p);
		if (errno == ENOENT)
			retval = 0;
		if (retval) {
			if (errno == ENOTEMPTY)
				return 0;
			err(udev, "rmdir(%s) failed: %m\n", p);
			break;
		}
		dbg(udev, "removed '%s'\n", p);
	}
	return 0;
}

/* Reset permissions on the device node, before unlinking it to make sure,
 * that permisions of possible hard links will be removed too.
 */
int unlink_secure(struct udev *udev, const char *filename)
{
	int retval;

	retval = chown(filename, 0, 0);
	if (retval)
		err(udev, "chown(%s, 0, 0) failed: %m\n", filename);

	retval = chmod(filename, 0000);
	if (retval)
		err(udev, "chmod(%s, 0000) failed: %m\n", filename);

	retval = unlink(filename);
	if (errno == ENOENT)
		retval = 0;

	if (retval)
		err(udev, "unlink(%s) failed: %m\n", filename);

	return retval;
}

uid_t lookup_user(struct udev *udev, const char *user)
{
	struct passwd *pw;
	uid_t uid = 0;

	errno = 0;
	pw = getpwnam(user);
	if (pw == NULL) {
		if (errno == 0 || errno == ENOENT || errno == ESRCH)
			err(udev, "specified user '%s' unknown\n", user);
		else
			err(udev, "error resolving user '%s': %m\n", user);
	} else
		uid = pw->pw_uid;

	return uid;
}

extern gid_t lookup_group(struct udev *udev, const char *group)
{
	struct group *gr;
	gid_t gid = 0;

	errno = 0;
	gr = getgrnam(group);
	if (gr == NULL) {
		if (errno == 0 || errno == ENOENT || errno == ESRCH)
			err(udev, "specified group '%s' unknown\n", group);
		else
			err(udev, "error resolving group '%s': %m\n", group);
	} else
		gid = gr->gr_gid;

	return gid;
}
