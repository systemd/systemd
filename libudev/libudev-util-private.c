/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2003-2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include <sys/param.h>

#include "libudev.h"
#include "libudev-private.h"

static int create_path(struct udev *udev, const char *path, bool selinux)
{
	char p[UTIL_PATH_SIZE];
	char *pos;
	struct stat stats;
	int err;

	util_strscpy(p, sizeof(p), path);
	pos = strrchr(p, '/');
	if (pos == NULL)
		return 0;
	while (pos != p && pos[-1] == '/')
		pos--;
	if (pos == p)
		return 0;
	pos[0] = '\0';

	dbg(udev, "stat '%s'\n", p);
	if (stat(p, &stats) == 0) {
		if ((stats.st_mode & S_IFMT) == S_IFDIR)
			return 0;
		else
			return -ENOTDIR;
	}

	err = util_create_path(udev, p);
	if (err != 0)
		return err;

	dbg(udev, "mkdir '%s'\n", p);
	if (selinux)
		udev_selinux_setfscreatecon(udev, p, S_IFDIR|0755);
	err = mkdir(p, 0755);
	if (err != 0) {
		err = -errno;
		if (err == -EEXIST && stat(p, &stats) == 0) {
			if ((stats.st_mode & S_IFMT) == S_IFDIR)
				err = 0;
			else
				err = -ENOTDIR;
		}
	}
	if (selinux)
		udev_selinux_resetfscreatecon(udev);
	return err;
}

int util_create_path(struct udev *udev, const char *path)
{
	return create_path(udev, path, false);
}

int util_create_path_selinux(struct udev *udev, const char *path)
{
	return create_path(udev, path, true);
}

int util_delete_path(struct udev *udev, const char *path)
{
	char p[UTIL_PATH_SIZE];
	char *pos;
	int err = 0;

	if (path[0] == '/')
		while(path[1] == '/')
			path++;
	util_strscpy(p, sizeof(p), path);
	pos = strrchr(p, '/');
	if (pos == p || pos == NULL)
		return 0;

	for (;;) {
		*pos = '\0';
		pos = strrchr(p, '/');

		/* don't remove the last one */
		if ((pos == p) || (pos == NULL))
			break;

		err = rmdir(p);
		if (err < 0) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
	}
	return err;
}

/* Reset permissions on the device node, before unlinking it to make sure,
 * that permissions of possible hard links will be removed too.
 */
int util_unlink_secure(struct udev *udev, const char *filename)
{
	int err;

	chown(filename, 0, 0);
	chmod(filename, 0000);
	err = unlink(filename);
	if (errno == ENOENT)
		err = 0;
	if (err)
		err(udev, "unlink(%s) failed: %m\n", filename);
	return err;
}

uid_t util_lookup_user(struct udev *udev, const char *user)
{
	char *endptr;
	size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	char buf[buflen];
	struct passwd pwbuf;
	struct passwd *pw;
	uid_t uid;

	if (strcmp(user, "root") == 0)
		return 0;
	uid = strtoul(user, &endptr, 10);
	if (endptr[0] == '\0')
		return uid;

	errno = getpwnam_r(user, &pwbuf, buf, buflen, &pw);
	if (pw != NULL)
		return pw->pw_uid;
	if (errno == 0 || errno == ENOENT || errno == ESRCH)
		err(udev, "specified user '%s' unknown\n", user);
	else
		err(udev, "error resolving user '%s': %m\n", user);
	return 0;
}

gid_t util_lookup_group(struct udev *udev, const char *group)
{
	char *endptr;
	size_t buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	char *buf;
	struct group grbuf;
	struct group *gr;
	gid_t gid = 0;

	if (strcmp(group, "root") == 0)
		return 0;
	gid = strtoul(group, &endptr, 10);
	if (endptr[0] == '\0')
		return gid;
	buf = NULL;
	gid = 0;
	for (;;) {
		char *newbuf;

		newbuf = realloc(buf, buflen);
		if (!newbuf)
			break;
		buf = newbuf;
		errno = getgrnam_r(group, &grbuf, buf, buflen, &gr);
		if (gr != NULL) {
			gid = gr->gr_gid;
		} else if (errno == ERANGE) {
			buflen *= 2;
			continue;
		} else if (errno == 0 || errno == ENOENT || errno == ESRCH) {
			err(udev, "specified group '%s' unknown\n", group);
		} else {
			err(udev, "error resolving group '%s': %m\n", group);
		}
		break;
	}
	free(buf);
	return gid;
}

/* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */
int util_resolve_subsys_kernel(struct udev *udev, const char *string,
			       char *result, size_t maxsize, int read_value)
{
	char temp[UTIL_PATH_SIZE];
	char *subsys;
	char *sysname;
	struct udev_device *dev;
	char *attr;

	if (string[0] != '[')
		return -1;

	util_strscpy(temp, sizeof(temp), string);

	subsys = &temp[1];

	sysname = strchr(subsys, '/');
	if (sysname == NULL)
		return -1;
	sysname[0] = '\0';
	sysname = &sysname[1];

	attr = strchr(sysname, ']');
	if (attr == NULL)
		return -1;
	attr[0] = '\0';
	attr = &attr[1];
	if (attr[0] == '/')
		attr = &attr[1];
	if (attr[0] == '\0')
		attr = NULL;

	if (read_value && attr == NULL)
		return -1;

	dev = udev_device_new_from_subsystem_sysname(udev, subsys, sysname);
	if (dev == NULL)
		return -1;

	if (read_value) {
		const char *val;

		val = udev_device_get_sysattr_value(dev, attr);
		if (val != NULL)
			util_strscpy(result, maxsize, val);
		else
			result[0] = '\0';
		info(udev, "value '[%s/%s]%s' is '%s'\n", subsys, sysname, attr, result);
	} else {
		size_t l;
		char *s;

		s = result;
		l = util_strpcpyl(&s, maxsize, udev_device_get_syspath(dev), NULL);
		if (attr != NULL)
			util_strpcpyl(&s, l, "/", attr, NULL);
		info(udev, "path '[%s/%s]%s' is '%s'\n", subsys, sysname, attr, result);
	}
	udev_device_unref(dev);
	return 0;
}
