/*
 * udev-add.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 *
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
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>
#ifndef __KLIBC__
#include <pwd.h>
#include <utmp.h>
#endif

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_lib.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"
#include "udevdb.h"
#include "klibc_fixups.h"

#define LOCAL_USER "$local"

/* 
 * Right now the major/minor of a device is stored in a file called
 * "dev" in sysfs.
 * The number is stored as:
 * 	MM:mm
 * 		MM is the major
 * 		mm is the minor
 * 		The value is in decimal.
 */
static int get_major_minor(struct sysfs_class_device *class_dev, struct udevice *udev)
{
	int retval = -ENODEV;
	struct sysfs_attribute *attr = NULL;

	attr = sysfs_get_classdev_attr(class_dev, "dev");
	if (attr == NULL)
		goto exit;
	dbg("dev='%s'", attr->value);

	if (sscanf(attr->value, "%u:%u", &udev->major, &udev->minor) != 2)
		goto exit;
	dbg("found major=%d, minor=%d", udev->major, udev->minor);

	retval = 0;
exit:
	return retval;
}

static int create_path(char *file)
{
	char p[NAME_SIZE];
	char *pos;
	int retval;
	struct stat stats;
	
	strfieldcpy(p, file);
	pos = strchr(p+1, '/');
	while (1) {
		pos = strchr(pos+1, '/');
		if (pos == NULL)
			break;
		*pos = 0x00;
		if (stat(p, &stats)) {
			retval = mkdir(p, 0755);
			if (retval != 0) {
				dbg("mkdir(%s) failed with error '%s'",
				    p, strerror(errno));
				return retval;
			}
			dbg("created '%s'", p);
		}
		*pos = '/';
	}
	return 0;
}

static int make_node(char *filename, int major, int minor, unsigned int mode, uid_t uid, gid_t gid)
{
	int retval;

	retval = mknod(filename, mode, makedev(major, minor));
	if (retval != 0) {
		dbg("mknod(%s, %#o, %u, %u) failed with error '%s'",
		    filename, mode, major, minor, strerror(errno));
		return retval;
	}

	dbg("chmod(%s, %#o)", filename, mode);
	retval = chmod(filename, mode);
	if (retval != 0) {
		dbg("chmod(%s, %#o) failed with error '%s'",
		    filename, mode, strerror(errno));
		return retval;
	}

	if (uid != 0 || gid != 0) {
		dbg("chown(%s, %u, %u)", filename, uid, gid);
		retval = chown(filename, uid, gid);
		if (retval != 0) {
			dbg("chown(%s, %u, %u) failed with error '%s'",
			    filename, uid, gid, strerror(errno));
			return retval;
		}
	}

	return 0;
}

/* get the local logged in user */
static void set_to_local_user(char *user)
{
	struct utmp *u;
	time_t recent = 0;

	strfieldcpymax(user, default_owner_str, OWNER_SIZE);
	setutent();
	while (1) {
		u = getutent();
		if (u == NULL)
			break;

		/* is this a user login ? */
		if (u->ut_type != USER_PROCESS)
			continue;

		/* is this a local login ? */
		if (strcmp(u->ut_host, ""))
			continue;

		if (u->ut_time > recent) {
			recent = u->ut_time;
			strfieldcpymax(user, u->ut_user, OWNER_SIZE);
			dbg("local user is '%s'", user);
			break;
		}
	}
	endutent();
}

/* Used to unlink existing files to ensure that our new file/symlink is created */
static int unlink_entry(char *filename)
{
	struct stat stats;
	int retval = 0;
	
	if (lstat(filename, &stats) == 0) {
		if ((stats.st_mode & S_IFMT) != S_IFDIR) {
			retval = unlink(filename);
			if (retval) {
				dbg("unlink(%s) failed with error '%s'",
				    filename, strerror(errno));
			}
		}
	}
	return retval;
}

static int create_node(struct udevice *dev, int fake)
{
	char filename[NAME_SIZE];
	char linkname[NAME_SIZE];
	char linktarget[NAME_SIZE];
	char partitionname[NAME_SIZE];
	int retval = 0;
	uid_t uid = 0;
	gid_t gid = 0;
	int i;
	int tail;
	char *pos;
	int len;

	strfieldcpy(filename, udev_root);
	strfieldcat(filename, dev->name);

	switch (dev->type) {
	case 'b':
		dev->mode |= S_IFBLK;
		break;
	case 'c':
	case 'u':
		dev->mode |= S_IFCHR;
		break;
	case 'p':
		dev->mode |= S_IFIFO;
		break;
	default:
		dbg("unknown node type %c\n", dev->type);
		return -EINVAL;
	}

	/* create parent directories if needed */
	if (strrchr(dev->name, '/'))
		create_path(filename);

	if (dev->owner[0] != '\0') {
		char *endptr;
		unsigned long id = strtoul(dev->owner, &endptr, 10);
		if (endptr[0] == '\0')
			uid = (uid_t) id;
		else {
			struct passwd *pw;
			if (strncmp(dev->owner, LOCAL_USER, sizeof(LOCAL_USER)) == 0)
				set_to_local_user(dev->owner);

			pw = getpwnam(dev->owner);
			if (pw == NULL)
				dbg("specified user unknown '%s'", dev->owner);
			else
				uid = pw->pw_uid;
		}
	}

	if (dev->group[0] != '\0') {
		char *endptr;
		unsigned long id = strtoul(dev->group, &endptr, 10);
		if (endptr[0] == '\0')
			gid = (gid_t) id;
		else {
			struct group *gr = getgrnam(dev->group);
			if (gr == NULL)
				dbg("specified group unknown '%s'", dev->group);
			else
				gid = gr->gr_gid;
		}
	}

	if (!fake) {
		unlink_entry(filename);
		info("creating device node '%s'", filename);
		make_node(filename, dev->major, dev->minor, dev->mode, uid, gid);
	} else {
		info("creating device node '%s', major = '%d', minor = '%d', "
		     "mode = '%#o', uid = '%d', gid = '%d'", filename,
		     dev->major, dev->minor, (mode_t)dev->mode, uid, gid);
	}

	/* create partitions if requested */
	if (dev->partitions > 0) {
		info("creating device partition nodes '%s[1-%i]'", filename, dev->partitions);
		if (!fake) {
			for (i = 1; i <= dev->partitions; i++) {
				strfieldcpy(partitionname, filename);
				strintcat(partitionname, i);
				unlink_entry(partitionname);
				make_node(partitionname, dev->major,
					  dev->minor + i, dev->mode, uid, gid);
			}
		}
	}

	/* create symlink if requested */
	foreach_strpart(dev->symlink, " ", pos, len) {
		strfieldcpymax(linkname, pos, len+1);
		strfieldcpy(filename, udev_root);
		strfieldcat(filename, linkname);
		dbg("symlink '%s' to node '%s' requested", filename, dev->name);
		if (!fake)
			if (strrchr(linkname, '/'))
				create_path(filename);

		/* optimize relative link */
		linktarget[0] = '\0';
		i = 0;
		tail = 0;
		while ((dev->name[i] == linkname[i]) && dev->name[i]) {
			if (dev->name[i] == '/')
				tail = i+1;
			i++;
		}
		while (linkname[i] != '\0') {
			if (linkname[i] == '/')
				strfieldcat(linktarget, "../");
			i++;
		}

		strfieldcat(linktarget, &dev->name[tail]);

		if (!fake)
			unlink_entry(filename);

		dbg("symlink(%s, %s)", linktarget, filename);
		if (!fake) {
			retval = symlink(linktarget, filename);
			if (retval != 0)
				dbg("symlink(%s, %s) failed with error '%s'",
				    linktarget, filename, strerror(errno));
		}
	}

	return retval;
}

static struct sysfs_class_device *get_class_dev(char *device_name)
{
	char dev_path[SYSFS_PATH_MAX];
	struct sysfs_class_device *class_dev = NULL;

	strfieldcpy(dev_path, sysfs_path);
	strfieldcat(dev_path, device_name);
	dbg("looking at '%s'", dev_path);

	/* open up the sysfs class device for this thing... */
	class_dev = sysfs_open_class_device_path(dev_path);
	if (class_dev == NULL) {
		dbg ("sysfs_open_class_device_path failed");
		goto exit;
	}
	dbg("class_dev->name='%s'", class_dev->name);

exit:
	return class_dev;
}

/* wait for the "dev" file to show up in the directory in sysfs.
 * If it doesn't happen in about 10 seconds, give up.
 */
#define SECONDS_TO_WAIT_FOR_DEV		10
static int sleep_for_dev(char *path)
{
	char filename[SYSFS_PATH_MAX + 6];
	int loop = SECONDS_TO_WAIT_FOR_DEV;
	int retval;

	strfieldcpy(filename, sysfs_path);
	strfieldcat(filename, path);
	strfieldcat(filename, "/dev");

	while (loop--) {
		struct stat buf;

		dbg("looking for '%s'", filename);
		retval = stat(filename, &buf);
		if (retval == 0)
			goto exit;

		/* sleep to give the kernel a chance to create the dev file */
		sleep(1);
	}
	retval = -ENODEV;
exit:
	return retval;
}

int udev_add_device(char *path, char *subsystem, int fake)
{
	struct sysfs_class_device *class_dev = NULL;
	struct udevice dev;
	int retval = -EINVAL;

	memset(&dev, 0x00, sizeof(dev));

	/* for now, the block layer is the only place where block devices are */
	if (strcmp(subsystem, "block") == 0)
		dev.type = 'b';
	else
		dev.type = 'c';

	retval = sleep_for_dev(path);
	if (retval != 0)
		goto exit;

	class_dev = get_class_dev(path);
	if (class_dev == NULL)
		goto exit;

	retval = get_major_minor(class_dev, &dev);
	if (retval != 0) {
		dbg("get_major_minor failed");
		goto exit;
	}

	retval = namedev_name_device(class_dev, &dev);
	if (retval != 0)
		goto exit;

	if (!fake) {
		retval = udevdb_add_dev(path, &dev);
		if (retval != 0)
			dbg("udevdb_add_dev failed, but we are going to try "
			    "to create the node anyway. But remove might not "
			    "work properly for this device.");

	}
	dbg("name='%s'", dev.name);
	retval = create_node(&dev, fake);

	if ((retval == 0) && (!fake))
		dev_d_send(&dev, subsystem);

exit:
	if (class_dev)
		sysfs_close_class_device(class_dev);

	return retval;
}
