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
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
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
	struct sysfs_attribute *attr = NULL;

	attr = sysfs_get_classdev_attr(class_dev, "dev");
	if (attr == NULL)
		goto error;
	dbg("dev='%s'", attr->value);

	if (sscanf(attr->value, "%u:%u", &udev->major, &udev->minor) != 2)
		goto error;
	dbg("found major=%d, minor=%d", udev->major, udev->minor);

	return 0;
error:
	return -1;
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

static int make_node(char *file, int major, int minor, unsigned int mode, uid_t uid, gid_t gid)
{
	struct stat stats;
	int retval = 0;

	if (stat(file, &stats) != 0)
		goto create;

	/* preserve node with already correct numbers, to not change the inode number */
	if (((stats.st_mode & S_IFMT) == S_IFBLK || (stats.st_mode & S_IFMT) == S_IFCHR) &&
	    (stats.st_rdev == makedev(major, minor))) {
		dbg("preserve file '%s', cause it has correct dev_t", file);
		goto perms;
	}

	if (unlink(file) != 0)
		dbg("unlink(%s) failed with error '%s'", file, strerror(errno));
	else
		dbg("already present file '%s' unlinked", file);

create:
	retval = mknod(file, mode, makedev(major, minor));
	if (retval != 0) {
		dbg("mknod(%s, %#o, %u, %u) failed with error '%s'",
		    file, mode, major, minor, strerror(errno));
		goto exit;
	}

perms:
	dbg("chmod(%s, %#o)", file, mode);
	if (chmod(file, mode) != 0) {
		dbg("chmod(%s, %#o) failed with error '%s'", file, mode, strerror(errno));
		goto exit;
	}

	if (uid != 0 || gid != 0) {
		dbg("chown(%s, %u, %u)", file, uid, gid);
		if (chown(file, uid, gid) != 0) {
			dbg("chown(%s, %u, %u) failed with error '%s'",
			    file, uid, gid, strerror(errno));
			goto exit;
		}
	}

exit:
	return retval;
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

static int create_node(struct udevice *dev, int fake)
{
	char filename[NAME_SIZE];
	char linkname[NAME_SIZE];
	char linktarget[NAME_SIZE];
	char partitionname[NAME_SIZE];
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
		info("creating device node '%s'", filename);
		if (make_node(filename, dev->major, dev->minor, dev->mode, uid, gid) != 0)
			goto error;
	} else {
		info("creating device node '%s', major = '%d', minor = '%d', "
		     "mode = '%#o', uid = '%d', gid = '%d'", filename,
		     dev->major, dev->minor, (mode_t)dev->mode, uid, gid);
	}

	/* create all_partitions if requested */
	if (dev->partitions > 0) {
		info("creating device partition nodes '%s[1-%i]'", filename, dev->partitions);
		if (!fake) {
			for (i = 1; i <= dev->partitions; i++) {
				strfieldcpy(partitionname, filename);
				strintcat(partitionname, i);
				make_node(partitionname, dev->major,
					  dev->minor + i, dev->mode, uid, gid);
			}
		}
	}

	/* create symlink(s) if requested */
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

		dbg("symlink(%s, %s)", linktarget, filename);
		if (!fake) {
			unlink(filename);
			if (symlink(linktarget, filename) != 0)
				dbg("symlink(%s, %s) failed with error '%s'",
				    linktarget, filename, strerror(errno));
		}
	}

	return 0;
error:
	return -1;
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
#define SECONDS_TO_WAIT_FOR_FILE	10
static int sleep_for_file(char *path, char* file)
{
	char filename[SYSFS_PATH_MAX + 6];
	int loop = SECONDS_TO_WAIT_FOR_FILE;
	int retval;

	strfieldcpy(filename, sysfs_path);
	strfieldcat(filename, path);
	strfieldcat(filename, file);

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

static int rename_net_if(struct udevice *dev, int fake)
{
	int sk;
	struct ifreq ifr;
	int retval;

	dbg("changing net interface name from '%s' to '%s'", dev->kernel_name, dev->name);
	if (fake)
		return 0;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		dbg("error opening socket");
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	strfieldcpy(ifr.ifr_name, dev->kernel_name);
	strfieldcpy(ifr.ifr_newname, dev->name);

	retval = ioctl(sk, SIOCSIFNAME, &ifr);
	if (retval != 0)
		dbg("error changing net interface name");
	close(sk);

	return retval;
}

int udev_add_device(char *path, char *subsystem, int fake)
{
	struct sysfs_class_device *class_dev;
	struct udevice dev;
	char devpath[DEVPATH_SIZE];
	char *pos;
	int retval;

	memset(&dev, 0x00, sizeof(dev));

	dev.type = get_device_type(path, subsystem);
	switch (dev.type) {
	case 'b':
	case 'c':
		retval = sleep_for_file(path, "/dev");
		break;

	case 'n':
		retval = sleep_for_file(path, "/address");
		break;

	default:
		dbg("unknown device type '%c'", dev.type);
		return -1;
	}

	class_dev = get_class_dev(path);
	if (class_dev == NULL)
		return -1;

	if (dev.type == 'b' || dev.type == 'c') {
		retval = get_major_minor(class_dev, &dev);
		if (retval != 0) {
			dbg("get_major_minor failed");
			goto exit;
		}
	}

	if (namedev_name_device(class_dev, &dev) != 0)
		goto exit;

	dbg("name='%s'", dev.name);

	switch (dev.type) {
	case 'b':
	case 'c':
		retval = create_node(&dev, fake);
		if (retval != 0)
			goto exit;
		if ((!fake) && (udevdb_add_dev(path, &dev) != 0))
			dbg("udevdb_add_dev failed, but we are going to try "
			    "to create the node anyway. But remove might not "
			    "work properly for this device.");

		dev_d_send(&dev, subsystem, path);
		break;

	case 'n':
		strfieldcpy(devpath, path);
		if (strcmp(dev.name, dev.kernel_name) != 0) {
			retval = rename_net_if(&dev, fake);
			if (retval != 0)
				goto exit;
			/* netif's are keyed with the configured name, cause
			 * the original kernel name sleeps with the fishes
			 */
			pos = strrchr(devpath, '/');
			if (pos != NULL) {
				pos[1] = '\0';
				strfieldcat(devpath, dev.name);
			}
		}
		if ((!fake) && (udevdb_add_dev(devpath, &dev) != 0))
			dbg("udevdb_add_dev failed");

		dev_d_send(&dev, subsystem, devpath);
		break;
	}

exit:
	sysfs_close_class_device(class_dev);

	return retval;
}
