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

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_sysfs.h"
#include "udev_version.h"
#include "logging.h"
#include "udev_rules.h"
#include "udev_db.h"
#include "udev_selinux.h"


int udev_make_node(struct udevice *udev, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid)
{
	struct stat stats;
	int retval = 0;

	if (stat(file, &stats) != 0)
		goto create;

	/* preserve node with already correct numbers, to not change the inode number */
	if (((stats.st_mode & S_IFMT) == S_IFBLK || (stats.st_mode & S_IFMT) == S_IFCHR) &&
	    (stats.st_rdev == devt)) {
		info("preserve file '%s', cause it has correct dev_t", file);
		selinux_setfilecon(file, udev->kernel_name, stats.st_mode);
		goto perms;
	}

	if (unlink(file) != 0)
		dbg("unlink(%s) failed with error '%s'", file, strerror(errno));
	else
		dbg("already present file '%s' unlinked", file);

create:
	switch (udev->type) {
	case DEV_BLOCK:
		mode |= S_IFBLK;
		break;
	case DEV_CLASS:
		mode |= S_IFCHR;
		break;
	default:
		dbg("unknown node type %c\n", udev->type);
		return -EINVAL;
	}

	selinux_setfscreatecon(file, udev->kernel_name, mode);
	retval = mknod(file, mode, devt);
	selinux_resetfscreatecon();
	if (retval != 0) {
		err("mknod(%s, %#o, %u, %u) failed with error '%s'",
		    file, mode, major(devt), minor(devt), strerror(errno));
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

static int create_node(struct udevice *udev, struct sysfs_class_device *class_dev)
{
	char filename[PATH_SIZE];
	char partitionname[PATH_SIZE];
	struct name_entry *name_loop;
	uid_t uid;
	gid_t gid;
	int tail;
	int i;

	snprintf(filename, sizeof(filename), "%s/%s", udev_root, udev->name);
	filename[sizeof(filename)-1] = '\0';

	/* create parent directories if needed */
	if (strchr(udev->name, '/'))
		create_path(filename);

	if (strcmp(udev->owner, "root") == 0)
		uid = 0;
	else {
		char *endptr;
		unsigned long id;

		id = strtoul(udev->owner, &endptr, 10);
		if (endptr[0] == '\0')
			uid = (uid_t) id;
		else
			uid = lookup_user(udev->owner);
	}

	if (strcmp(udev->group, "root") == 0)
		gid = 0;
	else {
		char *endptr;
		unsigned long id;

		id = strtoul(udev->group, &endptr, 10);
		if (endptr[0] == '\0')
			gid = (gid_t) id;
		else
			gid = lookup_group(udev->group);
	}

	if (!udev->test_run) {
		info("creating device node '%s'", filename);
		if (udev_make_node(udev, filename, udev->devt, udev->mode, uid, gid) != 0)
			goto error;
	} else {
		info("creating device node '%s', major = '%d', minor = '%d', "
		     "mode = '%#o', uid = '%d', gid = '%d'", filename,
		     major(udev->devt), minor(udev->devt), udev->mode, uid, gid);
	}

	/* create all_partitions if requested */
	if (udev->partitions) {
		struct sysfs_attribute *attr;
		int range;

		/* take the maximum registered minor range */
		attr = sysfs_get_classdev_attr(class_dev, "range");
		if (attr) {
			range = atoi(attr->value);
			if (range > 1)
				udev->partitions = range-1;
		}
		info("creating device partition nodes '%s[1-%i]'", filename, udev->partitions);
		if (!udev->test_run) {
			for (i = 1; i <= udev->partitions; i++) {
				dev_t part_devt;

				snprintf(partitionname, sizeof(partitionname), "%s%d", filename, i);
				partitionname[sizeof(partitionname)-1] = '\0';
				part_devt = makedev(major(udev->devt), minor(udev->devt) + i);
				udev_make_node(udev, partitionname, part_devt, udev->mode, uid, gid);
			}
		}
	}

	/* create symlink(s) if requested */
	list_for_each_entry(name_loop, &udev->symlink_list, node) {
		int retval;
		char linktarget[PATH_SIZE];

		snprintf(filename, sizeof(filename), "%s/%s", udev_root, name_loop->name);
		filename[sizeof(filename)-1] = '\0';

		dbg("symlink '%s' to node '%s' requested", filename, udev->name);
		if (!udev->test_run)
			if (strchr(filename, '/'))
				create_path(filename);

		/* optimize relative link */
		linktarget[0] = '\0';
		i = 0;
		tail = 0;
		while (udev->name[i] && (udev->name[i] == name_loop->name[i])) {
			if (udev->name[i] == '/')
				tail = i+1;
			i++;
		}
		while (name_loop->name[i] != '\0') {
			if (name_loop->name[i] == '/')
				strlcat(linktarget, "../", sizeof(linktarget));
			i++;
		}

		strlcat(linktarget, &udev->name[tail], sizeof(linktarget));

		dbg("symlink(%s, %s)", linktarget, filename);
		if (!udev->test_run) {
			unlink(filename);
			selinux_setfscreatecon(filename, NULL, S_IFLNK);
			retval = symlink(linktarget, filename);
			selinux_resetfscreatecon();
			if (retval != 0)
				dbg("symlink(%s, %s) failed with error '%s'",
				    linktarget, filename, strerror(errno));
		}
	}

	return 0;
error:
	return -1;
}

static int rename_net_if(struct udevice *udev)
{
	int sk;
	struct ifreq ifr;
	int retval;

	info("changing net interface name from '%s' to '%s'", udev->kernel_name, udev->name);
	if (udev->test_run)
		return 0;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		dbg("error opening socket");
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	strlcpy(ifr.ifr_name, udev->kernel_name, IFNAMSIZ);
	strlcpy(ifr.ifr_newname, udev->name, IFNAMSIZ);

	retval = ioctl(sk, SIOCSIFNAME, &ifr);
	if (retval != 0)
		dbg("error changing net interface name");
	close(sk);

	return retval;
}

int udev_add_device(struct udevice *udev, struct sysfs_class_device *class_dev)
{
	char *pos;
	int retval = 0;

	dbg("adding name='%s'", udev->name);
	selinux_init();

	if (udev->type == DEV_BLOCK || udev->type == DEV_CLASS) {
		retval = create_node(udev, class_dev);
		if (retval != 0)
			goto exit;

		if (udev_db_add_device(udev) != 0)
			dbg("udev_db_add_dev failed, but we create the node anyway, "
			    "remove might not work for custom names");

		/* use full path to the environment */
		snprintf(udev->devname, sizeof(udev->devname), "%s/%s", udev_root, udev->name);
		udev->devname[sizeof(udev->devname)-1] = '\0';

	} else if (udev->type == DEV_NET) {
		/* look if we want to change the name of the netif */
		if (strcmp(udev->name, udev->kernel_name) != 0) {
			retval = rename_net_if(udev);
			if (retval != 0)
				goto exit;

			/* we've changed the name, now fake the devpath, cause the
			 * original kernel name sleeps with the fishes and we don't
			 * get an event from the kernel with the new name
			 */
			pos = strrchr(udev->devpath, '/');
			if (pos != NULL) {
				pos[1] = '\0';
				strlcat(udev->devpath, udev->name, sizeof(udev->devpath));
				setenv("DEVPATH", udev->devpath, 1);
				setenv("INTERFACE", udev->name, 1);
			}

			/* use netif name for the environment */
			strlcpy(udev->devname, udev->name, sizeof(udev->devname));
		}
	}

exit:
	selinux_exit();
	return retval;
}
