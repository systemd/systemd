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
#include <pwd.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_sysfs.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"
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
		dbg("preserve file '%s', cause it has correct dev_t", file);
		selinux_setfilecon(file, udev->kernel_name, stats.st_mode);
		goto perms;
	}

	if (unlink(file) != 0)
		dbg("unlink(%s) failed with error '%s'", file, strerror(errno));
	else
		dbg("already present file '%s' unlinked", file);

create:
	switch (udev->type) {
	case 'b':
		mode |= S_IFBLK;
		break;
	case 'c':
	case 'u':
		mode |= S_IFCHR;
		break;
	case 'p':
		mode |= S_IFIFO;
		break;
	default:
		dbg("unknown node type %c\n", udev->type);
		return -EINVAL;
	}

	selinux_setfscreatecon(file, udev->kernel_name, mode);
	retval = mknod(file, mode, devt);
	if (retval != 0) {
		dbg("mknod(%s, %#o, %u, %u) failed with error '%s'",
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
	char filename[NAME_SIZE];
	char partitionname[NAME_SIZE];
	uid_t uid = 0;
	gid_t gid = 0;
	int tail;
	char *pos;
	int len;
		int i;

	snprintf(filename, NAME_SIZE, "%s/%s", udev_root, udev->name);
	filename[NAME_SIZE-1] = '\0';

	/* create parent directories if needed */
	if (strchr(udev->name, '/'))
		create_path(filename);

	if (udev->owner[0] != '\0') {
		char *endptr;
		unsigned long id = strtoul(udev->owner, &endptr, 10);

		if (endptr[0] == '\0')
			uid = (uid_t) id;
		else {
			struct passwd *pw;

			pw = getpwnam(udev->owner);
			if (pw == NULL)
				dbg("specified user unknown '%s'", udev->owner);
			else
				uid = pw->pw_uid;
		}
	}

	if (udev->group[0] != '\0') {
		char *endptr;
		unsigned long id = strtoul(udev->group, &endptr, 10);

		if (endptr[0] == '\0')
			gid = (gid_t) id;
		else {
			struct group *gr = getgrnam(udev->group);
			if (gr == NULL)
				dbg("specified group unknown '%s'", udev->group);
			else
				gid = gr->gr_gid;
		}
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

				strfieldcpy(partitionname, filename);
				strintcat(partitionname, i);
				part_devt = makedev(major(udev->devt), minor(udev->devt)+1);
				udev_make_node(udev, partitionname, part_devt, udev->mode, uid, gid);
			}
		}
	}

	/* create symlink(s) if requested */
	foreach_strpart(udev->symlink, " ", pos, len) {
		char linkname[NAME_SIZE];
		char linktarget[NAME_SIZE];

		strfieldcpymax(linkname, pos, len+1);
		snprintf(filename, NAME_SIZE, "%s/%s", udev_root, linkname);
		filename[NAME_SIZE-1] = '\0';

		dbg("symlink '%s' to node '%s' requested", filename, udev->name);
		if (!udev->test_run)
			if (strrchr(linkname, '/'))
				create_path(filename);

		/* optimize relative link */
		linktarget[0] = '\0';
		i = 0;
		tail = 0;
		while ((udev->name[i] == linkname[i]) && udev->name[i]) {
			if (udev->name[i] == '/')
				tail = i+1;
			i++;
		}
		while (linkname[i] != '\0') {
			if (linkname[i] == '/')
				strfieldcat(linktarget, "../");
			i++;
		}

		strfieldcat(linktarget, &udev->name[tail]);

		dbg("symlink(%s, %s)", linktarget, filename);
		if (!udev->test_run) {
			selinux_setfscreatecon(filename, udev->kernel_name, S_IFLNK);
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

static int rename_net_if(struct udevice *udev)
{
	int sk;
	struct ifreq ifr;
	int retval;

	dbg("changing net interface name from '%s' to '%s'", udev->kernel_name, udev->name);
	if (udev->test_run)
		return 0;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		dbg("error opening socket");
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	strfieldcpy(ifr.ifr_name, udev->kernel_name);
	strfieldcpy(ifr.ifr_newname, udev->name);

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

	if (udev->type == 'b' || udev->type == 'c') {
		udev->devt = get_devt(class_dev);
		if (!udev->devt) {
			dbg("no dev-file found, do nothing");
			return 0;
		}
	}

	if (namedev_name_device(udev, class_dev) != 0)
		return 0;

	dbg("adding name='%s'", udev->name);

	selinux_init();

	if (udev->type == 'b' || udev->type == 'c') {
		retval = create_node(udev, class_dev);
		if (retval != 0)
			goto exit;

		if (udev_db_add_device(udev) != 0)
			dbg("udev_db_add_dev failed, but we create the node anyway, "
			    "remove might not work for custom names");

		/* use full path to the environment */
		snprintf(udev->devname, NAME_SIZE, "%s/%s", udev_root, udev->name);
		udev->devname[NAME_SIZE-1] = '\0';

	} else if (udev->type == 'n') {
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
				strfieldcat(udev->devpath, udev->name);
				setenv("DEVPATH", udev->devpath, 1);
				setenv("INTERFACE", udev->name, 1);
			}

			/* use netif name for the environment */
			strfieldcpy(udev->devname, udev->name);
		}
	}

exit:
	selinux_restore();

	return retval;
}
