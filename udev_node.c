/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
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
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"
#include "udev_rules.h"
#include "udev_selinux.h"


int udev_node_mknod(struct udevice *udev, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid)
{
	struct stat stats;
	int retval = 0;

	if (major(devt) != 0 && strcmp(udev->dev->subsystem, "block") == 0)
		mode |= S_IFBLK;
	else
		mode |= S_IFCHR;

	if (stat(file, &stats) != 0)
		goto create;

	/* preserve node with already correct numbers, to prevent changing the inode number */
	if ((stats.st_mode & S_IFMT) == (mode & S_IFMT) && (stats.st_rdev == devt)) {
		info("preserve file '%s', because it has correct dev_t", file);
		selinux_setfilecon(file, udev->dev->kernel, stats.st_mode);
		goto perms;
	}

	if (unlink(file) != 0)
		err("unlink(%s) failed: %s", file, strerror(errno));
	else
		dbg("already present file '%s' unlinked", file);

create:
	selinux_setfscreatecon(file, udev->dev->kernel, mode);
	retval = mknod(file, mode, devt);
	selinux_resetfscreatecon();
	if (retval != 0) {
		err("mknod(%s, %#o, %u, %u) failed: %s",
		    file, mode, major(devt), minor(devt), strerror(errno));
		goto exit;
	}

perms:
	dbg("chmod(%s, %#o)", file, mode);
	if (chmod(file, mode) != 0) {
		err("chmod(%s, %#o) failed: %s", file, mode, strerror(errno));
		goto exit;
	}

	if (uid != 0 || gid != 0) {
		dbg("chown(%s, %u, %u)", file, uid, gid);
		if (chown(file, uid, gid) != 0) {
			err("chown(%s, %u, %u) failed: %s",
			    file, uid, gid, strerror(errno));
			goto exit;
		}
	}

exit:
	return retval;
}

static int node_symlink(const char *node, const char *slink)
{
	char target[PATH_SIZE] = "";
	char buf[PATH_SIZE];
	int i = 0;
	int tail = 0;
	int len;

	/* use relative link */
	while (node[i] && (node[i] == slink[i])) {
		if (node[i] == '/')
			tail = i+1;
		i++;
	}
	while (slink[i] != '\0') {
		if (slink[i] == '/')
			strlcat(target, "../", sizeof(target));
		i++;
	}
	strlcat(target, &node[tail], sizeof(target));

	/* look if symlink already exists */
	len = readlink(slink, buf, sizeof(buf));
	if (len > 0) {
		buf[len] = '\0';
		if (strcmp(target, buf) == 0) {
			info("preserving symlink '%s' to '%s'", slink, target);
			selinux_setfilecon(slink, NULL, S_IFLNK);
			goto exit;
		}
		info("link '%s' points to different target '%s', delete it", slink, buf);
		unlink(slink);
	}

	/* create link */
	info("creating symlink '%s' to '%s'", slink, target);
	selinux_setfscreatecon(slink, NULL, S_IFLNK);
	if (symlink(target, slink) != 0)
		err("symlink(%s, %s) failed: %s", target, slink, strerror(errno));
	selinux_resetfscreatecon();

exit:
	return 0;
}

int udev_node_add(struct udevice *udev, struct udevice *udev_old)
{
	char filename[PATH_SIZE];
	uid_t uid;
	gid_t gid;
	int i;
	int retval = 0;

	snprintf(filename, sizeof(filename), "%s/%s", udev_root, udev->name);
	filename[sizeof(filename)-1] = '\0';

	/* create parent directories if needed */
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

	info("creating device node '%s', major = '%d', minor = '%d', " "mode = '%#o', uid = '%d', gid = '%d'",
	     filename, major(udev->devt), minor(udev->devt), udev->mode, uid, gid);

	if (!udev->test_run)
		if (udev_node_mknod(udev, filename, udev->devt, udev->mode, uid, gid) != 0) {
			retval = -1;
			goto exit;
		}

	setenv("DEVNAME", filename, 1);

	/* create all_partitions if requested */
	if (udev->partitions) {
		char partitionname[PATH_SIZE];
		char *attr;
		int range;

		/* take the maximum registered minor range */
		attr = sysfs_attr_get_value(udev->dev->devpath, "range");
		if (attr) {
			range = atoi(attr);
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
				udev_node_mknod(udev, partitionname, part_devt, udev->mode, uid, gid);
			}
		}
	}

	/* create symlink(s) if requested */
	if (!list_empty(&udev->symlink_list)) {
		struct name_entry *name_loop;
		char symlinks[PATH_SIZE] = "";

		list_for_each_entry(name_loop, &udev->symlink_list, node) {
			char slink[PATH_SIZE];

			strlcpy(slink, udev_root, sizeof(slink));
			strlcat(slink, "/", sizeof(slink));
			strlcat(slink, name_loop->name, sizeof(slink));

			info("creating symlink '%s' to node '%s'", slink, filename);
			if (!udev->test_run) {
				create_path(slink);
				node_symlink(filename, slink);
			}

			strlcat(symlinks, slink, sizeof(symlinks));
			strlcat(symlinks, " ", sizeof(symlinks));
		}

		remove_trailing_chars(symlinks, ' ');
		setenv("DEVLINKS", symlinks, 1);
	}

exit:
	return retval;
}

void udev_node_remove_symlinks(struct udevice *udev)
{
	char filename[PATH_SIZE];
	struct name_entry *name_loop;
	struct stat stats;

	if (!list_empty(&udev->symlink_list)) {
		char symlinks[PATH_SIZE] = "";

		list_for_each_entry(name_loop, &udev->symlink_list, node) {
			char devpath[PATH_SIZE];

			snprintf(filename, sizeof(filename), "%s/%s", udev_root, name_loop->name);
			filename[sizeof(filename)-1] = '\0';

			if (stat(filename, &stats) != 0) {
				dbg("symlink '%s' not found", filename);
				continue;
			}
			if (udev->devt && stats.st_rdev != udev->devt) {
				info("symlink '%s' points to a different device, skip removal", filename);
				continue;
			}

			info("removing symlink '%s'", filename);
			if (!udev->test_run) {
				unlink(filename);
				delete_path(filename);
			}

			/* see if another device wants this symlink */
			if (udev_db_lookup_name(name_loop->name, devpath, sizeof(devpath)) == 0) {
				struct udevice *old;

				info("found overwritten symlink '%s' of '%s'", name_loop->name, devpath);
				old = udev_device_init();
				if (old != NULL) {
					if (udev_db_get_device(old, devpath) == 0) {
						char slink[PATH_SIZE];
						char node[PATH_SIZE];

						strlcpy(slink, udev_root, sizeof(slink));
						strlcat(slink, "/", sizeof(slink));
						strlcat(slink, name_loop->name, sizeof(slink));
						strlcpy(node, udev_root, sizeof(node));
						strlcat(node, "/", sizeof(node));
						strlcat(node, old->name, sizeof(node));
						info("restore symlink '%s' to '%s'", slink, node);
						if (!udev->test_run)
							node_symlink(node, slink);
					}
					udev_device_cleanup(old);
				}
			}

			strlcat(symlinks, filename, sizeof(symlinks));
			strlcat(symlinks, " ", sizeof(symlinks));
		}

		remove_trailing_chars(symlinks, ' ');
		if (symlinks[0] != '\0')
			setenv("DEVLINKS", symlinks, 1);
	}
}

int udev_node_remove(struct udevice *udev)
{
	char filename[PATH_SIZE];
	char partitionname[PATH_SIZE];
	struct stat stats;
	int retval;
	int num;

	udev_node_remove_symlinks(udev);

	snprintf(filename, sizeof(filename), "%s/%s", udev_root, udev->name);
	filename[sizeof(filename)-1] = '\0';
	if (stat(filename, &stats) != 0) {
		dbg("device node '%s' not found", filename);
		return -1;
	}
	if (udev->devt && stats.st_rdev != udev->devt) {
		info("device node '%s' points to a different device, skip removal", filename);
		return -1;
	}

	info("removing device node '%s'", filename);
	retval = unlink_secure(filename);
	if (retval)
		return retval;

	setenv("DEVNAME", filename, 1);
	num = udev->partitions;
	if (num > 0) {
		int i;

		info("removing all_partitions '%s[1-%i]'", filename, num);
		if (num > 255)
			return -1;
		for (i = 1; i <= num; i++) {
			snprintf(partitionname, sizeof(partitionname), "%s%d", filename, i);
			partitionname[sizeof(partitionname)-1] = '\0';
			unlink_secure(partitionname);
		}
	}
	delete_path(filename);
	return retval;
}
