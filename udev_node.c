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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"
#include "udev_rules.h"
#include "udev_selinux.h"

#define TMP_FILE_EXT		".udev-tmp"

int udev_node_mknod(struct udevice *udev, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid)
{
	char file_tmp[PATH_SIZE + sizeof(TMP_FILE_EXT)];
	struct stat stats;
	int retval = 0;

	if (major(devt) != 0 && strcmp(udev->dev->subsystem, "block") == 0)
		mode |= S_IFBLK;
	else
		mode |= S_IFCHR;

	if (lstat(file, &stats) == 0) {
		if ((stats.st_mode & S_IFMT) == (mode & S_IFMT) && (stats.st_rdev == devt)) {
			info("preserve file '%s', because it has correct dev_t", file);
			selinux_setfilecon(file, udev->dev->kernel, stats.st_mode);
			goto perms;
		}
	} else {
		selinux_setfscreatecon(file, udev->dev->kernel, mode);
		retval = mknod(file, mode, devt);
		selinux_resetfscreatecon();
		if (retval == 0)
			goto perms;
	}

	info("atomically replace '%s'", file);
	strlcpy(file_tmp, file, sizeof(file_tmp));
	strlcat(file_tmp, TMP_FILE_EXT, sizeof(file_tmp));
	selinux_setfscreatecon(file_tmp, udev->dev->kernel, mode);
	retval = mknod(file_tmp, mode, devt);
	selinux_resetfscreatecon();
	if (retval != 0) {
		err("mknod(%s, %#o, %u, %u) failed: %s",
		    file_tmp, mode, major(devt), minor(devt), strerror(errno));
		goto exit;
	}
	retval = rename(file_tmp, file);
	if (retval != 0) {
		err("rename(%s, %s) failed: %s",
		    file_tmp, file, strerror(errno));
		unlink(file_tmp);
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
	struct stat stats;
	char target[PATH_SIZE] = "";
	char slink_tmp[PATH_SIZE + sizeof(TMP_FILE_EXT)];
	int i = 0;
	int tail = 0;
	int len;
	int retval = 0;

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

	/* preserve link with correct target, do not replace node of other device */
	if (lstat(slink, &stats) == 0) {
		if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {
			struct stat stats2;

			info("found existing node instead of symlink '%s'", slink);
			if (lstat(node, &stats2) == 0) {
				if ((stats.st_mode & S_IFMT) == (stats2.st_mode & S_IFMT) &&
				    stats.st_rdev == stats2.st_rdev) {
					info("replace device node '%s' with symlink to our node '%s'", slink, node);
				} else {
					err("device node '%s' already exists, link '%s' will not overwrite it", node, slink);
					goto exit;
				}
			}
		} else if (S_ISLNK(stats.st_mode)) {
			char buf[PATH_SIZE];

			info("found existing symlink '%s'", slink);
			len = readlink(slink, buf, sizeof(buf));
			if (len > 0) {
				buf[len] = '\0';
				if (strcmp(target, buf) == 0) {
					info("preserve already existing symlink '%s' to '%s'", slink, target);
					selinux_setfilecon(slink, NULL, S_IFLNK);
					goto exit;
				}
			}
		}
	} else {
		info("creating symlink '%s' to '%s'", slink, target);
		selinux_setfscreatecon(slink, NULL, S_IFLNK);
		retval = symlink(target, slink);
		selinux_resetfscreatecon();
		if (retval == 0)
			goto exit;
	}

	info("atomically replace '%s'", slink);
	strlcpy(slink_tmp, slink, sizeof(slink_tmp));
	strlcat(slink_tmp, TMP_FILE_EXT, sizeof(slink_tmp));
	selinux_setfscreatecon(slink_tmp, NULL, S_IFLNK);
	retval = symlink(target, slink_tmp);
	selinux_resetfscreatecon();
	if (retval != 0) {
		err("symlink(%s, %s) failed: %s", target, slink_tmp, strerror(errno));
		goto exit;
	}
	retval = rename(slink_tmp, slink);
	if (retval != 0) {
		err("rename(%s, %s) failed: %s", slink_tmp, slink, strerror(errno));
		unlink(slink_tmp);
		goto exit;
	}
exit:
	return retval;
}

static int update_link(struct udevice *udev, const char *name)
{
	LIST_HEAD(name_list);
	char slink[PATH_SIZE];
	char node[PATH_SIZE];
	struct udevice *udev_db;
	struct name_entry *device;
	char target[PATH_MAX] = "";
	int count;
	int priority = 0;
	int rc = 0;

	strlcpy(slink, udev_root, sizeof(slink));
	strlcat(slink, "/", sizeof(slink));
	strlcat(slink, name, sizeof(slink));

	count = udev_db_get_devices_by_name(name, &name_list);
	info("found %i devices with name '%s'", count, name);

	/* if we don't have a reference, delete it */
	if (count <= 0) {
		info("no reference left, remove '%s'", name);
		if (!udev->test_run) {
			unlink(slink);
			delete_path(slink);
		}
		goto out;
	}

	/* find the device with the highest priority */
	list_for_each_entry(device, &name_list, node) {
		info("found '%s' for '%s'", device->name, name);

		/* did we find ourself? we win, if we have the same priority */
		if (strcmp(udev->dev->devpath, device->name) == 0) {
			info("compare (our own) priority of '%s' %i >= %i",
			     udev->dev->devpath, udev->link_priority, priority);
			if (target[0] == '\0' || udev->link_priority >= priority) {
				priority = udev->link_priority;
				strlcpy(target, udev->name, sizeof(target));
			}
			continue;
		}

		/* or something else, then read priority from database */
		udev_db = udev_device_init(NULL);
		if (udev_db == NULL)
			continue;
		if (udev_db_get_device(udev_db, device->name) == 0) {
			info("compare priority of '%s' %i > %i",
			     udev_db->dev->devpath, udev_db->link_priority, priority);
			if (target[0] == '\0' || udev_db->link_priority > priority) {
				priority = udev_db->link_priority;
				strlcpy(target, udev_db->name, sizeof(target));
			}
		}
		udev_device_cleanup(udev_db);
	}
	name_list_cleanup(&name_list);

	if (target[0] == '\0') {
		err("missing target for '%s'", name);
		rc = -1;
		goto out;
	}

	/* create symlink to the target with the highest priority */
	strlcpy(node, udev_root, sizeof(node));
	strlcat(node, "/", sizeof(node));
	strlcat(node, target, sizeof(node));
	info("'%s' with target '%s' has the highest priority %i, create it", name, target, priority);
	if (!udev->test_run) {
		create_path(slink);
		node_symlink(node, slink);
	}
out:
	return rc;
}

void udev_node_update_symlinks(struct udevice *udev, struct udevice *udev_old)
{
	struct name_entry *name_loop;
	char symlinks[PATH_SIZE] = "";

	list_for_each_entry(name_loop, &udev->symlink_list, node) {
		info("update symlink '%s' of '%s'", name_loop->name, udev->dev->devpath);
		update_link(udev, name_loop->name);
		strlcat(symlinks, udev_root, sizeof(symlinks));
		strlcat(symlinks, "/", sizeof(symlinks));
		strlcat(symlinks, name_loop->name, sizeof(symlinks));
		strlcat(symlinks, " ", sizeof(symlinks));
	}

	/* export symlinks to environment */
	remove_trailing_chars(symlinks, ' ');
	if (symlinks[0] != '\0')
		setenv("DEVLINKS", symlinks, 1);

	/* update possible left-over symlinks (device metadata changed) */
	if (udev_old != NULL) {
		struct name_entry *link_loop;
		struct name_entry *link_old_loop;
		int found;

		/* remove current symlinks from old list */
		list_for_each_entry(link_old_loop, &udev_old->symlink_list, node) {
			found = 0;
			list_for_each_entry(link_loop, &udev->symlink_list, node) {
				if (strcmp(link_old_loop->name, link_loop->name) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				/* link does no longer belong to this device */
				info("update old symlink '%s' no longer belonging to '%s'",
				     link_old_loop->name, udev->dev->devpath);
				update_link(udev, link_old_loop->name);
			}
		}

		/*
		 * if the node name has changed, delete the node,
		 * or possibly restore a symlink of another device
		 */
		if (strcmp(udev->name, udev_old->name) != 0)
			update_link(udev, udev_old->name);
	}
}

int udev_node_add(struct udevice *udev)
{
	char filename[PATH_SIZE];
	uid_t uid;
	gid_t gid;
	int i;
	int retval = 0;

	strlcpy(filename, udev_root, sizeof(filename));
	strlcat(filename, "/", sizeof(filename));
	strlcat(filename, udev->name, sizeof(filename));
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

	info("creating device node '%s', major=%d, minor=%d, mode=%#o, uid=%d, gid=%d",
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
		if (attr != NULL) {
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
exit:
	return retval;
}

int udev_node_remove(struct udevice *udev)
{
	char filename[PATH_SIZE];
	char partitionname[PATH_SIZE];
	struct stat stats;
	int retval = 0;
	int num;

	strlcpy(filename, udev_root, sizeof(filename));
	strlcat(filename, "/", sizeof(filename));
	strlcat(filename, udev->name, sizeof(filename));
	if (stat(filename, &stats) != 0) {
		dbg("device node '%s' not found", filename);
		return -1;
	}
	if (udev->devt && stats.st_rdev != udev->devt) {
		info("device node '%s' points to a different device, skip removal", filename);
		return -1;
	}

	info("removing device node '%s'", filename);
	if (!udev->test_run)
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
			if (!udev->test_run)
				unlink_secure(partitionname);
		}
	}
	delete_path(filename);
	return retval;
}
