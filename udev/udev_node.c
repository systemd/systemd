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

#define TMP_FILE_EXT		".udev-tmp"

int udev_node_mknod(struct udevice *udevice, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid)
{
	char file_tmp[PATH_SIZE + sizeof(TMP_FILE_EXT)];
	struct stat stats;
	int preserve = 0;
	int err = 0;

	if (major(devt) != 0 && strcmp(udevice->dev->subsystem, "block") == 0)
		mode |= S_IFBLK;
	else
		mode |= S_IFCHR;

	if (lstat(file, &stats) == 0) {
		if (((stats.st_mode & S_IFMT) == (mode & S_IFMT)) && (stats.st_rdev == devt)) {
			info(udevice->udev, "preserve file '%s', because it has correct dev_t\n", file);
			preserve = 1;
			udev_selinux_lsetfilecon(udevice->udev, file, mode);
		} else {
			info(udevice->udev, "atomically replace existing file '%s'\n", file);
			strlcpy(file_tmp, file, sizeof(file_tmp));
			strlcat(file_tmp, TMP_FILE_EXT, sizeof(file_tmp));
			unlink(file_tmp);
			udev_selinux_setfscreatecon(udevice->udev, file_tmp, mode);
			err = mknod(file_tmp, mode, devt);
			udev_selinux_resetfscreatecon(udevice->udev);
			if (err != 0) {
				err(udevice->udev, "mknod(%s, %#o, %u, %u) failed: %s\n",
				    file_tmp, mode, major(devt), minor(devt), strerror(errno));
				goto exit;
			}
			err = rename(file_tmp, file);
			if (err != 0) {
				err(udevice->udev, "rename(%s, %s) failed: %s\n", file_tmp, file, strerror(errno));
				unlink(file_tmp);
			}
		}
	} else {
		info(udevice->udev, "mknod(%s, %#o, (%u,%u))\n", file, mode, major(devt), minor(devt));
		udev_selinux_setfscreatecon(udevice->udev, file, mode);
		err = mknod(file, mode, devt);
		udev_selinux_resetfscreatecon(udevice->udev);
		if (err != 0) {
			err(udevice->udev, "mknod(%s, %#o, (%u,%u) failed: %s\n",
			    file, mode, major(devt), minor(devt), strerror(errno));
			goto exit;
		}
	}

	if (!preserve || stats.st_mode != mode) {
		info(udevice->udev, "chmod(%s, %#o)\n", file, mode);
		err = chmod(file, mode);
		if (err != 0) {
			err(udevice->udev, "chmod(%s, %#o) failed: %s\n", file, mode, strerror(errno));
			goto exit;
		}
	}

	if (!preserve || stats.st_uid != uid || stats.st_gid != gid) {
		info(udevice->udev, "chown(%s, %u, %u)\n", file, uid, gid);
		err = chown(file, uid, gid);
		if (err != 0) {
			err(udevice->udev, "chown(%s, %u, %u) failed: %s\n", file, uid, gid, strerror(errno));
			goto exit;
		}
	}
exit:
	return err;
}

static int node_symlink(struct udevice *udevice, const char *node, const char *slink)
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

			info(udevice->udev, "found existing node instead of symlink '%s'\n", slink);
			if (lstat(node, &stats2) == 0) {
				if ((stats.st_mode & S_IFMT) == (stats2.st_mode & S_IFMT) &&
				    stats.st_rdev == stats2.st_rdev) {
					info(udevice->udev, "replace device node '%s' with symlink to our node '%s'\n", slink, node);
				} else {
					err(udevice->udev, "device node '%s' already exists, link to '%s' will not overwrite it\n", slink, node);
					goto exit;
				}
			}
		} else if (S_ISLNK(stats.st_mode)) {
			char buf[PATH_SIZE];

			info(udevice->udev, "found existing symlink '%s'\n", slink);
			len = readlink(slink, buf, sizeof(buf));
			if (len > 0) {
				buf[len] = '\0';
				if (strcmp(target, buf) == 0) {
					info(udevice->udev, "preserve already existing symlink '%s' to '%s'\n", slink, target);
					udev_selinux_lsetfilecon(udevice->udev, slink, S_IFLNK);
					goto exit;
				}
			}
		}
	} else {
		info(udevice->udev, "creating symlink '%s' to '%s'\n", slink, target);
		udev_selinux_setfscreatecon(udevice->udev, slink, S_IFLNK);
		retval = symlink(target, slink);
		udev_selinux_resetfscreatecon(udevice->udev);
		if (retval == 0)
			goto exit;
	}

	info(udevice->udev, "atomically replace '%s'\n", slink);
	strlcpy(slink_tmp, slink, sizeof(slink_tmp));
	strlcat(slink_tmp, TMP_FILE_EXT, sizeof(slink_tmp));
	unlink(slink_tmp);
	udev_selinux_setfscreatecon(udevice->udev, slink, S_IFLNK);
	retval = symlink(target, slink_tmp);
	udev_selinux_resetfscreatecon(udevice->udev);
	if (retval != 0) {
		err(udevice->udev, "symlink(%s, %s) failed: %s\n", target, slink_tmp, strerror(errno));
		goto exit;
	}
	retval = rename(slink_tmp, slink);
	if (retval != 0) {
		err(udevice->udev, "rename(%s, %s) failed: %s\n", slink_tmp, slink, strerror(errno));
		unlink(slink_tmp);
		goto exit;
	}
exit:
	return retval;
}

static int update_link(struct udevice *udevice, const char *name)
{
	LIST_HEAD(name_list);
	char slink[PATH_SIZE];
	char node[PATH_SIZE];
	struct udevice *udevice_db;
	struct name_entry *device;
	char target[PATH_MAX] = "";
	int count;
	int priority = 0;
	int rc = 0;

	strlcpy(slink, udev_get_dev_path(udevice->udev), sizeof(slink));
	strlcat(slink, "/", sizeof(slink));
	strlcat(slink, name, sizeof(slink));

	count = udev_db_get_devices_by_name(udevice->udev, name, &name_list);
	info(udevice->udev, "found %i devices with name '%s'\n", count, name);

	/* if we don't have a reference, delete it */
	if (count <= 0) {
		info(udevice->udev, "no reference left, remove '%s'\n", name);
		if (!udevice->test_run) {
			unlink(slink);
			delete_path(udevice->udev, slink);
		}
		goto out;
	}

	/* find the device with the highest priority */
	list_for_each_entry(device, &name_list, node) {
		info(udevice->udev, "found '%s' for '%s'\n", device->name, name);

		/* did we find ourself? we win, if we have the same priority */
		if (strcmp(udevice->dev->devpath, device->name) == 0) {
			info(udevice->udev, "compare (our own) priority of '%s' %i >= %i\n",
			     udevice->dev->devpath, udevice->link_priority, priority);
			if (strcmp(udevice->name, name) == 0) {
				info(udevice->udev, "'%s' is our device node, database inconsistent, skip link update\n", udevice->name);
			} else if (target[0] == '\0' || udevice->link_priority >= priority) {
				priority = udevice->link_priority;
				strlcpy(target, udevice->name, sizeof(target));
			}
			continue;
		}

		/* another device, read priority from database */
		udevice_db = udev_device_init(udevice->udev);
		if (udevice_db == NULL)
			continue;
		if (udev_db_get_device(udevice_db, device->name) == 0) {
			if (strcmp(udevice_db->name, name) == 0) {
				info(udevice->udev, "'%s' is a device node of '%s', skip link update\n", udevice_db->name, device->name);
			} else {
				info(udevice->udev, "compare priority of '%s' %i > %i\n",
				     udevice_db->dev->devpath, udevice_db->link_priority, priority);
				if (target[0] == '\0' || udevice_db->link_priority > priority) {
					priority = udevice_db->link_priority;
					strlcpy(target, udevice_db->name, sizeof(target));
				}
			}
		}
		udev_device_cleanup(udevice_db);
	}
	name_list_cleanup(udevice->udev, &name_list);

	if (target[0] == '\0') {
		info(udevice->udev, "no current target for '%s' found\n", name);
		rc = 1;
		goto out;
	}

	/* create symlink to the target with the highest priority */
	strlcpy(node, udev_get_dev_path(udevice->udev), sizeof(node));
	strlcat(node, "/", sizeof(node));
	strlcat(node, target, sizeof(node));
	info(udevice->udev, "'%s' with target '%s' has the highest priority %i, create it\n", name, target, priority);
	if (!udevice->test_run) {
		create_path(udevice->udev, slink);
		node_symlink(udevice, node, slink);
	}
out:
	return rc;
}

void udev_node_update_symlinks(struct udevice *udevice, struct udevice *udevice_old)
{
	struct name_entry *name_loop;
	char symlinks[PATH_SIZE] = "";

	list_for_each_entry(name_loop, &udevice->symlink_list, node) {
		info(udevice->udev, "update symlink '%s' of '%s'\n", name_loop->name, udevice->dev->devpath);
		update_link(udevice, name_loop->name);
		strlcat(symlinks, udev_get_dev_path(udevice->udev), sizeof(symlinks));
		strlcat(symlinks, "/", sizeof(symlinks));
		strlcat(symlinks, name_loop->name, sizeof(symlinks));
		strlcat(symlinks, " ", sizeof(symlinks));
	}

	/* export symlinks to environment */
	remove_trailing_chars(symlinks, ' ');
	if (symlinks[0] != '\0')
		setenv("DEVLINKS", symlinks, 1);

	/* update possible left-over symlinks (device metadata changed) */
	if (udevice_old != NULL) {
		struct name_entry *link_loop;
		struct name_entry *link_old_loop;
		int found;

		/* remove current symlinks from old list */
		list_for_each_entry(link_old_loop, &udevice_old->symlink_list, node) {
			found = 0;
			list_for_each_entry(link_loop, &udevice->symlink_list, node) {
				if (strcmp(link_old_loop->name, link_loop->name) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				/* link does no longer belong to this device */
				info(udevice->udev, "update old symlink '%s' no longer belonging to '%s'\n",
				     link_old_loop->name, udevice->dev->devpath);
				update_link(udevice, link_old_loop->name);
			}
		}

		/*
		 * if the node name has changed, delete the node,
		 * or possibly restore a symlink of another device
		 */
		if (strcmp(udevice->name, udevice_old->name) != 0)
			update_link(udevice, udevice_old->name);
	}
}

int udev_node_add(struct udevice *udevice)
{
	char filename[PATH_SIZE];
	uid_t uid;
	gid_t gid;
	int i;
	int retval = 0;

	strlcpy(filename, udev_get_dev_path(udevice->udev), sizeof(filename));
	strlcat(filename, "/", sizeof(filename));
	strlcat(filename, udevice->name, sizeof(filename));
	create_path(udevice->udev, filename);

	if (strcmp(udevice->owner, "root") == 0)
		uid = 0;
	else {
		char *endptr;
		unsigned long id;

		id = strtoul(udevice->owner, &endptr, 10);
		if (endptr[0] == '\0')
			uid = (uid_t) id;
		else
			uid = lookup_user(udevice->udev, udevice->owner);
	}

	if (strcmp(udevice->group, "root") == 0)
		gid = 0;
	else {
		char *endptr;
		unsigned long id;

		id = strtoul(udevice->group, &endptr, 10);
		if (endptr[0] == '\0')
			gid = (gid_t) id;
		else
			gid = lookup_group(udevice->udev, udevice->group);
	}

	info(udevice->udev, "creating device node '%s', major=%d, minor=%d, mode=%#o, uid=%d, gid=%d\n",
	     filename, major(udevice->devt), minor(udevice->devt), udevice->mode, uid, gid);

	if (!udevice->test_run)
		if (udev_node_mknod(udevice, filename, udevice->devt, udevice->mode, uid, gid) != 0) {
			retval = -1;
			goto exit;
		}

	setenv("DEVNAME", filename, 1);

	/* create all_partitions if requested */
	if (udevice->partitions) {
		char partitionname[PATH_SIZE];
		char *attr;
		int range;

		/* take the maximum registered minor range */
		attr = sysfs_attr_get_value(udevice->udev, udevice->dev->devpath, "range");
		if (attr != NULL) {
			range = atoi(attr);
			if (range > 1)
				udevice->partitions = range-1;
		}
		info(udevice->udev, "creating device partition nodes '%s[1-%i]'\n", filename, udevice->partitions);
		if (!udevice->test_run) {
			for (i = 1; i <= udevice->partitions; i++) {
				dev_t part_devt;

				snprintf(partitionname, sizeof(partitionname), "%s%d", filename, i);
				partitionname[sizeof(partitionname)-1] = '\0';
				part_devt = makedev(major(udevice->devt), minor(udevice->devt) + i);
				udev_node_mknod(udevice, partitionname, part_devt, udevice->mode, uid, gid);
			}
		}
	}
exit:
	return retval;
}

int udev_node_remove(struct udevice *udevice)
{
	char filename[PATH_SIZE];
	char partitionname[PATH_SIZE];
	struct stat stats;
	int retval = 0;
	int num;

	strlcpy(filename, udev_get_dev_path(udevice->udev), sizeof(filename));
	strlcat(filename, "/", sizeof(filename));
	strlcat(filename, udevice->name, sizeof(filename));
	if (stat(filename, &stats) != 0) {
		info(udevice->udev, "device node '%s' not found\n", filename);
		return 0;
	}
	if (udevice->devt && stats.st_rdev != udevice->devt) {
		info(udevice->udev, "device node '%s' points to a different device, skip removal\n", filename);
		return -1;
	}

	info(udevice->udev, "removing device node '%s'\n", filename);
	if (!udevice->test_run)
		retval = unlink_secure(udevice->udev, filename);
	if (retval)
		return retval;

	setenv("DEVNAME", filename, 1);
	num = udevice->partitions;
	if (num > 0) {
		int i;

		info(udevice->udev, "removing all_partitions '%s[1-%i]'\n", filename, num);
		if (num > 255)
			return -1;
		for (i = 1; i <= num; i++) {
			snprintf(partitionname, sizeof(partitionname), "%s%d", filename, i);
			partitionname[sizeof(partitionname)-1] = '\0';
			if (!udevice->test_run)
				unlink_secure(udevice->udev, partitionname);
		}
	}
	delete_path(udevice->udev, filename);
	return retval;
}
