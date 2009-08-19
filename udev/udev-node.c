/*
 * Copyright (C) 2003-2008 Kay Sievers <kay.sievers@vrfy.org>
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

#define TMP_FILE_EXT		".udev-tmp"

/* reverse mapping from the device file name to the devpath */
static int name_index(struct udev_device *dev, const char *name, int add)
{
	struct udev *udev = udev_device_get_udev(dev);
	char name_enc[UTIL_PATH_SIZE];
	char filename[UTIL_PATH_SIZE * 2];

	util_path_encode(&name[strlen(udev_get_dev_path(udev))+1], name_enc, sizeof(name_enc));
	snprintf(filename, sizeof(filename), "%s/.udev/names/%s/%u:%u", udev_get_dev_path(udev), name_enc,
		 major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)));

	if (add) {
		dbg(udev, "creating index: '%s'\n", filename);
		util_create_path(udev, filename);
		symlink(udev_device_get_devpath(dev), filename);
	} else {
		dbg(udev, "removing index: '%s'\n", filename);
		unlink(filename);
		util_delete_path(udev, filename);
	}
	return 0;
}

int udev_node_mknod(struct udev_device *dev, const char *file, dev_t devnum, mode_t mode, uid_t uid, gid_t gid)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct stat stats;
	int preserve = 0;
	int err = 0;

	if (major(devnum) == 0)
		devnum = udev_device_get_devnum(dev);

	if (strcmp(udev_device_get_subsystem(dev), "block") == 0)
		mode |= S_IFBLK;
	else
		mode |= S_IFCHR;

	if (file == NULL)
		file = udev_device_get_devnode(dev);

	if (lstat(file, &stats) == 0) {
		if (((stats.st_mode & S_IFMT) == (mode & S_IFMT)) && (stats.st_rdev == devnum)) {
			info(udev, "preserve file '%s', because it has correct dev_t\n", file);
			preserve = 1;
			udev_selinux_lsetfilecon(udev, file, mode);
		} else {
			char file_tmp[UTIL_PATH_SIZE + sizeof(TMP_FILE_EXT)];

			info(udev, "atomically replace existing file '%s'\n", file);
			util_strscpyl(file_tmp, sizeof(file_tmp), file, TMP_FILE_EXT, NULL);
			unlink(file_tmp);
			udev_selinux_setfscreatecon(udev, file_tmp, mode);
			err = mknod(file_tmp, mode, devnum);
			udev_selinux_resetfscreatecon(udev);
			if (err != 0) {
				err(udev, "mknod(%s, %#o, %u, %u) failed: %m\n",
				    file_tmp, mode, major(devnum), minor(devnum));
				goto exit;
			}
			err = rename(file_tmp, file);
			if (err != 0) {
				err(udev, "rename(%s, %s) failed: %m\n", file_tmp, file);
				unlink(file_tmp);
			}
		}
	} else {
		info(udev, "mknod(%s, %#o, (%u,%u))\n", file, mode, major(devnum), minor(devnum));
		udev_selinux_setfscreatecon(udev, file, mode);
		err = mknod(file, mode, devnum);
		udev_selinux_resetfscreatecon(udev);
		if (err != 0) {
			err(udev, "mknod(%s, %#o, (%u,%u) failed: %m\n", file, mode, major(devnum), minor(devnum));
			goto exit;
		}
	}

	if (!preserve || stats.st_mode != mode) {
		info(udev, "chmod(%s, %#o)\n", file, mode);
		err = chmod(file, mode);
		if (err != 0) {
			err(udev, "chmod(%s, %#o) failed: %m\n", file, mode);
			goto exit;
		}
	}

	if (!preserve || stats.st_uid != uid || stats.st_gid != gid) {
		info(udev, "chown(%s, %u, %u)\n", file, uid, gid);
		err = chown(file, uid, gid);
		if (err != 0) {
			err(udev, "chown(%s, %u, %u) failed: %m\n", file, uid, gid);
			goto exit;
		}
	}
exit:
	return err;
}

static int node_symlink(struct udev *udev, const char *node, const char *slink)
{
	struct stat stats;
	char target[UTIL_PATH_SIZE];
	char *s;
	size_t l;
	char slink_tmp[UTIL_PATH_SIZE + sizeof(TMP_FILE_EXT)];
	int i = 0;
	int tail = 0;
	int err = 0;

	/* use relative link */
	target[0] = '\0';
	while (node[i] && (node[i] == slink[i])) {
		if (node[i] == '/')
			tail = i+1;
		i++;
	}
	s = target;
	l = sizeof(target);
	while (slink[i] != '\0') {
		if (slink[i] == '/')
			l = util_strpcpy(&s, l, "../");
		i++;
	}
	l = util_strscpy(s, l, &node[tail]);
	if (l == 0) {
		err = -EINVAL;
		goto exit;
	}

	/* preserve link with correct target, do not replace node of other device */
	if (lstat(slink, &stats) == 0) {
		if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {
			struct stat stats2;

			info(udev, "found existing node instead of symlink '%s'\n", slink);
			if (lstat(node, &stats2) == 0) {
				if ((stats.st_mode & S_IFMT) == (stats2.st_mode & S_IFMT) &&
				    stats.st_rdev == stats2.st_rdev) {
					info(udev, "replace device node '%s' with symlink to our node '%s'\n",
					     slink, node);
				} else {
					err(udev, "device node '%s' already exists, "
					    "link to '%s' will not overwrite it\n",
					    slink, node);
					goto exit;
				}
			}
		} else if (S_ISLNK(stats.st_mode)) {
			char buf[UTIL_PATH_SIZE];
			int len;

			dbg(udev, "found existing symlink '%s'\n", slink);
			len = readlink(slink, buf, sizeof(buf));
			if (len > 0) {
				buf[len] = '\0';
				if (strcmp(target, buf) == 0) {
					info(udev, "preserve already existing symlink '%s' to '%s'\n",
					     slink, target);
					udev_selinux_lsetfilecon(udev, slink, S_IFLNK);
					goto exit;
				}
			}
		}
	} else {
		info(udev, "creating symlink '%s' to '%s'\n", slink, target);
		udev_selinux_setfscreatecon(udev, slink, S_IFLNK);
		err = symlink(target, slink);
		udev_selinux_resetfscreatecon(udev);
		if (err == 0)
			goto exit;
	}

	info(udev, "atomically replace '%s'\n", slink);
	util_strscpyl(slink_tmp, sizeof(slink_tmp), slink, TMP_FILE_EXT, NULL);
	unlink(slink_tmp);
	udev_selinux_setfscreatecon(udev, slink, S_IFLNK);
	err = symlink(target, slink_tmp);
	udev_selinux_resetfscreatecon(udev);
	if (err != 0) {
		err(udev, "symlink(%s, %s) failed: %m\n", target, slink_tmp);
		goto exit;
	}
	err = rename(slink_tmp, slink);
	if (err != 0) {
		err(udev, "rename(%s, %s) failed: %m\n", slink_tmp, slink);
		unlink(slink_tmp);
	}
exit:
	return err;
}

static int name_index_get_devices(struct udev *udev, const char *name, struct udev_list_node *dev_list)
{
	char dirname[UTIL_PATH_SIZE];
	char *s;
	size_t l;
	DIR *dir;
	int count = 0;

	s = dirname;
	l = util_strpcpyl(&s, sizeof(dirname), udev_get_dev_path(udev),
		      "/.udev/names/", NULL);
	util_path_encode(&name[strlen(udev_get_dev_path(udev))+1], s, l);
	dir = opendir(dirname);
	if (dir == NULL) {
		dbg(udev, "no index directory '%s': %m\n", dirname);
		count = -1;
		goto out;
	}
	dbg(udev, "found index directory '%s'\n", dirname);

	while (1) {
		struct dirent *dent;
		char devpath[UTIL_PATH_SIZE];
		char syspath[UTIL_PATH_SIZE];
		int len;

		dent = readdir(dir);
		if (dent == NULL || dent->d_name[0] == '\0')
			break;
		if (dent->d_name[0] == '.')
			continue;

		len = readlinkat(dirfd(dir), dent->d_name, devpath, sizeof(devpath));
		if (len < 0 || (size_t)len >= sizeof(devpath))
			continue;
		devpath[len] = '\0';
		util_strscpyl(syspath, sizeof(syspath), udev_get_sys_path(udev), devpath, NULL);
		udev_list_entry_add(udev, dev_list, syspath, NULL, 1, 0);
		count++;
	}
	closedir(dir);
out:
	return count;
}

static int update_link(struct udev_device *dev, const char *slink)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_list_node dev_list;
	struct udev_list_entry *dev_entry;
	char target[UTIL_PATH_SIZE];
	int count;
	int priority = 0;
	int rc = 0;

	dbg(udev, "update symlink '%s' of '%s'\n", slink, udev_device_get_syspath(dev));

	udev_list_init(&dev_list);
	count = name_index_get_devices(udev, slink, &dev_list);
	if (count > 1)
		info(udev, "found %i devices with name '%s'\n", count, slink);

	/* if we don't have a reference, delete it */
	if (count <= 0) {
		info(udev, "no reference left, remove '%s'\n", slink);
		unlink(slink);
		util_delete_path(udev, slink);
		goto out;
	}

	/* find the device with the highest priority */
	target[0] = '\0';
	udev_list_entry_foreach(dev_entry, udev_list_get_entry(&dev_list)) {
		const char *syspath;
		struct udev_device *dev_db;
		const char *devnode;

		syspath = udev_list_entry_get_name(dev_entry);
		dbg(udev, "found '%s' for '%s'\n", syspath, slink);

		/* did we find ourself? we win, if we have the same priority */
		if (strcmp(udev_device_get_syspath(dev), syspath) == 0) {
			dbg(udev, "compare (our own) priority of '%s' %i >= %i\n",
			    udev_device_get_devpath(dev), udev_device_get_devlink_priority(dev), priority);
			if (strcmp(udev_device_get_devnode(dev), slink) == 0) {
				info(udev, "'%s' is our device node, database inconsistent, skip link update\n",
				     udev_device_get_devnode(dev));
			} else if (target[0] == '\0' || udev_device_get_devlink_priority(dev) >= priority) {
				priority = udev_device_get_devlink_priority(dev);
				util_strscpy(target, sizeof(target), udev_device_get_devnode(dev));
			}
			continue;
		}

		/* another device, read priority from database */
		dev_db = udev_device_new_from_syspath(udev, syspath);
		if (dev_db == NULL)
			continue;
		devnode = udev_device_get_devnode(dev_db);
		if (devnode != NULL) {
			if (strcmp(devnode, slink) == 0) {
				info(udev, "'%s' is a device node of '%s', skip link update\n",
				     devnode, syspath);
			} else {
				dbg(udev, "compare priority of '%s' %i > %i\n",
				    udev_device_get_devpath(dev_db),
				    udev_device_get_devlink_priority(dev_db),
				    priority);
				if (target[0] == '\0' || udev_device_get_devlink_priority(dev_db) > priority) {
					priority = udev_device_get_devlink_priority(dev_db);
					util_strscpy(target, sizeof(target), devnode);
				}
			}
		}
		udev_device_unref(dev_db);
	}
	udev_list_cleanup_entries(udev, &dev_list);

	if (target[0] == '\0') {
		info(udev, "no current target for '%s' found\n", slink);
		rc = 1;
		goto out;
	}

	/* create symlink to the target with the highest priority */
	info(udev, "'%s' with target '%s' has the highest priority %i, create it\n", slink, target, priority);
	util_create_path(udev, slink);
	node_symlink(udev, target, slink);
out:
	return rc;
}

void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_list_entry *list_entry;
	const char *devnode_old;

	/* update possible left-over symlinks */
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev_old)) {
		const char *name = udev_list_entry_get_name(list_entry);
		struct udev_list_entry *list_entry_current;
		int found;

		/* check if old link name is now our node name */
		if (strcmp(name, udev_device_get_devnode(dev)) == 0)
			continue;

		/* check if old link name still belongs to this device */
		found = 0;
		udev_list_entry_foreach(list_entry_current, udev_device_get_devlinks_list_entry(dev)) {
			const char *name_current = udev_list_entry_get_name(list_entry_current);

			if (strcmp(name, name_current) == 0) {
				found = 1;
				break;
			}
		}
		if (found)
			continue;

		info(udev, "update old name, '%s' no longer belonging to '%s'\n",
		     name, udev_device_get_devpath(dev));
		name_index(dev, name, 0);
		update_link(dev, name);
	}

	/*
	 * if the node name has changed, delete the node,
	 * and possibly restore a symlink of a different device
	 */
	devnode_old = udev_device_get_devnode(dev_old);
	if (devnode_old != NULL) {
		const char *devnode = udev_device_get_devnode(dev);

		if (devnode != NULL && strcmp(devnode_old, devnode) != 0) {
			info(udev, "node has changed from '%s' to '%s'\n", devnode_old, devnode);
			name_index(dev, devnode_old, 0);
			update_link(dev, devnode_old);
		}
	}
}

int udev_node_add(struct udev_device *dev, mode_t mode, uid_t uid, gid_t gid)
{
	struct udev *udev = udev_device_get_udev(dev);
	int i;
	int num;
	struct udev_list_entry *list_entry;
	int err = 0;

	info(udev, "creating device node '%s', devnum=%d:%d, mode=%#o, uid=%d, gid=%d\n",
	     udev_device_get_devnode(dev),
	     major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)),
	     mode, uid, gid);

	util_create_path(udev, udev_device_get_devnode(dev));
	if (udev_node_mknod(dev, NULL, makedev(0,0), mode, uid, gid) != 0) {
		err = -1;
		goto exit;
	}

	/* create all_partitions if requested */
	num = udev_device_get_num_fake_partitions(dev);
	if (num > 0) {
		info(udev, "creating device partition nodes '%s[1-%i]'\n", udev_device_get_devnode(dev), num);
		for (i = 1; i <= num; i++) {
			char partitionname[UTIL_PATH_SIZE];
			dev_t part_devnum;

			snprintf(partitionname, sizeof(partitionname), "%s%d",
				 udev_device_get_devnode(dev), i);
			partitionname[sizeof(partitionname)-1] = '\0';
			part_devnum = makedev(major(udev_device_get_devnum(dev)),
					    minor(udev_device_get_devnum(dev)) + i);
			udev_node_mknod(dev, partitionname, part_devnum, mode, uid, gid);
		}
	}

	/* add node to name index */
	name_index(dev, udev_device_get_devnode(dev), 1);

	/* create/update symlinks, add symlinks to name index */
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
		name_index(dev, udev_list_entry_get_name(list_entry), 1);
		update_link(dev, udev_list_entry_get_name(list_entry));
	}
exit:
	return err;
}

int udev_node_remove(struct udev_device *dev)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_list_entry *list_entry;
	const char *devnode;
	char partitionname[UTIL_PATH_SIZE];
	struct stat stats;
	int err = 0;
	int num;

	/* remove node from name index */
	name_index(dev, udev_device_get_devnode(dev), 0);

	/* remove,update symlinks, remove symlinks from name index */
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
		name_index(dev, udev_list_entry_get_name(list_entry), 0);
		update_link(dev, udev_list_entry_get_name(list_entry));
	}

	devnode = udev_device_get_devnode(dev);
	if (devnode == NULL)
		return 0;
	if (stat(devnode, &stats) != 0) {
		info(udev, "device node '%s' not found\n", devnode);
		return 0;
	}
	if (stats.st_rdev != udev_device_get_devnum(dev)) {
		info(udev, "device node '%s' points to a different device, skip removal\n", devnode);
		return -1;
	}

	info(udev, "removing device node '%s'\n", devnode);
	err = util_unlink_secure(udev, devnode);
	if (err)
		return err;

	num = udev_device_get_num_fake_partitions(dev);
	if (num > 0) {
		int i;

		info(udev, "removing all_partitions '%s[1-%i]'\n", devnode, num);
		if (num > 255)
			return -1;
		for (i = 1; i <= num; i++) {
			snprintf(partitionname, sizeof(partitionname), "%s%d", devnode, i);
			partitionname[sizeof(partitionname)-1] = '\0';
			util_unlink_secure(udev, partitionname);
		}
	}
	util_delete_path(udev, devnode);
	return err;
}
