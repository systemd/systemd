/*
 * Copyright (C) 2003-2013 Kay Sievers <kay@vrfy.org>
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "formats-util.h"
#include "fs-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "string-util.h"
#include "udev.h"

static int node_symlink(struct udev_device *dev, const char *node, const char *slink) {
        struct stat stats;
        char target[UTIL_PATH_SIZE];
        char *s;
        size_t l;
        char slink_tmp[UTIL_PATH_SIZE + 32];
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
                        l = strpcpy(&s, l, "../");
                i++;
        }
        l = strscpy(s, l, &node[tail]);
        if (l == 0) {
                err = -EINVAL;
                goto exit;
        }

        /* preserve link with correct target, do not replace node of other device */
        if (lstat(slink, &stats) == 0) {
                if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {
                        log_error("conflicting device node '%s' found, link to '%s' will not be created", slink, node);
                        goto exit;
                } else if (S_ISLNK(stats.st_mode)) {
                        char buf[UTIL_PATH_SIZE];
                        int len;

                        len = readlink(slink, buf, sizeof(buf));
                        if (len > 0 && len < (int)sizeof(buf)) {
                                buf[len] = '\0';
                                if (streq(target, buf)) {
                                        log_debug("preserve already existing symlink '%s' to '%s'", slink, target);
                                        label_fix(slink, true, false);
                                        utimensat(AT_FDCWD, slink, NULL, AT_SYMLINK_NOFOLLOW);
                                        goto exit;
                                }
                        }
                }
        } else {
                log_debug("creating symlink '%s' to '%s'", slink, target);
                do {
                        err = mkdir_parents_label(slink, 0755);
                        if (err != 0 && err != -ENOENT)
                                break;
                        mac_selinux_create_file_prepare(slink, S_IFLNK);
                        err = symlink(target, slink);
                        if (err != 0)
                                err = -errno;
                        mac_selinux_create_file_clear();
                } while (err == -ENOENT);
                if (err == 0)
                        goto exit;
        }

        log_debug("atomically replace '%s'", slink);
        strscpyl(slink_tmp, sizeof(slink_tmp), slink, ".tmp-", udev_device_get_id_filename(dev), NULL);
        unlink(slink_tmp);
        do {
                err = mkdir_parents_label(slink_tmp, 0755);
                if (err != 0 && err != -ENOENT)
                        break;
                mac_selinux_create_file_prepare(slink_tmp, S_IFLNK);
                err = symlink(target, slink_tmp);
                if (err != 0)
                        err = -errno;
                mac_selinux_create_file_clear();
        } while (err == -ENOENT);
        if (err != 0) {
                log_error_errno(errno, "symlink '%s' '%s' failed: %m", target, slink_tmp);
                goto exit;
        }
        err = rename(slink_tmp, slink);
        if (err != 0) {
                log_error_errno(errno, "rename '%s' '%s' failed: %m", slink_tmp, slink);
                unlink(slink_tmp);
        }
exit:
        return err;
}

/* find device node of device with highest priority */
static const char *link_find_prioritized(struct udev_device *dev, bool add, const char *stackdir, char *buf, size_t bufsize) {
        struct udev *udev = udev_device_get_udev(dev);
        DIR *dir;
        int priority = 0;
        const char *target = NULL;

        if (add) {
                priority = udev_device_get_devlink_priority(dev);
                strscpy(buf, bufsize, udev_device_get_devnode(dev));
                target = buf;
        }

        dir = opendir(stackdir);
        if (dir == NULL)
                return target;
        for (;;) {
                struct udev_device *dev_db;
                struct dirent *dent;

                dent = readdir(dir);
                if (dent == NULL || dent->d_name[0] == '\0')
                        break;
                if (dent->d_name[0] == '.')
                        continue;

                log_debug("found '%s' claiming '%s'", dent->d_name, stackdir);

                /* did we find ourself? */
                if (streq(dent->d_name, udev_device_get_id_filename(dev)))
                        continue;

                dev_db = udev_device_new_from_device_id(udev, dent->d_name);
                if (dev_db != NULL) {
                        const char *devnode;

                        devnode = udev_device_get_devnode(dev_db);
                        if (devnode != NULL) {
                                if (target == NULL || udev_device_get_devlink_priority(dev_db) > priority) {
                                        log_debug("'%s' claims priority %i for '%s'",
                                                  udev_device_get_syspath(dev_db), udev_device_get_devlink_priority(dev_db), stackdir);
                                        priority = udev_device_get_devlink_priority(dev_db);
                                        strscpy(buf, bufsize, devnode);
                                        target = buf;
                                }
                        }
                        udev_device_unref(dev_db);
                }
        }
        closedir(dir);
        return target;
}

/* manage "stack of names" with possibly specified device priorities */
static void link_update(struct udev_device *dev, const char *slink, bool add) {
        char name_enc[UTIL_PATH_SIZE];
        char filename[UTIL_PATH_SIZE * 2];
        char dirname[UTIL_PATH_SIZE];
        const char *target;
        char buf[UTIL_PATH_SIZE];

        util_path_encode(slink + strlen("/dev"), name_enc, sizeof(name_enc));
        strscpyl(dirname, sizeof(dirname), "/run/udev/links/", name_enc, NULL);
        strscpyl(filename, sizeof(filename), dirname, "/", udev_device_get_id_filename(dev), NULL);

        if (!add && unlink(filename) == 0)
                rmdir(dirname);

        target = link_find_prioritized(dev, add, dirname, buf, sizeof(buf));
        if (target == NULL) {
                log_debug("no reference left, remove '%s'", slink);
                if (unlink(slink) == 0)
                        rmdir_parents(slink, "/");
        } else {
                log_debug("creating link '%s' to '%s'", slink, target);
                node_symlink(dev, target, slink);
        }

        if (add) {
                int err;

                do {
                        int fd;

                        err = mkdir_parents(filename, 0755);
                        if (err != 0 && err != -ENOENT)
                                break;
                        fd = open(filename, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC|O_NOFOLLOW, 0444);
                        if (fd >= 0)
                                close(fd);
                        else
                                err = -errno;
                } while (err == -ENOENT);
        }
}

void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old) {
        struct udev_list_entry *list_entry;

        /* update possible left-over symlinks */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev_old)) {
                const char *name = udev_list_entry_get_name(list_entry);
                struct udev_list_entry *list_entry_current;
                int found;

                /* check if old link name still belongs to this device */
                found = 0;
                udev_list_entry_foreach(list_entry_current, udev_device_get_devlinks_list_entry(dev)) {
                        const char *name_current = udev_list_entry_get_name(list_entry_current);

                        if (streq(name, name_current)) {
                                found = 1;
                                break;
                        }
                }
                if (found)
                        continue;

                log_debug("update old name, '%s' no longer belonging to '%s'",
                     name, udev_device_get_devpath(dev));
                link_update(dev, name, false);
        }
}

static int node_permissions_apply(struct udev_device *dev, bool apply,
                                  mode_t mode, uid_t uid, gid_t gid,
                                  struct udev_list *seclabel_list) {
        const char *devnode = udev_device_get_devnode(dev);
        dev_t devnum = udev_device_get_devnum(dev);
        struct stat stats;
        struct udev_list_entry *entry;
        int err = 0;

        if (streq(udev_device_get_subsystem(dev), "block"))
                mode |= S_IFBLK;
        else
                mode |= S_IFCHR;

        if (lstat(devnode, &stats) != 0) {
                err = log_debug_errno(errno, "can not stat() node '%s' (%m)", devnode);
                goto out;
        }

        if (((stats.st_mode & S_IFMT) != (mode & S_IFMT)) || (stats.st_rdev != devnum)) {
                err = -EEXIST;
                log_debug("found node '%s' with non-matching devnum %s, skip handling",
                          udev_device_get_devnode(dev), udev_device_get_id_filename(dev));
                goto out;
        }

        if (apply) {
                bool selinux = false;
                bool smack = false;

                if ((stats.st_mode & 0777) != (mode & 0777) || stats.st_uid != uid || stats.st_gid != gid) {
                        log_debug("set permissions %s, %#o, uid=%u, gid=%u", devnode, mode, uid, gid);
                        err = chmod(devnode, mode);
                        if (err < 0)
                                log_warning_errno(errno, "setting mode of %s to %#o failed: %m", devnode, mode);
                        err = chown(devnode, uid, gid);
                        if (err < 0)
                                log_warning_errno(errno, "setting owner of %s to uid=%u, gid=%u failed: %m", devnode, uid, gid);
                } else {
                        log_debug("preserve permissions %s, %#o, uid=%u, gid=%u", devnode, mode, uid, gid);
                }

                /* apply SECLABEL{$module}=$label */
                udev_list_entry_foreach(entry, udev_list_get_entry(seclabel_list)) {
                        const char *name, *label;
                        int r;

                        name = udev_list_entry_get_name(entry);
                        label = udev_list_entry_get_value(entry);

                        if (streq(name, "selinux")) {
                                selinux = true;

                                r = mac_selinux_apply(devnode, label);
                                if (r < 0)
                                        log_error_errno(r, "SECLABEL: failed to set SELinux label '%s': %m", label);
                                else
                                        log_debug("SECLABEL: set SELinux label '%s'", label);

                        } else if (streq(name, "smack")) {
                                smack = true;

                                r = mac_smack_apply(devnode, SMACK_ATTR_ACCESS, label);
                                if (r < 0)
                                        log_error_errno(r, "SECLABEL: failed to set SMACK label '%s': %m", label);
                                else
                                        log_debug("SECLABEL: set SMACK label '%s'", label);

                        } else
                                log_error("SECLABEL: unknown subsystem, ignoring '%s'='%s'", name, label);
                }

                /* set the defaults */
                if (!selinux)
                        mac_selinux_fix(devnode, true, false);
                if (!smack)
                        mac_smack_apply(devnode, SMACK_ATTR_ACCESS, NULL);
        }

        /* always update timestamp when we re-use the node, like on media change events */
        utimensat(AT_FDCWD, devnode, NULL, 0);
out:
        return err;
}

void udev_node_add(struct udev_device *dev, bool apply,
                   mode_t mode, uid_t uid, gid_t gid,
                   struct udev_list *seclabel_list) {
        char filename[UTIL_PATH_SIZE];
        struct udev_list_entry *list_entry;

        log_debug("handling device node '%s', devnum=%s, mode=%#o, uid="UID_FMT", gid="GID_FMT,
                  udev_device_get_devnode(dev), udev_device_get_id_filename(dev), mode, uid, gid);

        if (node_permissions_apply(dev, apply, mode, uid, gid, seclabel_list) < 0)
                return;

        /* always add /dev/{block,char}/$major:$minor */
        snprintf(filename, sizeof(filename), "/dev/%s/%u:%u",
                 streq(udev_device_get_subsystem(dev), "block") ? "block" : "char",
                 major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)));
        node_symlink(dev, udev_device_get_devnode(dev), filename);

        /* create/update symlinks, add symlinks to name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev))
                        link_update(dev, udev_list_entry_get_name(list_entry), true);
}

void udev_node_remove(struct udev_device *dev) {
        struct udev_list_entry *list_entry;
        char filename[UTIL_PATH_SIZE];

        /* remove/update symlinks, remove symlinks from name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev))
                link_update(dev, udev_list_entry_get_name(list_entry), false);

        /* remove /dev/{block,char}/$major:$minor */
        snprintf(filename, sizeof(filename), "/dev/%s/%u:%u",
                 streq(udev_device_get_subsystem(dev), "block") ? "block" : "char",
                 major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)));
        unlink(filename);
}
