/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "device-nodes.h"
#include "device-private.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "sd-device.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "udev.h"
#include "libudev-device-internal.h"

#define LINK_UPDATE_MAX_RETRIES 128

static int node_symlink(sd_device *dev, const char *node, const char *slink) {
        struct stat stats;
        char target[UTIL_PATH_SIZE];
        char *s;
        const char *id_filename;
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
                                        (void) label_fix(slink, LABEL_IGNORE_ENOENT);
                                        utimensat(AT_FDCWD, slink, NULL, AT_SYMLINK_NOFOLLOW);
                                        goto exit;
                                }
                        }
                }
        } else {
                log_debug("creating symlink '%s' to '%s'", slink, target);
                do {
                        err = mkdir_parents_label(slink, 0755);
                        if (!IN_SET(err, 0, -ENOENT))
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
        err = device_get_id_filename(dev, &id_filename);
        if (err < 0)
                return log_error_errno(err, "Failed to get id_filename: %m");
        strscpyl(slink_tmp, sizeof(slink_tmp), slink, ".tmp-", id_filename, NULL);
        unlink(slink_tmp);
        do {
                err = mkdir_parents_label(slink_tmp, 0755);
                if (!IN_SET(err, 0, -ENOENT))
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
        } else
                /* Tell caller that we replaced already existing symlink. */
                return 1;
exit:
        return err;
}

/* find device node of device with highest priority */
static int link_find_prioritized(sd_device *dev, bool add, const char *stackdir, char **ret) {
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *target = NULL;
        struct dirent *dent;
        int r, priority = 0;

        assert(!add || dev);
        assert(stackdir);
        assert(ret);

        if (add) {
                const char *devnode;

                r = device_get_devlink_priority(dev, &priority);
                if (r < 0)
                        return r;

                r = sd_device_get_devname(dev, &devnode);
                if (r < 0)
                        return r;

                target = strdup(devnode);
                if (!target)
                        return -ENOMEM;
        }

        dir = opendir(stackdir);
        if (!dir) {
                if (target) {
                        *ret = TAKE_PTR(target);
                        return 0;
                }

                return -errno;
        }

        FOREACH_DIRENT_ALL(dent, dir, break) {
                _cleanup_(sd_device_unrefp) sd_device *dev_db = NULL;
                const char *devnode, *id_filename;
                int db_prio = 0;

                if (dent->d_name[0] == '\0')
                        break;
                if (dent->d_name[0] == '.')
                        continue;

                log_debug("Found '%s' claiming '%s'", dent->d_name, stackdir);

                if (device_get_id_filename(dev, &id_filename) < 0)
                        continue;

                /* did we find ourself? */
                if (streq(dent->d_name, id_filename))
                        continue;

                if (sd_device_new_from_device_id(&dev_db, dent->d_name) < 0)
                        continue;

                if (sd_device_get_devname(dev_db, &devnode) < 0)
                        continue;

                if (device_get_devlink_priority(dev_db, &db_prio) < 0)
                        continue;

                if (target && db_prio <= priority)
                        continue;

                if (DEBUG_LOGGING) {
                        const char *syspath = NULL;

                        (void) sd_device_get_syspath(dev_db, &syspath);
                        log_debug("Device '%s' claims priority %i for '%s'", strnull(syspath), db_prio, stackdir);
                }

                r = free_and_strdup(&target, devnode);
                if (r < 0)
                        return r;
                priority = db_prio;
        }

        if (!target)
                return -ENOENT;

        *ret = TAKE_PTR(target);
        return 0;
}


/* manage "stack of names" with possibly specified device priorities */
static int link_update(sd_device *dev, const char *slink, bool add) {
        _cleanup_free_ char *filename = NULL, *dirname = NULL;
        char name_enc[PATH_MAX];
        const char *id_filename;
        int i, r, retries;

        assert(dev);
        assert(slink);

        r = device_get_id_filename(dev, &id_filename);
        if (r < 0)
                return log_debug_errno(r, "Failed to get id_filename: %m");

        util_path_encode(slink + STRLEN("/dev"), name_enc, sizeof(name_enc));
        dirname = path_join(NULL, "/run/udev/links/", name_enc);
        if (!dirname)
                return log_oom();
        filename = path_join(NULL, dirname, id_filename);
        if (!filename)
                return log_oom();

        if (!add) {
                if (unlink(filename) == 0)
                        (void) rmdir(dirname);
        } else
                for (;;) {
                        _cleanup_close_ int fd = -1;

                        r = mkdir_parents(filename, 0755);
                        if (!IN_SET(r, 0, -ENOENT))
                                return r;

                        fd = open(filename, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC|O_NOFOLLOW, 0444);
                        if (fd >= 0)
                                break;
                        if (errno != ENOENT)
                                return -errno;
                }

        /* If the database entry is not written yet we will just do one iteration and possibly wrong symlink
         * will be fixed in the second invocation. */
        (void) sd_device_get_is_initialized(dev, &r);
        retries = r > 0 ? LINK_UPDATE_MAX_RETRIES : 1;

        for (i = 0; i < retries; i++) {
                _cleanup_free_ char *target = NULL;
                struct stat st1 = {}, st2 = {};

                r = stat(dirname, &st1);
                if (r < 0 && errno != ENOENT)
                        return -errno;

                r = link_find_prioritized(dev, add, dirname, &target);
                if (r == -ENOENT) {
                        log_debug("No reference left, removing '%s'", slink);
                        if (unlink(slink) == 0)
                                (void) rmdir_parents(slink, "/");

                        break;
                } else if (r < 0)
                        return log_error_errno(r, "Failed to determine highest priority symlink: %m");

                r = node_symlink(dev, target, slink);
                if (r < 0) {
                        (void) unlink(filename);
                        break;
                } else if (r == 1)
                        /* We have replaced already existing symlink, possibly there is some other device trying
                         * to claim the same symlink. Let's do one more iteration to give us a chance to fix
                         * the error if other device actually claims the symlink with higher priority. */
                        continue;

               /* Skip the second stat() if the first failed, stat_inode_unmodified() would return false regardless. */
                if ((st1.st_mode & S_IFMT) != 0) {
                        r = stat(dirname, &st2);
                        if (r < 0 && errno != ENOENT)
                                return -errno;

                        if (stat_inode_unmodified(&st1, &st2))
                                break;
                }
        }

        return i < LINK_UPDATE_MAX_RETRIES ? 0 : -ELOOP;
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
                link_update(dev->device, name, false);
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
                err = log_debug_errno(errno, "cannot stat() node '%s' (%m)", devnode);
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
                        (void) mac_selinux_fix(devnode, LABEL_IGNORE_ENOENT);
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
        char filename[DEV_NUM_PATH_MAX];
        struct udev_list_entry *list_entry;

        log_debug("handling device node '%s', devnum=%s, mode=%#o, uid="UID_FMT", gid="GID_FMT,
                  udev_device_get_devnode(dev), udev_device_get_id_filename(dev), mode, uid, gid);

        if (node_permissions_apply(dev, apply, mode, uid, gid, seclabel_list) < 0)
                return;

        /* always add /dev/{block,char}/$major:$minor */
        xsprintf_dev_num_path(filename,
                              streq(udev_device_get_subsystem(dev), "block") ? "block" : "char",
                              udev_device_get_devnum(dev));
        node_symlink(dev->device, udev_device_get_devnode(dev), filename);

        /* create/update symlinks, add symlinks to name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
                int r;

                r = link_update(dev->device, udev_list_entry_get_name(list_entry), true);
                if (r < 0)
                        log_info_errno(r, "Failed to update device symlinks: %m");
        }
}

void udev_node_remove(struct udev_device *dev) {
        struct udev_list_entry *list_entry;
        char filename[DEV_NUM_PATH_MAX];

        /* remove/update symlinks, remove symlinks from name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
                int r;

                r = link_update(dev->device, udev_list_entry_get_name(list_entry), false);
                if (r < 0)
                        log_info_errno(r, "Failed to update device symlinks: %m");
        }

        /* remove /dev/{block,char}/$major:$minor */
        xsprintf_dev_num_path(filename,
                              streq(udev_device_get_subsystem(dev), "block") ? "block" : "char",
                              udev_device_get_devnum(dev));
        unlink(filename);
}
