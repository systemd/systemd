/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "libudev-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-node.h"
#include "user-util.h"

static int node_symlink(sd_device *dev, const char *node, const char *slink) {
        _cleanup_free_ char *slink_dirname = NULL, *target = NULL;
        const char *id_filename, *slink_tmp;
        struct stat stats;
        int r;

        assert(dev);
        assert(node);
        assert(slink);

        slink_dirname = dirname_malloc(slink);
        if (!slink_dirname)
                return log_oom();

        /* use relative link */
        r = path_make_relative(slink_dirname, node, &target);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get relative path from '%s' to '%s': %m", slink, node);

        /* preserve link with correct target, do not replace node of other device */
        if (lstat(slink, &stats) == 0) {
                if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {
                        log_device_error(dev, "Conflicting device node '%s' found, link to '%s' will not be created.", slink, node);
                        return -EOPNOTSUPP;
                } else if (S_ISLNK(stats.st_mode)) {
                        _cleanup_free_ char *buf = NULL;

                        if (readlink_malloc(slink, &buf) >= 0 &&
                            streq(target, buf)) {
                                log_device_debug(dev, "Preserve already existing symlink '%s' to '%s'", slink, target);
                                (void) label_fix(slink, LABEL_IGNORE_ENOENT);
                                (void) utimensat(AT_FDCWD, slink, NULL, AT_SYMLINK_NOFOLLOW);
                                return 0;
                        }
                }
        } else {
                log_device_debug(dev, "Creating symlink '%s' to '%s'", slink, target);
                do {
                        r = mkdir_parents_label(slink, 0755);
                        if (!IN_SET(r, 0, -ENOENT))
                                break;
                        mac_selinux_create_file_prepare(slink, S_IFLNK);
                        if (symlink(target, slink) < 0)
                                r = -errno;
                        mac_selinux_create_file_clear();
                } while (r == -ENOENT);
                if (r == 0)
                        return 0;
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to create symlink '%s' to '%s', trying to replace '%s': %m", slink, target, slink);
        }

        log_device_debug(dev, "Atomically replace '%s'", slink);
        r = device_get_id_filename(dev, &id_filename);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get id_filename: %m");
        slink_tmp = strjoina(slink, ".tmp-", id_filename);
        (void) unlink(slink_tmp);
        do {
                r = mkdir_parents_label(slink_tmp, 0755);
                if (!IN_SET(r, 0, -ENOENT))
                        break;
                mac_selinux_create_file_prepare(slink_tmp, S_IFLNK);
                if (symlink(target, slink_tmp) < 0)
                        r = -errno;
                mac_selinux_create_file_clear();
        } while (r == -ENOENT);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to create symlink '%s' to '%s': %m", slink_tmp, target);

        if (rename(slink_tmp, slink) < 0) {
                r = log_device_error_errno(dev, errno, "Failed to rename '%s' to '%s': %m", slink_tmp, slink);
                (void) unlink(slink_tmp);
        }

        return r;
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

                log_device_debug(dev, "Found '%s' claiming '%s'", dent->d_name, stackdir);

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

                log_device_debug(dev_db, "Device claims priority %i for '%s'", db_prio, stackdir);

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
        _cleanup_free_ char *target = NULL, *filename = NULL, *dirname = NULL;
        char name_enc[PATH_MAX];
        const char *id_filename;
        int r;

        assert(dev);
        assert(slink);

        r = device_get_id_filename(dev, &id_filename);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get id_filename: %m");

        util_path_encode(slink + STRLEN("/dev"), name_enc, sizeof(name_enc));
        dirname = path_join("/run/udev/links/", name_enc);
        if (!dirname)
                return log_oom();
        filename = path_join(dirname, id_filename);
        if (!filename)
                return log_oom();

        if (!add && unlink(filename) == 0)
                (void) rmdir(dirname);

        r = link_find_prioritized(dev, add, dirname, &target);
        if (r < 0) {
                log_device_debug(dev, "No reference left, removing '%s'", slink);
                if (unlink(slink) == 0)
                        (void) rmdir_parents(slink, "/");
        } else
                (void) node_symlink(dev, target, slink);

        if (add)
                do {
                        _cleanup_close_ int fd = -1;

                        r = mkdir_parents(filename, 0755);
                        if (!IN_SET(r, 0, -ENOENT))
                                break;
                        fd = open(filename, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC|O_NOFOLLOW, 0444);
                        if (fd < 0)
                                r = -errno;
                } while (r == -ENOENT);

        return r;
}

int udev_node_update_old_links(sd_device *dev, sd_device *dev_old) {
        const char *name, *devpath;
        int r;

        assert(dev);
        assert(dev_old);

        r = sd_device_get_devpath(dev, &devpath);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devpath: %m");

        /* update possible left-over symlinks */
        FOREACH_DEVICE_DEVLINK(dev_old, name) {
                const char *name_current;
                bool found = false;

                /* check if old link name still belongs to this device */
                FOREACH_DEVICE_DEVLINK(dev, name_current)
                        if (streq(name, name_current)) {
                                found = true;
                                break;
                        }

                if (found)
                        continue;

                log_device_debug(dev, "Updating old name, '%s' no longer belonging to '%s'",
                                 name, devpath);
                link_update(dev, name, false);
        }

        return 0;
}

static int node_permissions_apply(sd_device *dev, bool apply_mac,
                                  mode_t mode, uid_t uid, gid_t gid,
                                  OrderedHashmap *seclabel_list) {
        const char *devnode, *subsystem, *id_filename = NULL;
        struct stat stats;
        dev_t devnum;
        bool apply_mode, apply_uid, apply_gid;
        int r;

        assert(dev);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devname: %m");
        r = sd_device_get_subsystem(dev, &subsystem);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get subsystem: %m");
        r = sd_device_get_devnum(dev, &devnum);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devnum: %m");
        (void) device_get_id_filename(dev, &id_filename);

        if (streq(subsystem, "block"))
                mode |= S_IFBLK;
        else
                mode |= S_IFCHR;

        if (lstat(devnode, &stats) < 0)
                return log_device_debug_errno(dev, errno, "cannot stat() node %s: %m", devnode);

        if ((mode != MODE_INVALID && (stats.st_mode & S_IFMT) != (mode & S_IFMT)) || stats.st_rdev != devnum)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EEXIST),
                                              "Found node '%s' with non-matching devnum %s, skip handling",
                                              devnode, id_filename);

        apply_mode = mode != MODE_INVALID && (stats.st_mode & 0777) != (mode & 0777);
        apply_uid = uid_is_valid(uid) && stats.st_uid != uid;
        apply_gid = gid_is_valid(gid) && stats.st_gid != gid;

        if (apply_mode || apply_uid || apply_gid || apply_mac) {
                bool selinux = false, smack = false;
                const char *name, *label;
                Iterator i;

                if (apply_mode || apply_uid || apply_gid) {
                        log_device_debug(dev, "Setting permissions %s, uid=" UID_FMT ", gid=" GID_FMT ", mode=%#o",
                                         devnode,
                                         uid_is_valid(uid) ? uid : stats.st_uid,
                                         gid_is_valid(gid) ? gid : stats.st_gid,
                                         mode != MODE_INVALID ? mode & 0777 : stats.st_mode & 0777);

                        r = chmod_and_chown(devnode, mode, uid, gid);
                        if (r < 0)
                                log_device_warning_errno(dev, r, "Failed to set owner/mode of %s to uid=" UID_FMT ", gid=" GID_FMT ", mode=%#o: %m",
                                                         devnode,
                                                         uid_is_valid(uid) ? uid : stats.st_uid,
                                                         gid_is_valid(gid) ? gid : stats.st_gid,
                                                         mode != MODE_INVALID ? mode & 0777 : stats.st_mode & 0777);
                } else
                        log_device_debug(dev, "Preserve permissions of %s, uid=" UID_FMT ", gid=" GID_FMT ", mode=%#o",
                                         devnode,
                                         uid_is_valid(uid) ? uid : stats.st_uid,
                                         gid_is_valid(gid) ? gid : stats.st_gid,
                                         mode != MODE_INVALID ? mode & 0777 : stats.st_mode & 0777);

                /* apply SECLABEL{$module}=$label */
                ORDERED_HASHMAP_FOREACH_KEY(label, name, seclabel_list, i) {
                        int q;

                        if (streq(name, "selinux")) {
                                selinux = true;

                                q = mac_selinux_apply(devnode, label);
                                if (q < 0)
                                        log_device_error_errno(dev, q, "SECLABEL: failed to set SELinux label '%s': %m", label);
                                else
                                        log_device_debug(dev, "SECLABEL: set SELinux label '%s'", label);

                        } else if (streq(name, "smack")) {
                                smack = true;

                                q = mac_smack_apply(devnode, SMACK_ATTR_ACCESS, label);
                                if (q < 0)
                                        log_device_error_errno(dev, q, "SECLABEL: failed to set SMACK label '%s': %m", label);
                                else
                                        log_device_debug(dev, "SECLABEL: set SMACK label '%s'", label);

                        } else
                                log_device_error(dev, "SECLABEL: unknown subsystem, ignoring '%s'='%s'", name, label);
                }

                /* set the defaults */
                if (!selinux)
                        (void) mac_selinux_fix(devnode, LABEL_IGNORE_ENOENT);
                if (!smack)
                        (void) mac_smack_apply(devnode, SMACK_ATTR_ACCESS, NULL);
        }

        /* always update timestamp when we re-use the node, like on media change events */
        (void) utimensat(AT_FDCWD, devnode, NULL, 0);

        return r;
}

static int xsprintf_dev_num_path_from_sd_device(sd_device *dev, char **ret) {
        char filename[DEV_NUM_PATH_MAX], *s;
        const char *subsystem;
        dev_t devnum;
        int r;

        assert(ret);

        r = sd_device_get_subsystem(dev, &subsystem);
        if (r < 0)
                return r;

        r = sd_device_get_devnum(dev, &devnum);
        if (r < 0)
                return r;

        xsprintf_dev_num_path(filename,
                              streq(subsystem, "block") ? "block" : "char",
                              devnum);

        s = strdup(filename);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int udev_node_add(sd_device *dev, bool apply,
                  mode_t mode, uid_t uid, gid_t gid,
                  OrderedHashmap *seclabel_list) {
        const char *devnode, *devlink;
        _cleanup_free_ char *filename = NULL;
        int r;

        assert(dev);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devnode: %m");

        if (DEBUG_LOGGING) {
                const char *id_filename = NULL;

                (void) device_get_id_filename(dev, &id_filename);
                log_device_debug(dev, "Handling device node '%s', devnum=%s", devnode, strnull(id_filename));
        }

        r = node_permissions_apply(dev, apply, mode, uid, gid, seclabel_list);
        if (r < 0)
                return r;

        r = xsprintf_dev_num_path_from_sd_device(dev, &filename);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device path: %m");

        /* always add /dev/{block,char}/$major:$minor */
        (void) node_symlink(dev, devnode, filename);

        /* create/update symlinks, add symlinks to name index */
        FOREACH_DEVICE_DEVLINK(dev, devlink)
                (void) link_update(dev, devlink, true);

        return 0;
}

int udev_node_remove(sd_device *dev) {
        _cleanup_free_ char *filename = NULL;
        const char *devlink;
        int r;

        assert(dev);

        /* remove/update symlinks, remove symlinks from name index */
        FOREACH_DEVICE_DEVLINK(dev, devlink)
                (void) link_update(dev, devlink, false);

        r = xsprintf_dev_num_path_from_sd_device(dev, &filename);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device path: %m");

        /* remove /dev/{block,char}/$major:$minor */
        (void) unlink(filename);

        return 0;
}
