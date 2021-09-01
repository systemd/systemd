/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "mkdir.h"
#include "path-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-node.h"
#include "user-util.h"

#define CREATE_LINK_MAX_RETRIES 128
#define LINK_UPDATE_MAX_RETRIES 128
#define TOUCH_FILE_MAX_RETRIES  128
#define UDEV_NODE_HASH_KEY SD_ID128_MAKE(b9,6a,f1,ce,40,31,44,1a,9e,19,ec,8b,ae,f3,e3,2f)

static int create_symlink(const char *target, const char *slink) {
        int r;

        assert(target);
        assert(slink);

        for (unsigned i = 0; i < CREATE_LINK_MAX_RETRIES; i++) {
                r = mkdir_parents_label(slink, 0755);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                mac_selinux_create_file_prepare(slink, S_IFLNK);
                if (symlink(target, slink) < 0)
                        r = -errno;
                else
                        r = 0;
                mac_selinux_create_file_clear();
                if (r != -ENOENT)
                        return r;
        }

        return r;
}

static int node_symlink(sd_device *dev, const char *node, const char *slink) {
        _cleanup_free_ char *slink_dirname = NULL, *target = NULL;
        const char *id, *slink_tmp;
        struct stat stats;
        int r;

        assert(dev);
        assert(node);
        assert(slink);

        r = path_extract_directory(slink, &slink_dirname);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get parent directory of '%s': %m", slink);

        /* use relative link */
        r = path_make_relative(slink_dirname, node, &target);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get relative path from '%s' to '%s': %m", slink, node);

        if (lstat(slink, &stats) >= 0) {
                _cleanup_free_ char *buf = NULL;

                if (!S_ISLNK(stats.st_mode))
                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EEXIST),
                                                      "Conflicting inode '%s' found, link to '%s' will not be created.", slink, node);

                if (readlink_malloc(slink, &buf) >= 0 &&
                    path_equal(target, buf)) {
                        /* preserve link with correct target, do not replace node of other device */
                        log_device_debug(dev, "Preserve already existing symlink '%s' to '%s'", slink, target);

                        (void) label_fix(slink, LABEL_IGNORE_ENOENT);
                        (void) utimensat(AT_FDCWD, slink, NULL, AT_SYMLINK_NOFOLLOW);

                        return 0;
                }
        } else if (errno == ENOENT) {
                log_device_debug(dev, "Creating symlink '%s' to '%s'", slink, target);

                r = create_symlink(target, slink);
                if (r >= 0)
                        return 0;

                log_device_debug_errno(dev, r, "Failed to create symlink '%s' to '%s', trying to replace '%s': %m", slink, target, slink);
        } else
                return log_device_debug_errno(dev, errno, "Failed to lstat() '%s': %m", slink);

        log_device_debug(dev, "Atomically replace '%s'", slink);

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device id: %m");
        slink_tmp = strjoina(slink, ".tmp-", id);

        (void) unlink(slink_tmp);

        r = create_symlink(target, slink_tmp);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to create symlink '%s' to '%s': %m", slink_tmp, target);

        if (rename(slink_tmp, slink) < 0) {
                r = log_device_debug_errno(dev, errno, "Failed to rename '%s' to '%s': %m", slink_tmp, slink);
                (void) unlink(slink_tmp);
                return r;
        }

        /* Tell caller that we replaced already existing symlink. */
        return 1;
}

static int link_find_prioritized(sd_device *dev, bool add, const char *stackdir, char **ret) {
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *target = NULL;
        struct dirent *dent;
        int r, priority = 0;
        const char *id;

        assert(dev);
        assert(stackdir);
        assert(ret);

        /* Find device node of device with highest priority. This returns 1 if a device found, 0 if no
         * device found, or a negative errno. */

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
                if (errno == ENOENT) {
                        *ret = TAKE_PTR(target);
                        return !!*ret;
                }

                return -errno;
        }

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return r;

        FOREACH_DIRENT_ALL(dent, dir, break) {
                _cleanup_(sd_device_unrefp) sd_device *dev_db = NULL;
                const char *devnode;
                int db_prio = 0;

                if (dent->d_name[0] == '\0')
                        break;
                if (dent->d_name[0] == '.')
                        continue;

                log_device_debug(dev, "Found '%s' claiming '%s'", dent->d_name, stackdir);

                /* did we find ourself? */
                if (streq(dent->d_name, id))
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

        *ret = TAKE_PTR(target);
        return !!*ret;
}

size_t udev_node_escape_path(const char *src, char *dest, size_t size) {
        size_t i, j;
        uint64_t h;

        assert(src);
        assert(dest);
        assert(size >= 12);

        for (i = 0, j = 0; src[i] != '\0'; i++) {
                if (src[i] == '/') {
                        if (j+4 >= size - 12 + 1)
                                goto toolong;
                        memcpy(&dest[j], "\\x2f", 4);
                        j += 4;
                } else if (src[i] == '\\') {
                        if (j+4 >= size - 12 + 1)
                                goto toolong;
                        memcpy(&dest[j], "\\x5c", 4);
                        j += 4;
                } else {
                        if (j+1 >= size - 12 + 1)
                                goto toolong;
                        dest[j] = src[i];
                        j++;
                }
        }
        dest[j] = '\0';
        return j;

toolong:
        /* If the input path is too long to encode as a filename, then let's suffix with a string
         * generated from the hash of the path. */

        h = siphash24_string(src, UDEV_NODE_HASH_KEY.bytes);

        for (unsigned k = 0; k <= 10; k++)
                dest[size - k - 2] = urlsafe_base64char((h >> (k * 6)) & 63);

        dest[size - 1] = '\0';
        return size - 1;
}

/* manage "stack of names" with possibly specified device priorities */
static int link_update(sd_device *dev, const char *slink_in, bool add) {
        _cleanup_free_ char *slink = NULL, *filename = NULL, *dirname = NULL;
        const char *slink_name, *id;
        char name_enc[NAME_MAX+1];
        int i, r, retries;

        assert(dev);
        assert(slink_in);

        slink = strdup(slink_in);
        if (!slink)
                return log_oom_debug();

        path_simplify(slink);

        slink_name = path_startswith(slink, "/dev");
        if (!slink_name ||
            empty_or_root(slink_name) ||
            !path_is_normalized(slink_name))
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Invalid symbolic link of device node: %s", slink);

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device id: %m");

        (void) udev_node_escape_path(slink_name, name_enc, sizeof(name_enc));
        dirname = path_join("/run/udev/links/", name_enc);
        if (!dirname)
                return log_oom_debug();

        filename = path_join(dirname, id);
        if (!filename)
                return log_oom_debug();

        if (!add) {
                if (unlink(filename) < 0 && errno != ENOENT)
                        log_device_debug_errno(dev, errno, "Failed to remove %s, ignoring: %m", filename);

                (void) rmdir(dirname);
        } else {
                for (unsigned j = 0; j < TOUCH_FILE_MAX_RETRIES; j++) {
                        /* This may fail with -ENOENT when the parent directory is removed during
                         * creating the file by another udevd worker. */
                        r = touch_file(filename, /* parents= */ true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0444);
                        if (r != -ENOENT)
                                break;
                }
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to create %s: %m", filename);
        }

        /* If the database entry is not written yet we will just do one iteration and possibly wrong symlink
         * will be fixed in the second invocation. */
        retries = sd_device_get_is_initialized(dev) > 0 ? LINK_UPDATE_MAX_RETRIES : 1;

        for (i = 0; i < retries; i++) {
                _cleanup_free_ char *target = NULL;
                struct stat st1 = {}, st2 = {};

                r = stat(dirname, &st1);
                if (r < 0 && errno != ENOENT)
                        return log_device_debug_errno(dev, errno, "Failed to stat %s: %m", dirname);

                r = link_find_prioritized(dev, add, dirname, &target);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to determine highest priority for symlink '%s': %m", slink);
                if (r == 0) {
                        log_device_debug(dev, "No reference left for '%s', removing", slink);

                        if (unlink(slink) < 0 && errno != ENOENT)
                                log_device_debug_errno(dev, errno, "Failed to remove '%s', ignoring: %m", slink);

                        (void) rmdir_parents(slink, "/dev");
                        break;
                }

                r = node_symlink(dev, target, slink);
                if (r < 0)
                        return r;
                if (r == 1)
                        /* We have replaced already existing symlink, possibly there is some other device trying
                         * to claim the same symlink. Let's do one more iteration to give us a chance to fix
                         * the error if other device actually claims the symlink with higher priority. */
                        continue;

                /* Skip the second stat() if the first failed, stat_inode_unmodified() would return false regardless. */
                if ((st1.st_mode & S_IFMT) != 0) {
                        r = stat(dirname, &st2);
                        if (r < 0 && errno != ENOENT)
                                return log_device_debug_errno(dev, errno, "Failed to stat %s: %m", dirname);

                        if (stat_inode_unmodified(&st1, &st2))
                                break;
                }
        }

        return i < LINK_UPDATE_MAX_RETRIES ? 0 : -ELOOP;
}

static int device_get_devpath_by_devnum(sd_device *dev, char **ret) {
        const char *subsystem;
        dev_t devnum;
        int r;

        assert(dev);
        assert(ret);

        r = sd_device_get_subsystem(dev, &subsystem);
        if (r < 0)
                return r;

        r = sd_device_get_devnum(dev, &devnum);
        if (r < 0)
                return r;

        return device_path_make_major_minor(streq(subsystem, "block") ? S_IFBLK : S_IFCHR, devnum, ret);
}

int udev_node_update(sd_device *dev, sd_device *dev_old) {
        _cleanup_free_ char *filename = NULL;
        const char *devnode, *devlink;
        int r;

        assert(dev);
        assert(dev_old);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devnode: %m");

        if (DEBUG_LOGGING) {
                const char *id = NULL;

                (void) device_get_device_id(dev, &id);
                log_device_debug(dev, "Handling device node '%s', devnum=%s", devnode, strna(id));
        }

        /* update possible left-over symlinks */
        FOREACH_DEVICE_DEVLINK(dev_old, devlink) {
                /* check if old link name still belongs to this device */
                if (device_has_devlink(dev, devlink))
                        continue;

                log_device_debug(dev,
                                 "Removing/updating old device symlink '%s', which is no longer belonging to this device.",
                                 devlink);

                r = link_update(dev, devlink, /* add = */ false);
                if (r < 0)
                        log_device_warning_errno(dev, r,
                                                 "Failed to remove/update device symlink '%s', ignoring: %m",
                                                 devlink);
        }

        /* create/update symlinks, add symlinks to name index */
        FOREACH_DEVICE_DEVLINK(dev, devlink) {
                r = link_update(dev, devlink, /* add = */ true);
                if (r < 0)
                        log_device_warning_errno(dev, r,
                                                 "Failed to create/update device symlink '%s', ignoring: %m",
                                                 devlink);
        }

        r = device_get_devpath_by_devnum(dev, &filename);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device path: %m");

        /* always add /dev/{block,char}/$major:$minor */
        r = node_symlink(dev, devnode, filename);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to create device symlink '%s': %m", filename);

        return 0;
}

int udev_node_remove(sd_device *dev) {
        _cleanup_free_ char *filename = NULL;
        const char *devlink;
        int r;

        assert(dev);

        /* remove/update symlinks, remove symlinks from name index */
        FOREACH_DEVICE_DEVLINK(dev, devlink) {
                r = link_update(dev, devlink, /* add = */ false);
                if (r < 0)
                        log_device_warning_errno(dev, r,
                                                 "Failed to remove/update device symlink '%s', ignoring: %m",
                                                 devlink);
        }

        r = device_get_devpath_by_devnum(dev, &filename);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device path: %m");

        /* remove /dev/{block,char}/$major:$minor */
        if (unlink(filename) < 0 && errno != ENOENT)
                return log_device_debug_errno(dev, errno, "Failed to remove '%s': %m", filename);

        return 0;
}

int udev_node_apply_permissions(
                sd_device *dev,
                bool apply_mac,
                mode_t mode,
                uid_t uid,
                gid_t gid,
                OrderedHashmap *seclabel_list) {

        const char *devnode, *subsystem, *id = NULL;
        bool apply_mode, apply_uid, apply_gid;
        _cleanup_close_ int node_fd = -1;
        struct stat stats;
        dev_t devnum;
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
        (void) device_get_device_id(dev, &id);

        if (streq(subsystem, "block"))
                mode |= S_IFBLK;
        else
                mode |= S_IFCHR;

        node_fd = open(devnode, O_PATH|O_NOFOLLOW|O_CLOEXEC);
        if (node_fd < 0) {
                if (errno == ENOENT) {
                        log_device_debug_errno(dev, errno, "Device node %s is missing, skipping handling.", devnode);
                        return 0; /* This is necessarily racey, so ignore missing the device */
                }

                return log_device_debug_errno(dev, errno, "Cannot open node %s: %m", devnode);
        }

        if (fstat(node_fd, &stats) < 0)
                return log_device_debug_errno(dev, errno, "cannot stat() node %s: %m", devnode);

        if ((mode != MODE_INVALID && (stats.st_mode & S_IFMT) != (mode & S_IFMT)) || stats.st_rdev != devnum) {
                log_device_debug(dev, "Found node '%s' with non-matching devnum %s, skipping handling.",
                                 devnode, strna(id));
                return 0; /* We might process a device that already got replaced by the time we have a look
                           * at it, handle this gracefully and step away. */
        }

        apply_mode = mode != MODE_INVALID && (stats.st_mode & 0777) != (mode & 0777);
        apply_uid = uid_is_valid(uid) && stats.st_uid != uid;
        apply_gid = gid_is_valid(gid) && stats.st_gid != gid;

        if (apply_mode || apply_uid || apply_gid || apply_mac) {
                bool selinux = false, smack = false;
                const char *name, *label;

                if (apply_mode || apply_uid || apply_gid) {
                        log_device_debug(dev, "Setting permissions %s, uid=" UID_FMT ", gid=" GID_FMT ", mode=%#o",
                                         devnode,
                                         uid_is_valid(uid) ? uid : stats.st_uid,
                                         gid_is_valid(gid) ? gid : stats.st_gid,
                                         mode != MODE_INVALID ? mode & 0777 : stats.st_mode & 0777);

                        r = fchmod_and_chown(node_fd, mode, uid, gid);
                        if (r < 0)
                                log_device_full_errno(dev, r == -ENOENT ? LOG_DEBUG : LOG_ERR, r,
                                                      "Failed to set owner/mode of %s to uid=" UID_FMT
                                                      ", gid=" GID_FMT ", mode=%#o: %m",
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
                ORDERED_HASHMAP_FOREACH_KEY(label, name, seclabel_list) {
                        int q;

                        if (streq(name, "selinux")) {
                                selinux = true;

                                q = mac_selinux_apply_fd(node_fd, devnode, label);
                                if (q < 0)
                                        log_device_full_errno(dev, q == -ENOENT ? LOG_DEBUG : LOG_ERR, q,
                                                              "SECLABEL: failed to set SELinux label '%s': %m", label);
                                else
                                        log_device_debug(dev, "SECLABEL: set SELinux label '%s'", label);

                        } else if (streq(name, "smack")) {
                                smack = true;

                                q = mac_smack_apply_fd(node_fd, SMACK_ATTR_ACCESS, label);
                                if (q < 0)
                                        log_device_full_errno(dev, q == -ENOENT ? LOG_DEBUG : LOG_ERR, q,
                                                              "SECLABEL: failed to set SMACK label '%s': %m", label);
                                else
                                        log_device_debug(dev, "SECLABEL: set SMACK label '%s'", label);

                        } else
                                log_device_error(dev, "SECLABEL: unknown subsystem, ignoring '%s'='%s'", name, label);
                }

                /* set the defaults */
                if (!selinux)
                        (void) mac_selinux_fix_fd(node_fd, devnode, LABEL_IGNORE_ENOENT);
                if (!smack)
                        (void) mac_smack_apply_fd(node_fd, SMACK_ATTR_ACCESS, NULL);
        }

        /* always update timestamp when we re-use the node, like on media change events */
        r = futimens_opath(node_fd, NULL);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to adjust timestamp of node %s: %m", devnode);

        return 0;
}
