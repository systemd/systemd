/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <sys/file.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "path-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "udev-node.h"
#include "user-util.h"

#define UDEV_NODE_HASH_KEY SD_ID128_MAKE(b9,6a,f1,ce,40,31,44,1a,9e,19,ec,8b,ae,f3,e3,2f)

static int create_symlink(const char *target, const char *slink) {
        int r;

        assert(target);
        assert(slink);

        (void) unlink(slink);

        r = mkdir_parents_label(slink, 0755);
        if (r < 0)
                return r;

        mac_selinux_create_file_prepare(slink, S_IFLNK);
        r = RET_NERRNO(symlink(target, slink));
        mac_selinux_create_file_clear();

        return r;
}

static int node_symlink(sd_device *dev, const char *devnode, const char *slink) {
        _cleanup_free_ char *target = NULL, *slink_tmp = NULL;
        struct stat st;
        int r;

        assert(dev);
        assert(slink);

        if (!devnode) {
                r = sd_device_get_devname(dev, &devnode);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to get device node: %m");
        }

        if (lstat(slink, &st) >= 0) {
                if (!S_ISLNK(st.st_mode))
                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EEXIST),
                                                      "Conflicting inode '%s' found, symlink to '%s' will not be created.",
                                                      slink, devnode);
        } else if (errno != ENOENT)
                return log_device_debug_errno(dev, errno, "Failed to lstat() '%s': %m", slink);

        /* use relative link */
        r = path_make_relative_parent(slink, devnode, &target);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get relative path from '%s' to '%s': %m", slink, devnode);

        r = tempfn_xxxxxx(slink, NULL, &slink_tmp);
        if (r < 0)
                log_device_debug_errno(dev, r,
                                       "Failed to generate temporary file name for symlink '%s', "
                                       "creating symlink non-atomically, ignoring: %m",
                                       slink);

        r = create_symlink(target, slink_tmp ?: slink);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to create symlink '%s' to '%s': %m", slink_tmp ?: slink, target);

        if (slink_tmp && rename(slink_tmp, slink) < 0) {
                r = log_device_debug_errno(dev, errno, "Failed to rename '%s' to '%s': %m", slink_tmp, slink);
                (void) unlink(slink_tmp);
                return r;
        }

        return 0;
}

static int stack_directory_find_prioritized_devnode(sd_device *dev, const char *dirname, bool add, char **ret) {
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ char *devnode = NULL;
        int r, priority = 0;
        const char *id;

        assert(dev);
        assert(dirname);
        assert(ret);

        /* Find device node of device with highest priority. This returns 1 if a device found, 0 if no
         * device found, or a negative errno on error. */

        if (add) {
                const char *n;

                r = device_get_devlink_priority(dev, &priority);
                if (r < 0)
                        return r;

                r = sd_device_get_devname(dev, &n);
                if (r < 0)
                        return r;

                devnode = strdup(n);
                if (!devnode)
                        return -ENOMEM;
        }

        dir = opendir(dirname);
        if (!dir)
                return -errno;

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return r;

        FOREACH_DIRENT_ALL(de, dir, break) {
                _cleanup_free_ char *buf = NULL;
                const char *tmp_devnode;
                int tmp_prio;

                if (de->d_name[0] == '.')
                        continue;

                /* skip ourself */
                if (streq(de->d_name, id))
                        continue;

                r = readlinkat_malloc(dirfd(dir), de->d_name, &buf);
                if (r >= 0) {
                        char *colon;

                        /* New format. The devnode and priority can be obtained from symlink. */

                        colon = strchr(buf, ':');
                        if (!colon || colon == buf)
                                continue;

                        *colon = '\0';

                        if (safe_atoi(buf, &tmp_prio) < 0)
                                continue;

                        if (devnode && tmp_prio <= priority)
                                continue;

                        tmp_devnode = colon + 1;

                } else if (r == -EINVAL) {
                        _cleanup_(sd_device_unrefp) sd_device *tmp_dev = NULL;

                        /* When EINVAL, the file is not a symlink. Assume it is a regular file, which
                         * means the old format. The devnode and priority must be obtained from uevent
                         * and udev database files. */

                        if (sd_device_new_from_device_id(&tmp_dev, de->d_name) < 0)
                                continue;

                        if (device_get_devlink_priority(tmp_dev, &tmp_prio) < 0)
                                continue;

                        if (devnode && tmp_prio <= priority)
                                continue;

                        if (sd_device_get_devname(tmp_dev, &tmp_devnode) < 0)
                                continue;

                } else {
                        log_device_debug_errno(dev, r, "Failed to read symlink %s, ignoring: %m", de->d_name);
                        continue;
                }

                if (isempty(path_startswith(tmp_devnode, "/dev")))
                        continue;

                r = free_and_strdup(&devnode, tmp_devnode);
                if (r < 0)
                        return r;

                priority = tmp_prio;
        }

        *ret = TAKE_PTR(devnode);
        return !!*ret;
}

static int stack_directory_update(sd_device *dev, int fd, bool add) {
        const char *id;
        int r;

        assert(dev);
        assert(fd >= 0);

        r = device_get_device_id(dev, &id);
        if (r < 0)
                return r;

        if (add) {
                _cleanup_free_ char *data = NULL, *buf = NULL;
                const char *devname;
                int priority;

                r = sd_device_get_devname(dev, &devname);
                if (r < 0)
                        return r;

                r = device_get_devlink_priority(dev, &priority);
                if (r < 0)
                        return r;

                if (asprintf(&data, "%i:%s", priority, devname) < 0)
                        return -ENOMEM;

                if (readlinkat_malloc(fd, id, &buf) >= 0 && streq(buf, data))
                        return 0; /* Unchanged. */

                (void) unlinkat(fd, id, 0);

                if (symlinkat(data, fd, id) < 0)
                        return -errno;

        } else {
                if (unlinkat(fd, id, 0) < 0) {
                        if (errno == ENOENT)
                                return 0; /* Unchanged. */
                        return -errno;
                }
        }

        return 1; /* Updated. */
}

static int stack_directory_lock(const char *dirname) {
        _cleanup_close_ int fd = -1;
        int r;

        assert(dirname);

        r = mkdir_parents(dirname, 0755);
        if (r < 0)
                return r;

        fd = open_mkdir_at(AT_FDCWD, dirname, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY, 0700);
        if (fd < 0)
                return fd;

        /* To prevent an arbitrary processe locks the directory. */
        if (fchmod(fd, 0700) < 0)
                return -errno;

        if (flock(fd, LOCK_EX) < 0)
                return -errno;

        return TAKE_FD(fd);
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

static int stack_directory_get_name(const char *slink, char **ret) {
        _cleanup_free_ char *s = NULL, *dirname = NULL;
        char name_enc[NAME_MAX+1];
        const char *name;

        assert(slink);
        assert(ret);

        s = strdup(slink);
        if (!s)
                return -ENOMEM;

        path_simplify(s);

        if (!path_is_normalized(s))
                return -EINVAL;

        name = path_startswith(s, "/dev");
        if (empty_or_root(name))
                return -EINVAL;

        udev_node_escape_path(name, name_enc, sizeof(name_enc));

        dirname = path_join("/run/udev/links", name_enc);
        if (!dirname)
                return -ENOMEM;

        *ret = TAKE_PTR(dirname);
        return 0;
}

static int link_update(sd_device *dev, const char *slink, bool add) {
        _cleanup_free_ char *dirname = NULL, *devnode = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(dev);
        assert(slink);

        r = stack_directory_get_name(slink, &dirname);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to build stack directory name for '%s': %m", slink);

        fd = stack_directory_lock(dirname);
        if (fd < 0)
                return log_device_debug_errno(dev, fd, "Failed to lock stack directory '%s': %m", dirname);

        r = stack_directory_update(dev, fd, add);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to update stack directory '%s': %m", dirname);
        if (r == 0)
                return 0; /* The contents of the stack directory is unchanged. */

        r = stack_directory_find_prioritized_devnode(dev, dirname, add, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to determine device node with the highest priority for '%s': %m", slink);
        if (r > 0)
                return node_symlink(dev, devnode, slink);

        log_device_debug(dev, "No reference left for '%s', removing", slink);

        if (unlink(slink) < 0 && errno != ENOENT)
                log_device_debug_errno(dev, errno, "Failed to remove '%s', ignoring: %m", slink);

        (void) rmdir_parents(slink, "/dev");

        return 0;
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
        const char *devlink;
        int r;

        assert(dev);
        assert(dev_old);

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
        r = node_symlink(dev, NULL, filename);
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

static int udev_node_apply_permissions_impl(
                sd_device *dev, /* can be NULL, only used for logging. */
                int node_fd,
                const char *devnode,
                bool apply_mac,
                mode_t mode,
                uid_t uid,
                gid_t gid,
                OrderedHashmap *seclabel_list) {

        bool apply_mode, apply_uid, apply_gid;
        struct stat stats;
        int r;

        assert(node_fd >= 0);
        assert(devnode);

        if (fstat(node_fd, &stats) < 0)
                return log_device_debug_errno(dev, errno, "cannot stat() node %s: %m", devnode);

        /* If group is set, but mode is not set, "upgrade" mode for the group. */
        if (mode == MODE_INVALID && gid_is_valid(gid) && gid > 0)
                mode = 0660;

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

int udev_node_apply_permissions(
                sd_device *dev,
                bool apply_mac,
                mode_t mode,
                uid_t uid,
                gid_t gid,
                OrderedHashmap *seclabel_list) {

        const char *devnode;
        _cleanup_close_ int node_fd = -1;
        int r;

        assert(dev);

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get devname: %m");

        node_fd = sd_device_open(dev, O_PATH|O_CLOEXEC);
        if (node_fd < 0) {
                if (ERRNO_IS_DEVICE_ABSENT(node_fd)) {
                        log_device_debug_errno(dev, node_fd, "Device node %s is missing, skipping handling.", devnode);
                        return 0; /* This is necessarily racey, so ignore missing the device */
                }

                return log_device_debug_errno(dev, node_fd, "Cannot open node %s: %m", devnode);
        }

        return udev_node_apply_permissions_impl(dev, node_fd, devnode, apply_mac, mode, uid, gid, seclabel_list);
}

int static_node_apply_permissions(
                const char *name,
                mode_t mode,
                uid_t uid,
                gid_t gid,
                char **tags) {

        _cleanup_free_ char *unescaped_filename = NULL;
        _cleanup_close_ int node_fd = -1;
        const char *devnode;
        struct stat stats;
        int r;

        assert(name);

        if (uid == UID_INVALID && gid == GID_INVALID && mode == MODE_INVALID && !tags)
                return 0;

        devnode = strjoina("/dev/", name);

        node_fd = open(devnode, O_PATH|O_CLOEXEC);
        if (node_fd < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", devnode);
                return 0;
        }

        if (fstat(node_fd, &stats) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", devnode);

        if (!S_ISBLK(stats.st_mode) && !S_ISCHR(stats.st_mode)) {
                log_warning("%s is neither block nor character device, ignoring.", devnode);
                return 0;
        }

        if (!strv_isempty(tags)) {
                unescaped_filename = xescape(name, "/.");
                if (!unescaped_filename)
                        return log_oom();
        }

        /* export the tags to a directory as symlinks, allowing otherwise dead nodes to be tagged */
        STRV_FOREACH(t, tags) {
                _cleanup_free_ char *p = NULL;

                p = path_join("/run/udev/static_node-tags/", *t, unescaped_filename);
                if (!p)
                        return log_oom();

                r = mkdir_parents(p, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create parent directory for %s: %m", p);

                r = symlink(devnode, p);
                if (r < 0 && errno != EEXIST)
                        return log_error_errno(errno, "Failed to create symlink %s -> %s: %m", p, devnode);
        }

        return udev_node_apply_permissions_impl(NULL, node_fd, devnode, false, mode, uid, gid, NULL);
}
