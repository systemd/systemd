/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "sd-login.h"

#include "acl-util.h"
#include "device-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "login-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "udev-acl.h"

#if HAVE_ACL
int devnode_acl(int fd, uid_t uid) {
        bool changed = false, found = false;
        int r;

        assert(fd >= 0);

        _cleanup_(acl_freep) acl_t acl = NULL;
        acl = acl_get_file(FORMAT_PROC_FD_PATH(fd), ACL_TYPE_ACCESS);
        if (!acl)
                return -errno;

        acl_entry_t entry;
        for (r = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
             r > 0;
             r = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry)) {

                acl_tag_t tag;
                if (acl_get_tag_type(entry, &tag) < 0)
                        return -errno;

                if (tag != ACL_USER)
                        continue;

                if (uid > 0) {
                        uid_t *u = acl_get_qualifier(entry);
                        if (!u)
                                return -errno;

                        if (*u == uid) {
                                acl_permset_t permset;
                                if (acl_get_permset(entry, &permset) < 0)
                                        return -errno;

                                int rd = acl_get_perm(permset, ACL_READ);
                                if (rd < 0)
                                        return -errno;

                                int wt = acl_get_perm(permset, ACL_WRITE);
                                if (wt < 0)
                                        return -errno;

                                if (!rd || !wt) {
                                        if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0)
                                                return -errno;

                                        changed = true;
                                }

                                found = true;
                                continue;
                        }
                }

                if (acl_delete_entry(acl, entry) < 0)
                        return -errno;

                changed = true;
        }
        if (r < 0)
                return -errno;

        if (!found && uid > 0) {
                if (acl_create_entry(&acl, &entry) < 0)
                        return -errno;

                if (acl_set_tag_type(entry, ACL_USER) < 0)
                        return -errno;

                if (acl_set_qualifier(entry, &uid) < 0)
                        return -errno;

                acl_permset_t permset;
                if (acl_get_permset(entry, &permset) < 0)
                        return -errno;

                if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0)
                        return -errno;

                changed = true;
        }

        if (!changed)
                return 0;

        if (acl_calc_mask(&acl) < 0)
                return -errno;

        if (acl_set_file(FORMAT_PROC_FD_PATH(fd), ACL_TYPE_ACCESS, acl) < 0)
                return -errno;

        return 0;
}
#endif

int static_node_acl(const char *seat) {
#if HAVE_ACL
        int r, ret = 0;

        /* Don't muck around with ACLs when logind is not running on the system. */
        if (!logind_running())
                return 0;

        if (isempty(seat))
                seat = "seat0";

        _cleanup_closedir_ DIR *dir = opendir("/run/udev/static_node-tags/uaccess/");
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open /run/udev/static_node-tags/uaccess/: %m");
        }

        uid_t uid;
        r = sd_seat_get_active(seat, /* ret_session = */ NULL, &uid);
        if (r < 0) {
                if (!IN_SET(r, -ENXIO, -ENODATA))
                        RET_GATHER(ret, log_warning_errno(r, "Failed to determine active user on seat %s: %m", seat));
                uid = 0;
        }

        FOREACH_DIRENT(de, dir, return -errno) {
                _cleanup_close_ int fd = RET_NERRNO(openat(dirfd(dir), de->d_name, O_CLOEXEC|O_PATH));
                if (ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(fd))
                        continue;
                if (fd < 0) {
                        RET_GATHER(ret, log_warning_errno(fd, "Failed to open '/run/udev/static_node-tags/uaccess/%s': %m", de->d_name));
                        continue;
                }

                struct stat st;
                if (fstat(fd, &st) < 0) {
                        RET_GATHER(ret, log_warning_errno(errno, "Failed to stat '/run/udev/static_node-tags/uaccess/%s': %m", de->d_name));
                        continue;
                }

                r = stat_verify_device_node(&st);
                if (r < 0) {
                        RET_GATHER(ret, log_warning_errno(fd, "'/run/udev/static_node-tags/uaccess/%s' points to a non-device node: %m", de->d_name));
                        continue;
                }

                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                if (sd_device_new_from_stat_rdev(&dev, &st) >= 0) {
                        log_device_debug(dev, "'/run/udev/static_node-tags/uaccess/%s' points to a non-static device node, ignoring.", de->d_name);
                        continue;
                }

                r = devnode_acl(fd, uid);
                if (r >= 0 || r == -ENOENT)
                        continue;

                /* de->d_name is escaped, like "snd\x2ftimer", hence let's use the path to node, if possible. */
                _cleanup_free_ char *node = NULL;
                (void) fd_get_path(fd, &node);

                if (uid != 0) {
                        RET_GATHER(ret, log_warning_errno(r, "Failed to apply ACL on '%s': %m", node ?: de->d_name));

                        /* Better be safe than sorry and reset ACL */
                        r = devnode_acl(fd, /* uid = */ 0);
                        if (r >= 0 || r == -ENOENT)
                                continue;
                }
                if (r < 0)
                        RET_GATHER(ret, log_warning_errno(r, "Failed to flush ACL on '%s': %m", node ?: de->d_name));
        }

        return ret;
#else
        return -EOPNOTSUPP;
#endif
}
