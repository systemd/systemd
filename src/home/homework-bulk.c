/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright © 2024 GNOME Foundation Inc.
 *      Original Author: Adrian Vovk
 */

#include "copy.h"
#include "dirent-util.h"
#include "fileio.h"
#include "fd-util.h"
#include "fs-util.h"
#include "home-util.h"
#include "homework-bulk.h"
#include "homework.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "umask-util.h"
#include "utf8.h"

#define BULK_MAX_SIZE ((off_t)(64U*1024U*1024U))

static int copy_bulk_file(int src_dfd, const char *name, int dest_dfd) {
        _cleanup_close_ int src = -EBADF, dest = -EBADF;
        int r;

        assert(src_dfd >= 0);
        assert(name);
        assert(dest_dfd >= 0);

        src = openat(src_dfd, name, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (src < 0)
                return log_debug_errno(errno, "Failed to open %s in src bulk: %m", name);

        WITH_UMASK(0000) {
                dest = openat(dest_dfd, name, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0644);
                if (dest < 0)
                        return log_debug_errno(errno, "Failed to create/open %s in dest bulk: %m", name);
        }

        r = copy_bytes(src, dest, UINT64_MAX, 0);
        if (r < 0)
                return r;

        if (fchown(dest, 0, 0) < 0)
                return log_debug_errno(errno, "Failed to chown %s in dest bulk: %m", name);

        return 0;
}

static int overwrite_bulk(int src_fd, int dest_fd) {
        _cleanup_close_ int src_dup = -EBADF, dest_dup = -EBADF;
        _cleanup_closedir_ DIR *d = NULL;
        off_t total_size = 0;
        int r;

        assert(src_fd >= 0);
        assert(dest_fd >= 0);

        src_dup = fcntl(src_fd, F_DUPFD_CLOEXEC, 3);
        if (src_dup < 0)
                return log_debug_errno(errno, "failed to duplicate src bulk dir fd: %m");
        dest_dup = fcntl(dest_fd, F_DUPFD_CLOEXEC, 3);
        if (dest_dup < 0)
                return log_debug_errno(errno, "Failed to dupliate dest bulk dir fd: %m");

        r = rm_rf_children(TAKE_FD(dest_dup), REMOVE_PHYSICAL|REMOVE_SUBVOLUME, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to clear dest bulk dir: %m");

        d = take_fdopendir(&src_dup);
        if (!d)
                return log_debug_errno(errno, "Failed to reopen src bulk dir: %m");

        FOREACH_DIRENT_ALL(de, d, return log_debug_errno(errno, "Failed to read src bulk dir: %m")) {
                struct stat st;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        return log_debug_errno(errno, "Failed to stat %s in bulk dir: %m", de->d_name);

                if (!S_ISREG(st.st_mode)) {
                        log_warning("Entry %s in bulk directory is not a regular file. Skipping.", de->d_name);
                        continue;
                }

                if (!ascii_is_valid(de->d_name) || string_has_cc(de->d_name, NULL)) {
                        log_warning("File %s in bulk directory has invalid filename. Skipping.", de->d_name);
                        continue;
                }

                total_size += st.st_size;
                if (total_size > BULK_MAX_SIZE)
                        return -ENOSPC;

                r = copy_bulk_file(src_fd, de->d_name, dest_fd);
                if (r < 0)
                        return r;
        }

        return 0;
}

int home_reconcile_bulk_dirs(UserRecord *h, int root_fd, int reconciled) {
        _cleanup_close_ int sys_fd = -EBADF, embedded_fd = -EBADF;
        _cleanup_free_ char *sys_path = NULL;
        int r;

        assert(h);
        assert(root_fd >= 0);
        assert(reconciled >= 0);

        if (reconciled == USER_RECONCILE_IDENTICAL)
                return 0;

        sys_path = path_join(home_system_bulk_dir(), h->user_name);
        if (!sys_path)
                return log_oom();
        sys_fd = open(sys_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (sys_fd < 0)
                return log_error_errno(errno, "Failed to open system bulk dir %s: %m", sys_path);

        embedded_fd = open_mkdir_at(root_fd, ".identity/bulk", O_CLOEXEC, 0700);
        if (embedded_fd < 0)
                return log_error_errno(embedded_fd, "Failed to create/open embedded bulk dir: %m");

        if (reconciled == USER_RECONCILE_HOST_WON)
                r = overwrite_bulk(sys_fd, embedded_fd);
        else {
                assert(reconciled == USER_RECONCILE_EMBEDDED_WON);
                r = overwrite_bulk(embedded_fd, sys_fd);
        }

        if (r == -ENOSPC)
                return log_error_errno(r, "Bulk directory has exceeded size limit!");

        if (reconciled == USER_RECONCILE_HOST_WON) {
                if (r < 0)
                        return log_error_errno(r, "Failed to replace embedded bulk with system bulk: %m");
                log_info("Replaced embedded bulk dir with contents of system bulk dir.");
        } else {
                if (r < 0)
                        return log_error_errno(r, "Failed to replace system bulk with embedded bulk: %m");
                log_info("Replaced system bulk dir with contents of embedded bulk dir.");
        }
        return 0;
}
