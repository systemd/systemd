/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright © 2024 GNOME Foundation Inc.
 *      Original Author: Adrian Vovk
 */

#include "copy.h"
#include "fileio.h"
#include "fd-util.h"
#include "fs-util.h"
#include "home-util.h"
#include "homework-bulk.h"
#include "homework.h"
#include "macro.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "string-util.h"
#include "umask-util.h"
#include "utf8.h"

#define BULK_MAX_SIZE (64U*1024U*1024U)

struct bulk_overwrite_data {
        int dest_dfd;
        uint64_t total_size;
};

static int bulk_overwrite_callback(
                RecurseDirEvent event,
                const char *path,
                int dfd,
                int fd, /* unset! */
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        _cleanup_close_ int src = -EBADF, dest = -EBADF;
        struct bulk_overwrite_data *d = ASSERT_PTR(userdata);
        int r;

        if (event == RECURSE_DIR_ENTER) {
                log_warning("Entry %s in bulk directory is a directory. Skipping.", de->d_name);
                return RECURSE_DIR_SKIP_ENTRY;
        }
        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (!S_ISREG(sx->stx_mode)) {
                log_warning("Entry %s in bulk directory is not a regular file. Skipping.", de->d_name);
                return RECURSE_DIR_CONTINUE;
        }

        if (!ascii_is_valid(de->d_name) || string_has_cc(de->d_name, NULL)) {
                log_warning("File %s in bulk directory has invalid filename. Skipping.", de->d_name);
                return RECURSE_DIR_CONTINUE;
        }

        d->total_size += sx->stx_size;
        if (d->total_size > BULK_MAX_SIZE) {
                log_warning("Bulk directory has exceeded its size limit. Not copying any further.");
                return RECURSE_DIR_LEAVE_DIRECTORY;
        }

        src = openat(dfd, de->d_name, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (src < 0)
                return log_debug_errno(errno, "Failed to open %s in src bulk: %m", path);

        WITH_UMASK(0000) {
                dest = openat(d->dest_dfd, path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0644);
                if (dest < 0)
                        return log_debug_errno(errno, "Failed to create/open %s in dest bulk: %m", path);
        }

        r = copy_bytes(src, dest, UINT64_MAX, 0);
        if (r < 0)
                return r;

        if (fchown(dest, 0, 0) < 0)
                return log_debug_errno(errno, "Failed to chown %s in dest bulk: %m", path);

        return RECURSE_DIR_CONTINUE;
}

static int overwrite_bulk(int src_fd, int dest_fd) {
        _cleanup_close_ int dest_dup = -EBADF;
        struct bulk_overwrite_data userdata = {
                .dest_dfd = dest_fd,
                .total_size = 0,
        };
        int r;

        assert(src_fd >= 0);
        assert(dest_fd >= 0);

        dest_dup = fcntl(dest_fd, F_DUPFD_CLOEXEC, 3);
        if (dest_dup < 0)
                return log_debug_errno(errno, "Failed to dupliate dest bulk dir fd: %m");

        r = rm_rf_children(TAKE_FD(dest_dup), REMOVE_PHYSICAL|REMOVE_SUBVOLUME, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to clear dest bulk dir: %m");

        return recurse_dir_at(src_fd, ".", STATX_TYPE|STATX_SIZE, UINT_MAX, RECURSE_DIR_SORT,
                              bulk_overwrite_callback, &userdata);
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

        if (reconciled == USER_RECONCILE_HOST_WON) {
                r = overwrite_bulk(sys_fd, embedded_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace embedded bulk with system bulk: %m");

                log_info("Replaced embedded bulk dir with contents of system bulk dir.");
        } else {
                assert(reconciled == USER_RECONCILE_EMBEDDED_WON);

                r = overwrite_bulk(embedded_fd, sys_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace system bulk with embedded bulk: %m");

                log_info("Replaced system bulk dir with contents of embedded bulk dir.");
        }
        return 0;
}

int home_apply_new_bulk_dir(UserRecord *h) {
        _cleanup_free_ char *new_path = NULL, *sys_path = NULL;
        _cleanup_close_ int new_fd = -EBADF, sys_fd = -EBADF;
        int r;

        r = user_record_steal_bulk_dir(h, &new_path);
        if (r == -ENOENT) /* No new bulk dir path was specified */
                return 0;
        if (r < 0)
                return r;

        new_fd = open(new_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (new_fd < 0)
                return log_error_errno(errno, "Failed to open replacement bulk dir %s: %m", new_path);

        sys_path = path_join(home_system_bulk_dir(), h->user_name);
        if (!sys_path)
                return log_oom();
        sys_fd = open(sys_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (sys_fd < 0)
                return log_error_errno(errno, "Failed to open system bulk dir %s: %m", sys_path);

        r = overwrite_bulk(new_fd, sys_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to replace system bulk directory with %s: %m", new_path);

        log_info("Replaced system bulk directory with contents of %s.", new_path);
        return 0;
}
