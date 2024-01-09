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
#include "homework-blob.h"
#include "homework.h"
#include "macro.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "string-util.h"
#include "umask-util.h"
#include "utf8.h"

#define BLOB_MAX_SIZE (64U*1024U*1024U)

struct blob_overwrite_data {
        int dest_dfd;
        uint64_t total_size;
        uid_t uid;
};

static int blob_overwrite_callback(
                RecurseDirEvent event,
                const char *path,
                int dfd,
                int fd, /* unset! */
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        _cleanup_close_ int src = -EBADF, dest = -EBADF;
        struct blob_overwrite_data *d = ASSERT_PTR(userdata);
        int r;

        if (event == RECURSE_DIR_ENTER) {
                log_warning("Entry %s in blob directory is a directory. Skipping.", de->d_name);
                return RECURSE_DIR_SKIP_ENTRY;
        }
        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (!S_ISREG(sx->stx_mode)) {
                log_warning("Entry %s in blob directory is not a regular file. Skipping.", de->d_name);
                return RECURSE_DIR_CONTINUE;
        }

        if (!ascii_is_valid(de->d_name) || string_has_cc(de->d_name, NULL)) {
                log_warning("File %s in blob directory has invalid filename. Skipping.", de->d_name);
                return RECURSE_DIR_CONTINUE;
        }

        d->total_size += sx->stx_size;
        if (d->total_size > BLOB_MAX_SIZE) {
                log_warning("Blob directory has exceeded its size limit. Not copying any further.");
                return RECURSE_DIR_LEAVE_DIRECTORY;
        }

        src = openat(dfd, de->d_name, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (src < 0)
                return log_debug_errno(errno, "Failed to open %s in src blob: %m", path);

        WITH_UMASK(0000) {
                dest = openat(d->dest_dfd, path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0644);
                if (dest < 0)
                        return log_debug_errno(errno, "Failed to create/open %s in dest blob: %m", path);
        }

        r = copy_bytes(src, dest, UINT64_MAX, 0);
        if (r < 0)
                return r;

        if (fchown(dest, d->uid, d->uid) < 0)
                return log_debug_errno(errno, "Failed to chown %s in dest blob: %m", path);

        return RECURSE_DIR_CONTINUE;
}

static int overwrite_blob(int src_fd, int dest_fd, uid_t uid) {
        _cleanup_close_ int dest_dup = -EBADF;
        struct blob_overwrite_data userdata = {
                .dest_dfd = dest_fd,
                .total_size = 0,
                .uid = uid,
        };
        int r;

        assert(src_fd >= 0);
        assert(dest_fd >= 0);

        dest_dup = fcntl(dest_fd, F_DUPFD_CLOEXEC, 3);
        if (dest_dup < 0)
                return log_debug_errno(errno, "Failed to dupliate dest blob dir fd: %m");

        r = rm_rf_children(TAKE_FD(dest_dup), REMOVE_PHYSICAL|REMOVE_SUBVOLUME, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to clear dest blob dir: %m");

        if (fchown(dest_fd, uid, uid) < 0)
                return log_debug_errno(r, "Failed to chown dest blob: %m");

        return recurse_dir_at(src_fd, ".", STATX_TYPE|STATX_SIZE, UINT_MAX, RECURSE_DIR_SORT,
                              blob_overwrite_callback, &userdata);
}

int home_reconcile_blob_dirs(UserRecord *h, int root_fd, int reconciled) {
        _cleanup_close_ int sys_fd = -EBADF, embedded_fd = -EBADF;
        _cleanup_free_ char *sys_path = NULL;
        int r;

        assert(h);
        assert(root_fd >= 0);
        assert(reconciled >= 0);

        if (reconciled == USER_RECONCILE_IDENTICAL)
                return 0;

        sys_path = path_join(home_system_blob_dir(), h->user_name);
        if (!sys_path)
                return log_oom();
        sys_fd = open(sys_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (sys_fd < 0)
                return log_error_errno(errno, "Failed to open system blob dir %s: %m", sys_path);

        embedded_fd = open_mkdir_at(root_fd, ".identity-blob", O_CLOEXEC, 0700);
        if (embedded_fd < 0)
                return log_error_errno(embedded_fd, "Failed to create/open embedded blob dir: %m");

        if (reconciled == USER_RECONCILE_HOST_WON) {
                r = overwrite_blob(sys_fd, embedded_fd, h->uid);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace embedded blob with system blob: %m");

                log_info("Replaced embedded blob dir with contents of system blob dir.");
        } else {
                assert(reconciled == USER_RECONCILE_EMBEDDED_WON);

                r = overwrite_blob(embedded_fd, sys_fd, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace system blob with embedded blob: %m");

                log_info("Replaced system blob dir with contents of embedded blob dir.");
        }
        return 0;
}
