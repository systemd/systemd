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
#include "install-file.h"
#include "macro.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "sha256.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"

#define BLOB_MAX_SIZE (64U*1024U*1024U)

static int copy_one_blob(
                int src,
                int dest_dfd,
                const char *name,
                uint64_t *total_size,
                uid_t uid,
                Hashmap *manifest) {
        _cleanup_close_ int dest = -EBADF;
        uint8_t hash[SHA256_DIGEST_SIZE];
        off_t initial, size;
        int r;

        if (!hashmap_contains(manifest, name)) {
                log_warning("File %s in blob directory is missing from manifest. Skipping.", name);
                return 0;
        }

        if (!suitable_blob_filename(name)) {
                log_warning("File %s in blob directory has invalid filename. Skipping.", name);
                return 0;
        }

        initial = lseek(src, 0, SEEK_CUR);
        if (initial < 0)
                return log_debug_errno(errno, "Failed to get initial pos on fd for %s in blob: %m", name);

        r = sha256_fd(src, hash);
        if (r < 0)
                return log_debug_errno(r, "Failed to compute sha256 for %s in blob: %m", name);

        size = lseek(src, 0, SEEK_CUR);
        if (size < 0)
                return log_debug_errno(errno, "Failed to get final pos on fd for %s in blob: %m", name);
        size -= initial;

        if (lseek(src, initial, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to rewind fd for %s in blob: %m", name);

        if (memcmp(hash, hashmap_get(manifest, name), SHA256_DIGEST_SIZE) != 0) {
                log_warning("File %s in blob directory has incorrect hash. Skipping.", name);
                return 0;
        }

        *total_size += size;
        if (*total_size > BLOB_MAX_SIZE) {
                log_warning("Blob directory has exceeded its size limit. Not copying any further.");
                return -EOVERFLOW;
        }

        WITH_UMASK(0000) {
                dest = openat(dest_dfd, name, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0644);
                if (dest < 0)
                        return log_debug_errno(errno, "Failed to create/open %s in dest blob: %m", name);
        }

        r = copy_bytes(src, dest, UINT64_MAX, 0);
        if (r < 0)
                return r;

        if (fchown(dest, uid, uid) < 0)
                return log_debug_errno(errno, "Failed to chown %s in dest blob: %m", name);

        return 0;
}

struct blob_copy_data {
        int dest_dfd;
        uint64_t total_size;
        uid_t uid;
        Hashmap *manifest;
};

static int blob_copy_callback(
                RecurseDirEvent event,
                const char *path,
                int dfd,
                int fd, /* unset! */
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        _cleanup_close_ int src = -EBADF;
        struct blob_copy_data *d = ASSERT_PTR(userdata);
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

        src = openat(dfd, de->d_name, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (src < 0)
                return log_debug_errno(errno, "Failed to open %s in src blob: %m", path);

        r = copy_one_blob(src, d->dest_dfd, de->d_name, &d->total_size, d->uid, d->manifest);
        if (r == -EOVERFLOW)
                return RECURSE_DIR_LEAVE_DIRECTORY;
        if (r < 0)
                return r;
        return RECURSE_DIR_CONTINUE;
}

static int replace_blob_at(
                int src_dfd,
                const char *src_name,
                int dest_dfd,
                const char *dest_name,
                Hashmap *manifest,
                mode_t mode,
                uid_t uid) {
        _cleanup_free_ char *fn = NULL;
        _cleanup_close_ int src_fd = -EBADF, dest_fd = -EBADF;
        struct blob_copy_data userdata;
        int r;

        assert(src_dfd >= 0);
        assert(src_name);
        assert(dest_dfd >= 0);
        assert(dest_name);

        src_fd = openat(src_dfd, src_name, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (src_fd < 0) {
                if (errno == ENOENT)
                        return 0;
                return log_debug_errno(errno, "Failed to open src blob dir: %m");
        }

        r = tempfn_random(dest_name, NULL, &fn);
        if (r < 0)
                return r;

        dest_fd = open_mkdir_at(dest_dfd, fn, O_EXCL|O_CLOEXEC, mode);
        if (dest_fd < 0)
                return log_debug_errno(dest_fd, "Failed to create/open dest blob dir: %m");

        /* Note: We do it this way instead of just using FOREACH_DIRENT so that we
         * walk the dirents in alphabetical order and thus behave deterministically
         * w.r.t. what happens if the dir hits its size quota */
        userdata = (struct blob_copy_data) {
                .dest_dfd = dest_fd,
                .total_size = 0,
                .uid = uid,
                .manifest = manifest,
        };
        r = recurse_dir_at(src_fd, ".", STATX_TYPE|STATX_SIZE, UINT_MAX, RECURSE_DIR_SORT,
                           blob_copy_callback, &userdata);
        if (r < 0) {
                r = log_debug_errno(r, "Failed to fill blob dir: %m");
                goto fail;
        }

        if (fchown(dest_fd, uid, uid) < 0) {
                r = log_debug_errno(errno, "Failed to chown dest blob: %m");
                goto fail;
        }

        r = install_file(dest_dfd, fn, dest_dfd, dest_name, INSTALL_REPLACE);
        if (r < 0) {
                r = log_debug_errno(errno, "Failed to move dest blob into place: %m");
                goto fail;
        }

        return 0;

fail:
        (void) rm_rf_at(dest_dfd, fn, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_MISSING_OK);
        return r;
}

int home_reconcile_blob_dirs(UserRecord *h, int root_fd, int reconciled) {
        _cleanup_close_ int sys_base_dfd = -EBADF;
        int r;

        assert(h);
        assert(root_fd >= 0);
        assert(reconciled >= 0);

        if (reconciled == USER_RECONCILE_IDENTICAL)
                return 0;

        sys_base_dfd = open(home_system_blob_dir(), O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (sys_base_dfd < 0)
                return log_error_errno(errno, "Failed to open system blob dir: %m");

        if (reconciled == USER_RECONCILE_HOST_WON) {
                r = replace_blob_at(sys_base_dfd, h->user_name, root_fd, ".identity-bulk",
                                    h->blob_manifest, 0600, h->uid);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace embedded blob with system blob: %m");

                log_info("Replaced embedded blob dir with contents of system blob dir.");
        } else {
                assert(reconciled == USER_RECONCILE_EMBEDDED_WON);

                r = replace_blob_at(root_fd, ".identity-bulk", sys_base_dfd, h->user_name,
                                    h->blob_manifest, 0755, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace system blob with embedded blob: %m");

                log_info("Replaced system blob dir with contents of embedded blob dir.");
        }
        return 0;
}

int home_apply_new_blob_dir(UserRecord *h, Hashmap *blobs) {
        _cleanup_free_ char *fn = NULL;
        _cleanup_close_ int base_dfd = -EBADF, dfd = -EBADF;
        uint64_t total_size;
        const char *filename;
        const void *v;
        int r;

        assert(h);

        if (!blobs) /* Shortcut: If no blobs are passed from dbus, we have nothing to do. */
                return 0;

        base_dfd = open(home_system_blob_dir(), O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (base_dfd < 0)
                return log_error_errno(errno, "Failed to open system blob base dir: %m");

        if (hashmap_isempty(blobs)) {
                /* Shortcut: If blobs was passed but empty, we can simply delete the contents
                 * of the directory. */
                r = rm_rf_at(base_dfd, h->user_name, REMOVE_PHYSICAL|REMOVE_MISSING_OK);
                if (r < 0)
                        return log_error_errno(errno, "Failed to empty out system blob dir: %m");
                return 0;
        }

        r = tempfn_random(h->user_name, NULL, &fn);
        if (r < 0)
                return r;

        dfd = open_mkdir_at(base_dfd, fn, O_EXCL|O_CLOEXEC, 0755);
        if (dfd < 0)
                return log_error_errno(errno, "Failed to create system blob dir: %m");

        HASHMAP_FOREACH_KEY(v, filename, blobs) {
                r = copy_one_blob(PTR_TO_FD(v), dfd, filename, &total_size, 0, h->blob_manifest);
                if (r == -EOVERFLOW)
                        break;
                if (r < 0)
                        goto fail;
        }

        if (fchown(dfd, 0, 0) < 0) {
                r = log_error_errno(errno, "Failed to change ownership of system blob dir: %m");
                goto fail;
        }

        r = install_file(base_dfd, fn, base_dfd, h->user_name, INSTALL_REPLACE);
        if (r < 0) {
                r = log_error_errno(errno, "Failed to move system blob dir into place: %m");
                goto fail;
        }

        log_info("Replaced system blob directory.");
        return 0;

fail:
        (void) rm_rf_at(base_dfd, fn, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_MISSING_OK);
        return r;
}
