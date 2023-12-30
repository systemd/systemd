/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright © 2023 GNOME Foundation Inc.
 *      Original Author: Adrian Vovk
 */

#include <sys/file.h>

#include "constants.h"
#include "copy.h"
#include "fileio.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "recurse-dir.h"
#include "sd-daemon.h"
#include "sd-path.h" // TODO: There's also a basic/path-lookup, which seems to do the same as sd-path... Why? Should we be using it instead?
#include "time-util.h"
#include "user-util.h"

static int open_bulk_dir(uint64_t prefix, const char *suffix, const char *type, int *ret) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *path = NULL;
        int r;

        r = sd_path_lookup(prefix, suffix, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to construct path of %s bulk dir: %m", type);

        r = mkdir_parents(path, 0700);
        if (r < 0)
                return log_error_errno(fd, "Failed to create parent of %s bulk dir: %m", type);

        fd = open_mkdir_at(AT_FDCWD, path, O_CLOEXEC, 0755);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create and open %s bulk dir: %m", type);

        log_debug("Locking %s bulk dir... (this could take a while!)", type);
        r = RET_NERRNO(flock(fd, LOCK_EX));
        if (r < 0)
                return log_error_errno(errno, "Failed to lock %s bulk dir: %m", type);

        *ret = TAKE_FD(fd);
        return 0;
}

static void fd_unlock_close(int *fd) {
        if (*fd < 0)
                return;

        if (flock(*fd, LOCK_UN) < 0)
                log_warning_errno(errno, "Failed to unlock fd, ignoring: %m");

        *fd = safe_close(*fd);
}

struct sync_delete_userdata {
        int src;
        usec_t last_sync;
};

static int sync_delete_callback(
                RecurseDirEvent event,
                const char *path,
                int dfd,
                int fd, /* unset! */
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {
        struct sync_delete_userdata *data = userdata;
        int action = 0; /* Default: act like unlink() */
        usec_t btime;
        int r;

        if (!IN_SET(event, RECURSE_DIR_ENTRY, RECURSE_DIR_LEAVE))
                /* We use DIR_LEAVE to ensure that we delete a dir only after
                 * we've recursively deleted everything inside of that dir. */
                return RECURSE_DIR_CONTINUE;
        if (event == RECURSE_DIR_LEAVE)
                action = AT_REMOVEDIR; /* act like rmdir() */

        r = RET_NERRNO(faccessat(data->src, path, F_OK, AT_SYMLINK_NOFOLLOW));
        if (r != -ENOENT) {
                if (r < 0)
                        return log_warning_errno(r, "Failed to check if %s exists in src: %m", path);
                else
                        return RECURSE_DIR_CONTINUE;
        }

        log_debug("Potential deleted file: %s", path);

        /* This file or dir exists in dest, but not in src. One of two cases:
         *   The file was created in dest since we last synced, OR
         *   The file was deleted from src */

        btime = statx_timestamp_load(&sx->stx_btime);
        if (btime == USEC_INFINITY) /* Don't know when file was created... play it safe */
                return RECURSE_DIR_CONTINUE;
        if (btime >= data->last_sync) /* File created after last sync */
                return RECURSE_DIR_CONTINUE;

        log_debug("Deleting %s", path);

        /* File was deleted from src. Let's delete it from dest. */
        if (unlinkat(dfd, de->d_name, action) < 0)
                return log_warning_errno(r, "Failed to unlink %s from dest: %m", path);

        return RECURSE_DIR_CONTINUE;
}

static int sync_delete(int src, int dest, usec_t last_sync) {
        /* If we never synced before, we cannot distinguish between
         * files that were deleted in src or files that were created
         * in dest. So, we lean towards the latter option to avoid
         * accidentally deleting something we shouldn't. */
        if (last_sync == USEC_INFINITY)
                return 0;

        return recurse_dir_at(dest, ".", STATX_BTIME, UINT_MAX, RECURSE_DIR_SAME_MOUNT, sync_delete_callback,
                              &(struct sync_delete_userdata) { .src = src, .last_sync = last_sync });
}

static int sync_copy(int src, int dest) {
        return copy_directory_at(src, ".", dest, ".", COPY_MERGE|COPY_REPLACE_UPDATED|COPY_HOLES|COPY_SAME_MOUNT);
}

static int run(int argc, char *argv[]) {
        _cleanup_(fd_unlock_close) int sys = -EBADF, home = -EBADF;
        _cleanup_free_ char *username = NULL, *timestamp_path = NULL;
        usec_t last_sync = USEC_INFINITY;
        int r;

        log_setup();

        /* Load the timestamp */
        r = sd_path_lookup(SD_PATH_USER_STATE_PRIVATE, "homed-bulk-sync-timestamp", &timestamp_path);
        if (r < 0)
                return log_error_errno(r, "Failed to construct path of timestamp file: %m");
        r = read_timestamp_file(timestamp_path, &last_sync);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to load timestamp from %s: %m", timestamp_path);
        log_debug("Last sync was %s", (last_sync != USEC_INFINITY) ? FORMAT_TIMESTAMP(last_sync) : "<NEVER>");

        /* Open the directories and lock them
         * NOTE: We must take sys lock before home lock to avoid deadlock w/ external software. */
        username = getusername_malloc();
        if (!username)
                return log_oom();
        r = open_bulk_dir(SD_PATH_SYSTEM_STATE_CACHE, strjoina("homed/", username), "system", &sys);
        if (r < 0)
                return r;
        r = open_bulk_dir(SD_PATH_USER_SHARED, "homed/", "home", &home);
        if (r < 0)
                return r;

        /* Propagate deleted files both ways */
        log_debug("Propagating deletions: sys → home");
        r = sync_delete(sys, home, last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to sync deleted files from system to home bulk dirs: %m");
        log_debug("Propagating deletions: home → sys");
        r = sync_delete(home, sys, last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to sync deleted files from home to system bulk dirs: %m");

        /* Propagate any new or updated files both ways */
        log_debug("Copying: sys → home");
        r = sync_copy(sys, home);
        if (r < 0)
                return log_error_errno(r, "Failed to sync added/updated files from system to home bulk dirs: %m");
        log_debug("Copying: home → sys");
        r = sync_copy(home, sys);
        if (r < 0)
                return log_error_errno(r, "Failed to sync added/updated files from home to system bulk dirs: %m");

        /* Update timestamp */
        last_sync = now(CLOCK_REALTIME);
        log_debug("Finished sync at %s", FORMAT_TIMESTAMP(last_sync));
        r = write_timestamp_file_atomic(timestamp_path, last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to save last sync timestamp: %m");

        /* Tell the service manager that we're about to quit. This makes the service manager
         * start queueing startup requests, so that if any writes happen between the time that
         * we drop our locks and the service exits we are immediately restarted. We ensure
         * that our notification is processed before we drop our locks via a barrier. */
        sd_notify(false, "STOPPING=1");
        sd_notify_barrier(false, UINT64_MAX);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
