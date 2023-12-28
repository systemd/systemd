/* SPDX-License-Identifier: LGPL-2.1-or-later 
 *
 * Copyright © 2023 GNOME Foundation Inc.
 *      Original Author: Adrian Vovk <adrianvovk@gmail.com>
 */

#include <fcntl.h>

#include "constants.h"
#include "copy.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "sd-path.h" // TODO: There's also a basic/path-lookup, which seems to do the same as sd-path... Why? Should we be using it instead?
#include "time-util.h"

static int open_bulk_dir(uint64_t prefix, const char *suffix, const char *type, int *ret) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ const char *path = NULL;
        int r;

        r = sd_path_lookup(prefix, suffix, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to construct path of %s bulk dir: %m", type);

        fd = open_mkdir_at(AT_FDCWD, path, O_CLOEXEC, 0755);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open %s bulk dir: %m", type);

        if (flock(fd, LOCK_EX|LOCK_NV) < 0)
                return log_error_errno("Failed to lock %s bulk dir: %m", type);

        *ret = TAKE_FD(fd);
        return 0;
}

static int fd_unlock_close(int *p) {
        if (*fd < 0)
                return;

        if (flock(*fd, LOCK_UN) < 0)
                log_warning_errno(errno, "Failed to unlock fd, ignoring: %m");

        *fd = safe_close(*fd);
}

static int sync_rm(BulkDir *src, BulkDir *dest) {
        // TODO
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(fd_unlock_close) int sys = -EBADF, home = -EBADF;
        _cleanup_free_ const char *username = NULL, *sys_path = NULL, *home_path = NULL, *timestamp_path = NULL;
        usec_t last_sync = 0;
        int r;

        log_setup();

        /* Open the directories and lock them */
        username = getusername_malloc();
        if (!username)
                return log_oom();
        r = open_bulk_dir(SD_PATH_SYSTEM_STATE_CACHE, strjoina("homed/", username), "system", &sys);
        if (r < 0)
                return r;
        r = open_bulk_dir(SD_PATH_USER_SHARED, "homed/", "home", &sys);
        if (r < 0)
                return r;

        /* Load the timestamp */
        r = sd_path_lookup(SD_PATH_USER_STATE_PRIVATE, "homed-bulk-sync-timestamp", &timestamp_path);
        if (r < 0)
                return log_error_errno(r, "Failed to construct path of timestamp file: %m");
        r = read_timestamp_file(timestamp_path, &last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to load timestamp from %s: %m", timestamp_path);

        /* Propagate deleted files both ways */
        r = sync_rm(sys, home, last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to sync deleted files from system to home bulk dirs: %m");
        r = sync_rm(home, sys, last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to sync deleted files from home to system bulk dirs: %m");

        /* Propagate any new or updated files both ways */
        r = copy_directory_at(c->sys_dfd, ".", c->home_dfd, ".", COPY_MERGE|COPY_REPLACE_UPDATED|COPY_HOLES);
        if (r < 0)
                return log_error_errno(r, "Failed to sync added/updated files from system to home bulk dirs: %m");
        r = copy_directory_at(c->home_dfd, ".", c->sys_dfd, ".", COPY_MERGE|COPY_REPLACE_UPDATED|COPY_HOLES);
        if (r < 0)
                return log_error_errno(r, "Failed to sync added/updated files from home to system bulk dirs: %m");

        /* Update timestamp */
        last_sync = now(CLOCK_MONOTONIC);
        r = write_timestamp_file_atomic(timestamp_path, last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to save last sync timestamp: %m");

        log_info("Synced");
        return 0;
}

DEFINE_MAIN_FUNCTION(run);
