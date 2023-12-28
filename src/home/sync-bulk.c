/* SPDX-License-Identifier: LGPL-2.1-or-later 
 *
 * Copyright © 2023 GNOME Foundation Inc.
 *      Original Author: Adrian Vovk <adrianvovk@gmail.com>
 */

#include <fcntl.h>

#include "alloc-util.h"
#include "constants.h"
#include "common-signal.h"
#include "copy.h"
#include "fileio.h"
#include "log.h"
#include "main-func.h"
#include "path-lookup.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "time-util.h"

typedef struct Context {
        /* Open system and home bulk dirs */
        int sys_dfd;
        int home_dfd;

        /* Timestamp of our last sync */
        const char *timestamp_path;
        usec_t last_sync;
} Context;

static Context *context_free(Context *c) {
        if (!c)
                return NULL;

        c->sys_dfd = safe_close(c->sys_dfd);
        c->home_dfd = safe_close(c->home_dfd);
        c->timestamp_path = mfree(c->timestamp_path);
        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Context*, context_free);

static Context *context_new(Context **ret) {
        _cleanup_(context_freep) Context *c = NULL;
        int r;

        c = new(Context, 1);
        if (!c)
                return log_oom();

        *c = (Context) {
                .sys_dfd = NULL,
                .home_dfd = NULL,
                .timestamp_path = NULL,
                .last_sync = 0, /* Ensures we don't delete things in sync_rm */
                .event = NULL,
                .sys_inotify = NULL,
                .home_inotify = NULL,
        }

        *ret = TAKE_PTR(c);
        return 0;
}

static inline int fd_lock(int fd) {
        if (flock(fd, LOCK_EX|LOCK_NV) < 0)
                return -errno;
        return dfd;
}

static inline void fd_unlock(int *fd) {
        if (*fd < 0)
                return;

        if (flock(*fd, LOCK_UN) < 0)
                log_warning_errno(errno, "Failed to unlock fd, ignoring: %m");
        *fd = -EBADF;
}

static int sync_rm(BulkDir *src, BulkDir *dest) {
        // TODO
        return 0;
}

static int context_sync(Context *c) {
        _cleanup_(fd_unlock) int sys_locked = -EBADF, home_locked = -EBADF;
        CopyFlags flags;
        int r;

        assert(c);
        sd_notify(false, "STATUS=Syncing bulk dirs");

        /* Lock the directories while we sync them */
        sys_locked = fd_lock(c->sys_dfd);
        if (sys_locked < 0)
                return log_error_errno(sys_locked, "Failed to lock system bulk dir: %m");
        home_locked = fd_lock(c->home_dfd);
        if (home_locked < 0)
                return log_error_errno(home_locked, "Failed to lock home bulk dir: %m");

        /* Propagate deleted files both ways */
        r = sync_rm(c->sys_dfd, c->home_dfd);
        if (r < 0)
                return log_error_errno(r, "Failed to sync deleted files from system to home bulk dirs: %m");
        r = sync_rm(c->home_dfd, c->sys_dfd);
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
        c->last_sync = now(CLOCK_MONOTONIC);
        r = write_timestamp_file_atomic(c->timestamp_path, c->last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to save last sync timestamp: %m");

        sd_notify(false, "STATUS=Waiting for inotify events");
        return 0;
}

static int handle_inotify(sd_event_source *src, const struct inotify_event *evt, void *userdata) {
        Context *c = userdata;

        log_info("Received inotify event. Syncing...");
        (void) context_sync(c);
}

static int event_loop_with_timeout(sd_event *e, usec_t timeout) {
        int r, exit;

        for (;;) {
                r = sd_event_get_state(e);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        break;

                r = sd_event_run(e, timeout);
                if (r < 0)
                        return r;

                if (r == 0) {
                        sd_notify(false, "STOPPING=1");
                        log_info("Quitting due to idle.");
                        return 0;
                }
        }

        r = sd_event_get_exit_code(e, &exit);
        if (r < 0)
                return r;
        return exit;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_freep) Context *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        log_setup();

        r = context_new(&c);
        if (r < 0)
                return r;

        /* Open the two directories we're going to be syncing */
        c->sys_dfd = open_mkdir_at(AT_FDCWD, "/TODO", O_CLOEXEC, 0755); // TODO: system path
        if (c->sys_dfd < 0)
                return log_error_errno(c->sys_dfd, "Failed to open system bulk dir: %m");
        c->home_dfd = open_mkdir_at(AT_FDCWD, "/TODO", O_CLOEXEC, 0755); // TODO: home path
        if (c->home_dfd < 0)
                return log_error_errno(c->home_dfd, "Failed to open home bulk dir: %m");

        /* Load the timestamp */
        r = xdg_user_state_dir(&c->timestamp_path, "/sd-homed-bulk-sync-timestamp");
        if (r < 0)
                return log_error_errno(r, "Failed to construct path of timestamp file: %m");
        r = read_timestamp_file(c->timestamp_path, &c->last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to load timestamp from %s: %m", c->timestamp_path);

        /* Set up the event loop
         *
         * This service is automatically started by the service manager whenever a sync needs
         * to be performed, via a .path unit that set up inotify watches on the two directories
         * we're interested in. However, while this service is running, more events might come in
         * that we need to handle; the .path unit will do nothing in this case since the service
         * is already running. Hence, we run our own event loop with our own inotify watches: this
         * allows us to wait for activity in the directory to "stabilize"
         */
        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to obtain event loop: %m");

        (void) sd_event_add_signal(event, NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK, NULL, INT_TO_PTR(0));
        (void) sd_event_add_signal(event, NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, NULL, INT_TO_PTR(0));
        (void) sd_event_add_signal(event, NULL, SIGRTMIN+18|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, NULL);

        /* Set up inotify watch for the directories */
        r = sd_event_add_inotify_fd(event, NULL, c->sys_dfd,
                                    IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE|IN_ONLYDIR,
                                    handle_inotify, c);
        if (r < 0)
                return log_error_errno(r, "Failed to set up inotify for system bulk dir: %m");
        r = sd_event_add_inotify_fd(event, NULL, c->home_dfd,
                                    IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE|IN_ONLYDIR,
                                    handle_inotify, c);
        if (r < 0)
                return log_error_errno(r, "Failed to set up inotify for home bulk dir: %m");

        /* Tell the service manager that we're all set up */
        sd_notify(false, "READY=1");

        /* Perform the sync we were started to do */
        r = context_sync(c);
        if (r < 0)
                return log_error_errno(r, "Failed to sync: %m");

        /* Run the loop */
        return event_loop_with_timeout(event, DEFAULT_EXIT_USEC);
}

DEFINE_MAIN_FUNCTION(run);
