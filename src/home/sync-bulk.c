/* SPDX-License-Identifier: LGPL-2.1-or-later 
 *
 * Copyright © 2023 GNOME Foundation Inc.
 *      Original Author: Adrian Vovk <adrianvovk@gmail.com>
 */

#include <fcntl.h>

#include "alloc-util.h"
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

        /* Event loop */
        sd_event *event;
        sd_event_source *sys_inotify;
        sd_event_source *home_inotify;
} Context;

static Context *context_free(Context *c) {
        if (!c)
                return NULL;

        c->sys_dfd = safe_close(c->sys_dfd);
        c->home_dfd = safe_close(c->home_dfd);
        
        c->timestamp_path = mfree(c->timestamp_path);

        c->sys_inotify = sd_event_source_disable_unref(c->sys_inotify);
        c->home_inotify = sd_event_source_disable_unref(c->home_inotify);
        c->event = sd_event_unref(c->event);

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

        /* Disable the inotify event sources so we don't immediately get called again */
        // TODO: Does this actually do anything? There doesn't seem to be any kind of way to skip inotify events
        // TODO: if this does work, switch to oneshot inotify and then turn it back on at the end of sync
        r = sd_event_source_set_enabled(c->sys_inotify, SD_EVENT_OFF);
        if (r >= 0)
                r = sd_event_source_set_enabled(c->home_inotify, SD_EVENT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to disable inotify event sources: %m");

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

        /* Now that we're done, re-enable inotify */
        r = sd_event_source_set_enabled(c->sys_inotify, SD_EVENT_ON);
        if (r >= 0)
                r = sd_event_source_set_enabled(c->home_inotify, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to disable inotify event sources: %m");

        return 0;
}

static int handle_inotify(sd_event_source *src, const struct inotify_event *evt, void *userdata) {
        Context *c = userdata;
        log_info("Received inotify event. Syncing...");
        (void) context_sync(c);
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_freep) Context *c = NULL;
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
        r = xdg_user_config_dir(&c->timestamp_path, "/sd-homed-bulk-sync-timestamp");
        if (r < 0)
                return log_error_errno(r, "Failed to construct path of timestamp file: %m");
        r = read_timestamp_file(c->timestamp_path, &c->last_sync);
        if (r < 0)
                return log_error_errno(r, "Failed to load timestamp from %s: %m", c->timestamp_path);

        /* Set up the event loop */
        r = sd_event_new(&c->event);
        if (r < 0)
                return log_error_errno(r, "Failed to obtain event loop: %m");

        (void) sd_event_set_watchdog(c->event, true);
        (void) sd_event_add_signal(c->event, NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK, NULL, INT_TO_PTR(0));
        (void) sd_event_add_signal(c->event, NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, NULL, INT_TO_PTR(0));
        (void) sd_event_add_signal(c->event, NULL, SIGRTMIN+18|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, NULL);

        /* Set up inotify watch for the directories */
        r = sd_event_add_inotify_fd(c->event, &c->sys_inotify, c->sys_dfd,
                                    IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE|IN_ONLYDIR,
                                    handle_inotify, c);
        if (r < 0)
                return log_error_errno(r, "Failed to set up inotify for system bulk dir: %m");
        r = sd_event_add_inotify_fd(c->event, &c->home_inotify, c->home_dfd,
                                    IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE|IN_ONLYDIR,
                                    handle_inotify, c);
        if (r < 0)
                return log_error_errno(r, "Failed to set up inotify for home bulk dir: %m");

        /* Sync in case things have changed */
        r = context_sync(c);
        if (r < 0)
                return log_error_errno(r, "Failed to perform first sync: %m");

        /* Run the loop */
        return sd_event_loop(c->event);
        
}

DEFINE_MAIN_FUNCTION(run);
