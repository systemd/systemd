/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "capability-util.h"
#include "fanotify-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mountpoint-util.h"
#include "rm-rf.h"
#include "set.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "tests.h"

#define N_FILES 10

typedef struct Context {
        int mount_fd;
        bool use_fid;
        Set *stats;
} Context;

static void context_done(Context *c) {
        assert(c);

        safe_close(c->mount_fd);
        set_free(c->stats);
}

static int on_fanotify(sd_event_source *s, int fanotify_fd, uint32_t revents, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        union fanotify_event_buffer buffer;
        ssize_t n = ASSERT_OK_ERRNO(read(fanotify_fd, &buffer, sizeof buffer));

        FOREACH_FANOTIFY_EVENT(e, buffer, n) {
                _unused_ _cleanup_close_ int event_fd = e->fd;

                ASSERT_EQ(e->vers, (uint8_t) FANOTIFY_METADATA_VERSION);
                if (!FLAGS_SET(e->mask, FAN_CLOSE_WRITE))
                        continue;

                _cleanup_close_ int fd_close = -EBADF;
                int fd = ASSERT_OK(fanotify_event_get_fd(e, c->mount_fd, /* sfs= */ NULL, &fd_close));

                /* A negative mount_fd or a NULL ret_fd_close are only fatal in FID mode; in classic mode the
                 * event already carries the fd, so they are ignored. */
                if (c->use_fid) {
                        int dummy = 42;
                        ASSERT_ERROR(fanotify_event_get_fd(e, -EBADF, /* sfs= */ NULL, &dummy), EINVAL);
                        ASSERT_EQ(dummy, 42);
                        ASSERT_ERROR(fanotify_event_get_fd(e, c->mount_fd, /* sfs= */ NULL, /* ret_fd_close= */ NULL), EINVAL);
                } else {
                        int dummy;
                        ASSERT_EQ(fanotify_event_get_fd(e, -EBADF, /* sfs= */ NULL, &dummy), e->fd);
                        ASSERT_EQ(dummy, -EBADF);
                        ASSERT_EQ(fanotify_event_get_fd(e, c->mount_fd, /* sfs= */ NULL, /* ret_fd_close= */ NULL), e->fd);
                }

                struct stat st;
                ASSERT_OK_ERRNO(fstat(fd, &st));
                _unused_ _cleanup_free_ struct stat *found = ASSERT_NOT_NULL(set_remove(c->stats, &st));

                /* Stop watching this inode. */
                ASSERT_OK(fanotify_mark_fd(fanotify_fd, FAN_MARK_REMOVE | FAN_MARK_INODE, FAN_CLOSE_WRITE, fd));
        }

        if (set_isempty(c->stats))
                return sd_event_exit(sd_event_source_get_event(s), 0);

        return 0;
}

static void test_fanotify(bool use_fid) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        unsigned flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK;

        /* open_by_handle_at() only works on file systems that support file handles. */
        if (use_fid) {
                if (ASSERT_OK_OR(name_to_handle_at_loop(
                                             AT_FDCWD, t,
                                             /* ret_handle= */ NULL,
                                             /* ret_mnt_id= */ NULL,
                                             /* ret_unique_mnt_id= */ NULL,
                                             /* flags= */ 0),
                                 -EOPNOTSUPP) < 0)
                        return (void) log_tests_skipped("file handles not supported");

                flags |= FAN_REPORT_FID;
        }

        _cleanup_close_ int fanotify_fd = ASSERT_OK_ERRNO(fanotify_init(flags, O_RDONLY | O_CLOEXEC));

        _cleanup_(context_done) Context c = {
                .mount_fd = ASSERT_OK_ERRNO(open(t, O_DIRECTORY | O_CLOEXEC)),
                .use_fid = use_fid,
        };

        for (size_t i = 0; i < N_FILES; i++) {
                _cleanup_free_ char *p = ASSERT_NOT_NULL(asprintf_safe("%s/f%zu", t, i));

                ASSERT_OK(touch(p));
                ASSERT_OK_ERRNO(fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_INODE, FAN_CLOSE_WRITE, AT_FDCWD, p));

                _cleanup_free_ struct stat *st = ASSERT_NOT_NULL(new(struct stat, 1));
                ASSERT_OK_ERRNO(stat(p, st));
                ASSERT_OK(set_ensure_consume(&c.stats, &inode_hash_ops, TAKE_PTR(st)));

                /* Trigger a FAN_CLOSE_WRITE for this file. */
                safe_close(ASSERT_OK_ERRNO(open(p, O_WRONLY | O_CLOEXEC)));
        }

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_new(&event));

        ASSERT_OK(sd_event_add_io(event, /* ret= */ NULL, fanotify_fd, EPOLLIN, on_fanotify, &c));
        ASSERT_OK(sd_event_add_time_relative(event, /* ret= */ NULL,
                                             CLOCK_MONOTONIC, 30 * USEC_PER_SEC, /* accuracy= */ 0,
                                             /* callback= */ NULL, INT_TO_PTR(-ETIMEDOUT)));

        ASSERT_OK(sd_event_loop(event));
}

TEST(fanotify_classic) {
        test_fanotify(false);
}

TEST(fanotify_fid) {
        if (have_effective_cap(CAP_DAC_READ_SEARCH) <= 0)
                return (void) log_tests_skipped("missing CAP_DAC_READ_SEARCH");

        test_fanotify(true);
}

static int intro(void) {
        if (have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return log_tests_skipped("missing CAP_SYS_ADMIN");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
