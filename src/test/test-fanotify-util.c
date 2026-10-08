/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "capability-util.h"
#include "errno-util.h"
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
        struct statfs sfs;
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
                ASSERT_EQ(e->vers, (uint8_t) FANOTIFY_METADATA_VERSION);

                if (!FLAGS_SET(e->mask, FAN_CLOSE_WRITE))
                        continue;

                _cleanup_close_ int fd = ASSERT_OK_ERRNO(fanotify_event_open_by_fid(e, c->mount_fd, &c->sfs));

                /* The sfs argument is optional. */
                safe_close(ASSERT_OK_ERRNO(fanotify_event_open_by_fid(e, c->mount_fd, /* sfs= */ NULL)));

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

TEST(fanotify) {
        int r;

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        _cleanup_(context_done) Context c = {
                .mount_fd = ASSERT_OK_ERRNO(open(t, O_DIRECTORY | O_CLOEXEC)),
        };
        ASSERT_OK_ERRNO(fstatfs(c.mount_fd, &c.sfs));

        if (memeqzero(&c.sfs.f_fsid, sizeof(c.sfs.f_fsid)))
                return (void) log_tests_skipped("FAN_REPORT_FID requires non-zero fsid, but it is zero");

        _cleanup_free_ struct file_handle *fh = NULL;
        r = name_to_handle_at_loop(
                        AT_FDCWD, t, &fh,
                        /* ret_mnt_id= */ NULL,
                        /* ret_unique_mnt_id= */ NULL,
                        /* flags= */ 0);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped("file handles not supported");
        ASSERT_OK(r);

        _cleanup_close_ int fd = RET_NERRNO(open_by_handle_at(c.mount_fd, fh, O_CLOEXEC | O_PATH));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fd) || ERRNO_IS_NEG_PRIVILEGE(fd))
                return (void) log_tests_skipped_errno(fd, "open_by_handle_at() failed");
        ASSERT_OK(fd);

        unsigned flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID;
        _cleanup_close_ int fanotify_fd = RET_NERRNO(fanotify_init(flags, O_RDONLY | O_CLOEXEC));
        /* May be blocked by seccomp, or require CAP_SYS_ADMIN in the initial user namespace
         * (e.g. inside an unprivileged container), or fanotify may be disabled in the kernel. */
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fanotify_fd) || ERRNO_IS_NEG_PRIVILEGE(fanotify_fd))
                return (void) log_tests_skipped_errno(fanotify_fd, "fanotify_init() failed");
        ASSERT_OK(fanotify_fd);

        for (size_t i = 0; i < N_FILES; i++) {
                _cleanup_free_ char *p = ASSERT_NOT_NULL(asprintf_safe("%s/f%zu", t, i));

                ASSERT_OK(touch(p));
                r = fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_INODE, FAN_CLOSE_WRITE, AT_FDCWD, p);
                if (r < 0 && errno == EXDEV) /* btrfs with kernel older than 6.8 */
                        return (void) log_tests_skipped("fanotify_mark() failed");
                ASSERT_OK_ERRNO(r);

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

static int intro(void) {
        if (have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return log_tests_skipped("missing CAP_SYS_ADMIN");
        if (have_effective_cap(CAP_DAC_READ_SEARCH) <= 0)
                return log_tests_skipped("missing CAP_DAC_READ_SEARCH");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
