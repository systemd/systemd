/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"

#include "errno-util.h"
#include "fd-util.h"
#include "lock-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

TEST(make_lock_file) {
        /* Exclusive locks must exclude other callers, while shared locks may coexist. A temporary
         * directory contains the lock file, which must be removed when its last holder releases it. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_(release_lock_file) LockFile lock1 = LOCK_FILE_INIT, lock2 = LOCK_FILE_INIT;

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        ASSERT_OK(make_lock_file_at(tfd, "lock", LOCK_EX, &lock1));
        ASSERT_OK_ERRNO(faccessat(tfd, "lock", F_OK, 0));
        ASSERT_ERROR(make_lock_file_at(tfd, "lock", LOCK_EX|LOCK_NB, &lock2), EBUSY);
        release_lock_file(&lock1);
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "lock", F_OK, 0)), ENOENT);
        ASSERT_OK(make_lock_file_at(tfd, "lock", LOCK_EX, &lock2));
        release_lock_file(&lock2);
        ASSERT_OK(make_lock_file_at(tfd, "lock", LOCK_SH, &lock1));
        ASSERT_OK_ERRNO(faccessat(tfd, "lock", F_OK, 0));
        ASSERT_OK(make_lock_file_at(tfd, "lock", LOCK_SH, &lock2));
        release_lock_file(&lock1);
        ASSERT_OK_ERRNO(faccessat(tfd, "lock", F_OK, 0));
        release_lock_file(&lock2);

        ASSERT_OK_ERRNO(fchdir(tfd));
        ASSERT_OK(make_lock_file_at(tfd, "lock", LOCK_EX, &lock1));
        ASSERT_ERROR(make_lock_file("lock", LOCK_EX|LOCK_NB, &lock2), EBUSY);
}

static void test_lock_generic_with_timeout_for_type(LockType type) {
        _cleanup_(unlink_tempfilep) char path[] = "/var/tmp/test-lock-util.XXXXXX";
        _cleanup_close_ int tfd = -EBADF, tfd2 = -EBADF;

        tfd = ASSERT_OK(mkostemp_safe(path));
        tfd2 = ASSERT_OK(fd_reopen(tfd, O_RDWR));

        ASSERT_OK(lock_generic(tfd, type, LOCK_EX));
        ASSERT_ERROR(lock_generic(tfd2, type, LOCK_EX|LOCK_NB), EWOULDBLOCK);

        usec_t start = now(CLOCK_MONOTONIC);
        ASSERT_ERROR(lock_generic_with_timeout(tfd2, type, LOCK_EX, 200 * USEC_PER_MSEC), ETIMEDOUT);
        ASSERT_GE(usec_sub_unsigned(now(CLOCK_MONOTONIC), start), 200 * USEC_PER_MSEC);
        ASSERT_ERROR_ERRNO(waitpid(-1, NULL, WNOHANG), ECHILD);

        ASSERT_OK(lock_generic(tfd, type, LOCK_UN));
        ASSERT_OK_ZERO(lock_generic_with_timeout(tfd2, type, LOCK_EX, 200 * USEC_PER_MSEC));
        ASSERT_ERROR(lock_generic(tfd, type, LOCK_EX|LOCK_NB), EWOULDBLOCK);
}

TEST(lock_generic_with_timeout) {
        /* Two descriptions of a temporary file must contend for BSD and OFD locks. A timed-out worker
         * must be reaped, and acquisition must succeed after the original holder releases its lock. */
        test_lock_generic_with_timeout_for_type(LOCK_BSD);
        test_lock_generic_with_timeout_for_type(LOCK_UNPOSIX);
}

TEST(lock_generic_with_timeout_infinity) {
        /* An unlimited wait must acquire the lock in the caller, including POSIX locks. A child opens
         * a second description of the temporary file and must fail to acquire a nonblocking lock. */
        LockType type;

        FOREACH_ARGUMENT(type, LOCK_BSD, LOCK_POSIX, LOCK_UNPOSIX) {
                _cleanup_(unlink_tempfilep) char path[] = "/var/tmp/test-lock-infinity.XXXXXX";
                _cleanup_close_ int fd = ASSERT_OK(mkostemp_safe(path));
                int status;

                ASSERT_OK_ZERO(lock_generic_with_timeout(fd, type, LOCK_EX, USEC_INFINITY));
                pid_t pid = fork();
                ASSERT_OK_ERRNO(pid);
                if (pid == 0) {
                        _cleanup_close_ int other = ASSERT_OK(fd_reopen(fd, O_RDWR));

                        ASSERT_ERROR(lock_generic_with_timeout(other, type, LOCK_EX|LOCK_NB, USEC_INFINITY), EAGAIN);
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_EQ(waitpid(pid, &status, 0), pid);
                ASSERT_TRUE(WIFEXITED(status));
                ASSERT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
                ASSERT_OK_ZERO(lock_generic_with_timeout(fd, type, LOCK_UN, USEC_INFINITY));
        }
}

TEST(lock_generic_with_timeout_acquisition) {
        /* A child releases a lock on a temporary file while the parent waits on a second description.
         * The timed helper must acquire the BSD or OFD lock and retain it after its worker exits. */
        LockType type;

        FOREACH_ARGUMENT(type, LOCK_BSD, LOCK_UNPOSIX) {
                _cleanup_(unlink_tempfilep) char path[] = "/var/tmp/test-lock-timeout.XXXXXX";
                _cleanup_close_ int fd = -EBADF, other = -EBADF;
                int status;

                fd = ASSERT_OK(mkostemp_safe(path));
                other = ASSERT_OK(fd_reopen(fd, O_RDWR));
                ASSERT_OK(lock_generic(fd, type, LOCK_EX));
                pid_t releaser = fork();
                ASSERT_OK_ERRNO(releaser);
                if (releaser == 0) {
                        ASSERT_OK_ERRNO(usleep(50 * USEC_PER_MSEC));
                        ASSERT_OK(lock_generic(fd, type, LOCK_UN));
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_OK(lock_generic_with_timeout(other, type, LOCK_EX, USEC_PER_SEC));
                ASSERT_EQ(waitpid(releaser, &status, 0), releaser);
                ASSERT_TRUE(WIFEXITED(status));
                ASSERT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
                ASSERT_ERROR_ERRNO(waitpid(-1, NULL, WNOHANG), ECHILD);
                ASSERT_ERROR(lock_generic(fd, type, LOCK_EX|LOCK_NB), EAGAIN);
        }
}

static int release_lock_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        release_lock_file(ASSERT_PTR(userdata));
        return 0;
}

TEST(make_lock_file_at_with_event) {
        /* A timer unlinks and releases a named lock while a worker waits on its inode. The worker must
         * reopen the path, acquire the replacement inode, and transfer its lock to the parent. A later
         * cancellation must reap its worker and leave the original holder's lock intact. */
        _cleanup_(rm_rf_physical_and_freep) char *directory = NULL;
        _cleanup_close_ int dfd = -EBADF;
        _cleanup_(release_lock_file) LockFile holder = LOCK_FILE_INIT, acquired = LOCK_FILE_INIT, probe = LOCK_FILE_INIT;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;

        dfd = ASSERT_OK(mkdtemp_open("/var/tmp/test-lock-event.XXXXXX", /* flags= */ 0, &directory));
        ASSERT_OK(make_lock_file_at(dfd, "lock", LOCK_EX, &holder));
        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(sd_event_add_time_relative(event, /* ret= */ NULL, CLOCK_MONOTONIC,
                                             50 * USEC_PER_MSEC, /* accuracy= */ 1, release_lock_handler, &holder));
        ASSERT_OK(make_lock_file_at_with_event(dfd, "lock", LOCK_EX, event, &acquired));
        ASSERT_ERROR_ERRNO(waitpid(-1, NULL, WNOHANG), ECHILD);
        ASSERT_ERROR(make_lock_file_at(dfd, "lock", LOCK_EX|LOCK_NB, &probe), EBUSY);
        release_lock_file(&acquired);
        ASSERT_ERROR_ERRNO(faccessat(dfd, "lock", F_OK, 0), ENOENT);

        /* Cancelling acquisition must preserve the original holder's lock and stop the worker. */
        event = sd_event_unref(event);
        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(make_lock_file_at(dfd, "lock", LOCK_EX, &holder));
        ASSERT_OK(sd_event_add_time_relative(event, /* ret= */ NULL, CLOCK_MONOTONIC,
                                             50 * USEC_PER_MSEC, /* accuracy= */ 1,
                                             /* callback= */ NULL, INT_TO_PTR(-ECANCELED)));
        ASSERT_ERROR(make_lock_file_at_with_event(dfd, "lock", LOCK_EX, event, &acquired), ECANCELED);
        ASSERT_ERROR_ERRNO(waitpid(-1, NULL, WNOHANG), ECHILD);
        ASSERT_LT(acquired.fd, 0);
        ASSERT_NULL(acquired.path);
        ASSERT_ERROR(make_lock_file_at(dfd, "lock", LOCK_EX|LOCK_NB, &probe), EBUSY);
}

DEFINE_TEST_MAIN(LOG_INFO);
