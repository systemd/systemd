/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "lock-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

TEST(make_lock_file) {
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
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, tfd2 = -EBADF;

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        tfd2 = ASSERT_OK(fd_reopen(tfd, O_CLOEXEC|O_DIRECTORY));

        ASSERT_OK(lock_generic(tfd, LOCK_BSD, LOCK_EX));
        ASSERT_ERROR(lock_generic(tfd2, LOCK_BSD, LOCK_EX|LOCK_NB), EWOULDBLOCK);

        usec_t start = now(CLOCK_MONOTONIC);
        ASSERT_ERROR(lock_generic_with_timeout(tfd2, LOCK_BSD, LOCK_EX, 200 * USEC_PER_MSEC), ETIMEDOUT);
        ASSERT_GE(usec_sub_unsigned(now(CLOCK_MONOTONIC), start), 200 * USEC_PER_MSEC);

        ASSERT_OK(lock_generic(tfd, LOCK_BSD, LOCK_UN));
        ASSERT_OK_ZERO(lock_generic_with_timeout(tfd2, LOCK_BSD, LOCK_EX, 200 * USEC_PER_MSEC));
        ASSERT_ERROR(lock_generic(tfd, LOCK_BSD, LOCK_EX|LOCK_NB), EWOULDBLOCK);
}

TEST(lock_generic_with_timeout) {
        test_lock_generic_with_timeout_for_type(LOCK_BSD);
        test_lock_generic_with_timeout_for_type(LOCK_UNPOSIX);
}

DEFINE_TEST_MAIN(LOG_INFO);
