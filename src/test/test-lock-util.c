/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>
#include <unistd.h>

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

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);

        assert_se(make_lock_file_at(tfd, "lock", LOCK_EX, &lock1) >= 0);
        assert_se(faccessat(tfd, "lock", F_OK, 0) >= 0);
        assert_se(make_lock_file_at(tfd, "lock", LOCK_EX|LOCK_NB, &lock2) == -EBUSY);
        release_lock_file(&lock1);
        assert_se(RET_NERRNO(faccessat(tfd, "lock", F_OK, 0)) == -ENOENT);
        assert_se(make_lock_file_at(tfd, "lock", LOCK_EX, &lock2) >= 0);
        release_lock_file(&lock2);
        assert_se(make_lock_file_at(tfd, "lock", LOCK_SH, &lock1) >= 0);
        assert_se(faccessat(tfd, "lock", F_OK, 0) >= 0);
        assert_se(make_lock_file_at(tfd, "lock", LOCK_SH, &lock2) >= 0);
        release_lock_file(&lock1);
        assert_se(faccessat(tfd, "lock", F_OK, 0) >= 0);
        release_lock_file(&lock2);

        assert_se(fchdir(tfd) >= 0);
        assert_se(make_lock_file_at(tfd, "lock", LOCK_EX, &lock1) >= 0);
        assert_se(make_lock_file("lock", LOCK_EX|LOCK_NB, &lock2) == -EBUSY);
}

static void test_lock_generic_with_timeout_for_type(LockType type) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, tfd2 = -EBADF;

        tfd = mkdtemp_open(NULL, 0, &t);
        assert_se(tfd >= 0);

        tfd2 = fd_reopen(tfd, O_CLOEXEC|O_DIRECTORY);
        assert_se(tfd2 >= 0);

        assert_se(lock_generic(tfd, LOCK_BSD, LOCK_EX) >= 0);
        assert_se(lock_generic(tfd2, LOCK_BSD, LOCK_EX|LOCK_NB) == -EWOULDBLOCK);

        usec_t start = now(CLOCK_MONOTONIC);
        assert_se(lock_generic_with_timeout(tfd2, LOCK_BSD, LOCK_EX, 200 * USEC_PER_MSEC) == -ETIMEDOUT);
        assert_se(usec_sub_unsigned(now(CLOCK_MONOTONIC), start) >= 200 * USEC_PER_MSEC);

        assert_se(lock_generic(tfd, LOCK_BSD, LOCK_UN) >= 0);
        assert_se(lock_generic_with_timeout(tfd2, LOCK_BSD, LOCK_EX, 200 * USEC_PER_MSEC) == 0);
        assert_se(lock_generic(tfd, LOCK_BSD, LOCK_EX|LOCK_NB) == -EWOULDBLOCK);
}

TEST(lock_generic_with_timeout) {
        test_lock_generic_with_timeout_for_type(LOCK_BSD);
        test_lock_generic_with_timeout_for_type(LOCK_UNPOSIX);
}

DEFINE_TEST_MAIN(LOG_INFO);
