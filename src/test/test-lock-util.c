/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fd-util.h"
#include "lock-util.h"
#include "rm-rf.h"
#include "tests.h"
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

DEFINE_TEST_MAIN(LOG_INFO);
