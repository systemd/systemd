/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "capability-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

TEST(mkdir_p_safe) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp));

        ASSERT_NOT_NULL(p = path_join(tmp, "run/aaa/bbb"));
        ASSERT_OK(mkdir_p(p, 0755));
        ASSERT_OK_POSITIVE(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "run/ccc/ddd"));
        ASSERT_OK(mkdir_p_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0));
        ASSERT_OK_POSITIVE(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "var/run"));
        ASSERT_OK(mkdir_parents_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0));
        ASSERT_OK_ERRNO(symlink("../run", p));
        ASSERT_OK_ZERO(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        ASSERT_ERROR(mkdir_safe(p, 0755, UID_INVALID, GID_INVALID, 0), ENOTDIR);
        ASSERT_OK(mkdir_safe(p, 0755, UID_INVALID, GID_INVALID, MKDIR_IGNORE_EXISTING));
        ASSERT_OK(mkdir_safe(p, 0755, UID_INVALID, GID_INVALID, MKDIR_FOLLOW_SYMLINK));
        ASSERT_OK_ZERO(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "var/run/hoge/foo/baz"));
        ASSERT_OK(mkdir_p_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0));
        ASSERT_OK_POSITIVE(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "not-exists"));
        ASSERT_NOT_NULL(q = path_join(p, "aaa"));
        ASSERT_ERROR(mkdir_p_safe(p, q, 0755, UID_INVALID, GID_INVALID, 0), ENOENT);

        p = mfree(p);
        q = mfree(q);
        ASSERT_NOT_NULL(p = path_join(tmp, "regular-file"));
        ASSERT_NOT_NULL(q = path_join(p, "aaa"));
        ASSERT_OK(touch(p));
        ASSERT_ERROR(mkdir_p_safe(p, q, 0755, UID_INVALID, GID_INVALID, 0), ENOTDIR);

        p = mfree(p);
        q = mfree(q);
        ASSERT_NOT_NULL(p = path_join(tmp, "symlink"));
        ASSERT_NOT_NULL(q = path_join(p, "hoge/foo"));
        ASSERT_OK_ERRNO(symlink("aaa", p));
        ASSERT_OK(mkdir_p_safe(tmp, q, 0755, UID_INVALID, GID_INVALID, 0));
        ASSERT_OK_POSITIVE(is_dir(q, false));
        ASSERT_OK_POSITIVE(is_dir(q, true));
        q = mfree(q);
        ASSERT_NOT_NULL(q = path_join(tmp, "aaa/hoge/foo"));
        ASSERT_OK_POSITIVE(is_dir(q, false));
        ASSERT_OK_POSITIVE(is_dir(q, true));

        ASSERT_ERROR(mkdir_p_safe(tmp, "/tmp/test-mkdir-outside", 0755, UID_INVALID, GID_INVALID, 0), EINVAL);

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "zero-mode/should-fail-to-create-child"));
        ASSERT_OK(mkdir_parents_safe(tmp, p, 0000, UID_INVALID, GID_INVALID, 0));
        ASSERT_OK(r = safe_fork("(test-mkdir-no-cap)", FORK_DEATHSIG_SIGTERM | FORK_WAIT | FORK_LOG, NULL));
        if (r == 0) {
                (void) capability_bounding_set_drop(0, /* right_now = */ true);
                ASSERT_ERROR(mkdir_p_safe(tmp, p, 0000, UID_INVALID, GID_INVALID, 0), EACCES);
                _exit(EXIT_SUCCESS);
        }
}

TEST(mkdir_p_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *p = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp));

        ASSERT_NOT_NULL(p = path_join(tmp, "run/aaa/bbb"));
        ASSERT_OK(mkdir_p_root(tmp, "/run/aaa/bbb", UID_INVALID, GID_INVALID, 0755));
        ASSERT_OK_POSITIVE(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "var/run"));
        ASSERT_OK(mkdir_parents_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0));
        ASSERT_OK_ERRNO(symlink("../run", p));
        ASSERT_OK_ZERO(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "var/run/hoge/foo/baz"));
        ASSERT_OK(mkdir_p_root(tmp, "/var/run/hoge/foo/baz", UID_INVALID, GID_INVALID, 0755));
        ASSERT_OK_POSITIVE(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "not-exists"));
        ASSERT_ERROR(mkdir_p_root(p, "/aaa", UID_INVALID, GID_INVALID, 0755), ENOENT);

        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(tmp, "regular-file"));
        ASSERT_OK(touch(p));
        ASSERT_ERROR(mkdir_p_root(p, "/aaa", UID_INVALID, GID_INVALID, 0755), ENOTDIR);

        /* FIXME: The tests below do not work.
        p = mfree(p);
        assert_se(p = path_join(tmp, "symlink"));
        assert_se(symlink("aaa", p) >= 0);
        assert_se(mkdir_p_root(tmp, "/symlink/hoge/foo", UID_INVALID, GID_INVALID, 0755) >= 0);
        p = mfree(p);
        assert_se(p = path_join(tmp, "symlink/hoge/foo"));
        assert_se(is_dir(p, false) > 0);
        assert_se(is_dir(p, true) > 0);
        p = mfree(p);
        assert_se(p = path_join(tmp, "aaa/hoge/foo"));
        assert_se(is_dir(p, false) > 0);
        assert_se(is_dir(p, true) > 0);
        */
}

TEST(mkdir_p_root_full) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *p = NULL;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp));

        ASSERT_NOT_NULL((p = path_join(tmp, "foo")));
        ASSERT_OK(mkdir_p_root_full(tmp, "/foo", UID_INVALID, GID_INVALID, 0755, 2 * USEC_PER_SEC, NULL));
        ASSERT_OK_POSITIVE(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));
        ASSERT_OK_ERRNO(stat(p, &st));
        ASSERT_EQ(st.st_mtim.tv_sec, 2);
        ASSERT_EQ(st.st_atim.tv_sec, 2);

        p = mfree(p);
        ASSERT_NOT_NULL((p = path_join(tmp, "dir-not-exists/foo")));
        ASSERT_OK(mkdir_p_root_full(NULL, p, UID_INVALID, GID_INVALID, 0755, 90 * USEC_PER_HOUR, NULL));
        ASSERT_OK_POSITIVE(is_dir(p, false));
        ASSERT_OK_POSITIVE(is_dir(p, true));
        p = mfree(p);
        ASSERT_NOT_NULL((p = path_join(tmp, "dir-not-exists")));
        ASSERT_OK_ERRNO(stat(p, &st));
        ASSERT_EQ(st.st_mtim.tv_sec, 90 * 60 * 60);
        ASSERT_EQ(st.st_atim.tv_sec, 90 * 60 * 60);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
