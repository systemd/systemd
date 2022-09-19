/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

TEST(mkdir_p_safe) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *p = NULL, *q = NULL;

        assert_se(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp) >= 0);

        assert_se(p = path_join(tmp, "run/aaa/bbb"));
        assert_se(mkdir_p(p, 0755) >= 0);
        assert_se(is_dir(p, false) > 0);
        assert_se(is_dir(p, true) > 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "run/ccc/ddd"));
        assert_se(mkdir_p_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0) >= 0);
        assert_se(is_dir(p, false) > 0);
        assert_se(is_dir(p, true) > 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "var/run"));
        assert_se(mkdir_parents_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0) >= 0);
        assert_se(symlink("../run", p) >= 0);
        assert_se(is_dir(p, false) == 0);
        assert_se(is_dir(p, true) > 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "var/run/hoge/foo/baz"));
        assert_se(mkdir_p_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0) >= 0);
        assert_se(is_dir(p, false) > 0);
        assert_se(is_dir(p, true) > 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "not-exists"));
        assert_se(q = path_join(p, "aaa"));
        assert_se(mkdir_p_safe(p, q, 0755, UID_INVALID, GID_INVALID, 0) == -ENOENT);

        p = mfree(p);
        q = mfree(q);
        assert_se(p = path_join(tmp, "regular-file"));
        assert_se(q = path_join(p, "aaa"));
        assert_se(touch(p) >= 0);
        assert_se(mkdir_p_safe(p, q, 0755, UID_INVALID, GID_INVALID, 0) == -ENOTDIR);

        p = mfree(p);
        q = mfree(q);
        assert_se(p = path_join(tmp, "symlink"));
        assert_se(q = path_join(p, "hoge/foo"));
        assert_se(symlink("aaa", p) >= 0);
        assert_se(mkdir_p_safe(tmp, q, 0755, UID_INVALID, GID_INVALID, 0) >= 0);
        assert_se(is_dir(q, false) > 0);
        assert_se(is_dir(q, true) > 0);
        q = mfree(q);
        assert_se(q = path_join(tmp, "aaa/hoge/foo"));
        assert_se(is_dir(q, false) > 0);
        assert_se(is_dir(q, true) > 0);

        assert_se(mkdir_p_safe(tmp, "/tmp/test-mkdir-outside", 0755, UID_INVALID, GID_INVALID, 0) == -ENOTDIR);
}

TEST(mkdir_p_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *p = NULL;

        assert_se(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp) >= 0);

        assert_se(p = path_join(tmp, "run/aaa/bbb"));
        assert_se(mkdir_p_root(tmp, "/run/aaa/bbb", UID_INVALID, GID_INVALID, 0755) >= 0);
        assert_se(is_dir(p, false) > 0);
        assert_se(is_dir(p, true) > 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "var/run"));
        assert_se(mkdir_parents_safe(tmp, p, 0755, UID_INVALID, GID_INVALID, 0) >= 0);
        assert_se(symlink("../run", p) >= 0);
        assert_se(is_dir(p, false) == 0);
        assert_se(is_dir(p, true) > 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "var/run/hoge/foo/baz"));
        assert_se(mkdir_p_root(tmp, "/var/run/hoge/foo/baz", UID_INVALID, GID_INVALID, 0755) >= 0);
        assert_se(is_dir(p, false) > 0);
        assert_se(is_dir(p, true) > 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "not-exists"));
        assert_se(mkdir_p_root(p, "/aaa", UID_INVALID, GID_INVALID, 0755) == -ENOENT);

        p = mfree(p);
        assert_se(p = path_join(tmp, "regular-file"));
        assert_se(touch(p) >= 0);
        assert_se(mkdir_p_root(p, "/aaa", UID_INVALID, GID_INVALID, 0755) == -ENOTDIR);

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

DEFINE_TEST_MAIN(LOG_DEBUG);
