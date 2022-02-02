/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(mkdir_p) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *p = NULL;

        assert_se(mkdtemp_malloc("/tmp/test-mkdir-XXXXXX", &tmp) >= 0);

        assert_se(p = path_join(tmp, "run"));
        assert_se(mkdir_p(p, 0755) >= 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "var/run"));
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(symlink("../run", p) >= 0);

        p = mfree(p);
        assert_se(p = path_join(tmp, "var/run/hoge/foo/baz"));
        assert_se(mkdir_p(p, 0755) >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
