/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-show.h"
#include "tests.h"

TEST(controller_is_valid) {
        assert_se(cg_controller_is_valid("foobar"));
        assert_se(cg_controller_is_valid("foo_bar"));
        assert_se(cg_controller_is_valid("name=foo"));
        assert_se(!cg_controller_is_valid(""));
        assert_se(!cg_controller_is_valid("name="));
        assert_se(!cg_controller_is_valid("="));
        assert_se(!cg_controller_is_valid("cpu,cpuacct"));
        assert_se(!cg_controller_is_valid("_"));
        assert_se(!cg_controller_is_valid("_foobar"));
        assert_se(!cg_controller_is_valid("tatü"));
}

TEST(cg_split_spec) {
        char *c, *p;

        ASSERT_OK_ZERO(cg_split_spec("foobar:/", &c, &p));
        ASSERT_STREQ(c, "foobar");
        ASSERT_STREQ(p, "/");
        c = mfree(c);
        p = mfree(p);

        ASSERT_OK_ZERO(cg_split_spec("foobar:", &c, &p));
        c = mfree(c);
        p = mfree(p);

        ASSERT_FAIL(cg_split_spec("foobar:asdfd", &c, &p));
        ASSERT_FAIL(cg_split_spec(":///", &c, &p));
        ASSERT_FAIL(cg_split_spec(":", &c, &p));
        ASSERT_FAIL(cg_split_spec("", &c, &p));
        ASSERT_FAIL(cg_split_spec("fo/obar:/", &c, &p));

        ASSERT_OK(cg_split_spec("/", &c, &p));
        ASSERT_NULL(c);
        ASSERT_STREQ(p, "/");
        p = mfree(p);

        ASSERT_OK(cg_split_spec("foo", &c, &p));
        ASSERT_STREQ(c, "foo");
        ASSERT_NULL(p);
        c = mfree(c);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
