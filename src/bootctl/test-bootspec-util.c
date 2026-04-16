/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bootspec-util.h"
#include "tests.h"

/* bootspec-util.c references arg_root; define it here so we can link the test. */
char *arg_root = NULL;

static void test_one(
                const char *entry_token,
                uint64_t entry_commit,
                const char *version,
                unsigned profile_nr,
                unsigned tries_left,
                const char *expected) {

        _cleanup_free_ char *fn = NULL;
        ASSERT_OK(boot_entry_make_commit_filename(entry_token, entry_commit, version, profile_nr, tries_left, &fn));
        ASSERT_STREQ(fn, expected);

        _cleanup_free_ char *token = NULL;
        uint64_t commit = 0;
        ASSERT_OK(boot_entry_parse_commit_filename(fn, &token, &commit));
        ASSERT_STREQ(token, entry_token);
        ASSERT_EQ(commit, entry_commit);
}

TEST(boot_entry_commit_filename) {
        test_one("foo", 1, NULL, 0, UINT_MAX, "foo-commit_1.conf");
        test_one("foo", 42, "1.0", 0, UINT_MAX, "foo-commit_42.1.0.conf");
        test_one("foo", 42, "1.0", 3, UINT_MAX, "foo-commit_42.1.0@3.conf");
        test_one("foo", 42, "1.0", 3, 5, "foo-commit_42.1.0@3+5.conf");
        test_one("foo", 42, NULL, 3, UINT_MAX, "foo-commit_42@3.conf");
        test_one("foo", 42, NULL, 3, 7, "foo-commit_42@3+7.conf");
        test_one("foo", 42, NULL, 0, 9, "foo-commit_42+7.conf");
        test_one("my-token", 123456, "v2", 0, UINT_MAX, "my-token-commit_123456.v2.conf");

        /* Invalid inputs for make */
        _cleanup_free_ char *fn = NULL;
        ASSERT_ERROR(boot_entry_make_commit_filename("foo/bar", 1, NULL, 0, UINT_MAX, &fn), EINVAL);
        ASSERT_ERROR(boot_entry_make_commit_filename("foo", 0, NULL, 0, UINT_MAX, &fn), EINVAL);
        ASSERT_ERROR(boot_entry_make_commit_filename("foo", UINT64_MAX, NULL, 0, UINT_MAX, &fn), EINVAL);

        /* Invalid inputs for parse */
        _cleanup_free_ char *token = NULL;
        uint64_t commit = 0;
        ASSERT_ERROR(boot_entry_parse_commit_filename("foo.conf", &token, &commit), EBADMSG);
        ASSERT_ERROR(boot_entry_parse_commit_filename("foo-commit_.conf", &token, &commit), EBADMSG);
        ASSERT_ERROR(boot_entry_parse_commit_filename("foo-commit_abc.conf", &token, &commit), EBADMSG);
        ASSERT_ERROR(boot_entry_parse_commit_filename("foo-commit_0.conf", &token, &commit), EBADMSG);
}

DEFINE_TEST_MAIN(LOG_INFO);
