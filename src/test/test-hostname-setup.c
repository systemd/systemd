/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(read_etc_hostname) {
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/hostname.XXXXXX";
        char *hostname;

        safe_close(ASSERT_FD(mkostemp_safe(path)));

        /* simple hostname */
        ASSERT_OK(write_string_file(path, "foo", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_STREQ(hostname, "foo");
        hostname = mfree(hostname);

        /* with comment */
        ASSERT_OK(write_string_file(path, "# comment\nfoo", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foo");
        hostname = mfree(hostname);

        /* with comment and extra whitespace */
        ASSERT_OK(write_string_file(path, "# comment\n\n foo ", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foo");
        hostname = mfree(hostname);

        /* cleans up name */
        ASSERT_OK(write_string_file(path, "!foo/bar.com", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foobar.com");
        hostname = mfree(hostname);

        /* with wildcards */
        ASSERT_OK(write_string_file(path, "foo????????x??????????u", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foo????????x??????????u");
        hostname = mfree(hostname);
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ true, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_FALSE(streq(hostname, "foo????????x??????????u"));
        ASSERT_EQ(fnmatch("foo????????x??????????u", hostname, /* flags= */ 0), 0);
        hostname = mfree(hostname);

        /* no value set */
        hostname = (char*) 0x1234;
        ASSERT_OK(write_string_file(path, "# nothing here\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));
        ASSERT_ERROR(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname), ENOENT);
        assert(hostname == (char*) 0x1234);  /* does not touch argument on error */

        /* nonexisting file */
        ASSERT_ERROR(read_etc_hostname("/non/existing", /* substitute_wildcards= */ false, &hostname), ENOENT);
        assert(hostname == (char*) 0x1234);  /* does not touch argument on error */
}

TEST(hostname_setup) {
        hostname_setup(false);
}

TEST(hostname_malloc) {
        _cleanup_free_ char *h = NULL, *l = NULL;

        assert_se(h = gethostname_malloc());
        log_info("hostname_malloc: \"%s\"", h);

        assert_se(l = gethostname_short_malloc());
        log_info("hostname_short_malloc: \"%s\"", l);
}

TEST(default_hostname) {
        if (!hostname_is_valid(FALLBACK_HOSTNAME, 0)) {
                log_error("Configured fallback hostname \"%s\" is not valid.", FALLBACK_HOSTNAME);
                exit(EXIT_FAILURE);
        }

        _cleanup_free_ char *n = get_default_hostname();
        assert_se(n);
        log_info("get_default_hostname: \"%s\"", n);
        assert_se(hostname_is_valid(n, 0));

        _cleanup_free_ char *m = get_default_hostname_raw();
        assert_se(m);
        log_info("get_default_hostname_raw: \"%s\"", m);
        assert_se(hostname_is_valid(m, VALID_HOSTNAME_QUESTION_MARK));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
