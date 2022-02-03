/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(read_etc_hostname) {
        char path[] = "/tmp/hostname.XXXXXX";
        char *hostname;
        int fd;

        fd = mkostemp_safe(path);
        assert_se(fd > 0);
        close(fd);

        /* simple hostname */
        assert_se(write_string_file(path, "foo", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(read_etc_hostname(path, &hostname) == 0);
        assert_se(streq(hostname, "foo"));
        hostname = mfree(hostname);

        /* with comment */
        assert_se(write_string_file(path, "# comment\nfoo", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(read_etc_hostname(path, &hostname) == 0);
        assert_se(hostname);
        assert_se(streq(hostname, "foo"));
        hostname = mfree(hostname);

        /* with comment and extra whitespace */
        assert_se(write_string_file(path, "# comment\n\n foo ", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(read_etc_hostname(path, &hostname) == 0);
        assert_se(hostname);
        assert_se(streq(hostname, "foo"));
        hostname = mfree(hostname);

        /* cleans up name */
        assert_se(write_string_file(path, "!foo/bar.com", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(read_etc_hostname(path, &hostname) == 0);
        assert_se(hostname);
        assert_se(streq(hostname, "foobar.com"));
        hostname = mfree(hostname);

        /* no value set */
        hostname = (char*) 0x1234;
        assert_se(write_string_file(path, "# nothing here\n", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(read_etc_hostname(path, &hostname) == -ENOENT);
        assert_se(hostname == (char*) 0x1234);  /* does not touch argument on error */

        /* nonexisting file */
        assert_se(read_etc_hostname("/non/existing", &hostname) == -ENOENT);
        assert_se(hostname == (char*) 0x1234);  /* does not touch argument on error */

        unlink(path);
}

TEST(hostname_setup) {
        hostname_setup(false);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
