/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "open-file.h"
#include "string-util.h"
#include "tests.h"

TEST(open_file_parse) {
        _cleanup_(open_file_freep) OpenFile *of = NULL;
        int r;

        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:read-only", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "host-mount-namespace");
        assert_se(of->flags == OPENFILE_READ_ONLY);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "mnt");
        assert_se(of->flags == 0);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "host-mount-namespace");
        assert_se(of->flags == 0);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt::read-only", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "mnt");
        assert_se(of->flags == OPENFILE_READ_ONLY);

        of = open_file_free(of);
        r = open_file_parse("../file.dat:file:read-only", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:rw", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:append", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "host-mount-namespace");
        assert_se(of->flags == OPENFILE_APPEND);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:truncate", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "host-mount-namespace");
        assert_se(of->flags == OPENFILE_TRUNCATE);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:read-only,append", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:read-only,truncate", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:append,truncate", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:read-only,read-only", &of);

        assert_se(r == -EINVAL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:graceful", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "host-mount-namespace");
        assert_se(of->flags == OPENFILE_GRACEFUL);

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:read-only,graceful", &of);

        assert_se(r >= 0);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "host-mount-namespace");
        assert_se(of->flags == (OPENFILE_READ_ONLY | OPENFILE_GRACEFUL));

        of = open_file_free(of);
        r = open_file_parse("/proc/1/ns/mnt:host-mount-namespace:read-only:other", &of);

        assert_se(r == -EINVAL);
}

TEST(open_file_to_string) {
        _cleanup_free_ char *s = NULL;
        _cleanup_(open_file_freep) OpenFile *of = NULL;
        int r;

        assert_se(of = new (OpenFile, 1));
        *of = (OpenFile){ .path = strdup("/proc/1/ns/mnt"),
                          .fdname = strdup("host-mount-namespace"),
                          .flags = OPENFILE_READ_ONLY };

        r = open_file_to_string(of, &s);

        assert_se(r >= 0);
        ASSERT_STREQ(s, "/proc/1/ns/mnt:host-mount-namespace:read-only");

        s = mfree(s);
        of->flags = OPENFILE_APPEND;

        r = open_file_to_string(of, &s);

        assert_se(r >= 0);
        ASSERT_STREQ(s, "/proc/1/ns/mnt:host-mount-namespace:append");

        s = mfree(s);
        of->flags = OPENFILE_TRUNCATE;

        r = open_file_to_string(of, &s);

        assert_se(r >= 0);
        ASSERT_STREQ(s, "/proc/1/ns/mnt:host-mount-namespace:truncate");

        s = mfree(s);
        of->flags = OPENFILE_GRACEFUL;

        r = open_file_to_string(of, &s);

        assert_se(r >= 0);
        ASSERT_STREQ(s, "/proc/1/ns/mnt:host-mount-namespace:graceful");

        s = mfree(s);
        of->flags = OPENFILE_READ_ONLY | OPENFILE_GRACEFUL;

        r = open_file_to_string(of, &s);

        assert_se(r >= 0);
        ASSERT_STREQ(s, "/proc/1/ns/mnt:host-mount-namespace:read-only,graceful");

        s = mfree(s);
        of->flags = 0;

        r = open_file_to_string(of, &s);

        assert_se(r >= 0);
        ASSERT_STREQ(s, "/proc/1/ns/mnt:host-mount-namespace");

        s = mfree(s);
        assert_se(free_and_strdup(&of->fdname, "mnt"));
        of->flags = OPENFILE_READ_ONLY;

        r = open_file_to_string(of, &s);

        assert_se(r >= 0);
        ASSERT_STREQ(s, "/proc/1/ns/mnt::read-only");

        s = mfree(s);
        ASSERT_OK(free_and_strdup(&of->path, "/path:with:colon"));
        ASSERT_OK(free_and_strdup(&of->fdname, "path:with:colon"));
        of->flags = 0;

        ASSERT_OK(open_file_to_string(of, &s));
        ASSERT_STREQ(s, "/path\\x3awith\\x3acolon");
}

DEFINE_TEST_MAIN(LOG_INFO);
