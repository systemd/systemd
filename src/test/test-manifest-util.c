/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "manifest-util.h"
#include "strv.h"
#include "tests.h"

#define HASH_FOO "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
#define HASH_BAR "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"

static void assert_digest(const struct iovec *digest, const char *hex) {
        _cleanup_(iovec_done) struct iovec expected = {};

        ASSERT_OK(unhexmem(hex, &expected.iov_base, &expected.iov_len));
        ASSERT_EQ(iovec_memcmp(digest, &expected), 0);
}

TEST(manifest_parse_sums) {
        static const char text[] =
                HASH_FOO "  foo\n"
                HASH_BAR " *bar/baz\n"
                HASH_FOO "  with space\n"
                HASH_FOO "  plain\\backslash\n"
                "\\" HASH_BAR "  with\\nnewline\n"
                "\\" HASH_FOO "  back\\\\slash\\rcr\n"
                "B5BB9D8014A0F9B1D61E21E796D78DCCDF1352F23CD32812F4850B878AE4944C  upper\n"
                HASH_BAR "  crlf\r\n"
                HASH_FOO "  last"; /* no trailing newline */

        static const struct {
                const char *filename;
                const char *hash;
        } expected[] = {
                { "foo",                  HASH_FOO },
                { "bar/baz",              HASH_BAR },
                { "with space",           HASH_FOO },
                { "plain\\backslash",     HASH_FOO },
                { "with\nnewline",        HASH_BAR },
                { "back\\slash\rcr",      HASH_FOO },
                { "upper",                HASH_FOO },
                { "crlf",                 HASH_BAR },
                { "last",                 HASH_FOO },
        };

        _cleanup_fclose_ FILE *f = fmemopen_unlocked((void*) text, strlen(text), "r");
        ASSERT_NOT_NULL(f);
        size_t line_nr = 0;

        FOREACH_ELEMENT(e, expected) {
                _cleanup_free_ char *fn = NULL;
                _cleanup_(iovec_done) struct iovec digest = {};

                ASSERT_OK_POSITIVE(manifest_parse_sums(f, &line_nr, &fn, &digest));
                ASSERT_STREQ(fn, e->filename);
                assert_digest(&digest, e->hash);
                ASSERT_EQ(line_nr, (size_t) (e - expected + 1));
        }

        /* EOF, repeatedly */
        for (unsigned i = 0; i < 2; i++) {
                _cleanup_free_ char *fn = NULL;
                struct iovec digest = { .iov_base = (void*) 0x1, .iov_len = 1 };

                ASSERT_OK_ZERO(manifest_parse_sums(f, &line_nr, &fn, &digest));
                ASSERT_NULL(fn);
                ASSERT_FALSE(iovec_is_set(&digest));
                ASSERT_EQ(line_nr, ELEMENTSOF(expected));
        }
}

static int parse_one(const char *line) {
        _cleanup_fclose_ FILE *f = fmemopen_unlocked((void*) line, strlen(line), "r");
        ASSERT_NOT_NULL(f);
        _cleanup_free_ char *fn = NULL;
        _cleanup_(iovec_done) struct iovec digest = {};
        size_t line_nr = 0;
        int r;

        r = manifest_parse_sums(f, &line_nr, &fn, &digest);
        if (r < 0) {
                ASSERT_NULL(fn);
                ASSERT_FALSE(iovec_is_set(&digest));
        }

        return r;
}

TEST(manifest_parse_sums_invalid) {
        FOREACH_STRING(line,
                       /* too short */
                       "foo",
                       HASH_FOO,
                       HASH_FOO " ",
                       HASH_FOO "  ",
                       HASH_FOO " *",
                       "\\" HASH_FOO "  ",
                       /* broken digests */
                       "g5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c  foo",
                       "b5bb9d8014a0f9b1 61e21e796d78dccdf1352f23cd32812f4850b878ae4944c  foo",
                       "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae494  foo",
                       /* missing separator or binary/text marker */
                       HASH_FOO "x foo",
                       HASH_FOO "\tfoo bar",
                       HASH_FOO " xfoo",
                       /* paths that are not relative and normalized */
                       HASH_FOO "  /etc/passwd",
                       HASH_FOO "  ..",
                       HASH_FOO "  ../foo",
                       HASH_FOO "  foo/../bar",
                       HASH_FOO "  ./foo",
                       HASH_FOO "  foo/.",
                       "\\" HASH_FOO "  \\n/../foo",
                       /* invalid escaping */
                       "\\" HASH_FOO "  foo\\x",
                       "\\" HASH_FOO "  foo\\",
                       /* invalid UTF-8 */
                       HASH_FOO "  \xff\xfe")
                ASSERT_ERROR(parse_one(line), EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
