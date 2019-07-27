/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fd-util.h"
#include "escape.h"
#include "libmount-util.h"
#include "tests.h"

static void test_libmount_unescaping_one(
                const char *title,
                const char *string,
                bool may_fail,
                const char *expected_source,
                const char *expected_target) {
        /* A test for libmount really */
        int r;

        log_info("/* %s %s */", __func__, title);

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        f = fmemopen((char*) string, strlen(string), "re");
        assert_se(f);

        assert_se(libmount_parse(title, f, &table, &iter) >= 0);

        struct libmnt_fs *fs;
        const char *source, *target;
        _cleanup_free_ char *x = NULL, *cs = NULL, *s = NULL, *ct = NULL, *t = NULL;

        /* We allow this call and the checks below to fail in some cases. See the case definitions below. */

        r = mnt_table_next_fs(table, iter, &fs);
        if (r != 0 && may_fail) {
                log_error_errno(r, "mnt_table_next_fs failed: %m");
                return;
        }
        assert_se(r == 0);

        assert_se(x = cescape(string));

        assert_se(source = mnt_fs_get_source(fs));
        assert_se(target = mnt_fs_get_target(fs));

        assert_se(cs = cescape(source));
        assert_se(ct = cescape(target));

        assert_se(cunescape(source, UNESCAPE_RELAX, &s) >= 0);
        assert_se(cunescape(target, UNESCAPE_RELAX, &t) >= 0);

        log_info("from '%s'", x);
        log_info("source: '%s'", source);
        log_info("source: '%s'", cs);
        log_info("source: '%s'", s);
        log_info("expected: '%s'", strna(expected_source));
        log_info("target: '%s'", target);
        log_info("target: '%s'", ct);
        log_info("target: '%s'", t);
        log_info("expected: '%s'", strna(expected_target));

        assert_se(may_fail || streq(source, expected_source));
        assert_se(may_fail || streq(target, expected_target));

        assert_se(mnt_table_next_fs(table, iter, &fs) == 1);
}

static void test_libmount_unescaping(void) {
        test_libmount_unescaping_one(
                        "escaped space + utf8",
                        "729 38 0:59 / /tmp/„zupa\\040zębowa” rw,relatime shared:395 - tmpfs die\\040Brühe rw,seclabel",
                        false,
                        "die Brühe",
                        "/tmp/„zupa zębowa”"
        );

        test_libmount_unescaping_one(
                        "escaped newline",
                        "729 38 0:59 / /tmp/x\\012y rw,relatime shared:395 - tmpfs newline rw,seclabel",
                        false,
                        "newline",
                        "/tmp/x\ny"
        );

        /* The result of "mount -t tmpfs '' /tmp/emptysource".
         * This will fail with libmount <= v2.33.
         * See https://github.com/karelzak/util-linux/commit/18a52a5094.
         */
        test_libmount_unescaping_one(
                        "empty source",
                        "760 38 0:60 / /tmp/emptysource rw,relatime shared:410 - tmpfs  rw,seclabel",
                        true,
                        "",
                        "/tmp/emptysource"
        );

        /* The kernel leaves \r as is.
         * Also see https://github.com/karelzak/util-linux/issues/780.
         */
        test_libmount_unescaping_one(
                        "foo\\rbar",
                        "790 38 0:61 / /tmp/foo\rbar rw,relatime shared:425 - tmpfs tmpfs rw,seclabel",
                        true,
                        "tmpfs",
                        "/tmp/foo\rbar"
        );
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_libmount_unescaping();
        return 0;
}
