/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "escape.h"
#include "libmount-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

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

        f = fmemopen((char*) string, strlen(string), "r");
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

TEST(libmount_unescaping) {
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

/* C.f. test_path_is_temporary_fs() in test-stat-util.c. */
TEST(path_is_temporary_fs_harder) {
        char **args = saved_argc >= 2 ? strv_skip(saved_argv, 1) :
                                        STRV_MAKE("/", "/proc", "/var");
        int r;

        STRV_FOREACH(arg, args) {
                r = path_is_temporary_fs_harder(*arg);
                log_info("path_is_temporary_fs_harder(\"%s\"): %s",
                         *arg,
                         r >= 0 ? yes_no(r) : STRERROR(r));
        }
}

TEST(path_is_temporary_fs_mounts) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL, *var_tmp = NULL, *var_tmp_work = NULL;
        _cleanup_free_ char *upper = NULL, *lower = NULL, *lower2 = NULL, *work = NULL,
                            *merged = NULL, *merged2 = NULL, *merged3 = NULL, *merged4 = NULL,
                            *merged_work = NULL;
        int r;

        if (geteuid() != 0)
                return (void) log_tests_skipped("Lacking privileges for mounting");

        /* /tmp is usually tmpfs, /var/tmp is usually disk-based. */
        assert_se(mkdtemp_malloc("/tmp/test-libmount-XXXXXX", &tmp) >= 0);
        assert_se(mkdtemp_malloc("/var/tmp/test-libmount-XXXXXX", &var_tmp) >= 0);
        assert_se(mkdtemp_malloc("/var/tmp/test-libmount-XXXXXX", &var_tmp_work) >= 0);

        assert_se(upper = path_join(tmp, "upper"));
        assert_se(lower = path_join(tmp, "lower"));
        assert_se(lower2 = path_join(tmp, "lower2"));
        assert_se(work = path_join(tmp, "work"));
        assert_se(merged = path_join(tmp, "merged"));
        assert_se(merged2 = path_join(tmp, "merged2"));
        assert_se(merged3 = path_join(tmp, "merged3"));
        assert_se(merged4 = path_join(tmp, "merged4"));
        assert_se(merged_work = path_join(tmp, "merged/work"));

        assert_se(mkdir_p(upper, 0755) >= 0);
        assert_se(mkdir_p(lower, 0755) >= 0);
        assert_se(mkdir_p(lower2, 0755) >= 0);
        assert_se(mkdir_p(work, 0755) >= 0);
        assert_se(mkdir_p(merged, 0755) >= 0);
        assert_se(mkdir_p(merged2, 0755) >= 0);
        assert_se(mkdir_p(merged3, 0755) >= 0);
        assert_se(mkdir_p(merged4, 0755) >= 0);
        assert_se(mkdir_p(merged_work, 0755) >= 0);

        r = safe_fork("(test-tmpfs)",
                      FORK_DEATHSIG | FORK_LOG | FORK_WAIT | FORK_NEW_MOUNTNS, NULL);
        if (r == 0) {
                int tmpfs_upper = r = path_is_temporary_fs(upper);
                log_info("path_is_temporary_fs(%s): %s", upper, r >= 0 ? yes_no(r) : STRERROR(r));
                if (r < 0)
                        goto done;

                const char *opts =
                        strjoina("lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);

                /* plain /tmp */
                r = path_is_temporary_fs_harder(upper);
                log_info("path_is_temporary_fs_harder(%s): %s", upper, r >= 0 ? yes_no(r) : STRERROR(r));
                assert_se(r == tmpfs_upper);

                r = mount_nofollow_verbose(LOG_INFO, "overlay", merged, "overlay", 0, opts);
                if (r < 0)
                        log_notice_errno(r, "Mounting overlay didn't work: %m");
                else {
                        /* overlay (/tmp + /tmp) */
                        r = path_is_temporary_fs_harder(merged);
                        log_info("path_is_temporary_fs_harder(%s): %s", merged, r >= 0 ? yes_no(r) : STRERROR(r));
                        assert_se(r == tmpfs_upper);
                }

                int tmpfs_var_tmp = r = path_is_temporary_fs(var_tmp);
                log_info("path_is_temporary_fs(%s): %s", var_tmp, r >= 0 ? yes_no(r) : STRERROR(r));
                if (r < 0)
                        goto done;

                /* plain /var/tmp */
                r = path_is_temporary_fs_harder(var_tmp);
                log_info("path_is_temporary_fs_harder(%s): %s", var_tmp, r >= 0 ? yes_no(r) : STRERROR(r));
                assert_se(r == tmpfs_var_tmp);

                opts = strjoina("lowerdir=", lower, ",upperdir=", var_tmp, ",workdir=", var_tmp_work);

                r = mount_nofollow_verbose(LOG_INFO, "overlay", merged2, "overlay", 0, opts);
                if (r < 0)
                        log_notice_errno(r, "Mounting overlay didn't work: %m");
                else {
                        /* overlay (/tmp + /var/tmp) */
                        r = path_is_temporary_fs_harder(merged2);
                        log_info("path_is_temporary_fs_harder(%s): %s", merged2, r >= 0 ? yes_no(r) : STRERROR(r));
                        assert_se(r == tmpfs_var_tmp);
                }

                opts = strjoina("lowerdir=", merged2, ",upperdir=", upper, ",workdir=", work);

                r = mount_nofollow_verbose(LOG_INFO, "overlay", merged3, "overlay", 0, opts);
                if (r < 0)
                        log_notice_errno(r, "Mounting overlay didn't work: %m");
                else {
                        /* overlay (/tmp + /var/tmp) + /tmp */
                        r = path_is_temporary_fs_harder(merged3);
                        log_info("path_is_temporary_fs_harder(%s): %s", merged3, r >= 0 ? yes_no(r) : STRERROR(r));
                        assert_se(r == tmpfs_upper);
                }

                opts = strjoina("lowerdir=", lower, ",upperdir=", merged, ",workdir=", merged_work);

                r = mount_nofollow_verbose(LOG_INFO, "overlay", merged4, "overlay", 0, opts);
                if (r < 0)
                        log_notice_errno(r, "Mounting overlay didn't work: %m");
                else {
                        /* overlay /tmp + (/tmp + /tmp)
                         *
                         * This doesn't seem to work. Kernel says:
                         * overlayfs: filesystem on '/tmp/test-libmount-E97Gic/merged' not supported as upperdir
                         * But the docs don't give a definite answer whether this should work.
                         * mount(8) only says that lowerdir may be overlayfs.
                         * Let's test it anyway, in case is starts working in the future.
                         */
                        r = path_is_temporary_fs_harder(merged4);
                        log_info("path_is_temporary_fs_harder(%s): %s", merged4, r >= 0 ? yes_no(r) : STRERROR(r));
                        assert_se(r == tmpfs_upper);
                }

        done:
                _exit(EXIT_SUCCESS);
        }
        assert_se(r >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
