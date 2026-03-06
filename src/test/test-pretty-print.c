/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

#define CYLON_WIDTH 6

static void test_draw_cylon_one(unsigned pos) {
        char buf[CYLON_WIDTH + CYLON_BUFFER_EXTRA + 1];

        log_debug("/* %s(%u) */", __func__, pos);

        assert(pos <= CYLON_WIDTH + 1);

        memset(buf, 0xff, sizeof(buf));
        draw_cylon(buf, sizeof(buf), CYLON_WIDTH, pos);
        ASSERT_LE(strlen(buf), sizeof(buf));
}

TEST(draw_cylon) {
        bool saved = log_get_show_color();

        log_show_color(false);
        for (unsigned i = 0; i <= CYLON_WIDTH + 1; i++)
                test_draw_cylon_one(i);

        log_show_color(true);
        for (unsigned i = 0; i <= CYLON_WIDTH + 1; i++)
                test_draw_cylon_one(i);

        log_show_color(saved);
}

TEST(terminal_urlify) {
        _cleanup_free_ char *formatted = NULL;

        assert_se(terminal_urlify("https://www.freedesktop.org/wiki/Software/systemd", "systemd homepage", &formatted) >= 0);
        printf("Hey, consider visiting the %s right now! It is very good!\n", formatted);

        formatted = mfree(formatted);

        assert_se(terminal_urlify_path("/etc/fstab", "this link to your /etc/fstab", &formatted) >= 0);
        printf("Or click on %s to have a look at it!\n", formatted);
}

TEST(cat_files) {
        assert_se(cat_files("/no/such/file", NULL, 0) == -ENOENT);
        assert_se(cat_files(NULL, NULL, 0) == 0);

        if (access("/etc/fstab", R_OK) >= 0)
                assert_se(cat_files("/etc/fstab", STRV_MAKE("/etc/fstab", "/etc/fstab"), 0) == 0);

        /* Test masked file (symlink to /dev/null) - should succeed with exit code 0 */
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-cat-files-XXXXXX", &tmp));
        _cleanup_free_ char *masked_file = ASSERT_NOT_NULL(path_join(tmp, "masked.conf"));
        ASSERT_OK_ERRNO(symlink("/dev/null", masked_file));
        ASSERT_OK(cat_files(masked_file, /* dropins= */ NULL, /* flags= */ 0));
}

TEST(red_green_cross_check_mark) {
        bool b = false;

        printf("yea: <%s>\n", GREEN_CHECK_MARK());
        printf("nay: <%s>\n", RED_CROSS_MARK());

        printf("%s → %s → %s → %s\n",
               COLOR_MARK_BOOL(b),
               COLOR_MARK_BOOL(!b),
               COLOR_MARK_BOOL(!!b),
               COLOR_MARK_BOOL(!!!b));
}

TEST(print_separator) {
        print_separator();
}

DEFINE_TEST_MAIN(LOG_INFO);
