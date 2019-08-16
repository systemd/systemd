/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "macro.h"
#include "path-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "util.h"

static void test_default_term_for_tty(void) {
        log_info("/* %s */", __func__);

        puts(default_term_for_tty("/dev/tty23"));
        puts(default_term_for_tty("/dev/ttyS23"));
        puts(default_term_for_tty("/dev/tty0"));
        puts(default_term_for_tty("/dev/pty0"));
        puts(default_term_for_tty("/dev/pts/0"));
        puts(default_term_for_tty("/dev/console"));
        puts(default_term_for_tty("tty23"));
        puts(default_term_for_tty("ttyS23"));
        puts(default_term_for_tty("tty0"));
        puts(default_term_for_tty("pty0"));
        puts(default_term_for_tty("pts/0"));
        puts(default_term_for_tty("console"));
}

static void test_read_one_char(void) {
        _cleanup_fclose_ FILE *file = NULL;
        char r;
        bool need_nl;
        char name[] = "/tmp/test-read_one_char.XXXXXX";

        log_info("/* %s */", __func__);

        assert_se(fmkostemp_safe(name, "r+", &file) == 0);

        assert_se(fputs("c\n", file) >= 0);
        rewind(file);
        assert_se(read_one_char(file, &r, 1000000, &need_nl) >= 0);
        assert_se(!need_nl);
        assert_se(r == 'c');
        assert_se(read_one_char(file, &r, 1000000, &need_nl) < 0);

        rewind(file);
        assert_se(fputs("foobar\n", file) >= 0);
        rewind(file);
        assert_se(read_one_char(file, &r, 1000000, &need_nl) < 0);

        rewind(file);
        assert_se(fputs("\n", file) >= 0);
        rewind(file);
        assert_se(read_one_char(file, &r, 1000000, &need_nl) < 0);

        assert_se(unlink(name) >= 0);
}

static void test_getttyname_malloc(void) {
        _cleanup_free_ char *ttyname = NULL;
        _cleanup_close_ int master = -1;

        log_info("/* %s */", __func__);

        assert_se((master = posix_openpt(O_RDWR|O_NOCTTY)) >= 0);
        assert_se(getttyname_malloc(master, &ttyname) >= 0);
        log_info("ttyname = %s", ttyname);

        assert_se(PATH_IN_SET(ttyname, "ptmx", "pts/ptmx"));
}

static void test_one_color(const char *name, const char *color) {
        printf("<%s%s%s>\n", color, name, ansi_normal());
}

static void test_colors(void) {
        log_info("/* %s */", __func__);

        test_one_color("normal", ansi_normal());
        test_one_color("highlight", ansi_highlight());
        test_one_color("red", ansi_red());
        test_one_color("green", ansi_green());
        test_one_color("yellow", ansi_yellow());
        test_one_color("blue", ansi_blue());
        test_one_color("megenta", ansi_magenta());
        test_one_color("grey", ansi_grey());
        test_one_color("highlight-red", ansi_highlight_red());
        test_one_color("highlight-green", ansi_highlight_green());
        test_one_color("highlight-yellow", ansi_highlight_yellow());
        test_one_color("highlight-blue", ansi_highlight_blue());
        test_one_color("highlight-magenta", ansi_highlight_magenta());
        test_one_color("highlight-grey", ansi_highlight_grey());

        test_one_color("underline", ansi_underline());
        test_one_color("highlight-underline", ansi_highlight_underline());
        test_one_color("highlight-red-underline", ansi_highlight_red_underline());
        test_one_color("highlight-green-underline", ansi_highlight_green_underline());
        test_one_color("highlight-yellow-underline", ansi_highlight_yellow_underline());
        test_one_color("highlight-blue-underline", ansi_highlight_blue_underline());
        test_one_color("highlight-magenta-underline", ansi_highlight_magenta_underline());
        test_one_color("highlight-grey-underline", ansi_highlight_grey_underline());
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_default_term_for_tty();
        test_read_one_char();
        test_getttyname_malloc();
        test_colors();

        return 0;
}
