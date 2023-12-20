/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "path-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "tmpfile-util.h"

#define LOREM_IPSUM "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor " \
        "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation " \
        "ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit " \
        "in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat " \
        "non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

TEST(default_term_for_tty) {
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

TEST(read_one_char) {
        _cleanup_fclose_ FILE *file = NULL;
        char r;
        bool need_nl;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-read_one_char.XXXXXX";

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
}

TEST(getttyname_malloc) {
        _cleanup_free_ char *ttyname = NULL;
        _cleanup_close_ int master = -EBADF;

        assert_se((master = posix_openpt(O_RDWR|O_NOCTTY)) >= 0);
        assert_se(getttyname_malloc(master, &ttyname) >= 0);
        log_info("ttyname = %s", ttyname);

        assert_se(PATH_IN_SET(ttyname, "ptmx", "pts/ptmx"));
}

typedef struct {
        const char *name;
        const char* (*func)(void);
} Color;

static const Color colors[] = {
        { "normal", ansi_normal },
        { "highlight", ansi_highlight },
        { "black", ansi_black },
        { "red", ansi_red },
        { "green", ansi_green },
        { "yellow", ansi_yellow },
        { "blue", ansi_blue },
        { "magenta", ansi_magenta },
        { "cyan", ansi_cyan },
        { "white", ansi_white },
        { "grey", ansi_grey },

        { "bright-black", ansi_bright_black },
        { "bright-red", ansi_bright_red },
        { "bright-green", ansi_bright_green },
        { "bright-yellow", ansi_bright_yellow },
        { "bright-blue", ansi_bright_blue },
        { "bright-magenta", ansi_bright_magenta },
        { "bright-cyan", ansi_bright_cyan },
        { "bright-white", ansi_bright_white },

        { "highlight-black", ansi_highlight_black },
        { "highlight-red", ansi_highlight_red },
        { "highlight-green", ansi_highlight_green },
        { "highlight-yellow (original)", _ansi_highlight_yellow },
        { "highlight-yellow (replacement)", ansi_highlight_yellow },
        { "highlight-blue", ansi_highlight_blue },
        { "highlight-magenta", ansi_highlight_magenta },
        { "highlight-cyan", ansi_highlight_cyan },
        { "highlight-white", ansi_highlight_white },
        { "highlight-grey", ansi_highlight_grey },

        { "underline", ansi_underline },
        { "highlight-underline", ansi_highlight_underline },
        { "highlight-red-underline", ansi_highlight_red_underline },
        { "highlight-green-underline", ansi_highlight_green_underline },
        { "highlight-yellow-underline", ansi_highlight_yellow_underline },
        { "highlight-blue-underline", ansi_highlight_blue_underline },
        { "highlight-magenta-underline", ansi_highlight_magenta_underline },
        { "highlight-grey-underline", ansi_highlight_grey_underline },
};

TEST(colors) {
        for (size_t i = 0; i < ELEMENTSOF(colors); i++)
                printf("<%s%s%s>\n", colors[i].func(), colors[i].name, ansi_normal());
}

TEST(text) {
        for (size_t i = 0; !streq(colors[i].name, "underline"); i++) {
                bool blwh = strstr(colors[i].name, "black")
                        || strstr(colors[i].name, "white");

                printf("\n"
                       "Testing color %s%s\n%s%s%s\n",
                       colors[i].name,
                       blwh ? "" : ", this text should be readable",
                       colors[i].func(),
                       LOREM_IPSUM,
                       ansi_normal());
        }
}

TEST(get_ctty) {
        _cleanup_free_ char *ctty = NULL;
        struct stat st;
        dev_t devnr;
        int r;

        r = get_ctty(0, &devnr, &ctty);
        if (r < 0) {
                log_notice_errno(r, "Apparently called without a controlling TTY, cutting get_ctty() test short: %m");
                return;
        }

        /* In almost all cases STDIN will match our controlling TTY. Let's verify that and then compare paths */
        assert_se(fstat(STDIN_FILENO, &st) >= 0);
        if (S_ISCHR(st.st_mode) && st.st_rdev == devnr) {
                _cleanup_free_ char *stdin_name = NULL;

                assert_se(getttyname_malloc(STDIN_FILENO, &stdin_name) >= 0);
                assert_se(path_equal(stdin_name, ctty));
        } else
                log_notice("Not invoked with stdin == ctty, cutting get_ctty() test short");
}

TEST(get_default_background_color) {
        double red, green, blue;
        int r;

        r = get_default_background_color(&red, &green, &blue);
        if (r < 0)
                log_notice_errno(r, "Can't get terminal default background color: %m");
        else
                log_notice("R=%g G=%g B=%g", red, green, blue);
}

DEFINE_TEST_MAIN(LOG_INFO);
