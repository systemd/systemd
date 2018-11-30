/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
#include <stdio.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "macro.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "util.h"

static void test_default_term_for_tty(void) {
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

        assert(fmkostemp_safe(name, "r+", &file) == 0);

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

        unlink(name);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_default_term_for_tty();
        test_read_one_char();

        return 0;
}
