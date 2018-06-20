/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
#include <stdio.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "strv.h"
#include "terminal-util.h"
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
        int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        file = fdopen(fd, "r+");
        assert_se(file);
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

static void test_terminal_urlify(void) {
        _cleanup_free_ char *formatted = NULL;

        assert_se(terminal_urlify("https://www.freedesktop.org/wiki/Software/systemd/", "systemd homepage", &formatted) >= 0);
        printf("Hey, considere visiting the %s right now! It is very good!\n", formatted);

        formatted = mfree(formatted);

        assert_se(terminal_urlify_path("/etc/fstab", "this link to your /etc/fstab", &formatted) >= 0);
        printf("Or click on %s to have a look at it!\n", formatted);
}

static void test_cat_files(void) {
        assert_se(cat_files("/no/such/file", NULL, 0) == -ENOENT);
        assert_se(cat_files("/no/such/file", NULL, CAT_FLAGS_MAIN_FILE_OPTIONAL) == 0);

        if (access("/etc/fstab", R_OK) >= 0)
                assert_se(cat_files("/etc/fstab", STRV_MAKE("/etc/fstab", "/etc/fstab"), 0) == 0);
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_default_term_for_tty();
        test_read_one_char();
        test_terminal_urlify();
        test_cat_files();

        print_separator();

        return 0;
}
