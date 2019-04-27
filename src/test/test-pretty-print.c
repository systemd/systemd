/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "macro.h"
#include "pretty-print.h"
#include "strv.h"
#include "tests.h"

static void test_terminal_urlify(void) {
        _cleanup_free_ char *formatted = NULL;

        assert_se(terminal_urlify("https://www.freedesktop.org/wiki/Software/systemd/", "systemd homepage", &formatted) >= 0);
        printf("Hey, consider visiting the %s right now! It is very good!\n", formatted);

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
        test_setup_logging(LOG_INFO);

        test_terminal_urlify();
        test_cat_files();

        print_separator();

        return 0;
}
