/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "web-util.h"

static void test_is_valid_documentation_url(void) {
        assert_se(documentation_url_is_valid("http://www.freedesktop.org/wiki/Software/systemd"));
        assert_se(documentation_url_is_valid("https://www.kernel.org/doc/Documentation/binfmt_misc.txt"));  /* dead */
        assert_se(documentation_url_is_valid("https://www.kernel.org/doc/Documentation/admin-guide/binfmt-misc.rst"));
        assert_se(documentation_url_is_valid("https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html"));
        assert_se(documentation_url_is_valid("file:/foo/foo"));
        assert_se(documentation_url_is_valid("man:systemd.special(7)"));
        assert_se(documentation_url_is_valid("info:bar"));

        assert_se(!documentation_url_is_valid("foo:"));
        assert_se(!documentation_url_is_valid("info:"));
        assert_se(!documentation_url_is_valid(""));
}

int main(int argc, char *argv[]) {
        test_is_valid_documentation_url();

        return 0;
}
