/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "macro.h"
#include "replace-var.h"
#include "string-util.h"
#include "tests.h"

static char *lookup(const char *variable, void *userdata) {
        return strjoin("<<<", variable, ">>>");
}

TEST(replace_var) {
        char *r;

        assert_se(r = replace_var("@@@foobar@xyz@HALLO@foobar@test@@testtest@TEST@...@@@", lookup, NULL));
        puts(r);
        assert_se(streq(r, "@@@foobar@xyz<<<HALLO>>>foobar@test@@testtest<<<TEST>>>...@@@"));
        free(r);
}

TEST(strreplace) {
        char *r;

        assert_se(r = strreplace("XYZFFFFXYZFFFFXYZ", "XYZ", "ABC"));
        puts(r);
        assert_se(streq(r, "ABCFFFFABCFFFFABC"));
        free(r);
}

DEFINE_TEST_MAIN(LOG_INFO);
