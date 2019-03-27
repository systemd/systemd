/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "macro.h"
#include "replace-var.h"
#include "string-util.h"

static char *lookup(const char *variable, void *userdata) {
        return strjoin("<<<", variable, ">>>");
}

int main(int argc, char *argv[]) {
        char *r;

        assert_se(r = replace_var("@@@foobar@xyz@HALLO@foobar@test@@testtest@TEST@...@@@", lookup, NULL));
        puts(r);
        assert_se(streq(r, "@@@foobar@xyz<<<HALLO>>>foobar@test@@testtest<<<TEST>>>...@@@"));
        free(r);

        assert_se(r = strreplace("XYZFFFFXYZFFFFXYZ", "XYZ", "ABC"));
        puts(r);
        assert_se(streq(r, "ABCFFFFABCFFFFABC"));
        free(r);

        return 0;
}
