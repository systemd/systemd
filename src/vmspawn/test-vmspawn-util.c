/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "string-util.h"
#include "tests.h"
#include "vmspawn-util.h"

#define _ESCAPE_QEMU_VALUE_CHECK(str, correct, varname) \
        do {                                            \
                _cleanup_free_ char* varname = NULL;    \
                varname = escape_qemu_value(str);       \
                assert(varname);                        \
                assert_se(streq(varname, correct));     \
        } while (0)

#define ESCAPE_QEMU_VALUE_CHECK(str, correct) \
        _ESCAPE_QEMU_VALUE_CHECK(str, correct, conf##__COUNTER__)

TEST(escape_qemu_value) {
        ESCAPE_QEMU_VALUE_CHECK("abcde", "abcde");
        ESCAPE_QEMU_VALUE_CHECK("a,bcde", "a,,bcde");
        ESCAPE_QEMU_VALUE_CHECK(",,,", ",,,,,,");
        ESCAPE_QEMU_VALUE_CHECK("", "");
}

DEFINE_TEST_MAIN(LOG_INFO);
