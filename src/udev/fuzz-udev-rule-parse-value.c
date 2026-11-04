/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "alloc-util.h"
#include "fuzz.h"
#include "tests.h"
#include "udev-rules.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *str = NULL;
        int r;
        char *value = UINT_TO_PTR(0x12345678U);
        char *endpos = UINT_TO_PTR(0x87654321U);
        bool is_case_sensitive;

        fuzz_setup_logging();

        str = ASSERT_NOT_NULL(malloc(size + 1));
        memcpy(str, data, size);
        str[size] = '\0';

        r = udev_rule_parse_value(str, &value, &endpos, &is_case_sensitive);
        if (r < 0) {
                /* not modified on failure */
                ASSERT_PTR_EQ(value, UINT_TO_PTR(0x12345678U));
                ASSERT_PTR_EQ(endpos, UINT_TO_PTR(0x87654321U));
        } else {
                ASSERT_TRUE(endpos <= str + size);
                ASSERT_TRUE(endpos > str + 1);
        }

        return 0;
}
