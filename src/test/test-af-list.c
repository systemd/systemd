/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "tests.h"

_unused_
static const struct af_name* lookup_af(register const char *str, register GPERF_LEN_TYPE len);

#include "af-from-name.inc"
#include "af-to-name.inc"

TEST(af_list) {
        for (int i = 0; i < (int) ELEMENTSOF(af_names); i++)
                if (af_names[i]) {
                        ASSERT_STREQ(af_to_name(i), af_names[i]);
                        ASSERT_EQ(af_from_name(af_names[i]), i);
                }

        ASSERT_NULL(af_to_name(af_max()));
        ASSERT_NULL(af_to_name(0));
        ASSERT_NULL(af_to_name(-1));
        ASSERT_ERROR(af_from_name("huddlduddl"), EINVAL);
        ASSERT_ERROR(af_from_name(""), EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
