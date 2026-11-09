/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-network.h"
#include "strv.h"
#include "tests.h"

static void test_veth_extra_parse(void) {
        _cleanup_strv_free_ char **pairs = NULL;

        ASSERT_OK(veth_extra_parse(&pairs, "host0"));
        ASSERT_EQ(strv_length(pairs), 2U);
        ASSERT_STREQ(pairs[0], "host0");
        ASSERT_STREQ(pairs[1], "host0");

        strv_free(pairs);
        pairs = NULL;
        ASSERT_OK(veth_extra_parse(&pairs, "host0:"));
        ASSERT_EQ(strv_length(pairs), 2U);
        ASSERT_STREQ(pairs[0], "host0");
        ASSERT_STREQ(pairs[1], "host0");

        ASSERT_ERROR(veth_extra_parse(&pairs, "host0:bad/name"), EINVAL);
        ASSERT_ERROR(veth_extra_parse(&pairs, "bad/name:x"), EINVAL);
        ASSERT_ERROR(veth_extra_parse(&pairs, "a:b:c"), EINVAL);
        ASSERT_EQ(strv_length(pairs), 2U);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_veth_extra_parse();
        return 0;
}
