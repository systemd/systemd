/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-network.h"
#include "strv.h"
#include "tests.h"

TEST(veth_extra_parse) {
        _cleanup_strv_free_ char **pairs = NULL;

        ASSERT_OK(veth_extra_parse(&pairs, "host0"));
        ASSERT_STRV_EQ_SET(pairs, "host0", "host0");

        pairs = strv_free(pairs);
        ASSERT_OK(veth_extra_parse(&pairs, "host0:"));
        ASSERT_STRV_EQ_SET(pairs, "host0", "host0");

        ASSERT_OK(veth_extra_parse(&pairs, "host1:cont1"));
        ASSERT_STRV_EQ_SET(pairs, "host0", "host0", "host1", "cont1");

        ASSERT_ERROR(veth_extra_parse(&pairs, "host0:waytoolongifname"), EINVAL);
        ASSERT_ERROR(veth_extra_parse(&pairs, "host0:bad/name"), EINVAL);
        ASSERT_ERROR(veth_extra_parse(&pairs, "bad/name:x"), EINVAL);
        ASSERT_ERROR(veth_extra_parse(&pairs, "a:b:c"), EINVAL);
        ASSERT_EQ(strv_length(pairs), 4U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
