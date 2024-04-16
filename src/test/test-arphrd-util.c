/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <linux/if_arp.h>

#include "arphrd-util.h"
#include "string-util.h"
#include "tests.h"

TEST(arphrd) {
        for (int i = 0; i <= ARPHRD_VOID + 1; i++) {
                const char *name;

                name = arphrd_to_name(i);
                if (name) {
                        log_info("%i: %s", i, name);

                        ASSERT_EQ(arphrd_from_name(name), i);
                }
        }

        ASSERT_NULL(arphrd_to_name(ARPHRD_VOID + 1));
        assert_se(arphrd_from_name("huddlduddl") == -EINVAL);
        assert_se(arphrd_from_name("") == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
