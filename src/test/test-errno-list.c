/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "errno-list.h"
#include "errno-to-name.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"

TEST(errno_list) {
        for (size_t i = 0; i < ELEMENTSOF(errno_names); i++) {
                if (errno_names[i]) {
                        assert_se(streq(errno_to_name(i), errno_names[i]));
                        assert_se(errno_from_name(errno_names[i]) == (int) i);
                }
        }

#ifdef ECANCELLED
        /* ECANCELLED is an alias of ECANCELED. */
        assert_se(streq(errno_to_name(ECANCELLED), "ECANCELED"));
#endif
        assert_se(streq(errno_to_name(ECANCELED), "ECANCELED"));

#ifdef EREFUSED
        /* EREFUSED is an alias of ECONNREFUSED. */
        assert_se(streq(errno_to_name(EREFUSED), "ECONNREFUSED"));
#endif
        assert_se(streq(errno_to_name(ECONNREFUSED), "ECONNREFUSED"));
}

DEFINE_TEST_MAIN(LOG_INFO);
