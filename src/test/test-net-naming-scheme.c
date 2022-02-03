/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-naming-scheme.h"
#include "string-util.h"
#include "tests.h"

TEST(default_net_naming_scheme) {
        const NamingScheme *n;
        assert_se(n = naming_scheme_from_name(DEFAULT_NET_NAMING_SCHEME));
        log_info("default → %s", n->name);
}

TEST(naming_scheme_conversions) {
        const NamingScheme *n;
        assert_se(n = naming_scheme_from_name("latest"));
        log_info("latest → %s", n->name);

        assert_se(n = naming_scheme_from_name("v238"));
        assert_se(streq(n->name, "v238"));
}

DEFINE_TEST_MAIN(LOG_INFO);
