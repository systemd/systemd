/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-naming-scheme.h"
#include "string-util.h"
#include "tests.h"

static void test_default_net_naming_scheme(void) {
        log_info("/* %s */", __func__);

        const NamingScheme *n;
        assert_se(n = naming_scheme_from_name(DEFAULT_NET_NAMING_SCHEME));
        log_info("default → %s", n->name);
}

static void test_naming_scheme_conversions(void) {
        log_info("/* %s */", __func__);

        const NamingScheme *n;
        assert_se(n = naming_scheme_from_name("latest"));
        log_info("latest → %s", n->name);

        assert_se(n = naming_scheme_from_name("v238"));
        assert_se(streq(n->name, "v238"));
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_default_net_naming_scheme();
        test_naming_scheme_conversions();
}
