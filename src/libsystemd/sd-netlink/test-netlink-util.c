/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <unistd.h>

#include "netlink-util.h"
#include "strv.h"
#include "tests.h"

static void test_rtnl_set_link_name(sd_netlink *rtnl, int ifindex) {
        _cleanup_strv_free_ char **alternative_names = NULL;
        int r;

        log_debug("/* %s */", __func__);

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        /* Test that the new name (which is currently an alternative name) is
         * restored as an alternative name on error. Create an error by using
         * an invalid device name, namely one that exceeds IFNAMSIZ
         * (alternative names can exceed IFNAMSIZ, but not regular names). */
        r = rtnl_set_link_alternative_names(&rtnl, ifindex, STRV_MAKE("testlongalternativename"));
        if (r == -EPERM)
                return (void) log_tests_skipped("missing required capabilities");

        assert_se(r >= 0);
        assert_se(rtnl_set_link_name(&rtnl, ifindex, "testlongalternativename") == -EINVAL);
        assert_se(rtnl_get_link_alternative_names(&rtnl, ifindex, &alternative_names) >= 0);
        assert_se(strv_contains(alternative_names, "testlongalternativename"));
        assert_se(rtnl_delete_link_alternative_names(&rtnl, ifindex, STRV_MAKE("testlongalternativename")) >= 0);
}

int main(void) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int if_loopback;

        test_setup_logging(LOG_DEBUG);

        assert_se(sd_netlink_open(&rtnl) >= 0);
        assert_se(rtnl);
        assert_se((if_loopback = if_nametoindex("lo")) > 0);

        test_rtnl_set_link_name(rtnl, if_loopback);

        return EXIT_SUCCESS;
}
