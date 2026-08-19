/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-settings.h"
#include "test-tables.h"
#include "tests.h"

static void test_settings_network_veth(void) {
        char *interfaces[] = { (char*) "host", NULL };
        struct {
                Settings settings;
                int expected;
        } cases[] = {
                { { .private_network = -1, .network_veth = -1 }, -1 },
                { { .private_network = 0, .network_veth = -1 }, -1 },
                { { .private_network = 1, .network_veth = -1 }, -1 },
                { { .network_veth = -1, .network_namespace_path = (char*) "/run/netns/test" }, -1 },
                { {
                        .network_veth = -1,
                        .network_interfaces = interfaces,
                        .network_macvlan = interfaces,
                        .network_ipvlan = interfaces,
                        .network_veth_extra = interfaces,
                }, -1 },
                { { .network_veth = 0 }, 0 },
                { { .network_veth = 0, .network_bridge = (char*) "br0" }, 0 },
                { { .network_veth = 1 }, 1 },
                { { .network_veth = -1, .network_bridge = (char*) "br0" }, 1 },
                { { .network_veth = -1, .network_zone = (char*) "vz-test" }, 1 },
        };

        FOREACH_ELEMENT(c, cases)
                ASSERT_EQ(settings_network_veth(&c->settings), c->expected);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(ResolvConfMode, resolv_conf_mode, RESOLV_CONF_MODE);
        test_table(TimezoneMode, timezone_mode, TIMEZONE_MODE);
        test_settings_network_veth();

        return 0;
}
