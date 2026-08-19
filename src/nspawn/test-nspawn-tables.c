/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-settings.h"
#include "test-tables.h"
#include "tests.h"

TEST(settings_network_veth) {
        struct {
                const char *name;
                Settings settings;
                int expected;
        } cases[] = {
                { "unset",             { .private_network = -1, .network_veth = -1 }, -1 },
                { "veth-no",           { .private_network = -1, .network_veth =  0 },  0 },
                { "veth-yes",          { .private_network = -1, .network_veth =  1 },  1 },
                { "bridge",            { .private_network = -1, .network_veth = -1,
                                           .network_bridge = (char*) "br0" }, 1 },
                { "bridge-veth-no",    { .private_network = -1, .network_veth =  0,
                                           .network_bridge = (char*) "br0" }, 0 },
                { "bridge-veth-yes",   { .private_network = -1, .network_veth =  1,
                                           .network_bridge = (char*) "br0" }, 1 },
                { "zone",              { .private_network = -1, .network_veth = -1,
                                           .network_zone = (char*) "vz-test" }, 1 },
                { "zone-veth-no",      { .private_network = -1, .network_veth =  0,
                                           .network_zone = (char*) "vz-test" }, 0 },
                { "zone-veth-yes",     { .private_network = -1, .network_veth =  1,
                                           .network_zone = (char*) "vz-test" }, 1 },
        };

        FOREACH_ELEMENT(c, cases) {
                log_info("/* %s */", c->name);
                ASSERT_EQ(settings_network_veth(&c->settings), c->expected);
        }
}

TEST(tables) {
        test_table(ResolvConfMode, resolv_conf_mode, RESOLV_CONF_MODE);
        test_table(TimezoneMode, timezone_mode, TIMEZONE_MODE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
