/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-server.h"
#include "resolved-dns-transport.h"
#include "tests.h"

/* All feature levels, in the documented order from worst to best */
static const DnsServerFeatureLevel levels_in_order[] = {
        { .transport = DNS_TRANSPORT_DNS, .edns = DNS_SERVER_EDNS_LEVEL_NONE,  .udp = false },
        { .transport = DNS_TRANSPORT_DNS, .edns = DNS_SERVER_EDNS_LEVEL_NONE,  .udp = true  },
        { .transport = DNS_TRANSPORT_DNS, .edns = DNS_SERVER_EDNS_LEVEL_EDNS0, .udp = true  },
        { .transport = DNS_TRANSPORT_DOT, .edns = DNS_SERVER_EDNS_LEVEL_EDNS0, .udp = false },
        { .transport = DNS_TRANSPORT_DNS, .edns = DNS_SERVER_EDNS_LEVEL_DO,    .udp = true  },
        { .transport = DNS_TRANSPORT_DOT, .edns = DNS_SERVER_EDNS_LEVEL_DO,    .udp = false },
};

static const char* const level_names[] = {
        "TCP",
        "UDP",
        "UDP+EDNS0",
        "TLS+EDNS0",
        "UDP+EDNS0+DO",
        "TLS+EDNS0+DO",
};

assert_cc(ELEMENTSOF(levels_in_order) == ELEMENTSOF(level_names));

TEST(feature_level_compare_order) {
        for (size_t i = 0; i < ELEMENTSOF(levels_in_order); i++)
                for (size_t j = 0; j < ELEMENTSOF(levels_in_order); j++) {
                        ASSERT_EQ(dns_server_feature_level_compare(levels_in_order[i], levels_in_order[j]), CMP(i, j));
                        ASSERT_EQ(dns_server_feature_level_equal(levels_in_order[i], levels_in_order[j]), i == j);
                }
}

TEST(feature_level_to_string) {
        for (size_t i = 0; i < ELEMENTSOF(levels_in_order); i++)
                ASSERT_STREQ(dns_server_feature_level_to_string(levels_in_order[i]), level_names[i]);

        ASSERT_NULL(dns_server_feature_level_to_string(_DNS_SERVER_FEATURE_LEVEL_INVALID));
}

TEST(feature_level_constants) {
        ASSERT_TRUE(dns_server_feature_level_equal(DNS_SERVER_FEATURE_LEVEL_TCP, levels_in_order[0]));
        ASSERT_TRUE(dns_server_feature_level_equal(DNS_SERVER_FEATURE_LEVEL_UDP, levels_in_order[1]));
        ASSERT_TRUE(dns_server_feature_level_equal(DNS_SERVER_FEATURE_LEVEL_BEST, levels_in_order[ELEMENTSOF(levels_in_order) - 1]));
}

TEST(feature_level_invalid) {
        ASSERT_FALSE(dns_server_feature_level_is_valid(_DNS_SERVER_FEATURE_LEVEL_INVALID));
        ASSERT_TRUE(dns_server_feature_level_equal(_DNS_SERVER_FEATURE_LEVEL_INVALID, _DNS_SERVER_FEATURE_LEVEL_INVALID));

        /* Invalid feature levels sort before all valid ones */
        FOREACH_ELEMENT(l, levels_in_order) {
                ASSERT_TRUE(dns_server_feature_level_is_valid(*l));
                ASSERT_LT(dns_server_feature_level_compare(_DNS_SERVER_FEATURE_LEVEL_INVALID, *l), 0);
                ASSERT_GT(dns_server_feature_level_compare(*l, _DNS_SERVER_FEATURE_LEVEL_INVALID), 0);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG)
