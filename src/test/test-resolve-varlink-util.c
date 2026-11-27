/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "ordered-set.h"
#include "resolve-varlink-util.h"
#include "socket-netlink.h"
#include "strv.h"
#include "tests.h"

static OrderedSet* dispatch_servers(const char *json) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        OrderedSet *servers = NULL;

        ASSERT_OK(sd_json_parse(json, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(dispatch_dns_server_context_array("servers", v, /* flags= */ 0, &servers));

        return servers;
}

static void test_dispatch_refused_one(const char *json) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_ordered_set_free_ OrderedSet *servers = NULL;

        log_debug("/* %s(%s) */", __func__, json);

        ASSERT_OK(sd_json_parse(json, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_FAIL(dispatch_dns_server_context_array("servers", v, /* flags= */ 0, &servers));
        ASSERT_NULL(servers);
}

static void assert_server_string(const DNSServer *s, const char *expected) {
        _cleanup_(in_addr_full_freep) struct in_addr_full *a = NULL;

        ASSERT_OK(dns_server_to_in_addr_full(s, &a));
        ASSERT_STREQ(in_addr_full_to_string(a), expected);
}

TEST(dispatch_dns_server_context_array) {
        _cleanup_ordered_set_free_ OrderedSet *servers = NULL;
        DNSServer *s;

        /* The URI parts, the legacy fields, and the URI as a whole describe the same servers */
        servers = dispatch_servers(
                        "["
                        "{\"family\": 2, \"address\": [192, 0, 2, 1], \"port\": 853}, "
                        "{\"family\": 2, \"address\": [192, 0, 2, 2], \"port\": 853, \"name\": \"example.com\","
                        " \"scheme\": \"dnss\", \"parameters\": {\"downgrade\": \"5353\"}}, "
                        "{\"uri\": \"dnss://192.0.2.3#name=example.com&downgrade\"}, "
                        "{\"uri\": \"192.0.2.4:53#example.com\"}, "
                        "{\"family\": 2, \"address\": [192, 0, 2, 5], \"scheme\": \"dnz\", \"path\": \"a/b\", \"query\": \"c=d\"}"
                        "]");
        ASSERT_EQ(ordered_set_size(servers), 5U);

        /* Without a scheme, the default port of either transport is none */
        s = ordered_set_get(servers, ordered_set_first(servers));
        ASSERT_EQ(s->port, 0U);
        ASSERT_NULL(s->scheme);
        assert_server_string(s, "192.0.2.1");

        size_t i = 0;
        ORDERED_SET_FOREACH(s, servers) {
                switch (i++) {

                case 1:
                        /* With a scheme, only systemd-resolved knows the default port */
                        ASSERT_EQ(s->port, 853U);
                        ASSERT_TRUE(strv_equal(s->parameters, STRV_MAKE("downgrade=5353")));
                        assert_server_string(s, "dnss://192.0.2.2:853#name=example.com&downgrade=5353");
                        break;

                case 2:
                        ASSERT_NULL(s->uri);
                        ASSERT_STREQ(s->scheme, "dnss");
                        ASSERT_STREQ(s->server_name, "example.com");
                        ASSERT_TRUE(strv_equal(s->parameters, STRV_MAKE("downgrade=")));
                        assert_server_string(s, "dnss://192.0.2.3#name=example.com&downgrade");
                        break;

                case 3:
                        ASSERT_NULL(s->scheme);
                        ASSERT_EQ(s->port, 0U);
                        assert_server_string(s, "192.0.2.4#example.com");
                        break;

                case 4:
                        /* Unknown schemes are left to systemd-resolved */
                        assert_server_string(s, "dnz://192.0.2.5/a/b?c=d");
                        break;
                }
        }

        /* Neither an address nor a URI */
        test_dispatch_refused_one("[{\"port\": 53}]");
        /* The URI is the server as a whole */
        test_dispatch_refused_one("[{\"uri\": \"dnss://192.0.2.1\", \"family\": 2, \"address\": [192, 0, 2, 1]}]");
        test_dispatch_refused_one("[{\"uri\": \"dnss://192.0.2.1\", \"scheme\": \"dnss\"}]");
        test_dispatch_refused_one("[{\"uri\": \"dnss://\"}]");
        test_dispatch_refused_one("[{\"uri\": \"dns://127.0.0.53\"}]");
        /* URI parts without a scheme */
        test_dispatch_refused_one("[{\"family\": 2, \"address\": [192, 0, 2, 1], \"path\": \"a\"}]");
        test_dispatch_refused_one("[{\"family\": 2, \"address\": [192, 0, 2, 1], \"parameters\": {\"downgrade\": \"\"}}]");
        /* Invalid schemes and parts */
        test_dispatch_refused_one("[{\"family\": 2, \"address\": [192, 0, 2, 1], \"scheme\": \"DNS!\"}]");
        test_dispatch_refused_one("[{\"family\": 2, \"address\": [192, 0, 2, 1], \"scheme\": \"dns\", \"path\": \"a#b\"}]");
        /* The server name and interface have fields of their own */
        test_dispatch_refused_one("[{\"family\": 2, \"address\": [192, 0, 2, 1], \"scheme\": \"dns\", \"parameters\": {\"name\": \"x\"}}]");
        test_dispatch_refused_one("[{\"family\": 2, \"address\": [192, 0, 2, 1], \"scheme\": \"dns\", \"parameters\": {\"ifname\": \"1\"}}]");
        test_dispatch_refused_one("[{\"family\": 2, \"address\": [192, 0, 2, 1], \"scheme\": \"dns\", \"parameters\": {\"a\": 1}}]");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
