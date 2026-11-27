/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-internal.h"
#include "bus-message-util.h"
#include "socket-netlink.h"
#include "tests.h"

static sd_bus_message* dns_servers_message_new(sd_bus *bus, char **servers) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "SetDNSURI"));
        ASSERT_OK(sd_bus_message_append_strv(m, servers));
        ASSERT_OK(sd_bus_message_seal(m, 1, /* timeout_usec= */ 0));
        ASSERT_OK(sd_bus_message_rewind(m, /* complete= */ true));

        return TAKE_PTR(m);
}

static void test_read_dns_servers_refused_one(sd_bus *bus, const char *server) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        struct in_addr_full **dns = NULL;
        size_t n = 0;

        log_debug("/* %s(%s) */", __func__, server);

        m = dns_servers_message_new(bus, STRV_MAKE("192.0.2.1", server));
        ASSERT_ERROR(bus_message_read_dns_servers(m, &error, &dns, &n), EINVAL);
        ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS));
        ASSERT_NULL(dns);
        ASSERT_EQ(n, 0U);
}

TEST(bus_message_read_dns_servers) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        struct in_addr_full **dns = NULL;
        size_t n = 0;

        CLEANUP_ARRAY(dns, n, in_addr_full_free_array);

        /* A bus for message operations, no connection needed */
        ASSERT_OK(sd_bus_new(&bus));
        bus->state = BUS_RUNNING;

        m = dns_servers_message_new(bus, STRV_MAKE("192.0.2.1",
                                                   "192.0.2.2:53#example.com",
                                                   "dnss://192.0.2.3:853#downgrade",
                                                   "dnz://[2001:db8::1]:5353"));
        ASSERT_OK(bus_message_read_dns_servers(m, /* reterr_error= */ NULL, &dns, &n));
        ASSERT_EQ(n, 4U);

        ASSERT_STREQ(in_addr_full_to_string(dns[0]), "192.0.2.1");

        /* Without a scheme, the default port of either transport is none */
        ASSERT_EQ(dns[1]->port, 0U);
        ASSERT_STREQ(dns[1]->server_name, "example.com");

        /* With a scheme, only the syntax is checked, so ports and schemes are kept as given */
        ASSERT_STREQ(dns[2]->scheme, "dnss");
        ASSERT_EQ(dns[2]->port, 853U);
        ASSERT_STREQ(in_addr_full_to_string(dns[2]), "dnss://192.0.2.3:853#downgrade");
        ASSERT_STREQ(dns[3]->scheme, "dnz");
        ASSERT_EQ(dns[3]->family, AF_INET6);
        ASSERT_EQ(dns[3]->port, 5353U);

        test_read_dns_servers_refused_one(bus, "");
        test_read_dns_servers_refused_one(bus, "foo");
        test_read_dns_servers_refused_one(bus, "dnss://");
        /* Our own stub listener */
        test_read_dns_servers_refused_one(bus, "127.0.0.53");
        test_read_dns_servers_refused_one(bus, "dns://0.0.0.0");
        /* The interface is given by the link */
        test_read_dns_servers_refused_one(bus, "192.0.2.1%1");
        test_read_dns_servers_refused_one(bus, "dns://192.0.2.1#ifname=1");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
