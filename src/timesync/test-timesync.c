/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Some unit tests for the helper functions in timesyncd. */

#include "log.h"
#include "macro.h"
#include "timesyncd-conf.h"
#include "timesyncd-server.h"
#include "tests.h"

TEST(manager_parse_string) {
        /* Make sure that NTP_SERVERS is configured to something
         * that we can actually parse successfully. */

        _cleanup_(manager_freep) Manager *m = NULL;

        ASSERT_TRUE(manager_new(&m) == 0);

        ASSERT_TRUE(!m->have_fallbacks);
        ASSERT_TRUE(manager_parse_server_string(m, SERVER_FALLBACK, NTP_SERVERS) == 0);
        ASSERT_TRUE(m->have_fallbacks);
        ASSERT_TRUE(manager_parse_fallback_string(m, NTP_SERVERS) == 0);

        ASSERT_TRUE(manager_parse_server_string(m, SERVER_SYSTEM, "time1.foobar.com time2.foobar.com axrfav.,avf..ra time2.foobar.com:1234 10.0.0.1 fe80::1 [fe80::1] 10.0.0.1:1234 [fe80::1]:1234 12345..123") == 0);
        ASSERT_TRUE(manager_parse_server_string(m, SERVER_FALLBACK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra time2.foobar.com:1234 10.0.0.1 fe80::1 [fe80::1] 10.0.0.1:1234 [fe80::1]:1234 12345..123") == 0);
        ASSERT_TRUE(manager_parse_server_string(m, SERVER_LINK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra time2.foobar.com:1234 10.0.0.1 fe80::1 [fe80::1] 10.0.0.1:1234 [fe80::1]:1234 12345..123") == 0);
}

static void test_process_server_name_for_address_one(const char *name, const char* exp_addr, const char *exp_port) {
        char *addr = NULL, *port = NULL;

        ASSERT_TRUE(process_server_name_for_address(name, &addr, &port) >= 0);
        log_debug("For '%s', addr = %s / port = %s", name, addr, port);
        ASSERT_STREQ(addr, exp_addr);
        ASSERT_STREQ(port, exp_port);
}

TEST(process_server_name_for_address) {
        test_process_server_name_for_address_one("time.foobar.com", "time.foobar.com", NTP_SERVICE_PORT_NUMBER);
        test_process_server_name_for_address_one("8.8.8.8", "8.8.8.8", NTP_SERVICE_PORT_NUMBER);
        test_process_server_name_for_address_one("fe80::1", "fe80::1", NTP_SERVICE_PORT_NUMBER);
        /* call to resolve an IP::v:6 address with brackets but no port number fails, so strip '[]' */
        test_process_server_name_for_address_one("[fe80::1]", "fe80::1", NTP_SERVICE_PORT_NUMBER);
        test_process_server_name_for_address_one("time1.foobar.com:1234", "time1.foobar.com", "1234");
        test_process_server_name_for_address_one("8.8.8.8:1234", "8.8.8.8", "1234");
        test_process_server_name_for_address_one("[fe80::1]:1234", "fe80::1", "1234");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
