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

TEST(server_name_parse_port) {
        /* When supplied with a port number, use it (and re-use it if we fail to connect), and parse all of
         * host.domain, host.domain:port, I.P.v.4, IP::v:6, [IP::v:6], I.P.v.4:port, [IP::v:6]:port appropriately. */
        _cleanup_(server_name_freep) ServerName *n = NULL;
        n = new(ServerName, 1);
        *n = (ServerName) {
                .string = strdupa_safe("time1.foobar.com"),
                .overridden_port = NULL,
        };
        ASSERT_NULL(n->overridden_port); //no override

        ASSERT_TRUE(server_name_parse_port(n) == 0);
        ASSERT_STREQ(n->string, "time1.foobar.com");
        ASSERT_NULL(n->overridden_port); //no override

        n->string = strdupa_safe("8.8.8.8");
        ASSERT_TRUE(server_name_parse_port(n) == 0);
        ASSERT_STREQ(n->string, "8.8.8.8");
        ASSERT_NULL(n->overridden_port); //no override

        n->string = strdupa_safe("[fe80::1]"); // NB: won't resolve unless you remove the square brackets
        ASSERT_TRUE(server_name_parse_port(n) == 0);
        ASSERT_STREQ(n->string, "[fe80::1]");
        ASSERT_NULL(n->overridden_port); //no override

        n->string = strdupa_safe("fe80::1");
        ASSERT_TRUE(server_name_parse_port(n) == 0);
        ASSERT_STREQ(n->string, "fe80::1");
        ASSERT_NULL(n->overridden_port); //no override

        n->string = strdupa_safe("time1.foobar.com:1234");
        ASSERT_TRUE(server_name_parse_port(n) == 1);
        ASSERT_STREQ(n->string, "time1.foobar.com");
        ASSERT_TRUE(streq_ptr(n->overridden_port, "1234"));
        ASSERT_TRUE(server_name_parse_port(n) == 0);
        ASSERT_STREQ(n->string, "time1.foobar.com");
        ASSERT_STREQ(n->overridden_port, "1234"); //reuse (eg when re-connecting) retains override

        n->string = strdupa_safe("8.8.8.8:12323");
        ASSERT_TRUE(server_name_parse_port(n) == 1);
        ASSERT_STREQ(n->string, "8.8.8.8");
        ASSERT_STREQ(n->overridden_port, "12323");

        n->string = strdupa_safe("[fe80::1]:12345");
        ASSERT_TRUE(server_name_parse_port(n) == 2);
        ASSERT_STREQ(n->string, "[fe80::1]");
        ASSERT_STREQ(n->overridden_port, "12345");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
