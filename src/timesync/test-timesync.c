/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Some unit tests for the helper functions in timesyncd. */

#include "alloc-util.h"
#include "tests.h"
#include "timesyncd-conf.h"
#include "timesyncd-manager.h"
#include "timesyncd-server.h"

TEST(manager_parse_string) {
        /* Make sure that NTP_SERVERS is configured to something
         * that we can actually parse successfully. */

        _cleanup_(manager_freep) Manager *m = NULL;

        assert_se(manager_new(&m) == 0);

        assert_se(!m->fallback_set);
        assert_se(manager_parse_server_string(m, SERVER_FALLBACK, NTP_SERVERS) == 0);
        assert_se(m->fallback_set);
        assert_se(manager_parse_fallback_string(m, NTP_SERVERS) == 0);

        assert_se(manager_parse_server_string(m, SERVER_SYSTEM, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123") == 0);
        assert_se(manager_parse_server_string(m, SERVER_FALLBACK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123") == 0);
        assert_se(manager_parse_server_string(m, SERVER_LINK, "time1.foobar.com time2.foobar.com axrfav.,avf..ra 12345..123") == 0);
}

TEST(server_name_parse) {
        static const struct {
                const char *input;
                const char *expected_host;
                uint16_t expected_port;
        } valid[] = {
                { "time1.foobar.com",      "time1.foobar.com",  DEFAULT_NTP_PORT },
                { "time1.foobar.com:1234", "time1.foobar.com",  1234     },
                { "time1.foobar.com.",     "time1.foobar.com.", DEFAULT_NTP_PORT },
                { "10.0.0.1",              "10.0.0.1",          DEFAULT_NTP_PORT },
                { "10.0.0.1:1234",         "10.0.0.1",          1234     },
                { "10.0.0.1:65535",        "10.0.0.1",          65535    },
                { "2001:db8::10",          "2001:db8::10",      DEFAULT_NTP_PORT },
                /* Without square brackets the whole string is interpreted as an IPv6 address,
                 * and never split into "address:port". */
                { "2001:db8::10:1123",     "2001:db8::10:1123", DEFAULT_NTP_PORT },
                { "[2001:db8::10]:1123",   "2001:db8::10",      1123     },
                { "[2001:db8::10]:1",      "2001:db8::10",      1        },
                /* Zone suffixes are preserved verbatim and resolved at lookup time. */
                { "fe80::10%1",            "fe80::10%1",        DEFAULT_NTP_PORT },
                { "fe80::10%eth0",         "fe80::10%eth0",     DEFAULT_NTP_PORT },
                { "[fe80::10%1]:1123",     "fe80::10%1",        1123     },
                { "[fe80::10%eth0]:1123",  "fe80::10%eth0",     1123     },
                { "[fe80::10]:1123%eth0",  "fe80::10%eth0",     1123     },
                { "[fe80::10%eth0]:123",   "fe80::10%eth0",     DEFAULT_NTP_PORT },
                { "fe80::10%nonexistent-interface", "fe80::10%nonexistent-interface", DEFAULT_NTP_PORT },
        };

        static const char * const invalid[] = {
                "",
                ":123",
                "foo:",
                "foo:bar",
                "foo:bar:baz",
                "foo:0",
                "foo:65536",
                "10.0.0.1:0",
                "10.0.0.1:",
                "10.0.0.1:65536",
                "[2001:db8::10]",
                "[2001:db8::10]:",
                "[2001:db8::10]x:1123",
                "[fe80::10%eth0]",
                "[fe80::10%eth0]:",
                "[fe80::10%eth0]:0",
                "[fe80::10%eth0]:65536",
                "[fe80::10%]:1123",
                "[fe80::10]:1123%",
                "[fe80::10]:0%eth0",
                "[fe80::10]:65536%eth0",
                "[fe80::10%eth0]:1123%lo",
                "[fe80::10%eth0]x:1123",
                "[fe80::10%eth0]:1123]",
                "fe80::10%",
                "fe80::10%eth0:1234",
                "fe80::10%eth 0",
                "fe80::10%eth\t0",
                "fe80::10%eth\n0",
                "fe80::10%eth/0",
                "fe80::10%eth0#name",
                "fe80::10%.",
                "fe80::10%..",
                "fe80::10%0",
                "fe80::10%2147483648",
                "[fe80::10]:1123%eth 0",
                "[fe80::10%eth/0]:1123",
                "[fe80::10]:1123%"
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "192.168.1.1%eth0",
                "axrfav.,avf..ra",
                "12345..123",
                "foo[bar]",
        };

        FOREACH_ELEMENT(i, valid) {
                _cleanup_free_ char *host = NULL;
                uint16_t port = 0;

                ASSERT_OK(server_name_parse(i->input, &host, &port));
                ASSERT_STREQ(host, i->expected_host);
                ASSERT_EQ(port, i->expected_port);
        }

        FOREACH_ELEMENT(i, invalid)
                ASSERT_ERROR(server_name_parse(*i, /* ret_host= */ NULL, /* ret_port= */ NULL), EINVAL);
}

static size_t server_name_count(ServerName *first) {
        size_t n = 0;

        LIST_FOREACH(names, i, first)
                n++;

        return n;
}

TEST(manager_parse_server_port) {
        static const struct {
                const char *host;
                const char *string;
                uint16_t port;
        } expected[] = {
                { "time1.foobar.com", "time1.foobar.com:1234", 1234     },
                { "10.0.0.1",         "10.0.0.1",             DEFAULT_NTP_PORT },
                { "2001:db8::10",     "[2001:db8::10]:1123",  1123     },
                { "2001:db8::11",     "2001:db8::11",         DEFAULT_NTP_PORT },
                { "fe80::10%lo",      "[fe80::10]:1123%lo",   1123     },
                { "fe80::11%1",       "[fe80::11]:1123%1",    1123     },
                { "fe80::12%lo",      "fe80::12%lo",          DEFAULT_NTP_PORT },
        };
        _cleanup_(manager_freep) Manager *m = NULL;
        ServerName *n;

        ASSERT_OK(manager_new(&m));

        /* Port numbers, and invalid entries which are ignored */
        ASSERT_OK(manager_parse_server_string(m, SERVER_SYSTEM,
                "time1.foobar.com:1234 10.0.0.1 [2001:db8::10]:1123 2001:db8::11 [fe80::10]:1123%lo "
                "[fe80::11%1]:1123 [fe80::12%lo]:123 "
                "axrfav.,avf..ra foo:bar 10.0.0.1:0 [2001:db8::10] 12345..123"));

        ASSERT_EQ(server_name_count(m->system_servers), ELEMENTSOF(expected));

        n = m->system_servers;
        FOREACH_ELEMENT(i, expected) {
                ASSERT_NOT_NULL(n);
                ASSERT_STREQ(n->host, i->host);
                ASSERT_STREQ(n->string, i->string);
                ASSERT_EQ(n->port, i->port);
                n = n->names_next;
        }
        ASSERT_NULL(n);

        /* Duplicates are filtered out */
        ASSERT_OK(manager_parse_server_string(m, SERVER_SYSTEM,
                "time1.foobar.com:1234 10.0.0.1:123 [2001:db8::10]:1123 2001:db8::11 [fe80::10%lo]:1123 "
                "[fe80::11]:1123%1 fe80::12%lo"));
        ASSERT_EQ(server_name_count(m->system_servers), ELEMENTSOF(expected));

        /* Different ports are not duplicates */
        ASSERT_OK(manager_parse_server_string(m, SERVER_SYSTEM, "time1.foobar.com:123 [2001:db8::11]:1234"));
        ASSERT_EQ(server_name_count(m->system_servers), ELEMENTSOF(expected) + 2);

        /* FallbackNTP= takes the same syntax */
        ASSERT_OK(manager_parse_server_string(m, SERVER_FALLBACK, "time1.foobar.com:1234 [2001:db8::10]:1123"));
        ASSERT_EQ(server_name_count(m->fallback_servers), 2U);

        n = m->fallback_servers;
        ASSERT_NOT_NULL(n);
        ASSERT_STREQ(n->host, "time1.foobar.com");
        ASSERT_STREQ(n->string, "time1.foobar.com:1234");
        ASSERT_EQ(n->port, 1234);

        n = n->names_next;
        ASSERT_NOT_NULL(n);
        ASSERT_STREQ(n->host, "2001:db8::10");
        ASSERT_STREQ(n->string, "[2001:db8::10]:1123");
        ASSERT_EQ(n->port, 1123);
        ASSERT_NULL(n->names_next);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
