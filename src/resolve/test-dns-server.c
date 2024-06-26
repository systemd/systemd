/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "resolved-dns-server.h"
#include "resolved-manager.h"
#include "tests.h"

/* ================================================================
 * dns_server_move_back_and_unmark(), dns_server_unlink(),
 * dns_server_unlink_marked(), dns_server_mark_all()
 * ================================================================ */

static void check_dns_servers(Manager *manager, const char **names, size_t n) {
        ASSERT_NOT_NULL(manager);
        ASSERT_NOT_NULL(names);

        ASSERT_EQ(manager->n_dns_servers, n);

        size_t i = 0;

        LIST_FOREACH(servers, s, manager->dns_servers) {
                ASSERT_STREQ(s->server_name, names[i++]);
        }

        ASSERT_EQ(i, n);
}

TEST(dns_server_move_back_and_unmark) {
        Manager manager = {};
        DnsServer *server1 = NULL, *server2 = NULL, *server3 = NULL, *server4 = NULL;

        union in_addr_union addr1 = { .in.s_addr = htobe32(0xc0a80180) };
        union in_addr_union addr2 = { .in.s_addr = htobe32(0xc0a80181) };
        union in_addr_union addr3 = { .in.s_addr = htobe32(0xc0a80182) };
        union in_addr_union addr4 = { .in.s_addr = htobe32(0xc0a80183) };

        ASSERT_OK(dns_server_new(
                        &manager, &server1, DNS_SERVER_SYSTEM, NULL, AF_INET,
                        &addr1, 53, 0, "alice.local", RESOLVE_CONFIG_SOURCE_FILE));

        ASSERT_OK(dns_server_new(
                        &manager, &server2, DNS_SERVER_SYSTEM, NULL, AF_INET,
                        &addr2, 53, 0, "bob.local", RESOLVE_CONFIG_SOURCE_FILE));

        ASSERT_OK(dns_server_new(
                        &manager, &server3, DNS_SERVER_SYSTEM, NULL, AF_INET,
                        &addr3, 53, 0, "carol.local", RESOLVE_CONFIG_SOURCE_FILE));

        ASSERT_OK(dns_server_new(
                        &manager, &server4, DNS_SERVER_SYSTEM, NULL, AF_INET,
                        &addr4, 53, 0, "dave.local", RESOLVE_CONFIG_SOURCE_FILE));

        ASSERT_NOT_NULL(server1);
        ASSERT_NOT_NULL(server2);
        ASSERT_NOT_NULL(server3);
        ASSERT_NOT_NULL(server4);

        const char *names1[] = { "alice.local", "bob.local", "carol.local", "dave.local" };
        check_dns_servers(&manager, names1, 4);

        server1->marked = true;
        server2->marked = true;
        server3->marked = true;
        server4->marked = true;

        dns_server_move_back_and_unmark(server2);

        const char *names2[] = { "alice.local", "carol.local", "dave.local", "bob.local" };
        check_dns_servers(&manager, names2, 4);

        ASSERT_TRUE(server1->marked);
        ASSERT_FALSE(server2->marked);
        ASSERT_TRUE(server3->marked);
        ASSERT_TRUE(server4->marked);

        ASSERT_TRUE(server1->linked);
        ASSERT_TRUE(server2->linked);
        ASSERT_TRUE(server3->linked);
        ASSERT_TRUE(server4->linked);

        dns_server_unlink(server3);

        const char *names3[] = { "alice.local", "dave.local", "bob.local" };
        check_dns_servers(&manager, names3, 3);

        ASSERT_TRUE(server1->linked);
        ASSERT_TRUE(server2->linked);
        ASSERT_TRUE(server4->linked);

        server1->marked = false;
        server2->marked = true;
        server4->marked = false;

        ASSERT_TRUE(dns_server_unlink_marked(server1));

        const char *names4[] = { "alice.local", "dave.local" };
        check_dns_servers(&manager, names4, 2);

        dns_server_mark_all(server1);
        ASSERT_TRUE(dns_server_unlink_marked(server1));

        const char *names5[] = {};
        check_dns_servers(&manager, names5, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
