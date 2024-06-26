/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-server.h"
#include "resolved-manager.h"

#include "log.h"
#include "tests.h"

typedef struct ServerEnv {
        Manager manager;
        char *server_name;
        union in_addr_union server_addr;
        DnsServer *server;
} ServerEnv;

static void server_env_teardown(ServerEnv *env) {
        sd_event_unref(env->manager.event);
        free(env->server_name);
        dns_server_unref(env->server);
}

static void server_env_setup(ServerEnv *env) {
        env->manager = (Manager) {};
        ASSERT_OK(sd_event_new(&env->manager.event));

        env->server_name = strdup("server.local");
        env->server_addr.in.s_addr = htobe32(0xc0a80180);

        ASSERT_OK(dns_server_new(
                        &env->manager, &env->server, DNS_SERVER_SYSTEM, NULL, AF_INET,
                        &env->server_addr, 53, 0, env->server_name, RESOLVE_CONFIG_SOURCE_FILE));
}

/* ================================================================
 * dns_server_move_back_and_unmark(), dns_server_unlink(),
 * dns_server_unlink_marked(), dns_server_mark_all()
 * ================================================================ */

static void check_dns_servers(Manager *manager, const char **names, size_t n) {
        ASSERT_EQ(manager->n_dns_servers, n);

        size_t i = 0;

        LIST_FOREACH(servers, s, manager->dns_servers) {
                ASSERT_STREQ(s->server_name, names[i++]);
        }

        ASSERT_EQ(i, n);
}

TEST(dns_server_move_back_and_unmark) {
        Manager manager = {};
        _cleanup_(dns_server_unrefp) DnsServer *server1 = NULL, *server2 = NULL, *server3 = NULL, *server4 = NULL;

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
        ASSERT_FALSE(server3->linked);
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

/* ================================================================
 * dns_server_packet_received()
 * ================================================================ */

TEST(dns_server_packet_received_udp) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env);

        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_UDP;
        env.server->n_failed_udp = 100;

        dns_server_packet_received(env.server, IPPROTO_UDP, DNS_SERVER_FEATURE_LEVEL_UDP, 599);

        ASSERT_EQ(env.server->n_failed_udp, 0u);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
        ASSERT_EQ(env.server->received_udp_fragment_max, 599u);
}

TEST(dns_server_packet_received_tcp) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env);

        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TCP;
        env.server->n_failed_tcp = 100;

        dns_server_packet_received(env.server, IPPROTO_TCP, DNS_SERVER_FEATURE_LEVEL_TCP, 599);

        ASSERT_EQ(env.server->n_failed_tcp, 0u);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_TCP);
}


TEST(dns_server_packet_received_tls) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env);

        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN;
        env.server->n_failed_tls = 100;

        dns_server_packet_received(env.server, IPPROTO_TCP, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN, 599);

        ASSERT_EQ(env.server->n_failed_tls, 0u);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN);
}

TEST(dns_server_packet_received_non_tls) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env);

        dns_server_packet_received(env.server, IPPROTO_TCP, DNS_SERVER_FEATURE_LEVEL_DO, 599);

        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_TCP);
}

TEST(dns_server_packet_received_rrsig_missing) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;
        server_env_setup(&env);

        env.server->packet_rrsig_missing = false;

        level = DNS_SERVER_FEATURE_LEVEL_DO;
        dns_server_packet_received(env.server, IPPROTO_UDP, level, 599);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_DO);

        env.server->packet_rrsig_missing = true;
        env.server->verified_feature_level = _DNS_SERVER_FEATURE_LEVEL_INVALID;

        level = DNS_SERVER_FEATURE_LEVEL_DO;
        dns_server_packet_received(env.server, IPPROTO_UDP, level, 599);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);

        level = DNS_SERVER_FEATURE_LEVEL_TLS_DO;
        dns_server_packet_received(env.server, IPPROTO_UDP, level, 599);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN);
}

TEST(dns_server_packet_received_bad_opt) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;
        server_env_setup(&env);

        env.server->packet_bad_opt = true;

        level = DNS_SERVER_FEATURE_LEVEL_DO;
        dns_server_packet_received(env.server, IPPROTO_UDP, level, 599);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);

        env.server->packet_bad_opt = false;

        level = DNS_SERVER_FEATURE_LEVEL_DO;
        dns_server_packet_received(env.server, IPPROTO_UDP, level, 599);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_DO);
}

/* ================================================================
 * dns_server_packet_lost()
 * ================================================================ */

TEST(dns_server_packet_lost) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;
        size_t n, i;

        server_env_setup(&env);

        level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        env.server->possible_feature_level = level;

        n = 12;
        for (i = 0; i < n; i++) {
                dns_server_packet_lost(env.server, IPPROTO_UDP, level);
        }
        ASSERT_EQ(env.server->n_failed_udp, n);

        n = 34;
        for (i = 0; i < n; i++) {
                dns_server_packet_lost(env.server, IPPROTO_TCP, level);
        }
        ASSERT_EQ(env.server->n_failed_tcp, n);

        level = DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN;
        env.server->possible_feature_level = level;

        n = 56;
        for (i = 0; i < n; i++) {
                dns_server_packet_lost(env.server, IPPROTO_TCP, level);
        }
        ASSERT_EQ(env.server->n_failed_tls, n);

        env.server->possible_feature_level--;

        n = 78;
        for (i = 0; i < n; i++) {
                dns_server_packet_lost(env.server, IPPROTO_TCP, level);
        }
        ASSERT_EQ(env.server->n_failed_tls, 56u);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
