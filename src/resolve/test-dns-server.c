/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-server.h"
#include "resolved-manager.h"

#include "log.h"
#include "tests.h"

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "tmpfile-util.h"

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

static void server_env_setup(ServerEnv *env, bool is_stub) {
        env->manager = (Manager) {};
        ASSERT_OK(sd_event_new(&env->manager.event));

        env->server_name = strdup("server.local");

        uint32_t ip = is_stub ? INADDR_DNS_STUB : 0xc0a80180;
        env->server_addr.in.s_addr = htobe32(ip);

        ASSERT_OK(dns_server_new(
                        &env->manager, &env->server, DNS_SERVER_SYSTEM, NULL, AF_INET,
                        &env->server_addr, 53, 0, env->server_name, RESOLVE_CONFIG_SOURCE_FILE));
}

#define MAX_SERVERS 5

static const char *SERVER_NAMES[] = {
        "arsenal.local",
        "bank.local",
        "camden.local",
        "dalston.local",
        "euston.local"
};

typedef struct MultiServerEnv {
        Manager manager;
        size_t n_servers;
        union in_addr_union addrs[MAX_SERVERS];
        char *names[MAX_SERVERS];
        DnsServer *servers[MAX_SERVERS];
} MultiServerEnv;

static void multi_server_env_teardown(MultiServerEnv *env) {
        for (size_t i = 0; i < env->n_servers; i++)
                free(env->names[i]);

        dns_server_unlink_all(env->manager.dns_servers);
        env->n_servers = 0;
}

static void multi_server_env_setup(MultiServerEnv *env, size_t n) {
        ASSERT_TRUE(n <= MAX_SERVERS);

        env->manager = (Manager) {};
        env->n_servers = 0;

        for (size_t i = 0; i < n; i++) {
                uint32_t ip = (i == 0) ? INADDR_DNS_STUB : 0xc0a80180 + i;
                env->addrs[i].in.s_addr = htobe32(ip);
                env->names[i] = strdup(SERVER_NAMES[i]);

                ASSERT_OK(dns_server_new(
                                &env->manager, &env->servers[i], DNS_SERVER_SYSTEM, NULL, AF_INET,
                                &env->addrs[i], 53, 0, env->names[i], RESOLVE_CONFIG_SOURCE_FILE));

                env->n_servers++;
        }
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
        _cleanup_(multi_server_env_teardown) MultiServerEnv env;
        multi_server_env_setup(&env, 4);

        const char *names1[] = { "arsenal.local", "bank.local", "camden.local", "dalston.local" };
        check_dns_servers(&env.manager, names1, 4);

        env.servers[0]->marked = true;
        env.servers[1]->marked = true;
        env.servers[2]->marked = true;
        env.servers[3]->marked = true;

        dns_server_move_back_and_unmark(env.servers[1]);

        const char *names2[] = { "arsenal.local", "camden.local", "dalston.local", "bank.local" };
        check_dns_servers(&env.manager, names2, 4);

        ASSERT_TRUE(env.servers[0]->marked);
        ASSERT_FALSE(env.servers[1]->marked);
        ASSERT_TRUE(env.servers[2]->marked);
        ASSERT_TRUE(env.servers[3]->marked);

        ASSERT_TRUE(env.servers[0]->linked);
        ASSERT_TRUE(env.servers[1]->linked);
        ASSERT_TRUE(env.servers[2]->linked);
        ASSERT_TRUE(env.servers[3]->linked);

        dns_server_unlink(env.servers[2]);

        const char *names3[] = { "arsenal.local", "dalston.local", "bank.local" };
        check_dns_servers(&env.manager, names3, 3);

        ASSERT_TRUE(env.servers[0]->linked);
        ASSERT_TRUE(env.servers[1]->linked);
        ASSERT_TRUE(env.servers[3]->linked);

        env.servers[0]->marked = false;
        env.servers[1]->marked = true;
        env.servers[3]->marked = false;

        ASSERT_TRUE(dns_server_unlink_marked(env.servers[0]));

        const char *names4[] = { "arsenal.local", "dalston.local" };
        check_dns_servers(&env.manager, names4, 2);

        dns_server_mark_all(env.servers[0]);
        ASSERT_TRUE(dns_server_unlink_marked(env.servers[0]));

        const char *names5[] = {};
        check_dns_servers(&env.manager, names5, 0);
}

/* ================================================================
 * dns_server_find()
 * ================================================================ */

TEST(dns_server_find) {
        _cleanup_(multi_server_env_teardown) MultiServerEnv env;
        DnsServer *found = NULL;
        union in_addr_union addr;

        multi_server_env_setup(&env, 5);

        addr.in.s_addr = htobe32(0xc0a80180);
        found = dns_server_find(env.manager.dns_servers, AF_INET, &addr, 53, 0, "camden.local");
        ASSERT_NULL(found);

        addr.in.s_addr = htobe32(0xc0a80182);
        found = dns_server_find(env.manager.dns_servers, AF_INET, &addr, 53, 0, "camden.local");
        ASSERT_TRUE(found == env.servers[2]);

        found = dns_server_find(env.manager.dns_servers, AF_INET, &addr, 54, 0, "camden.local");
        ASSERT_NULL(found);

        found = dns_server_find(env.manager.dns_servers, AF_INET6, &addr, 53, 0, "camden.local");
        ASSERT_NULL(found);

        found = dns_server_find(env.manager.dns_servers, AF_INET, &addr, 53, 0, "dalston.local");
        ASSERT_NULL(found);
}

/* ================================================================
 * manager_get_first_dns_server()
 * ================================================================ */

TEST(manager_get_first_dns_server) {
        _cleanup_(multi_server_env_teardown) MultiServerEnv env;
        DnsServer *found = NULL;

        multi_server_env_setup(&env, 5);

        found = manager_get_first_dns_server(&env.manager, DNS_SERVER_SYSTEM);
        ASSERT_TRUE(found == env.servers[0]);
}

/* ================================================================
 * manager_get_dns_server()
 * ================================================================ */

TEST(manager_get_dns_server) {
        _cleanup_(multi_server_env_teardown) MultiServerEnv env;
        DnsServer *found = NULL;

        multi_server_env_setup(&env, 5);

        /* first server is a stub */
        found = manager_get_dns_server(&env.manager);
        ASSERT_TRUE(found == env.servers[1]);
}

TEST(manager_get_dns_server_fallback) {
        _cleanup_(server_env_teardown) ServerEnv env;
        _cleanup_(dns_server_unrefp) DnsServer *fallback;
        DnsServer *found = NULL;

        server_env_setup(&env, true);

        found = manager_get_dns_server(&env.manager);
        ASSERT_NULL(found);

        const char *name = "fallback.local";
        union in_addr_union addr = { .in.s_addr = htobe32(0xc0a80180) };

        ASSERT_OK(dns_server_new(
                        &env.manager, &fallback, DNS_SERVER_FALLBACK, NULL, AF_INET,
                        &addr, 53, 0, name, RESOLVE_CONFIG_SOURCE_FILE));

        found = manager_get_dns_server(&env.manager);
        ASSERT_TRUE(found == fallback);

        dns_server_unref(fallback);
}

/* ================================================================
 * dns_server_packet_received()
 * ================================================================ */

TEST(dns_server_packet_received_udp) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_UDP;
        env.server->n_failed_udp = 100;

        dns_server_packet_received(env.server, IPPROTO_UDP, DNS_SERVER_FEATURE_LEVEL_UDP, 599);

        ASSERT_EQ(env.server->n_failed_udp, 0u);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
        ASSERT_EQ(env.server->received_udp_fragment_max, 599u);
}

TEST(dns_server_packet_received_tcp) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TCP;
        env.server->n_failed_tcp = 100;

        dns_server_packet_received(env.server, IPPROTO_TCP, DNS_SERVER_FEATURE_LEVEL_TCP, 599);

        ASSERT_EQ(env.server->n_failed_tcp, 0u);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_TCP);
}


TEST(dns_server_packet_received_tls) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN;
        env.server->n_failed_tls = 100;

        dns_server_packet_received(env.server, IPPROTO_TCP, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN, 599);

        ASSERT_EQ(env.server->n_failed_tls, 0u);
        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN);
}

TEST(dns_server_packet_received_non_tls) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        dns_server_packet_received(env.server, IPPROTO_TCP, DNS_SERVER_FEATURE_LEVEL_DO, 599);

        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_TCP);
}

TEST(dns_server_packet_received_rrsig_missing) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;
        server_env_setup(&env, false);

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
        server_env_setup(&env, false);

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

        server_env_setup(&env, false);

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

/* ================================================================
 * dns_server_packet_truncated()
 * ================================================================ */

TEST(dns_server_packet_truncated) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;

        server_env_setup(&env, false);

        level = DNS_SERVER_FEATURE_LEVEL_UDP;
        env.server->possible_feature_level = level;
        env.server->packet_truncated = false;

        dns_server_packet_truncated(env.server, level);

        ASSERT_TRUE(env.server->packet_truncated);
}

/* ================================================================
 * dns_server_packet_rrsig_missing()
 * ================================================================ */

TEST(dns_server_packet_rrsig_missing) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;

        server_env_setup(&env, false);

        level = DNS_SERVER_FEATURE_LEVEL_TCP;
        env.server->verified_feature_level = level;
        env.server->packet_rrsig_missing = false;

        dns_server_packet_rrsig_missing(env.server, level);

        ASSERT_FALSE(env.server->packet_rrsig_missing);

        level = DNS_SERVER_FEATURE_LEVEL_DO;
        env.server->verified_feature_level = level;

        dns_server_packet_rrsig_missing(env.server, level);

        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
        ASSERT_TRUE(env.server->packet_rrsig_missing);
}

/* ================================================================
 * dns_server_packet_bad_opt()
 * ================================================================ */

TEST(dns_server_packet_bad_opt) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;

        server_env_setup(&env, false);

        level = DNS_SERVER_FEATURE_LEVEL_TCP;
        env.server->verified_feature_level = level;
        env.server->packet_bad_opt = false;

        dns_server_packet_rrsig_missing(env.server, level);

        ASSERT_FALSE(env.server->packet_bad_opt);

        level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        env.server->verified_feature_level = level;

        dns_server_packet_bad_opt(env.server, level);

        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
        ASSERT_TRUE(env.server->packet_bad_opt);
}

/* ================================================================
 * dns_server_packet_rcode_downgrade()
 * ================================================================ */

TEST(dns_server_packet_rcode_downgrade) {
        _cleanup_(server_env_teardown) ServerEnv env;

        server_env_setup(&env, false);

        env.server->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;

        dns_server_packet_rcode_downgrade(env.server, DNS_SERVER_FEATURE_LEVEL_UDP);

        ASSERT_EQ(env.server->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
}

/* ================================================================
 * dns_server_packet_invalid()
 * ================================================================ */

TEST(dns_server_packet_invalid) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;

        server_env_setup(&env, false);

        level = DNS_SERVER_FEATURE_LEVEL_UDP;
        env.server->possible_feature_level = level;
        env.server->packet_invalid = false;

        dns_server_packet_invalid(env.server, level);

        ASSERT_TRUE(env.server->packet_invalid);
}

/* ================================================================
 * dns_server_packet_do_off()
 * ================================================================ */

TEST(dns_server_packet_do_off) {
        _cleanup_(server_env_teardown) ServerEnv env;
        DnsServerFeatureLevel level;

        server_env_setup(&env, false);

        level = DNS_SERVER_FEATURE_LEVEL_UDP;
        env.server->possible_feature_level = level;
        env.server->packet_do_off = false;

        dns_server_packet_do_off(env.server, level);

        ASSERT_TRUE(env.server->packet_do_off);
}

/* ================================================================
 * dns_server_packet_udp_fragmented()
 * ================================================================ */

TEST(dns_server_packet_udp_fragmented) {
        _cleanup_(server_env_teardown) ServerEnv env;

        server_env_setup(&env, false);

        dns_server_packet_udp_fragmented(env.server, 599);

        ASSERT_EQ(env.server->received_udp_fragment_max, 599u);
        ASSERT_TRUE(env.server->packet_fragmented);
}

/* ================================================================
 * dns_server_possible_feature_level()
 * ================================================================ */

TEST(dns_server_possible_feature_level_grace_period_expired) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.manager.dnssec_mode = DNSSEC_NO;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TCP;
        env.server->verified_usec = 1;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
}

TEST(dns_server_possible_feature_level_raise_to_verified) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.manager.dnssec_mode = DNSSEC_NO;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
        env.server->possible_feature_level = _DNS_SERVER_FEATURE_LEVEL_MAX;
        env.server->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_TLS_DO;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_TLS_DO);
}

TEST(dns_server_possible_feature_level_drop_to_best) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.manager.dnssec_mode = DNSSEC_NO;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
        env.server->possible_feature_level = _DNS_SERVER_FEATURE_LEVEL_MAX;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
}

TEST(dns_server_possible_feature_level_tcp_failed) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->n_failed_tcp = 5;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TCP;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
}

TEST(dns_server_possible_feature_level_tls_failed) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->n_failed_tls = 5;
        env.server->possible_feature_level = _DNS_SERVER_FEATURE_LEVEL_MAX;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_OPPORTUNISTIC;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
}

TEST(dns_server_possible_feature_level_packet_failed_downgrade_ends0) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->packet_invalid = true;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
}

TEST(dns_server_possible_feature_level_packet_failed_downgrade_do) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->packet_invalid = true;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        env.manager.dnssec_mode = DNSSEC_YES;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_NO;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
}

TEST(dns_server_possible_feature_level_packet_failed_downgrade_tls_do) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->packet_invalid = true;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_TLS_DO;
        env.manager.dnssec_mode = DNSSEC_YES;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_YES;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_TLS_PLAIN);
}

TEST(dns_server_possible_feature_level_packet_bad_opt) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->packet_bad_opt = true;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;
        env.manager.dnssec_mode = DNSSEC_NO;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_NO;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
}

TEST(dns_server_possible_feature_level_packet_do_off) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->packet_do_off = true;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        env.manager.dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_NO;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
}

TEST(dns_server_possible_feature_level_packet_rrsig_missing) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->packet_rrsig_missing = true;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        env.manager.dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        env.manager.dns_over_tls_mode = DNS_OVER_TLS_NO;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
}

TEST(dns_server_possible_feature_level_udp_failed) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->n_failed_udp = 5;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
}

TEST(dns_server_possible_feature_level_tcp_failed_truncated) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->n_failed_tcp = 5;
        env.server->packet_truncated = true;
        env.server->possible_feature_level = DNS_SERVER_FEATURE_LEVEL_EDNS0;

        dns_server_possible_feature_level(env.server);

        ASSERT_EQ(env.server->possible_feature_level, DNS_SERVER_FEATURE_LEVEL_UDP);
}

/* ================================================================
 * dns_server_string(), dns_server_string_full()
 * ================================================================ */

TEST(dns_server_string) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        ASSERT_STREQ(dns_server_string(env.server), "192.168.1.128");
}

TEST(dns_server_string_full) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        const char *str = dns_server_string_full(env.server);
        ASSERT_STREQ(str, "192.168.1.128:53#server.local");
}

/* ================================================================
 * dns_server_dnssec_supported()
 * ================================================================ */

TEST(dns_server_dnssec_supported) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.manager.dnssec_mode = DNSSEC_YES;
        ASSERT_TRUE(dns_server_dnssec_supported(env.server));

        env.manager.dnssec_mode = DNSSEC_NO;
        env.server->packet_bad_opt = true;
        ASSERT_FALSE(dns_server_dnssec_supported(env.server));

        env.server->packet_bad_opt = false;
        env.server->packet_rrsig_missing = true;
        ASSERT_FALSE(dns_server_dnssec_supported(env.server));

        env.server->packet_rrsig_missing = false;
        env.server->packet_do_off = true;
        ASSERT_FALSE(dns_server_dnssec_supported(env.server));

        env.server->packet_do_off = false;
        env.server->n_failed_tcp = 5;
        ASSERT_FALSE(dns_server_dnssec_supported(env.server));

        env.server->n_failed_tcp = 0;
        ASSERT_TRUE(dns_server_dnssec_supported(env.server));
}

/* ================================================================
 * dns_server_dump()
 * ================================================================ */

static void check_dump_contents(FILE *f, const char **expected, size_t n) {
        char *actual[n];
        size_t i, r;
        rewind(f);

        for (i = 0; i < n; i++) {
                r = read_line(f, 1024, &actual[i]);
                ASSERT_GT(r, 0u);
        }

        for (i = 0; i < n; i++)
                ASSERT_STREQ(actual[i], expected[i]);

        for (i = 0; i < n; i++)
                free(actual[i]);
}

TEST(dns_server_dump) {
        _cleanup_(server_env_teardown) ServerEnv env;
        server_env_setup(&env, false);

        env.server->verified_feature_level = DNS_SERVER_FEATURE_LEVEL_DO;
        env.manager.dnssec_mode = DNSSEC_ALLOW_DOWNGRADE;
        env.server->received_udp_fragment_max = 1024;
        env.server->n_failed_tcp = 5;
        env.server->packet_bad_opt = true;
        env.server->packet_invalid = true;

        _cleanup_(unlink_tempfilep) char p[] = "/tmp/dns-server-dump-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        fmkostemp_safe(p, "r+", &f);
        dns_server_dump(env.server, f);

        const char *expected[] = {
                "[Server 192.168.1.128:53#server.local type=system]",
                "\tVerified feature level: UDP+EDNS0+DO",
                "\tPossible feature level: TLS+EDNS0+DO",
                "\tDNSSEC Mode: allow-downgrade",
                "\tCan do DNSSEC: no",
                "\tMaximum UDP fragment size received: 1024",
                "\tFailed UDP attempts: 0",
                "\tFailed TCP attempts: 5",
                "\tSeen truncated packet: no",
                "\tSeen OPT RR getting lost: yes",
                "\tSeen RRSIG RR missing: no",
                "\tSeen invalid packet: yes",
                "\tServer dropped DO flag: no"
        };
        check_dump_contents(f, expected, 13);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
