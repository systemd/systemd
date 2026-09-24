/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "resolved-dns-server.h"
#include "resolved-manager.h"
#include "tests.h"

typedef struct ServerEnv {
        Manager manager;
        DnsServer *server;
} ServerEnv;

static void server_env_teardown(ServerEnv *env) {
        assert(env);

        if (env->server)
                dns_server_unlink(env->server);
        sd_event_unref(env->manager.event);
}

static void server_env_setup(ServerEnv *env) {
        union in_addr_union server_addr = { .in.s_addr = htobe32(0xc0000201) }; /* 192.0.2.1 */

        assert(env);

        /* With DNSSEC enabled and no DNS-over-TLS the best feature level is DO. */
        env->manager = (Manager) {
                .dnssec_mode = DNSSEC_ALLOW_DOWNGRADE,
        };

        ASSERT_OK(sd_event_new(&env->manager.event));

        ASSERT_OK(dns_server_new(&env->manager, &env->server, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &server_addr, 53, /* ifindex= */ 0, /* server_name= */ NULL, RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_NOT_NULL(env->server);
}

/* ================================================================
 * dns_server_possible_feature_level()
 * ================================================================ */

/* Loses DNS_SERVER_FEATURE_RETRY_ATTEMPTS packets, which is private to resolved-dns-server.c */
static void lose_packets(DnsServer *s, DnsServerFeatureLevel level) {
        for (unsigned i = 0; i < 3; i++)
                dns_server_packet_lost(s, IPPROTO_UDP, level);
}

TEST(dns_server_grace_period_counts_from_feature_level_change) {
        _cleanup_(server_env_teardown) ServerEnv env = {};
        usec_t now_usec;
        DnsServer *s;

        server_env_setup(&env);
        s = env.server;

        /* Packet loss degrades the level before any reply arrived, restarting the grace period */
        ASSERT_EQ(dns_server_possible_feature_level(s), DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_OK(sd_event_now(env.manager.event, CLOCK_BOOTTIME, &now_usec));
        lose_packets(s, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_EQ(dns_server_possible_feature_level(s), DNS_SERVER_FEATURE_LEVEL_EDNS0);
        ASSERT_EQ(s->verified_feature_level, _DNS_SERVER_FEATURE_LEVEL_INVALID);
        ASSERT_GE(s->verified_usec, now_usec);

        /* Verifying a new level restarts it too */
        s->verified_usec = now_usec - 1;
        dns_server_packet_received(s, IPPROTO_UDP, DNS_SERVER_FEATURE_LEVEL_EDNS0, 512);
        ASSERT_EQ(s->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
        ASSERT_GE(s->verified_usec, now_usec);

        /* A further reply at the same level must not restart it. The clock is monotonic, so a restart
         * could not yield this value. */
        s->verified_usec = now_usec - 1;
        dns_server_packet_received(s, IPPROTO_UDP, DNS_SERVER_FEATURE_LEVEL_EDNS0, 512);
        ASSERT_EQ(s->verified_usec, now_usec - 1);
        ASSERT_EQ(dns_server_possible_feature_level(s), DNS_SERVER_FEATURE_LEVEL_EDNS0);

        /* Once it elapsed, the full feature set is retried and the grace period doubles. Shrink it rather
         * than moving the timestamp back, CLOCK_BOOTTIME may be below five minutes on a fresh test VM. */
        s->features_grace_period_usec = 1;
        s->verified_usec = now_usec - 1;
        ASSERT_EQ(dns_server_possible_feature_level(s), DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_EQ(s->features_grace_period_usec, 2u);

        /* A failed retry restarts it again on the way down, even though the verified level doesn't change */
        s->verified_usec = now_usec - 1;
        lose_packets(s, DNS_SERVER_FEATURE_LEVEL_DO);
        ASSERT_EQ(dns_server_possible_feature_level(s), DNS_SERVER_FEATURE_LEVEL_EDNS0);
        ASSERT_EQ(s->verified_feature_level, DNS_SERVER_FEATURE_LEVEL_EDNS0);
        ASSERT_GE(s->verified_usec, now_usec);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
