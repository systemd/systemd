/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-event.h"

#include "dns-packet.h"
#include "fd-util.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dns-transport.h"
#include "resolved-dns-transport-dns.h"
#include "resolved-dns-transport-dot.h"
#include "resolved-link.h"
#include "resolved-manager.h"
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

        /* The best level of the best transport this build supports */
#if ENABLE_DNS_OVER_TLS
        ASSERT_TRUE(dns_server_feature_level_equal(dns_server_feature_level_best(), levels_in_order[5]));
#else
        ASSERT_TRUE(dns_server_feature_level_equal(dns_server_feature_level_best(), levels_in_order[4]));
#endif
}

TEST(feature_level_for_transport) {
        /* Classic DNS does datagrams, at every EDNS level */
        for (DnsServerEdnsLevel e = 0; e < _DNS_SERVER_EDNS_LEVEL_MAX; e++) {
                DnsServerFeatureLevel l = dns_server_feature_level_for_transport(DNS_TRANSPORT_DNS, e);

                ASSERT_EQ(l.transport, DNS_TRANSPORT_DNS);
                ASSERT_EQ(l.edns, e);
                ASSERT_TRUE(l.udp);
        }

#if ENABLE_DNS_OVER_TLS
        /* DNS-over-TLS is stream-only and requires EDNS0, lower EDNS levels are raised to that */
        for (DnsServerEdnsLevel e = 0; e < _DNS_SERVER_EDNS_LEVEL_MAX; e++) {
                DnsServerFeatureLevel l = dns_server_feature_level_for_transport(DNS_TRANSPORT_DOT, e);

                ASSERT_EQ(l.transport, DNS_TRANSPORT_DOT);
                ASSERT_EQ(l.edns, MAX(e, DNS_SERVER_EDNS_LEVEL_EDNS0));
                ASSERT_FALSE(l.udp);
        }
#endif
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

TEST(encryption_mode_from_dns_over_tls_mode) {
        ASSERT_EQ(dns_encryption_mode_from_dns_over_tls_mode(DNS_OVER_TLS_NO), DNS_ENCRYPTION_NO);
        ASSERT_EQ(dns_encryption_mode_from_dns_over_tls_mode(DNS_OVER_TLS_OPPORTUNISTIC), DNS_ENCRYPTION_OPPORTUNISTIC);
        ASSERT_EQ(dns_encryption_mode_from_dns_over_tls_mode(DNS_OVER_TLS_YES), DNS_ENCRYPTION_REQUIRED);
        ASSERT_EQ(dns_encryption_mode_from_dns_over_tls_mode(_DNS_OVER_TLS_MODE_INVALID), DNS_ENCRYPTION_NO);
}

static void test_transport_policy_one(DnsEncryptionMode mode, const DnsTransportKind *expected, size_t n_expected) {
        DnsTransportPolicy p;

        log_debug("/* %s(%s) */", __func__, dns_encryption_mode_to_string(mode));

        dns_transport_policy_init(mode, &p);

        /* The permitted transports, in order of preference, each falling back to the next one */
        ASSERT_EQ(p.n_transports, n_expected);
        for (size_t i = 0; i < n_expected; i++) {
                ASSERT_EQ(p.transports[i], expected[i]);
                ASSERT_TRUE(dns_transport_policy_contains(&p, expected[i]));
                ASSERT_EQ(dns_transport_policy_next(&p, expected[i]),
                          i + 1 < n_expected ? expected[i + 1] : _DNS_TRANSPORT_KIND_INVALID);
        }

        /* Transports not permitted are neither contained nor fallen back from */
        for (DnsTransportKind k = 0; k < _DNS_TRANSPORT_KIND_MAX; k++) {
                bool permitted = false;

                for (size_t i = 0; i < n_expected; i++)
                        if (expected[i] == k)
                                permitted = true;
                if (permitted)
                        continue;

                ASSERT_FALSE(dns_transport_policy_contains(&p, k));
                ASSERT_EQ(dns_transport_policy_next(&p, k), _DNS_TRANSPORT_KIND_INVALID);
        }

        ASSERT_FALSE(dns_transport_policy_contains(&p, _DNS_TRANSPORT_KIND_INVALID));
        ASSERT_EQ(dns_transport_policy_next(&p, _DNS_TRANSPORT_KIND_INVALID), _DNS_TRANSPORT_KIND_INVALID);
}

TEST(transport_policy) {
        test_transport_policy_one(DNS_ENCRYPTION_NO,
                                  (const DnsTransportKind[]) { DNS_TRANSPORT_DNS }, 1);
        test_transport_policy_one(DNS_ENCRYPTION_OPPORTUNISTIC,
                                  (const DnsTransportKind[]) { DNS_TRANSPORT_DOT, DNS_TRANSPORT_DNS }, 2);
        test_transport_policy_one(DNS_ENCRYPTION_REQUIRED,
                                  (const DnsTransportKind[]) { DNS_TRANSPORT_DOT }, 1);
}

/* Indexes into levels_in_order[] */
enum {
        LEVEL_TCP,
        LEVEL_UDP,
        LEVEL_UDP_EDNS0,
        LEVEL_TLS_EDNS0,
        LEVEL_UDP_DO,
        LEVEL_TLS_DO,
        LEVEL_NONE = -1,        /* Nothing left to reduce to */
};

static void test_feature_level_reduce_one(DnsServer *s, int from, int expected) {
        DnsServerFeatureLevel l;

        log_debug("/* %s(%s → %s) */", __func__,
                  level_names[from], expected >= 0 ? level_names[expected] : "none");

        if (expected < 0) {
                ASSERT_FALSE(dns_server_feature_level_reduce(s, levels_in_order[from], &l));
                return;
        }

        ASSERT_TRUE(dns_server_feature_level_reduce(s, levels_in_order[from], &l));
        ASSERT_STREQ(dns_server_feature_level_to_string(l), level_names[expected]);
        ASSERT_TRUE(dns_server_feature_level_equal(l, levels_in_order[expected]));
}

TEST(feature_level_reduce) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        /* Classic DNS: first the EDNS level is lowered, down to plain UDP */
        manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
        test_feature_level_reduce_one(s, LEVEL_UDP_DO, LEVEL_UDP_EDNS0);
        test_feature_level_reduce_one(s, LEVEL_UDP_EDNS0, LEVEL_UDP);
        test_feature_level_reduce_one(s, LEVEL_UDP, LEVEL_NONE);
        test_feature_level_reduce_one(s, LEVEL_TCP, LEVEL_NONE);

#if ENABLE_DNS_OVER_TLS
        /* Opportunistic DNS-over-TLS: TLS requires EDNS0, below that we fall back to classic DNS */
        manager.dns_over_tls_mode = DNS_OVER_TLS_OPPORTUNISTIC;
        test_feature_level_reduce_one(s, LEVEL_TLS_DO, LEVEL_TLS_EDNS0);
        test_feature_level_reduce_one(s, LEVEL_TLS_EDNS0, LEVEL_UDP_EDNS0);
        test_feature_level_reduce_one(s, LEVEL_UDP_DO, LEVEL_UDP_EDNS0);
        test_feature_level_reduce_one(s, LEVEL_UDP_EDNS0, LEVEL_UDP);
        test_feature_level_reduce_one(s, LEVEL_UDP, LEVEL_NONE);

        /* Strict DNS-over-TLS: never fall back to classic DNS */
        manager.dns_over_tls_mode = DNS_OVER_TLS_YES;
        test_feature_level_reduce_one(s, LEVEL_TLS_DO, LEVEL_TLS_EDNS0);
        test_feature_level_reduce_one(s, LEVEL_TLS_EDNS0, LEVEL_NONE);

        /* Only the fallback to another transport consults the policy. A level of a transport the policy
         * doesn't permit anymore, from a transaction started before it changed, is reduced within its
         * transport. dns_server_possible_feature_level_clamped() then drops the resulting clamp, see
         * test_possible_feature_level_clamped(). */
        test_feature_level_reduce_one(s, LEVEL_UDP_DO, LEVEL_UDP_EDNS0);
        ASSERT_FALSE(dns_server_feature_level_permitted(s, levels_in_order[LEVEL_UDP_EDNS0]));
#endif

        dns_server_unlink(s);
}

TEST(feature_level_permitted) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        FOREACH_ELEMENT(l, levels_in_order) {
                manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
                ASSERT_EQ(dns_server_feature_level_permitted(s, *l), l->transport == DNS_TRANSPORT_DNS);
#if ENABLE_DNS_OVER_TLS
                manager.dns_over_tls_mode = DNS_OVER_TLS_OPPORTUNISTIC;
                ASSERT_TRUE(dns_server_feature_level_permitted(s, *l));
                manager.dns_over_tls_mode = DNS_OVER_TLS_YES;
                ASSERT_EQ(dns_server_feature_level_permitted(s, *l), l->transport == DNS_TRANSPORT_DOT);
#endif
        }

        dns_server_unlink(s);
}

/* The number of lost packets after which a transport degrades, see DNS_SERVER_FEATURE_RETRY_ATTEMPTS */
#define RETRY_ATTEMPTS 3U

static void possible_feature_level_setup(Manager *m, DnsServer *s, DnsOverTlsMode dns_over_tls, DnssecMode dnssec) {
        m->dns_over_tls_mode = dns_over_tls;
        m->dnssec_mode = dnssec;
        dns_server_reset_features(s);
}

static void assert_possible_feature_level(DnsServer *s, const char *expected) {
        ASSERT_STREQ(dns_server_feature_level_to_string(dns_server_possible_feature_level(s)), expected);
}

static void lose_packets(DnsServer *s, int protocol, unsigned n) {
        for (unsigned i = 0; i < n; i++)
                dns_server_packet_lost(s, protocol, dns_server_possible_feature_level(s));
}

TEST(possible_feature_level) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;

        /* The server never verifies a feature level here (verified_usec stays 0), hence the grace period
         * never expires and no event loop is needed. */
        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        /* Classic DNS: lost UDP packets first lower the EDNS level, then switch to TCP. Lost TCP
         * connections there switch back to UDP. */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_NO);
        assert_possible_feature_level(s, "UDP+EDNS0");
        lose_packets(s, IPPROTO_UDP, RETRY_ATTEMPTS - 1);
        assert_possible_feature_level(s, "UDP+EDNS0");
        lose_packets(s, IPPROTO_UDP, 1);
        assert_possible_feature_level(s, "UDP");
        lose_packets(s, IPPROTO_UDP, RETRY_ATTEMPTS);
        assert_possible_feature_level(s, "TCP");
        lose_packets(s, IPPROTO_TCP, RETRY_ATTEMPTS);
        assert_possible_feature_level(s, "UDP");

        /* Classic DNS: invalid replies lower the EDNS level, down to plain UDP */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_ALLOW_DOWNGRADE);
        assert_possible_feature_level(s, "UDP+EDNS0+DO");
        dns_server_packet_invalid(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP+EDNS0");
        dns_server_packet_invalid(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP");
        dns_server_packet_invalid(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP");

        /* Classic DNS: a missing OPT RR turns EDNS0 off */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_NO);
        dns_server_packet_bad_opt(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP");

        /* Classic DNS: if replies got truncated and TCP doesn't work either, the EDNS level is lowered, in
         * the hope that the reply then fits into a datagram */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_ALLOW_DOWNGRADE);
        assert_possible_feature_level(s, "UDP+EDNS0+DO");
        dns_server_packet_truncated(s, dns_server_possible_feature_level(s));
        lose_packets(s, IPPROTO_TCP, RETRY_ATTEMPTS - 1);
        assert_possible_feature_level(s, "UDP+EDNS0+DO");
        lose_packets(s, IPPROTO_TCP, 1);
        assert_possible_feature_level(s, "UDP+EDNS0");

        /* ... but strict DNSSEC mode requires the DO bit */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_YES);
        dns_server_packet_truncated(s, dns_server_possible_feature_level(s));
        lose_packets(s, IPPROTO_TCP, RETRY_ATTEMPTS);
        assert_possible_feature_level(s, "UDP+EDNS0+DO");

        /* Classic DNS: a server that doesn't copy the DO bit, or doesn't send RRSIGs, isn't asked for DNSSEC
         * data anymore */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_ALLOW_DOWNGRADE);
        dns_server_packet_do_off(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP+EDNS0");

        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_ALLOW_DOWNGRADE);
        dns_server_packet_rrsig_missing(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP+EDNS0");

        /* ... unless DNSSEC is strict */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_YES);
        dns_server_packet_do_off(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP+EDNS0+DO");

        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_YES);
        dns_server_packet_rrsig_missing(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP+EDNS0+DO");

#if ENABLE_DNS_OVER_TLS
        /* DNS-over-TLS requires EDNS0, invalid replies don't lower the EDNS level below that */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_ALLOW_DOWNGRADE);
        assert_possible_feature_level(s, "TLS+EDNS0+DO");
        dns_server_packet_invalid(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "TLS+EDNS0");
        dns_server_packet_invalid(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "TLS+EDNS0");

        /* Over DNS-over-TLS too, a dropped DO bit or missing RRSIGs turn DNSSEC off, keeping the transport */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_ALLOW_DOWNGRADE);
        dns_server_packet_do_off(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "TLS+EDNS0");

        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_ALLOW_DOWNGRADE);
        dns_server_packet_rrsig_missing(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "TLS+EDNS0");

        /* Opportunistic: a failed TLS connection falls back to the next transport, keeping the EDNS level */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_NO);
        assert_possible_feature_level(s, "TLS+EDNS0");
        lose_packets(s, IPPROTO_TCP, 1);
        assert_possible_feature_level(s, "UDP+EDNS0");

        /* Strict: there is no transport to fall back to */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_YES, DNSSEC_NO);
        assert_possible_feature_level(s, "TLS+EDNS0");
        lose_packets(s, IPPROTO_TCP, RETRY_ATTEMPTS);
        assert_possible_feature_level(s, "TLS+EDNS0");

        /* A missing OPT RR only turns EDNS0 off if the policy permits classic DNS */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_NO);
        dns_server_packet_bad_opt(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "UDP");

        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_YES, DNSSEC_NO);
        dns_server_packet_bad_opt(s, dns_server_possible_feature_level(s));
        assert_possible_feature_level(s, "TLS+EDNS0");

        /* If the policy changes without the features being reset, a transport it no longer permits is
         * dropped right away */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_NO);
        assert_possible_feature_level(s, "TLS+EDNS0");
        manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
        assert_possible_feature_level(s, "UDP+EDNS0");
#endif

        dns_server_unlink(s);
}

TEST(possible_feature_level_clamped) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServerFeatureLevel clamp;
        DnsServer *s = NULL;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_NO);

        /* Without a clamp, the possible feature level is used */
        clamp = _DNS_SERVER_FEATURE_LEVEL_INVALID;
        ASSERT_STREQ(dns_server_feature_level_to_string(dns_server_possible_feature_level_clamped(s, &clamp)), "UDP+EDNS0");

        /* A clamp lowers the feature level, but never raises it */
        clamp = levels_in_order[LEVEL_UDP];
        ASSERT_STREQ(dns_server_feature_level_to_string(dns_server_possible_feature_level_clamped(s, &clamp)), "UDP");
        ASSERT_TRUE(dns_server_feature_level_equal(clamp, levels_in_order[LEVEL_UDP]));

        clamp = levels_in_order[LEVEL_UDP_DO];
        ASSERT_STREQ(dns_server_feature_level_to_string(dns_server_possible_feature_level_clamped(s, &clamp)), "UDP+EDNS0");
        ASSERT_TRUE(dns_server_feature_level_equal(clamp, levels_in_order[LEVEL_UDP_DO]));

#if ENABLE_DNS_OVER_TLS
        /* A clamp determined before the policy stopped permitting its transport is dropped, rather than
         * sending queries over classic DNS although DNS-over-TLS is required now */
        clamp = levels_in_order[LEVEL_UDP];
        manager.dns_over_tls_mode = DNS_OVER_TLS_YES;
        ASSERT_STREQ(dns_server_feature_level_to_string(dns_server_possible_feature_level_clamped(s, &clamp)), "TLS+EDNS0");
        ASSERT_FALSE(dns_server_feature_level_is_valid(clamp));
#endif

        dns_server_unlink(s);
}

TEST(dnssec_supported) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        /* DNSSEC servers need working TCP (RFC 5966): classic DNS rules DNSSEC out after too many failed TCP
         * connections */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_ALLOW_DOWNGRADE);
        ASSERT_TRUE(dns_server_dnssec_supported(s));
        lose_packets(s, IPPROTO_TCP, RETRY_ATTEMPTS - 1);
        ASSERT_TRUE(dns_server_dnssec_supported(s));
        lose_packets(s, IPPROTO_TCP, 1);
        ASSERT_FALSE(dns_server_dnssec_supported(s));

        /* In strict DNSSEC mode DNSSEC is always assumed to be supported */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_YES);
        lose_packets(s, IPPROTO_TCP, RETRY_ATTEMPTS);
        ASSERT_TRUE(dns_server_dnssec_supported(s));

#if ENABLE_DNS_OVER_TLS
        /* Only the transport in use is asked: TCP failures classic DNS counted before we moved on to
         * DNS-over-TLS don't rule DNSSEC out */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_ALLOW_DOWNGRADE);
        assert_possible_feature_level(s, "TLS+EDNS0+DO");
        DNS_TRANSPORT_TO_DNS(s->transports[DNS_TRANSPORT_DNS])->n_failed_tcp = RETRY_ATTEMPTS;
        ASSERT_TRUE(dns_server_dnssec_supported(s));
#endif

        dns_server_unlink(s);
}

TEST(packet_rcode_downgrade) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));
        DnsTransportDns *d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(s->transports[DNS_TRANSPORT_DNS]));

        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_ALLOW_DOWNGRADE);
        assert_possible_feature_level(s, "UDP+EDNS0+DO");
        s->verified_feature_level = levels_in_order[LEVEL_UDP_DO];
        lose_packets(s, IPPROTO_UDP, RETRY_ATTEMPTS - 1);
        ASSERT_EQ(d->n_failed_udp, RETRY_ATTEMPTS - 1);

        /* A lower feature level that made an rcode error go away lowers both the possible and the verified
         * feature level right away, and restarts counting failures */
        dns_server_packet_rcode_downgrade(s, levels_in_order[LEVEL_UDP_EDNS0]);
        ASSERT_STREQ(dns_server_feature_level_to_string(s->possible_feature_level), "UDP+EDNS0");
        ASSERT_STREQ(dns_server_feature_level_to_string(s->verified_feature_level), "UDP+EDNS0");
        ASSERT_EQ(d->n_failed_udp, 0U);

        /* It never raises them though */
        lose_packets(s, IPPROTO_UDP, 1);
        dns_server_packet_rcode_downgrade(s, levels_in_order[LEVEL_UDP_DO]);
        ASSERT_STREQ(dns_server_feature_level_to_string(s->possible_feature_level), "UDP+EDNS0");
        ASSERT_STREQ(dns_server_feature_level_to_string(s->verified_feature_level), "UDP+EDNS0");
        ASSERT_EQ(d->n_failed_udp, 1U);

        s->verified_feature_level = levels_in_order[LEVEL_UDP];
        dns_server_packet_rcode_downgrade(s, levels_in_order[LEVEL_UDP_EDNS0]);
        ASSERT_STREQ(dns_server_feature_level_to_string(s->verified_feature_level), "UDP");

        dns_server_unlink(s);
}

static DnsPacket* adjusted_query(DnsServer *s, DnsServerFeatureLevel level) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsPacket *copy = NULL;

        ASSERT_OK(dns_packet_new_query(&p, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, /* dnssec_checking_disabled= */ false));
        ASSERT_OK(dns_server_adjust_opt(s, p, level));

        /* Return a parsed copy of the query, to inspect the OPT RR */
        ASSERT_OK(dns_packet_dup(&copy, p));
        ASSERT_OK(dns_packet_extract(copy));

        return copy;
}

static uint16_t announced_udp_size(DnsServer *s) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = adjusted_query(s, dns_server_possible_feature_level(s));

        ASSERT_NOT_NULL(p->opt);
        return dns_packet_payload_size_max(p);
}

TEST(adjust_opt) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        /* Below EDNS0 no OPT RR is added, from EDNS0 on it is, with the DO bit only set at DNSSEC levels */
        FOREACH_ELEMENT(l, levels_in_order) {
                _cleanup_(dns_packet_unrefp) DnsPacket *p = adjusted_query(s, *l);

                log_debug("/* %s(%s) */", __func__, dns_server_feature_level_to_string(*l));

                if (!DNS_SERVER_FEATURE_LEVEL_IS_EDNS0(*l)) {
                        ASSERT_NULL(p->opt);
                        continue;
                }

                ASSERT_NOT_NULL(p->opt);
                ASSERT_EQ(dns_packet_do(p), DNS_SERVER_FEATURE_LEVEL_IS_DNSSEC(*l));
        }

        dns_server_unlink(s);
}

TEST(udp_fragment_size) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;
        Link *link = NULL;

        /* Attach the server to a link, so that the MTU towards it is known */
        ASSERT_OK(link_new(&manager, &link, 1));
        link->mtu = 1500;
        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_LINK, link, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_NO);

        /* Without fragments, the MTU minus the IPv4 and UDP headers is announced */
        ASSERT_EQ(announced_udp_size(s), 1500U - UDP4_PACKET_HEADER_SIZE);

        /* Once the server's replies got fragmented, the announced size is capped at the largest fragment */
        dns_server_packet_udp_fragmented(s, 1200);
        ASSERT_EQ(announced_udp_size(s), 1200U);

        dns_server_packet_udp_fragmented(s, 1400);
        ASSERT_EQ(announced_udp_size(s), 1400U);

        dns_server_unlink(s);
        link = link_free(link);
        manager.links = hashmap_free(manager.links);
}

static void assert_verified_feature_level(DnsServer *s, const char *expected) {
        ASSERT_STREQ(dns_server_feature_level_to_string(s->verified_feature_level), expected);
}

TEST(packet_received) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL;
        DnsTransportDns *d;

        /* Verifying a feature level records when that happened, which takes the time from the event loop. The
         * loop never has to run for that though. */
        ASSERT_OK(sd_event_new(&event));
        manager.event = event;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));
        d = ASSERT_PTR(DNS_TRANSPORT_TO_DNS(s->transports[DNS_TRANSPORT_DNS]));

        /* A UDP reply verifies the level it was received at, resets the UDP failure counter, and records the
         * size of the datagram */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_NO);
        lose_packets(s, IPPROTO_UDP, RETRY_ATTEMPTS - 1);
        ASSERT_EQ(d->n_failed_udp, RETRY_ATTEMPTS - 1);
        dns_server_packet_received(s, IPPROTO_UDP, dns_server_possible_feature_level(s), 1000);
        ASSERT_EQ(d->n_failed_udp, 0U);
        ASSERT_EQ(d->received_udp_fragment_max, 1000U);
        assert_verified_feature_level(s, "UDP+EDNS0");

        /* Once verified, lost packets don't degrade the level anymore */
        lose_packets(s, IPPROTO_UDP, RETRY_ATTEMPTS);
        assert_possible_feature_level(s, "UDP+EDNS0");

        /* A TCP reply resets the TCP failure counter, but only verifies the TCP level, and isn't a datagram */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_NO);
        lose_packets(s, IPPROTO_TCP, RETRY_ATTEMPTS - 1);
        ASSERT_EQ(d->n_failed_tcp, RETRY_ATTEMPTS - 1);
        dns_server_packet_received(s, IPPROTO_TCP, dns_server_possible_feature_level(s), 1000);
        ASSERT_EQ(d->n_failed_tcp, 0U);
        ASSERT_EQ(d->received_udp_fragment_max, (size_t) DNS_PACKET_UNICAST_SIZE_MAX);
        assert_verified_feature_level(s, "TCP");

        /* Without RRSIGs, a reply sent with the DO bit only verifies EDNS0 */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_ALLOW_DOWNGRADE);
        dns_server_packet_rrsig_missing(s, levels_in_order[LEVEL_UDP_DO]);
        dns_server_packet_received(s, IPPROTO_UDP, levels_in_order[LEVEL_UDP_DO], 0);
        assert_verified_feature_level(s, "UDP+EDNS0");

        /* Once the OPT RR got lost, a reply sent with EDNS0 only verifies plain UDP */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_NO, DNSSEC_NO);
        dns_server_packet_bad_opt(s, levels_in_order[LEVEL_UDP_EDNS0]);
        dns_server_packet_received(s, IPPROTO_UDP, levels_in_order[LEVEL_UDP_EDNS0], 0);
        assert_verified_feature_level(s, "UDP");

#if ENABLE_DNS_OVER_TLS
        /* DNS-over-TLS replies arrive via TCP, but verify the TLS level itself */
        possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, DNSSEC_NO);
        dns_server_packet_received(s, IPPROTO_TCP, dns_server_possible_feature_level(s), 0);
        assert_verified_feature_level(s, "TLS+EDNS0");

        /* Once verified, a failed TLS connection doesn't make us fall back to classic DNS */
        lose_packets(s, IPPROTO_TCP, 1);
        assert_possible_feature_level(s, "TLS+EDNS0");

        /* ... unless the policy no longer permits DNS-over-TLS, in which case the verified level is ignored */
        manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
        assert_possible_feature_level(s, "UDP+EDNS0");
        assert_possible_feature_level(s, "UDP+EDNS0"); /* ... and doesn't take over again later */
#endif

        dns_server_unlink(s);
}

static int on_stream_packet_unexpected(DnsStream *s, DnsPacket *p) {
        assert_not_reached();
}

static DnsStream* idle_stream_new(Manager *m, int *ret_peer) {
        _cleanup_close_pair_ int fd[2] = EBADF_PAIR;
        DnsStream *stream;

        assert(m);
        assert(ret_peer);

        /* A stream on one end of a socket pair, which never sees any traffic */
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, fd));
        ASSERT_OK(dns_stream_new(m, &stream, DNS_STREAM_LOOKUP, DNS_PROTOCOL_DNS, fd[0], /* tfo_address= */ NULL,
                                 on_stream_packet_unexpected, /* complete= */ NULL, USEC_PER_HOUR));
        TAKE_FD(fd[0]);
        *ret_peer = TAKE_FD(fd[1]);

        return stream;
}

TEST(transport_port) {
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        DnsServer *s = NULL, *s_port = NULL;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));
        ASSERT_OK(dns_server_new(&manager, &s_port, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 5353, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        /* Without a port configured, each transport uses its own well-known port. A configured port is used
         * for all transports. */
        ASSERT_EQ(dns_server_transport_port(s->transports[DNS_TRANSPORT_DNS]), 53U);
        ASSERT_EQ(dns_server_transport_port(s_port->transports[DNS_TRANSPORT_DNS]), 5353U);
#if ENABLE_DNS_OVER_TLS
        ASSERT_EQ(dns_server_transport_port(s->transports[DNS_TRANSPORT_DOT]), 853U);
        ASSERT_EQ(dns_server_transport_port(s_port->transports[DNS_TRANSPORT_DOT]), 5353U);
#endif

        dns_server_unlink(s);
        dns_server_unlink(s_port);
}

TEST(transport_stream) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        _cleanup_close_ int peer_old = -EBADF, peer_cur = -EBADF;
        DnsServer *s = NULL;
        DnsServerTransport *tr;
        DnsStream *stream_old, *stream_cur;

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));
        tr = ASSERT_PTR(s->transports[DNS_TRANSPORT_DNS]);
        ASSERT_EQ(s->n_ref, 1U);

        /* A stream registered as the transport's long-lived one belongs to that transport, and keeps the
         * server alive */
        stream_old = idle_stream_new(&manager, &peer_old);
        dns_server_transport_set_stream(tr, stream_old);
        ASSERT_PTR_EQ(tr->stream, stream_old);
        ASSERT_PTR_EQ(stream_old->transport, tr);
        ASSERT_EQ(s->n_ref, 2U);

        /* A new one replaces it, the old one keeps belonging to the transport while it is still referenced
         * elsewhere, by us here, standing in for a transaction */
        stream_cur = idle_stream_new(&manager, &peer_cur);
        dns_server_transport_set_stream(tr, stream_cur);
        ASSERT_PTR_EQ(tr->stream, stream_cur);
        ASSERT_PTR_EQ(stream_old->transport, tr);
        ASSERT_PTR_EQ(stream_cur->transport, tr);
        ASSERT_EQ(s->n_ref, 3U);

        /* Transactions reuse the long-lived stream, rather than opening a new one */
        DnsStream *reused = NULL;
        ASSERT_OK(dns_server_transport_open_stream(tr, /* t= */ NULL, &reused));
        ASSERT_PTR_EQ(reused, stream_cur);
        dns_stream_unref(reused);

        /* Detaching a stream that isn't the long-lived one anymore leaves the current one alone */
        dns_stream_detach(stream_old);
        ASSERT_PTR_EQ(tr->stream, stream_cur);

        /* Detaching the long-lived one unregisters it */
        dns_stream_detach(stream_cur);
        ASSERT_NULL(tr->stream);

        /* The server is only released together with the streams */
        ASSERT_EQ(s->n_ref, 3U);
        dns_stream_unref(stream_old);
        dns_stream_unref(stream_cur);
        ASSERT_EQ(s->n_ref, 1U);

        dns_server_unlink(s);
}

TEST(transport_stream_replace_last_reference) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        _cleanup_close_ int peer_old = -EBADF, peer_new = -EBADF;
        DnsServer *s = NULL;
        DnsServerTransport *tr;
        DnsStream *stream_old, *stream_new;

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));
        tr = ASSERT_PTR(s->transports[DNS_TRANSPORT_DNS]);

        /* Leave the long-lived stream holding the only reference to the server. Unlinking drops the
         * server's streams too, hence register the stream only afterwards, while we hold a reference. */
        dns_server_ref(s);
        dns_server_unlink(s);
        stream_old = idle_stream_new(&manager, &peer_old);
        dns_server_transport_set_stream(tr, stream_old);
        dns_stream_unref(stream_old);
        dns_server_unref(s);
        ASSERT_EQ(s->n_ref, 1U);

        /* Replacing that stream must not free the server along with it */
        stream_new = idle_stream_new(&manager, &peer_new);
        dns_server_transport_set_stream(tr, stream_new);
        ASSERT_EQ(s->n_ref, 1U);
        ASSERT_PTR_EQ(tr->stream, stream_new);

        /* Dropping the last stream releases the server */
        dns_stream_detach(stream_new);
        dns_stream_unref(stream_new);
}

#if ENABLE_DNS_OVER_TLS
TEST(policy_drops_stream) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        _cleanup_close_ int peer = -EBADF;
        DnsServer *s = NULL;
        DnsStream *stream;
        DnssecMode dnssec;

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        /* The long-lived stream of a transport the policy no longer permits is closed, both if the transport
         * is dropped because the best feature level is lower (DNSSEC off), and because the policy doesn't
         * permit it (DNSSEC on, where the best level is UDP+EDNS0+DO, which ranks above TLS+EDNS0) */
        FOREACH_ARGUMENT(dnssec, DNSSEC_NO, DNSSEC_ALLOW_DOWNGRADE) {
                possible_feature_level_setup(&manager, s, DNS_OVER_TLS_OPPORTUNISTIC, dnssec);
                if (dnssec != DNSSEC_NO)
                        dns_server_packet_do_off(s, dns_server_possible_feature_level(s));
                assert_possible_feature_level(s, "TLS+EDNS0");

                stream = idle_stream_new(&manager, &peer);
                dns_server_transport_set_stream(s->transports[DNS_TRANSPORT_DOT], stream);

                manager.dns_over_tls_mode = DNS_OVER_TLS_NO;
                ASSERT_EQ(dns_server_possible_feature_level(s).transport, DNS_TRANSPORT_DNS);
                ASSERT_NULL(s->transports[DNS_TRANSPORT_DOT]->stream);

                stream = dns_stream_unref(stream);
                peer = safe_close(peer);
        }

        dns_server_unlink(s);
}

TEST(reset_features_detaches_tls_streams) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        union in_addr_union address = { .in.s_addr = htobe32(0xc0000201) };
        Manager manager = {};
        _cleanup_close_ int peer_old = -EBADF, peer_cur = -EBADF, peer_dns = -EBADF;
        DnsTlsServerData other = {};
        DnsServer *s = NULL;
        DnsStream *stream_old, *stream_cur, *stream_dns;

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;

        ASSERT_OK(dns_server_new(&manager, &s, DNS_SERVER_SYSTEM, /* link= */ NULL, /* delegate= */ NULL,
                                 AF_INET, &address, /* port= */ 0, /* ifindex= */ 0, /* server_name= */ NULL,
                                 RESOLVE_CONFIG_SOURCE_DBUS));

        DnsTransportDot *dot = ASSERT_PTR(DNS_TRANSPORT_TO_DOT(s->transports[DNS_TRANSPORT_DOT]));

        /* Two streams that save their TLS session to the server when shut down: one that has been replaced
         * as the default stream but is still referenced (by us, standing in for a transaction), and the
         * current default stream. */
        stream_old = idle_stream_new(&manager, &peer_old);
        stream_old->dnstls_data.server_data = &dot->tls_data;
        dns_server_transport_set_stream(&dot->meta, stream_old);

        stream_cur = idle_stream_new(&manager, &peer_cur);
        stream_cur->dnstls_data.server_data = &dot->tls_data;
        dns_server_transport_set_stream(&dot->meta, stream_cur);
        ASSERT_PTR_EQ(dot->meta.stream, stream_cur);

        /* A stream of another transport is left alone */
        stream_dns = idle_stream_new(&manager, &peer_dns);
        stream_dns->dnstls_data.server_data = &other;
        dns_server_transport_set_stream(s->transports[DNS_TRANSPORT_DNS], stream_dns);

        /* Resetting the features must not only forget the session, but also keep streams that outlive the
         * reset from saving theirs back, as it might have been negotiated without verifying the server. */
        dns_server_reset_features(s);
        ASSERT_NULL(dot->tls_data.session);
        ASSERT_NULL(dot->meta.stream);
        ASSERT_NULL(stream_old->dnstls_data.server_data);
        ASSERT_NULL(stream_cur->dnstls_data.server_data);
        ASSERT_PTR_EQ(stream_dns->dnstls_data.server_data, &other);

        dns_stream_unref(stream_old);
        dns_stream_unref(stream_cur);
        dns_stream_unref(stream_dns);
        dns_server_unlink(s);
}
#endif

DEFINE_TEST_MAIN(LOG_DEBUG)
