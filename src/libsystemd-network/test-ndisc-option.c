/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>
#include <sys/socket.h>

#include "sd-dns-resolver.h"
#include "sd-ndisc-protocol.h"

#include "dns-resolver-internal.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "icmp6-packet.h"
#include "in-addr-util.h"
#include "ndisc-option.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

#define EQ(a, b)                                \
        (CMP(a, b) == 0)

static bool ndisc_option_equal(sd_ndisc_option *a, sd_ndisc_option *b) {
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        if (!EQ(a->type, b->type))
                return false;

        switch (a->type) {
        case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
        case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
                return ether_addr_equal(&a->mac, &b->mac);

        case SD_NDISC_OPTION_PREFIX_INFORMATION:
                return
                        EQ(a->prefix.flags, b->prefix.flags) &&
                        EQ(a->prefix.prefixlen, b->prefix.prefixlen) &&
                        in6_addr_equal(&a->prefix.address, &b->prefix.address) &&
                        EQ(a->prefix.valid_lifetime, b->prefix.valid_lifetime) &&
                        EQ(a->prefix.preferred_lifetime, b->prefix.preferred_lifetime) &&
                        EQ(a->prefix.valid_until, b->prefix.valid_until) &&
                        EQ(a->prefix.preferred_until, b->prefix.preferred_until);

        case SD_NDISC_OPTION_REDIRECTED_HEADER:
                return memcmp(&a->hdr, &b->hdr, sizeof(struct ip6_hdr)) == 0;

        case SD_NDISC_OPTION_MTU:
                return EQ(a->mtu, b->mtu);

        case SD_NDISC_OPTION_HOME_AGENT:
                return
                        EQ(a->home_agent.preference, b->home_agent.preference) &&
                        EQ(a->home_agent.lifetime, b->home_agent.lifetime) &&
                        EQ(a->home_agent.valid_until, b->home_agent.valid_until);

        case SD_NDISC_OPTION_ROUTE_INFORMATION:
                return
                        EQ(a->route.preference, b->route.preference) &&
                        EQ(a->route.prefixlen, b->route.prefixlen) &&
                        in6_addr_equal(&a->route.address, &b->route.address) &&
                        EQ(a->route.lifetime, b->route.lifetime) &&
                        EQ(a->route.valid_until, b->route.valid_until);

        case SD_NDISC_OPTION_RDNSS:
                if (!EQ(a->rdnss.n_addresses, b->rdnss.n_addresses))
                        return false;

                for (size_t i = 0; i < a->rdnss.n_addresses; i++)
                        if (!in6_addr_equal(&a->rdnss.addresses[i], &b->rdnss.addresses[i]))
                                return false;

                return EQ(a->rdnss.lifetime, b->rdnss.lifetime) &&
                        EQ(a->rdnss.valid_until, b->rdnss.valid_until);

        case SD_NDISC_OPTION_FLAGS_EXTENSION:
                return EQ(a->extended_flags, b->extended_flags);

        case SD_NDISC_OPTION_DNSSL:
                return
                        strv_equal(a->dnssl.domains, b->dnssl.domains) &&
                        EQ(a->dnssl.lifetime, b->dnssl.lifetime) &&
                        EQ(a->dnssl.valid_until, b->dnssl.valid_until);

        case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                return streq(a->captive_portal, b->captive_portal);

        case SD_NDISC_OPTION_PREF64:
                return
                        EQ(a->prefix64.prefixlen, b->prefix64.prefixlen) &&
                        in6_addr_equal(&a->prefix64.prefix, &b->prefix64.prefix) &&
                        EQ(a->prefix64.lifetime, b->prefix64.lifetime) &&
                        EQ(a->prefix64.valid_until, b->prefix64.valid_until);

        case SD_NDISC_OPTION_ENCRYPTED_DNS:
                if (!EQ(a->encrypted_dns.lifetime, b->encrypted_dns.lifetime) ||
                    !EQ(a->encrypted_dns.valid_until, b->encrypted_dns.valid_until) ||
                    !EQ(a->encrypted_dns.resolver->priority, b->encrypted_dns.resolver->priority) ||
                    !streq_ptr(a->encrypted_dns.resolver->auth_name, b->encrypted_dns.resolver->auth_name) ||
                    !EQ(a->encrypted_dns.resolver->family, b->encrypted_dns.resolver->family) ||
                    !EQ(a->encrypted_dns.resolver->n_addrs, b->encrypted_dns.resolver->n_addrs))
                        return false;

                for (size_t i = 0; i < a->encrypted_dns.resolver->n_addrs; i++)
                        if (in_addr_equal(a->encrypted_dns.resolver->family,
                                          &a->encrypted_dns.resolver->addrs[i],
                                          &b->encrypted_dns.resolver->addrs[i]) <= 0)
                                return false;

                return
                        EQ(a->encrypted_dns.resolver->transports, b->encrypted_dns.resolver->transports) &&
                        EQ(a->encrypted_dns.resolver->port, b->encrypted_dns.resolver->port) &&
                        streq_ptr(a->encrypted_dns.resolver->dohpath, b->encrypted_dns.resolver->dohpath);
                break;
        default:
                return memcmp_nn(a->raw.bytes, a->raw.length, b->raw.bytes, b->raw.length) == 0;
        }
}

static void ndisc_round_trip(Set *options) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        ASSERT_OK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, /* protocol= */ 0, pair));

        static const struct nd_router_advert ra = {
                .nd_ra_type = ND_ROUTER_ADVERT,
        };

        ASSERT_OK(ndisc_send(pair[1], &(struct in6_addr) {}, &ra.nd_ra_hdr, options, now(CLOCK_BOOTTIME)));

        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        ASSERT_OK(icmp6_packet_receive(pair[0], &packet));

        _cleanup_set_free_ Set *reparsed = NULL;
        ASSERT_OK(ndisc_parse_options(packet, &reparsed));

        ASSERT_EQ(set_size(options), set_size(reparsed));

        sd_ndisc_option *option;
        SET_FOREACH(option, options) {
                bool found = false;
                sd_ndisc_option *p;
                SET_FOREACH(p, reparsed)
                        if (ndisc_option_equal(option, p)) {
                                found = true;
                                break;
                        }
                ASSERT_TRUE(found);
        }
}

TEST(ndisc_mac) {
        _cleanup_set_free_ Set *options = NULL;
        ASSERT_OK(ndisc_option_set_link_layer_address(
                                  &options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS,
                                  &(struct ether_addr) {{ 'A', 'B', 'C', '1', '2', '3' }}));
        ASSERT_OK(ndisc_option_set_link_layer_address(
                                  &options, SD_NDISC_OPTION_TARGET_LL_ADDRESS,
                                  &(struct ether_addr) {{ 'A', 'B', 'C', '1', '2', '4' }}));
        ndisc_round_trip(options);
}

static void append_prefix(
                Set **options,
                uint8_t flags,
                uint8_t prefixlen,
                const char *addr,
                usec_t valid_lifetime,
                usec_t preferred_lifetime) {

        union in_addr_union a;
        ASSERT_OK(in_addr_from_string(AF_INET6, addr, &a));
        ASSERT_OK(ndisc_option_set_prefix(options, flags, prefixlen, &a.in6, valid_lifetime, preferred_lifetime, USEC_INFINITY, USEC_INFINITY));
}

TEST(ndisc_prefix) {
        _cleanup_set_free_ Set *options = NULL;
        append_prefix(&options,
                      /* flags= */ 0,
                      /* prefixlen= */ 72,
                      "dead:beef:0:1::",
                      2 * USEC_PER_HOUR,
                      USEC_PER_HOUR);
        append_prefix(&options,
                      ND_OPT_PI_FLAG_AUTO,
                      /* prefixlen= */ 64,
                      "dead:beef:0:2::",
                      3 * USEC_PER_HOUR,
                      USEC_PER_HOUR);
        append_prefix(&options,
                      ND_OPT_PI_FLAG_ONLINK,
                      /* prefixlen= */ 64,
                      "dead:beef:0:3::",
                      4 * USEC_PER_HOUR,
                      USEC_PER_HOUR);
        ndisc_round_trip(options);
}

TEST(ndisc_mtu) {
        _cleanup_set_free_ Set *options = NULL;
        ASSERT_OK(ndisc_option_set_mtu(&options, 4096));
        ndisc_round_trip(options);
}

TEST(ndisc_home_agent) {
        _cleanup_set_free_ Set *options = NULL;
        ASSERT_OK(ndisc_option_set_home_agent(&options, 128, USEC_PER_HOUR, USEC_INFINITY));
        ndisc_round_trip(options);
}

static void append_route(
                Set **options,
                uint8_t preference,
                uint8_t prefixlen,
                const char *prefix,
                usec_t lifetime) {

        union in_addr_union a;
        ASSERT_OK(in_addr_from_string(AF_INET6, prefix, &a));
        ASSERT_OK(ndisc_option_set_route(options, preference, prefixlen, &a.in6, lifetime, USEC_INFINITY));
}

TEST(ndisc_route) {
        _cleanup_set_free_ Set *options = NULL;
        append_route(&options,
                     /* preference= */ SD_NDISC_PREFERENCE_LOW,
                     /* prefixlen= */ 64,
                     "dead:beef:0:1::",
                     1 * USEC_PER_HOUR);
        append_route(&options,
                     /* preference= */ SD_NDISC_PREFERENCE_MEDIUM,
                     /* prefixlen= */ 72,
                     "dead:beef:0:2::",
                     2 * USEC_PER_HOUR);
        append_route(&options,
                     /* preference= */ SD_NDISC_PREFERENCE_HIGH,
                     /* prefixlen= */ 80,
                     "dead:beef:0:3::",
                     3 * USEC_PER_HOUR);
        ndisc_round_trip(options);
}

static void append_rdnss(
                Set **options,
                char* const* addrs,
                usec_t lifetime) {

        _cleanup_free_ struct in6_addr *addresses = ASSERT_NOT_NULL(new(struct in6_addr, strv_length(addrs)));
        size_t n = 0;
        STRV_FOREACH(s, addrs) {
                union in_addr_union a;
                ASSERT_OK(in_addr_from_string(AF_INET6, *s, &a));
                addresses[n++] = a.in6;
        }

        ASSERT_OK(ndisc_option_set_rdnss(options, n, addresses, lifetime, USEC_INFINITY));
}

TEST(ndisc_rdnss) {
        _cleanup_set_free_ Set *options = NULL;
        append_rdnss(&options,
                     STRV_MAKE("dead:beef::1"),
                     1 * USEC_PER_HOUR);
        append_rdnss(&options,
                     STRV_MAKE("dead:beef::2", "dead:beef::3", "dead:beef::4"),
                     2 * USEC_PER_HOUR);
        ndisc_round_trip(options);
}

TEST(ndisc_flags_extension) {
        _cleanup_set_free_ Set *options = NULL;
        ASSERT_OK(ndisc_option_add_flags_extension(&options, /* offset= */ 0, UINT64_C(0x0066554433221100)));
        ndisc_round_trip(options);
}

TEST(ndisc_dnssl) {
        _cleanup_set_free_ Set *options = NULL;
        ASSERT_OK(ndisc_option_set_dnssl(
                                  &options,
                                  STRV_MAKE("dns1.example.com"),
                                  1 * USEC_PER_HOUR, USEC_INFINITY));
        ASSERT_OK(ndisc_option_set_dnssl(
                                  &options,
                                  STRV_MAKE("dns2.example.com", "dns3.example.com", "dns4.example.com"),
                                  2 * USEC_PER_HOUR, USEC_INFINITY));
        ndisc_round_trip(options);
}

TEST(ndisc_captive_portal) {
        _cleanup_set_free_ Set *options = NULL;
        ndisc_option_set_captive_portal(&options, "https://captive-portal.example.com");
        ndisc_round_trip(options);
}

static void append_prefix64(
                Set **options,
                uint8_t prefixlen,
                const char *prefix,
                usec_t lifetime) {

        union in_addr_union a;
        ASSERT_OK(in_addr_from_string(AF_INET6, prefix, &a));
        ASSERT_OK(ndisc_option_set_prefix64(options, prefixlen, &a.in6, lifetime, USEC_INFINITY));
}

TEST(ndisc_prefix64) {
        _cleanup_set_free_ Set *options = NULL;
        append_prefix64(&options,
                        /* prefixlen= */ 56,
                        "dead:beef:0:1::",
                        1 * USEC_PER_HOUR);
        append_prefix64(&options,
                        /* prefixlen= */ 64,
                        "dead:beef:0:2::",
                        2 * USEC_PER_HOUR);
        append_prefix64(&options,
                        /* prefixlen= */ 96,
                        "dead:beef:0:3::",
                        3 * USEC_PER_HOUR);
        ndisc_round_trip(options);
}

static void append_dnr(
                Set **options,
                uint16_t priority,
                const char *auth_name,
                char* const* addrs,
                sd_dns_alpn_flags transports,
                uint16_t port,
                const char *dohpath) {

        _cleanup_(sd_dns_resolver_unrefp) sd_dns_resolver *res = ASSERT_NOT_NULL(new0(sd_dns_resolver, 1));
        res->priority = priority;
        ASSERT_OK(strdup_to(&res->auth_name, auth_name));
        res->addrs = ASSERT_NOT_NULL(new(union in_addr_union, strv_length(addrs)));
        STRV_FOREACH(a, addrs)
                ASSERT_OK(in_addr_from_string_auto(*a, &res->family, &res->addrs[res->n_addrs++]));
        res->transports = transports;
        res->port = port;
        ASSERT_OK(strdup_to(&res->dohpath, dohpath));

        ASSERT_OK(ndisc_option_set_encrypted_dns(options, TAKE_PTR(res), 3600 * USEC_PER_SEC, USEC_INFINITY));
}

TEST(ndisc_dnr) {
        _cleanup_set_free_ Set *options = NULL;
        append_dnr(&options,
                   /* priority= */ 1,
                   "dns.example.com",
                   STRV_MAKE("2001:db8::1"),
                   SD_DNS_ALPN_DOT,
                   /* port= */ 0,
                   /* dohpath= */ NULL);
        append_dnr(&options,
                   /* priority= */ 5,
                   "resolver.example.org",
                   STRV_MAKE("2001:db8::53", "2001:db8::54", "2001:db8::55"),
                   SD_DNS_ALPN_DOT | SD_DNS_ALPN_HTTP_2_TLS | SD_DNS_ALPN_HTTP_3 | SD_DNS_ALPN_DOQ,
                   /* port= */ 853,
                   "/dns-query{?dns}");
        ndisc_round_trip(options);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
