/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Round-trip test for the RFC 9463 Encrypted DNS (DNR) NDisc option.
 *
 * Build an option with ndisc_option_set_encrypted_dns(), serialise it into a Router
 * Advertisement with ndisc_send(), read it back and parse it. Whatever we put in must
 * come back out.
 */

#include <netinet/icmp6.h>
#include <sys/socket.h>

#include "sd-dns-resolver.h"

#include "alloc-util.h"
#include "dns-resolver-internal.h"
#include "fd-util.h"
#include "icmp6-packet.h"
#include "in-addr-util.h"
#include "ndisc-option.h"
#include "sd-ndisc-protocol.h"
#include "set.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

#define TEST_LIFETIME (3600 * USEC_PER_SEC)

static sd_dns_resolver* make_resolver(
                uint16_t priority,
                const char *auth_name,
                const char *addr,
                sd_dns_alpn_flags transports,
                uint16_t port,
                const char *dohpath) {

        _cleanup_(sd_dns_resolver_unrefp) sd_dns_resolver *res = NULL;

        ASSERT_NOT_NULL(res = new0(sd_dns_resolver, 1));
        ASSERT_NOT_NULL(res->auth_name = strdup(auth_name));
        ASSERT_NOT_NULL(res->addrs = new(union in_addr_union, 1));
        ASSERT_GE(in_addr_from_string(AF_INET6, addr, &res->addrs[0]), 0);

        res->priority = priority;
        res->family = AF_INET6;
        res->n_addrs = 1;
        res->transports = transports;
        res->port = port;

        if (dohpath)
                ASSERT_NOT_NULL(res->dohpath = strdup(dohpath));

        return TAKE_PTR(res);
}

/* Returns the single SD_NDISC_OPTION_ENCRYPTED_DNS option in the set, or NULL if there is
 * none.
 */
static sd_ndisc_option* dnr_option_get_encrypted_dns(Set *options) {
        sd_ndisc_option *found = NULL, *p;

        SET_FOREACH(p, options) {
                if (p->type != SD_NDISC_OPTION_ENCRYPTED_DNS)
                        continue;

                found = p;
        }

        return found;
}

/* Serialise a single DNR option into an RA, read it back and parse it. On success the
 * reparsed option set is returned in ret_options, which owns the option handed back in
 * ret_option. Returns -ENOENT if the option did not survive the round trip. */
static int dnr_round_trip(sd_dns_resolver *res, Set **ret_options, sd_ndisc_option **ret_option) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        _cleanup_set_free_ Set *built = NULL, *reparsed = NULL;
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        sd_ndisc_option *p;
        int r;

        ASSERT_NOT_NULL(res);
        ASSERT_NOT_NULL(ret_options);
        ASSERT_NOT_NULL(ret_option);

        /* Takes ownership of res. */
        r = ndisc_option_set_encrypted_dns(&built, /* offset= */ 0, res,
                                           TEST_LIFETIME, USEC_INFINITY);
        if (r < 0)
                return r;

        /* Sanity-check what we are about to send: one DNR option, holding the very resolver
         * we handed over, with the lifetime we asked for and the offset that marks an option
         * we are building rather than one we parsed. */
        p = dnr_option_get_encrypted_dns(built);
        if (!p)
                return -ENOENT;

        ASSERT_TRUE(p->offset == 0);
        ASSERT_TRUE(p->encrypted_dns.resolver == res);
        ASSERT_EQ(p->encrypted_dns.lifetime, TEST_LIFETIME);
        ASSERT_EQ(p->encrypted_dns.valid_until, USEC_INFINITY);

        ASSERT_GE(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair), 0);

        struct nd_router_advert ra = {
                .nd_ra_type = ND_ROUTER_ADVERT,
        };

        r = ndisc_send(pair[1], &(struct in6_addr) {}, &ra.nd_ra_hdr,
                       built, now(CLOCK_BOOTTIME));
        if (r < 0)
                return r;

        r = icmp6_packet_receive(pair[0], &packet);
        if (r < 0)
                return r;

        /* Note: ndisc_parse_options() logs and skips options it cannot parse, so a
         * successful return here says nothing about whether the option survived. */
        r = ndisc_parse_options(packet, &reparsed);
        if (r < 0)
                return r;

        /* The RA carries nothing but our DNR option. */
        ASSERT_TRUE(set_size(reparsed) == 1);

        p = dnr_option_get_encrypted_dns(reparsed);
        if (!p)
                return -ENOENT;

        /* The DNR option is the first and only option, hence it sits right behind the RA
         * header. The parser must not have handed us the object we built above. */
        ASSERT_EQ(p->offset, sizeof(struct nd_router_advert));
        ASSERT_NOT_NULL(p->encrypted_dns.resolver);

        /* Lifetimes go on the wire in seconds, and TEST_LIFETIME is a whole number of them,
         * so this must come back unscathed. Parsed options carry no deadline. */
        ASSERT_EQ(p->encrypted_dns.lifetime, TEST_LIFETIME);
        ASSERT_EQ(p->encrypted_dns.valid_until, USEC_INFINITY);

        *ret_option = p;
        *ret_options = TAKE_PTR(reparsed);
        return 0;
}

static void verify_round_trip(
                uint16_t priority,
                const char *auth_name,
                const char *addr,
                sd_dns_alpn_flags transports,
                uint16_t port,
                const char *dohpath) {

        _cleanup_set_free_ Set *options = NULL;
        sd_ndisc_option *p = NULL; /* owned by options */
        union in_addr_union expect_addr;

        ASSERT_GE(in_addr_from_string(AF_INET6, addr, &expect_addr), 0);

        ASSERT_EQ(dnr_round_trip(make_resolver(priority, auth_name, addr, transports, port,dohpath),
                                 &options, &p), 0);

        const sd_dns_resolver *out = p->encrypted_dns.resolver;

        ASSERT_EQ(out->priority, priority);
        ASSERT_TRUE(streq(out->auth_name, auth_name));
        ASSERT_EQ(out->family, AF_INET6);
        ASSERT_TRUE(out->n_addrs == 1);
        ASSERT_GT(in_addr_equal(AF_INET6, &out->addrs[0], &expect_addr), 0);
        ASSERT_EQ(out->transports, transports);
        ASSERT_EQ(out->port, port);
        ASSERT_TRUE(streq_ptr(out->dohpath, dohpath));
}

/* Minimal option: ADN + one address + a single ALPN SvcParam.
 */
TEST(dnr_round_trip_minimal) {
        verify_round_trip(/* priority= */ 1,
                          "dns.example.com",
                          "2001:db8::1",
                          SD_DNS_ALPN_DOT,
                          /* port= */ 0,
                          /* dohpath= */ NULL);
}

/* All optional SvcParams present (alpn=1, port=3, dohpath=7), which must appear in
 * strictly increasing key order per RFC 9460 § 2.2.
 */
TEST(dnr_round_trip_full) {
        verify_round_trip(/* priority= */ 5,
                          "resolver.example.org",
                          "2001:db8::53",
                          SD_DNS_ALPN_DOT | SD_DNS_ALPN_HTTP_2_TLS | SD_DNS_ALPN_HTTP_3 | SD_DNS_ALPN_DOQ,
                          /* port= */ 853,
                          "/dns-query{?dns}");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
