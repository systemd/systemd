/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "firewall-util.h"
#include "log.h"
#include "random-util.h"
#include "tests.h"

#define MAKE_IN_ADDR_UNION(a,b,c,d) (union in_addr_union) { .in.s_addr = htobe32((uint32_t) (a) << 24 | (uint32_t) (b) << 16 | (uint32_t) (c) << 8 | (uint32_t) (d))}
#define MAKE_IN6_ADDR_UNION(str, u) assert_se(in_addr_from_string(AF_INET6, str, u) >= 0)
#define assert_in6_eq(a, b) assert_se(memcmp(a, b, FAMILY_ADDRESS_SIZE(AF_INET6)) == 0)
#define assert_in6_eq_str(str, u)               \
        ({                                      \
                union in_addr_union _t;         \
                MAKE_IN6_ADDR_UNION(str, &_t);  \
                assert_in6_eq(u, &_t);           \
        })

void nft_in6addr_to_range(const union in_addr_union *source, unsigned int prefixlen,
                          struct in6_addr *start, struct in6_addr *end);

static void test_v6(FirewallContext **ctx) {
        union in_addr_union u = {}, u2 = {};
        uint8_t prefixlen;
        int r;

        MAKE_IN6_ADDR_UNION("dead::beef", &u);

        r = fw_add_masquerade(ctx, true, AF_INET6, &u, 128);
        if (r < 0)
                log_error_errno(r, "Failed to modify ipv6 firewall: %m");

        r = fw_add_masquerade(ctx, false, AF_INET6, &u, 128);
        if (r < 0)
                log_error_errno(r, "Failed to modify ipv6 firewall: %m");

        r = fw_add_masquerade(ctx, true, AF_INET6, &u, 64);
        if (r < 0)
                log_error_errno(r, "Failed to modify ipv6 firewall: %m");

        r = fw_add_masquerade(ctx, false, AF_INET6, &u, 64);
        if (r < 0)
                log_error_errno(r, "Failed to modify ipv6 firewall: %m");

        r = fw_add_local_dnat(ctx, true, AF_INET6, IPPROTO_TCP, 4711, &u, 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        MAKE_IN6_ADDR_UNION("1c3::c01d", &u2);
        r = fw_add_local_dnat(ctx, true, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, &u);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(ctx, false, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        prefixlen = random_u32() % (128 + 1 - 8);
        prefixlen += 8;
        pseudo_random_bytes(&u, sizeof(u));

        r = fw_add_masquerade(ctx, true, AF_INET6, &u, prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify ipv6 firewall: %m");

        r = fw_add_masquerade(ctx, false, AF_INET6, &u, prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify ipv6 firewall: %m");
}

static void test_v6_range(void) {
        unsigned int prefixlen = 64;
        union in_addr_union a, b, s;

        MAKE_IN6_ADDR_UNION("dead:0:0:beef::", &s);

        nft_in6addr_to_range(&s, prefixlen, &a.in6, &b.in6);
        assert_in6_eq(&s, &a);
        assert_in6_eq_str("dead:0:0:bef0::", &b);

        MAKE_IN6_ADDR_UNION("2001::", &s);
        prefixlen = 56;
        nft_in6addr_to_range(&s, prefixlen, &a.in6, &b.in6);
        assert_in6_eq(&s, &a);
        assert_in6_eq_str("2001:0:0:0100::", &b);

        prefixlen = 48;
        nft_in6addr_to_range(&s, prefixlen, &a.in6, &b.in6);
        assert_in6_eq(&s, &a);
        assert_in6_eq_str("2001:0:0001::", &b);

        prefixlen = 65;
        nft_in6addr_to_range(&s, prefixlen, &a.in6, &b.in6);
        assert_in6_eq_str("2001::", &a);
        assert_in6_eq_str("2001::8000:0:0:0", &b);

        prefixlen = 66;
        nft_in6addr_to_range(&s, prefixlen, &a.in6, &b.in6);
        assert_in6_eq(&s, &a);
        assert_in6_eq_str("2001::4000:0:0:0", &b);

        prefixlen = 127;
        nft_in6addr_to_range(&s, prefixlen, &a.in6, &b.in6);
        assert_in6_eq(&s, &a);
        assert_in6_eq_str("2001::0002", &b);

        MAKE_IN6_ADDR_UNION("dead:beef::1", &s);
        prefixlen = 64;
        nft_in6addr_to_range(&s, prefixlen, &a.in6, &b.in6);
        assert_in6_eq_str("dead:beef::", &a);
        assert_in6_eq_str("dead:beef:0:1::", &b);
}

int main(int argc, char *argv[]) {
        _cleanup_(fw_ctx_freep) FirewallContext *ctx;
        int r;
        test_setup_logging(LOG_DEBUG);
        uint8_t prefixlen = 32;

        r = fw_ctx_new(&ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to init firewall: %m");

        r = fw_add_masquerade(&ctx, true, AF_INET, NULL, 0);
        if (r == 0)
                log_error("Expected failure: NULL source");

        r = fw_add_masquerade(&ctx, true, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,0), 0);
        if (r == 0)
                log_error("Expected failure: 0 prefixlen");

        r = fw_add_masquerade(&ctx, true, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,3), prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        prefixlen = 28;
        r = fw_add_masquerade(&ctx, true, AF_INET, &MAKE_IN_ADDR_UNION(10,0,2,0), prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_masquerade(&ctx, false, AF_INET, &MAKE_IN_ADDR_UNION(10,0,2,0), prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_masquerade(&ctx, false, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,3), 32);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 4), 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 4), 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 5), 815, &MAKE_IN_ADDR_UNION(1, 2, 3, 4));
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(&ctx, false, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 5), 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        test_v6(&ctx);
        test_v6_range();

        return 0;
}
