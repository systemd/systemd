/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <arpa/inet.h>
#include <stdlib.h>

#include "firewall-util.h"
#include "log.h"
#include "random-util.h"
#include "tests.h"

#define MAKE_IN_ADDR_UNION(a,b,c,d) (union in_addr_union) { .in.s_addr = htobe32((uint32_t) (a) << 24 | (uint32_t) (b) << 16 | (uint32_t) (c) << 8 | (uint32_t) (d))}

static void make_in6_addr_union(const char *addr, union in_addr_union *u) {
        assert_se(inet_pton(AF_INET6, addr, &u->in6) >= 0);
}

static void test_v6(FirewallContext **ctx) {
        union in_addr_union u = {}, u2 = {};
        uint8_t prefixlen;
        int r;

        make_in6_addr_union("dead::beef", &u);

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

        make_in6_addr_union("1c3::c01d", &u2);
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

        return 0;
}
