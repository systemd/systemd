/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "firewall-util.h"
#include "firewall-util-private.h"
#include "log.h"
#include "random-util.h"
#include "tests.h"

#define MAKE_IN_ADDR_UNION(a,b,c,d) (union in_addr_union) { .in.s_addr = htobe32((uint32_t) (a) << 24 | (uint32_t) (b) << 16 | (uint32_t) (c) << 8 | (uint32_t) (d))}
#define MAKE_IN6_ADDR_UNION(str, u) assert_se(in_addr_from_string(AF_INET6, str, u) >= 0)

static void test_v6(FirewallContext *ctx) {
        union in_addr_union u1 = {}, u2 = {};
        uint8_t prefixlen;

        MAKE_IN6_ADDR_UNION("dead::beef", &u1);
        MAKE_IN6_ADDR_UNION("1c3::c01d", &u2);

        assert_se(fw_add_masquerade(&ctx, true, AF_INET6, &u1, 128) >= 0);
        assert_se(fw_add_masquerade(&ctx, false, AF_INET6, &u1, 128) >= 0);
        assert_se(fw_add_masquerade(&ctx, true, AF_INET6, &u1, 64) >= 0);
        assert_se(fw_add_masquerade(&ctx, false, AF_INET6, &u1, 64) >= 0);
        int r = fw_add_local_dnat(&ctx, true, AF_INET6, IPPROTO_TCP, 4711, &u1, 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to set dnat: %m");
        assert(r >= 0);
        assert_se(fw_add_local_dnat(&ctx, true, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, &u1) >= 0);
        assert_se(fw_add_local_dnat(&ctx, false, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, NULL) >= 0);

        prefixlen = random_u32() % (128 + 1 - 8);
        prefixlen += 8;
        pseudo_random_bytes(&u1, sizeof(u1));

        assert_se(fw_add_masquerade(&ctx, true, AF_INET6, &u1, prefixlen) >= 0);
        assert_se(fw_add_masquerade(&ctx, false, AF_INET6, &u1, prefixlen) >= 0);
}

static int test_v4(FirewallContext *ctx) {
        int r;

        assert(fw_add_masquerade(&ctx, true, AF_INET, NULL, 0) == -EINVAL);
        assert(fw_add_masquerade(&ctx, true, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,0), 0) == -EINVAL);

        r = fw_add_masquerade(&ctx, true, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,3), 32);
        if (r == -EOPNOTSUPP)
                return log_info_errno(r, "firewall %s backend seems not supported, skipping test.",
                                      firewall_backend_to_string(ctx->backend));
        assert(r >= 0);

        assert(fw_add_masquerade(&ctx, true, AF_INET, &MAKE_IN_ADDR_UNION(10,0,2,0), 28) >= 0);
        assert(fw_add_masquerade(&ctx, false, AF_INET, &MAKE_IN_ADDR_UNION(10,0,2,0), 28) >= 0);
        assert(fw_add_masquerade(&ctx, false, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,3), 32) >= 0);
        assert(fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 4), 815, NULL) >= 0);
        assert(fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 4), 815, NULL) >= 0);
        assert(fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 5), 815, &MAKE_IN_ADDR_UNION(1, 2, 3, 4)) >= 0);
        assert(fw_add_local_dnat(&ctx, false, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 5), 815, NULL) >= 0);

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(fw_ctx_freep) FirewallContext *ctx = NULL;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        assert_se(fw_ctx_new(&ctx) >= 0);

        firewall_backend_probe(ctx);

        if (ctx->backend == _FW_BACKEND_INVALID)
                return EXIT_TEST_SKIP;

        log_debug("testing with %s backend.", firewall_backend_to_string(ctx->backend));
        r = test_v4(ctx);
        if (r < 0)
                return EXIT_TEST_SKIP;

        if (ctx->backend == FW_BACKEND_NFTABLES) {
                test_v6(ctx);

#if HAVE_LIBIPTC
                ctx->backend = FW_BACKEND_IPTABLES;
                log_debug("testing with %s backend.", firewall_backend_to_string(ctx->backend));
                (void) test_v4(ctx);
#endif
        }

        return 0;
}
