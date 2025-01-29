/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "firewall-util.h"
#include "firewall-util-private.h"
#include "log.h"
#include "random-util.h"
#include "socket-util.h"
#include "tests.h"

static void test_v6(FirewallContext *ctx) {
        union in_addr_union u1, u2, u3;
        uint8_t prefixlen;
        int r;

        ASSERT_NOT_NULL(ctx);

        log_info("/* %s(backend=%s) */", __func__, firewall_backend_to_string(ctx->backend));

        if (!socket_ipv6_is_supported())
                return log_info("IPv6 is not supported by kernel, skipping tests.");

        ASSERT_OK(in_addr_from_string(AF_INET6, "dead::beef", &u1));
        ASSERT_OK(in_addr_from_string(AF_INET6, "1c3::c01d", &u2));

        prefixlen = random_u64_range(128 + 1 - 8) + 8;
        random_bytes(&u3, sizeof(u3));

        ASSERT_OK(fw_add_masquerade(&ctx, true, AF_INET6, &u1, 128));
        ASSERT_OK(fw_add_masquerade(&ctx, false, AF_INET6, &u1, 128));
        ASSERT_OK(fw_add_masquerade(&ctx, true, AF_INET6, &u1, 64));
        ASSERT_OK(fw_add_masquerade(&ctx, false, AF_INET6, &u1, 64));
        ASSERT_OK(fw_add_masquerade(&ctx, true, AF_INET6, &u3, prefixlen));
        ASSERT_OK(fw_add_masquerade(&ctx, false, AF_INET6, &u3, prefixlen));

        r = fw_add_local_dnat(&ctx, true, AF_INET6, IPPROTO_TCP, 4711, &u1, 815, NULL);
        if (r == -EOPNOTSUPP) {
                log_info("IPv6 DNAT seems not supported, skipping the following tests.");
                return;
        }
        ASSERT_OK(r);

        ASSERT_OK(fw_add_local_dnat(&ctx, true, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, &u1));
        ASSERT_OK(fw_add_local_dnat(&ctx, false, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, NULL));
}

static union in_addr_union *parse_addr(const char *str, union in_addr_union *u) {
        ASSERT_NOT_NULL(str);
        ASSERT_NOT_NULL(u);
        ASSERT_OK(in_addr_from_string(AF_INET, str, u));
        return u;
}

static bool test_v4(FirewallContext *ctx) {
        union in_addr_union u, v;
        int r;

        ASSERT_NOT_NULL(ctx);

        log_info("/* %s(backend=%s) */", __func__, firewall_backend_to_string(ctx->backend));

#if HAVE_LIBIPTC
        if (ctx->backend == FW_BACKEND_IPTABLES && fw_iptables_init_nat(NULL) < 0) {
                log_debug("iptables backend is used, but nat table is not enabled, skipping tests");
                return false;
        }
#endif

        ASSERT_ERROR(fw_add_masquerade(&ctx, true, AF_INET, NULL, 0), EINVAL);
        ASSERT_ERROR(fw_add_masquerade(&ctx, true, AF_INET, parse_addr("10.1.2.0", &u), 0), EINVAL);

        r = fw_add_masquerade(&ctx, true, AF_INET, parse_addr("10.1.2.3", &u), 32);
        if (r < 0) {
                bool ignore = IN_SET(r, -EPERM, -EOPNOTSUPP, -ENOPROTOOPT);

                log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r,
                               "Failed to add IPv4 masquerade%s: %m",
                               ignore ? ", skipping following tests" : "");

                if (ignore)
                        return false;
        }
        ASSERT_OK(r);

        ASSERT_OK(fw_add_masquerade(&ctx, true, AF_INET, parse_addr("10.0.2.0", &u), 28));
        ASSERT_OK(fw_add_masquerade(&ctx, false, AF_INET, parse_addr("10.0.2.0", &u), 28));
        ASSERT_OK(fw_add_masquerade(&ctx, false, AF_INET, parse_addr("10.1.2.3", &u), 32));
        ASSERT_OK(fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.4", &u), 815, NULL));
        ASSERT_OK(fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.4", &u), 815, NULL));
        ASSERT_OK(fw_add_local_dnat(&ctx, true, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.5", &u), 815, parse_addr("1.2.3.4", &v)));
        ASSERT_OK(fw_add_local_dnat(&ctx, false, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.5", &u), 815, NULL));

        return true;
}

int main(int argc, char *argv[]) {
        _cleanup_(fw_ctx_freep) FirewallContext *ctx = NULL;

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        ASSERT_OK_ERRNO(setenv("SYSTEMD_FIREWALL_UTIL_NFT_TABLE_NAME", "io.systemd-test.nat", /* overwrite = */ true));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_FIREWALL_UTIL_DNAT_MAP_NAME", "test_map_port_ipport", /* overwrite = */ true));

        ASSERT_OK(fw_ctx_new(&ctx));
        ASSERT_NOT_NULL(ctx);

        if (ctx->backend == FW_BACKEND_NONE)
                return log_tests_skipped("no firewall backend supported");

        if (test_v4(ctx) && ctx->backend == FW_BACKEND_NFTABLES)
                test_v6(ctx);

#if HAVE_LIBIPTC
        if (ctx->backend != FW_BACKEND_IPTABLES) {
                ctx->backend = FW_BACKEND_IPTABLES;
                test_v4(ctx);
        }
#endif

        return 0;
}
