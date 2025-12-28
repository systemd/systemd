/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "firewall-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "netlink-internal.h"
#include "random-util.h"
#include "socket-util.h"
#include "tests.h"

static sd_netlink *nfnl = NULL;

TEST(v6) {
        union in_addr_union u1, u2, u3;
        uint8_t prefixlen;
        int r;

        ASSERT_NOT_NULL(nfnl);

        if (!socket_ipv6_is_supported())
                return log_info("IPv6 is not supported by kernel, skipping tests.");

        ASSERT_OK(in_addr_from_string(AF_INET6, "dead::beef", &u1));
        ASSERT_OK(in_addr_from_string(AF_INET6, "1c3::c01d", &u2));

        prefixlen = random_u64_range(128 + 1 - 8) + 8;
        random_bytes(&u3, sizeof(u3));

        ASSERT_OK_OR(r = fw_nftables_add_masquerade(nfnl, true, AF_INET6, &u1, 128),
                     -EPERM, -EOPNOTSUPP, -ENOPROTOOPT);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to add IPv6 masquerade");

        ASSERT_OK(fw_nftables_add_masquerade(nfnl, false, AF_INET6, &u1, 128));
        ASSERT_OK(fw_nftables_add_masquerade(nfnl, true, AF_INET6, &u1, 64));
        ASSERT_OK(fw_nftables_add_masquerade(nfnl, false, AF_INET6, &u1, 64));
        ASSERT_OK(fw_nftables_add_masquerade(nfnl, true, AF_INET6, &u3, prefixlen));
        ASSERT_OK(fw_nftables_add_masquerade(nfnl, false, AF_INET6, &u3, prefixlen));
        ASSERT_OK(fw_nftables_add_local_dnat(nfnl, true, AF_INET6, IPPROTO_TCP, 4711, &u1, 815, NULL));
        ASSERT_OK(fw_nftables_add_local_dnat(nfnl, true, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, &u1));
        ASSERT_OK(fw_nftables_add_local_dnat(nfnl, false, AF_INET6, IPPROTO_TCP, 4711, &u2, 815, NULL));
}

static union in_addr_union *parse_addr(const char *str, union in_addr_union *u) {
        ASSERT_NOT_NULL(str);
        ASSERT_NOT_NULL(u);
        ASSERT_OK(in_addr_from_string(AF_INET, str, u));
        return u;
}

TEST(v4) {
        union in_addr_union u, v;
        int r;

        ASSERT_NOT_NULL(nfnl);

        ASSERT_ERROR(fw_nftables_add_masquerade(nfnl, true, AF_INET, NULL, 0), EINVAL);
        ASSERT_ERROR(fw_nftables_add_masquerade(nfnl, true, AF_INET, parse_addr("10.1.2.0", &u), 0), EINVAL);

        ASSERT_OK_OR(r = fw_nftables_add_masquerade(nfnl, true, AF_INET, parse_addr("10.1.2.3", &u), 32),
                     -EPERM, -EOPNOTSUPP, -ENOPROTOOPT);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to add IPv4 masquerade");

        ASSERT_OK(fw_nftables_add_masquerade(nfnl, true, AF_INET, parse_addr("10.0.2.0", &u), 28));
        ASSERT_OK(fw_nftables_add_masquerade(nfnl, false, AF_INET, parse_addr("10.0.2.0", &u), 28));
        ASSERT_OK(fw_nftables_add_masquerade(nfnl, false, AF_INET, parse_addr("10.1.2.3", &u), 32));
        ASSERT_OK(fw_nftables_add_local_dnat(nfnl, true, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.4", &u), 815, NULL));
        ASSERT_OK(fw_nftables_add_local_dnat(nfnl, true, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.4", &u), 815, NULL));
        ASSERT_OK(fw_nftables_add_local_dnat(nfnl, true, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.5", &u), 815, parse_addr("1.2.3.4", &v)));
        ASSERT_OK(fw_nftables_add_local_dnat(nfnl, false, AF_INET, IPPROTO_TCP, 4711, parse_addr("1.2.3.5", &u), 815, NULL));
}

static int intro(void) {
        int r;

        ASSERT_OK_ERRNO(setenv("SYSTEMD_FIREWALL_UTIL_NFT_TABLE_NAME", "io.systemd-test.nat", /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_FIREWALL_UTIL_DNAT_MAP_NAME", "test_map_port_ipport", /* overwrite= */ true));

        r = sd_nfnl_socket_open(&nfnl);
        if (r < 0)
                return log_tests_skipped_errno(r, "Failed to initialize nftables");

        return 0;
}

static int outro(void) {
        sd_netlink_unref(nfnl);
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, outro);
