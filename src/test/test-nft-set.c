/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-netlink.h"

#include "firewall-util.h"
#include "in-addr-util.h"
#include "netlink-internal.h"
#include "parse-util.h"
#include "string-util.h"
#include "tests.h"

int main(int argc, char **argv) {
        ASSERT_EQ(argc, 7);

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        int nfproto;
        nfproto = nfproto_from_string(argv[2]);
        ASSERT_TRUE(nfproto_is_valid(nfproto));

        const char *table = argv[3], *set = argv[4];

        _cleanup_(sd_netlink_unrefp) sd_netlink *nfnl = NULL;
        ASSERT_OK(sd_nfnl_socket_open(&nfnl));

        bool add;
        if (streq(argv[1], "add"))
                add = true;
        else
                add = false;

        if (streq(argv[5], "uint32")) {
                uint32_t element;

                ASSERT_OK_ZERO(safe_atou32(argv[6], &element));

                ASSERT_OK_ZERO(nft_set_element_modify_any(nfnl, add, nfproto, table, set,
                                                          &element, sizeof(element)));
        } else if (streq(argv[5], "uint64")) {
                uint64_t element;

                ASSERT_OK_ZERO(safe_atou64(argv[6], &element));

                ASSERT_OK_ZERO(nft_set_element_modify_any(nfnl, add, nfproto, table, set,
                                                          &element, sizeof(element)));
        } else if (streq(argv[5], "in_addr")) {
                union in_addr_union addr;
                int af;

                ASSERT_OK_ZERO(in_addr_from_string_auto(argv[6], &af, &addr));

                ASSERT_OK_ZERO(nft_set_element_modify_ip(nfnl, add, nfproto, af, table, set, &addr));
        } else if (streq(argv[5], "network")) {
                union in_addr_union addr;
                int af;
                unsigned char prefixlen;

                ASSERT_OK_ZERO(in_addr_prefix_from_string_auto(argv[6], &af, &addr, &prefixlen));

                ASSERT_OK_ZERO(nft_set_element_modify_iprange(nfnl, add, nfproto, af, table, set,
                                                              &addr, prefixlen));
        }

        return 0;
}
