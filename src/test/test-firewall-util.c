/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "firewall-util.h"
#include "log.h"
#include "tests.h"

#define MAKE_IN_ADDR_UNION(a,b,c,d) (union in_addr_union) { .in.s_addr = htobe32((uint32_t) (a) << 24 | (uint32_t) (b) << 16 | (uint32_t) (c) << 8 | (uint32_t) (d))}

int main(int argc, char *argv[]) {
        int r;
        test_setup_logging(LOG_DEBUG);
        uint8_t prefixlen = 32;

        r = fw_add_masquerade(true, AF_INET, NULL, 0);
        if (r == 0)
                log_error("Expected failure: NULL source");

        r = fw_add_masquerade(true, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,0), 0);
        if (r == 0)
                log_error("Expected failure: 0 prefixlen");

        r = fw_add_masquerade(true, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,3), prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        prefixlen = 28;
        r = fw_add_masquerade(true, AF_INET, &MAKE_IN_ADDR_UNION(10,0,2,0), prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_masquerade(false, AF_INET, &MAKE_IN_ADDR_UNION(10,0,2,0), prefixlen);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_masquerade(false, AF_INET, &MAKE_IN_ADDR_UNION(10,1,2,3), 32);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 4), 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 4), 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(true, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 5), 815, &MAKE_IN_ADDR_UNION(1, 2, 3, 4));
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_add_local_dnat(false, AF_INET, IPPROTO_TCP, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 5), 815, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        return 0;
}
