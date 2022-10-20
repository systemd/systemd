/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "af-list.h"
#include "alloc-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "tests.h"

static void print_local_addresses(struct local_address *a, unsigned n) {
        for (unsigned i = 0; i < n; i++) {
                _cleanup_free_ char *b = NULL;

                assert_se(in_addr_to_string(a[i].family, &a[i].address, &b) >= 0);
                log_debug("%s if%i scope=%i metric=%u address=%s", af_to_name(a[i].family), a[i].ifindex, a[i].scope, a[i].metric, b);
        }
}

TEST(local_addresses) {
        struct local_address *a = NULL;
        int n;

        n = local_addresses(NULL, 0, AF_INET, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:0, AF_INET) */");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_addresses(NULL, 0, AF_INET6, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:0, AF_INET6) */");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_addresses(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:0, AF_UNSPEC) */");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_addresses(NULL, 1, AF_INET, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:1, AF_INET) */");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_addresses(NULL, 1, AF_INET6, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:1, AF_INET6) */");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_addresses(NULL, 1, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Addresses(ifindex:1, AF_UNSPEC) */");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_gateways(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Gateways */");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_outbounds(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);
        log_debug("/* Local Outbounds */");
        print_local_addresses(a, (unsigned) n);
        free(a);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
