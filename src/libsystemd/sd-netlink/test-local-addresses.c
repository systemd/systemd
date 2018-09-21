/* SPDX-License-Identifier: LGPL-2.1+ */

#include "af-list.h"
#include "alloc-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "tests.h"

static void print_local_addresses(struct local_address *a, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++) {
                _cleanup_free_ char *b = NULL;

                assert_se(in_addr_to_string(a[i].family, &a[i].address, &b) >= 0);
                printf("%s if%i scope=%i metric=%u address=%s\n", af_to_name(a[i].family), a[i].ifindex, a[i].scope, a[i].metric, b);
        }
}

int main(int argc, char *argv[]) {
        struct local_address *a;
        int n;

        test_setup_logging(LOG_DEBUG);

        a = NULL;
        n = local_addresses(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);

        printf("Local Addresses:\n");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_gateways(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);

        printf("Local Gateways:\n");
        print_local_addresses(a, (unsigned) n);
        free(a);

        return 0;
}
