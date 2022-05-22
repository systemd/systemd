/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <unistd.h>

#include "firewall-util.h"
#include "in-addr-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "tests.h"

int main(int argc, char **argv) {
        int r;

        assert_se(argc == 7);

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        int nfproto;
        nfproto = nfproto_from_string(argv[2]);
        assert_se(nfproto > 0);

        const NFTSetContext nft_set_context = {
                .nfproto = nfproto,
                .table = argv[3],
                .set = argv[4],
        };

        if (streq(argv[5], "uint32")) {
                uint32_t element;
                r = safe_atou32(argv[6], &element);
                assert_se(r == 0);

                if (streq(argv[1], "add"))
                        r = nft_set_element_add_uint32(&nft_set_context, element);
                else
                        r = nft_set_element_del_uint32(&nft_set_context, element);
                assert_se(r == 0);
        } else if (streq(argv[5], "uint64")) {
                uint64_t element;
                r = safe_atou64(argv[6], &element);
                assert_se(r == 0);

                if (streq(argv[1], "add"))
                        r = nft_set_element_add_uint64(&nft_set_context, element);
                else
                        r = nft_set_element_del_uint64(&nft_set_context, element);
                assert_se(r == 0);
        } else {
                union in_addr_union addr;
                int af;
                unsigned char prefixlen;

                r = in_addr_prefix_from_string_auto(argv[6], &af, &addr, &prefixlen);
                assert_se(r == 0);

                if (streq(argv[1], "add"))
                        r = nft_set_element_add_in_addr(&nft_set_context, af, &addr, prefixlen);
                else
                        r = nft_set_element_del_in_addr(&nft_set_context, af, &addr, prefixlen);
                assert_se(r == 0);
        }

        return 0;
}
