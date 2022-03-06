/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <unistd.h>

#include "firewall-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "tests.h"

int main(int argc, char **argv) {
        int r;

        assert_se(argc == 6);

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        int nfproto;
        nfproto = nfproto_from_string(argv[2]);
        assert_se(nfproto > 0);

        uint32_t element;
        r = safe_atou32(argv[5], &element);
        assert_se(r == 0);

        const NFTSetContext nft_set_context = {
                .nfproto = nfproto,
                .table = argv[3],
                .set = argv[4],
        };

        if (streq(argv[1], "add"))
                r = nft_set_element_add_uint32(&nft_set_context, element);
        else
                r = nft_set_element_del_uint32(&nft_set_context, element);
        assert_se(r == 0);

        return 0;
}
