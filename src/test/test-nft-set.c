/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <unistd.h>

#include "firewall-util.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

int main(int argc, char **argv) {
        int r;
        assert(argc == 6);

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        int family;
        family = nfproto_from_string(argv[2]);

        if (streq(argv[1], "add"))
                r = nft_set_element_add_uint32(family, argv[3], argv[4], strtol(argv[5], NULL, 0));
        else
                r = nft_set_element_del_uint32(family, argv[3], argv[4], strtol(argv[5], NULL, 0));
        assert(r == 0);

        return 0;
}
